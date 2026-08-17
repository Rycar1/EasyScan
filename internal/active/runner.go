// Package active runs explicitly authorized, bounded verification tasks. It is
// deliberately separate from passive traffic processing and enforces scope,
// rate and request-count guardrails before making any network connection.
package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	KindPortScan  = "port_scan"
	KindBasicAuth = "basic_auth_check"
	KindCrawl     = "web_crawl"
	KindHeadless  = "web_crawl_headless"
)

// CommonPorts is a fixed, intentionally small set. The runner does not
// accept arbitrary ports, ranges, CIDRs, or host lists.
var CommonPorts = []int{21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 110, 111, 123, 135, 137, 139, 143, 161, 389, 443, 445, 465, 514, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 2049, 2375, 3000, 3128, 3306, 3389, 4000, 4443, 5000, 5432, 5672, 5900, 6379, 6443, 7001, 8000, 8080, 8443}

var crawlLinkPattern = regexp.MustCompile(`(?is)\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)')`)

type Repository interface {
	CreateTask(model.ActiveTask) error
	UpdateTask(model.ActiveTask) error
	ListTasks(int) ([]model.ActiveTask, error)
	AddTaskResult(model.TaskResult) error
	ListTaskResults(string, int) ([]model.TaskResult, error)
	AddAudit(model.AuditEvent) error
	ListAudit(int) ([]model.AuditEvent, error)
}

type FeatureGate interface {
	Enabled(string) bool
}

type allowAllFeatures struct{}

func (allowAllFeatures) Enabled(string) bool { return true }

type Runner struct {
	cfg      config.Config
	engine   *engine.Engine
	store    Repository
	tasks    chan struct{}
	requests chan struct{}
	interval <-chan time.Time
	ticker   *time.Ticker
	mu       sync.Mutex
	cancels  map[string]context.CancelFunc
	sessions map[string]taskSession
	features FeatureGate
	workers  sync.WaitGroup
	stopped  bool
}

type Request struct {
	Kind           string            `json:"kind"`
	Target         string            `json:"target"`
	SessionHeaders map[string]string `json:"session_headers,omitempty"`
}

// taskSession is deliberately memory-only. It is never copied into the task,
// result, audit event, SQLite database, or report.
type taskSession struct {
	headers  http.Header
	pinned   map[string][]net.IP
	failures int
}

func New(cfg config.Config, e *engine.Engine, store Repository, gates ...FeatureGate) *Runner {
	intervalMS := cfg.Active.MinIntervalMS
	if cfg.WebScan.HTTP.MaxQPS > 0 {
		qpsInterval := (1000 + cfg.WebScan.HTTP.MaxQPS - 1) / cfg.WebScan.HTTP.MaxQPS
		if qpsInterval > intervalMS {
			intervalMS = qpsInterval
		}
	}
	interval := time.NewTicker(time.Duration(intervalMS) * time.Millisecond)
	if intervalMS == 0 {
		interval = time.NewTicker(time.Millisecond)
	}
	gate := FeatureGate(allowAllFeatures{})
	if len(gates) > 0 && gates[0] != nil {
		gate = gates[0]
	}
	return &Runner{cfg: cfg, engine: e, store: store, tasks: make(chan struct{}, cfg.Active.MaxConcurrentTasks), requests: make(chan struct{}, cfg.Active.MaxConcurrentRequests), interval: interval.C, ticker: interval, cancels: map[string]context.CancelFunc{}, sessions: map[string]taskSession{}, features: gate}
}

func (r *Runner) Submit(request Request) (model.ActiveTask, error) {
	r.mu.Lock()
	stopped := r.stopped
	r.mu.Unlock()
	if stopped {
		return model.ActiveTask{}, errors.New("主动扫描服务正在关闭")
	}
	request.Kind = strings.ToLower(strings.TrimSpace(request.Kind))
	if request.Kind != KindPortScan && request.Kind != KindBasicAuth && request.Kind != KindCrawl && request.Kind != KindHeadless {
		return model.ActiveTask{}, fmt.Errorf("不支持的扫描类型 %q", request.Kind)
	}
	if !r.features.Enabled("active." + request.Kind) {
		return model.ActiveTask{}, fmt.Errorf("本地 feature 策略已关闭 %q", request.Kind)
	}
	if request.Kind == KindHeadless && !r.cfg.Active.EnableHeadlessCrawl {
		return model.ActiveTask{}, errors.New("浏览器爬取未启用；将 active.enable_headless_crawl 设为 true 后再试")
	}
	target, err := r.normalizeTarget(request.Kind, request.Target)
	if err != nil {
		return model.ActiveTask{}, err
	}
	headers, err := sanitizeSessionHeaders(request.SessionHeaders)
	if err != nil {
		return model.ActiveTask{}, err
	}
	if request.Kind == KindBasicAuth && len(headers) > 0 {
		return model.ActiveTask{}, errors.New("HTTP Basic 认证检测不支持携带登录会话头")
	}
	now := time.Now().UTC()
	task := model.ActiveTask{ID: newID(), Kind: request.Kind, Target: target, Status: "queued", CreatedAt: now, Summary: map[string]int{}}
	if err := r.store.CreateTask(task); err != nil {
		return model.ActiveTask{}, fmt.Errorf("save task: %w", err)
	}
	_ = r.audit(task.ID, "active_task_created", "accepted", task.Kind+" "+task.Target)
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancels[task.ID] = cancel
	r.sessions[task.ID] = taskSession{headers: headers, pinned: map[string][]net.IP{}}
	r.mu.Unlock()
	r.mu.Lock()
	if r.stopped {
		delete(r.cancels, task.ID)
		delete(r.sessions, task.ID)
		r.mu.Unlock()
		cancel()
		return model.ActiveTask{}, errors.New("主动扫描服务正在关闭")
	}
	r.workers.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.workers.Done()
		r.run(ctx, task)
	}()
	return task, nil
}

func (r *Runner) Cancel(id string) error {
	r.mu.Lock()
	cancel, exists := r.cancels[id]
	r.mu.Unlock()
	if !exists {
		return errors.New("任务未在运行")
	}
	cancel()
	return nil
}

func (r *Runner) ListTasks(limit int) ([]model.ActiveTask, error) { return r.store.ListTasks(limit) }
func (r *Runner) ListTaskResults(id string, limit int) ([]model.TaskResult, error) {
	return r.store.ListTaskResults(id, limit)
}
func (r *Runner) ListAudit(limit int) ([]model.AuditEvent, error) { return r.store.ListAudit(limit) }

// Shutdown cancels queued and running verification tasks, then waits until no
// task can write to its repository. It is safe to call more than once.
func (r *Runner) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	if !r.stopped {
		r.stopped = true
		if r.ticker != nil {
			r.ticker.Stop()
		}
		for _, cancel := range r.cancels {
			cancel()
		}
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runner) run(ctx context.Context, task model.ActiveTask) {
	select {
	case r.tasks <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-r.tasks; r.mu.Lock(); delete(r.cancels, task.ID); delete(r.sessions, task.ID); r.mu.Unlock() }()
	now := time.Now().UTC()
	task.Status = "running"
	task.StartedAt = &now
	_ = r.store.UpdateTask(task)
	_ = r.audit(task.ID, "active_task_started", "running", task.Kind)
	var err error
	if err = r.pinTaskTarget(task); err != nil {
		finished := time.Now().UTC()
		task.FinishedAt, task.Status, task.Error = &finished, "failed", err.Error()
		_ = r.audit(task.ID, "active_task_finished", "failed", task.Error)
		_ = r.store.UpdateTask(task)
		return
	}
	switch task.Kind {
	case KindPortScan:
		err = r.portScan(ctx, &task)
	case KindBasicAuth:
		err = r.basicAuth(ctx, &task)
	case KindCrawl:
		err = r.crawl(ctx, &task)
	case KindHeadless:
		err = r.headlessCrawl(ctx, &task)
	}
	finished := time.Now().UTC()
	task.FinishedAt = &finished
	if errors.Is(err, context.Canceled) {
		task.Status = "cancelled"
		task.Error = "操作员已取消"
		_ = r.audit(task.ID, "active_task_finished", "cancelled", task.Error)
	} else if err != nil {
		task.Status = "failed"
		task.Error = err.Error()
		_ = r.audit(task.ID, "active_task_finished", "failed", task.Error)
	} else {
		task.Status = "completed"
		_ = r.audit(task.ID, "active_task_finished", "completed", fmt.Sprintf("%d requests", task.Summary["requests"]))
	}
	_ = r.store.UpdateTask(task)
}

func (r *Runner) normalizeTarget(kind, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("请填写目标")
	}
	if kind == KindPortScan {
		host := raw
		if parsedHost, _, err := net.SplitHostPort(raw); err == nil {
			host = parsedHost
		}
		if strings.ContainsAny(host, "/:?@") || host == "" {
			return "", errors.New("端口扫描目标仅支持一个主机名或 IP 地址")
		}
		if !r.engine.AllowsActiveHost(host) {
			return "", errors.New("目标不在主动扫描范围内；请将该主机加入 scope.allow_hosts")
		}
		return host, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", errors.New("目标需填写不含认证信息的 http 或 https URL")
	}
	if !r.engine.AllowsActiveHost(u.Hostname()) {
		return "", errors.New("目标不在主动扫描范围内；请将该主机加入 scope.allow_hosts")
	}
	u.Fragment = ""
	return u.String(), nil
}

func sanitizeSessionHeaders(input map[string]string) (http.Header, error) {
	result := make(http.Header)
	for rawName, rawValue := range input {
		name, value := http.CanonicalHeaderKey(strings.TrimSpace(rawName)), strings.TrimSpace(rawValue)
		if value == "" {
			continue
		}
		if len(name) > 80 || len(value) > 8192 || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("会话头格式无效")
		}
		if name != "Cookie" && name != "Authorization" && name != "X-Csrf-Token" && name != "X-Requested-With" {
			return nil, fmt.Errorf("不允许使用会话头 %q", rawName)
		}
		result.Set(name, value)
	}
	return result, nil
}

func (r *Runner) pinTaskTarget(task model.ActiveTask) error {
	host := task.Target
	if task.Kind != KindPortScan {
		parsed, err := url.Parse(task.Target)
		if err != nil {
			return err
		}
		host = parsed.Hostname()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("解析主动扫描目标 %q 失败：%w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("主动扫描目标 %q 未解析到地址", host)
	}
	if net.ParseIP(host) == nil && !r.cfg.Scope.AllowPrivateIPs {
		for _, ip := range ips {
			if isPrivateOrLocalIP(ip) {
				return fmt.Errorf("目标 %q 解析到内网或本地地址；授权的内网目标可将 scope.allow_private_ips 设为 true", host)
			}
		}
	}
	r.mu.Lock()
	session := r.sessions[task.ID]
	session.pinned[strings.ToLower(host)] = append([]net.IP(nil), ips...)
	r.sessions[task.ID] = session
	r.mu.Unlock()
	return nil
}

func isPrivateOrLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast()
}

func (r *Runner) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.interval:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.requests <- struct{}{}:
		return nil
	}
}
func (r *Runner) release() { <-r.requests }

func (r *Runner) httpAllowed(taskID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[taskID].failures < r.cfg.WebScan.HTTP.MaxFailures
}

func (r *Runner) noteHTTPResult(taskID string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session := r.sessions[taskID]
	if err == nil {
		session.failures = 0
	} else {
		session.failures++
	}
	r.sessions[taskID] = session
}

func (r *Runner) blockedPath(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return true
	}
	path := strings.ToLower(parsed.EscapedPath())
	if path == "" {
		path = "/"
	}
	for _, raw := range r.cfg.WebScan.HTTP.DisallowedScanPath {
		needle := strings.ToLower(strings.TrimSpace(raw))
		if needle != "" && strings.Contains(path, needle) {
			return true
		}
	}
	return false
}

func (r *Runner) excludedSuffix(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return true
	}
	path := strings.ToLower(parsed.Path)
	for _, raw := range r.cfg.WebScan.Crawler.ExcludedSuffixes {
		suffix := strings.ToLower(strings.TrimSpace(raw))
		if suffix != "" && strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
func (r *Runner) record(task *model.ActiveTask, kind, target, status, detail string, metadata map[string]string) {
	now := time.Now().UTC()
	task.Summary["results"]++
	_ = r.store.AddTaskResult(model.TaskResult{ID: newID(), TaskID: task.ID, Kind: kind, Target: target, Status: status, Detail: detail, Metadata: metadata, ObservedAt: now})
}
func (r *Runner) audit(taskID, action, outcome, detail string) error {
	return r.store.AddAudit(model.AuditEvent{ID: newID(), TaskID: taskID, Action: action, Outcome: outcome, Detail: detail, CreatedAt: time.Now().UTC()})
}

func (r *Runner) portScan(ctx context.Context, task *model.ActiveTask) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, port := range CommonPorts {
		if task.Summary["requests"] >= r.cfg.Active.MaxRequestsPerTask {
			break
		}
		task.Summary["requests"]++
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if err := r.acquire(ctx); err != nil {
				return
			}
			defer r.release()
			conn, err := r.dialTask(task.ID)(ctx, "tcp", net.JoinHostPort(task.Target, fmt.Sprint(port)))
			if err != nil {
				mu.Lock()
				task.Summary["closed"]++
				mu.Unlock()
				return
			}
			_ = conn.Close()
			mu.Lock()
			task.Summary["open"]++
			r.record(task, KindPortScan, net.JoinHostPort(task.Target, fmt.Sprint(port)), "open", "TCP 端口开放", map[string]string{"port": fmt.Sprint(port), "service": serviceName(port)})
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return ctx.Err()
}

// crawl is a bounded, same-origin GET crawler for server-rendered HTML. It
// avoids form submission, JavaScript execution, external links, file downloads
// and navigation to logout-like paths. Every observed response feeds the same
// passive analysis and asset inventory pipeline.
func (r *Runner) crawl(ctx context.Context, task *model.ActiveTask) error {
	root, err := url.Parse(task.Target)
	if err != nil {
		return err
	}
	root.Fragment = ""
	client := r.probeClient(task.ID)
	type crawlItem struct {
		url   string
		depth int
	}
	queue := []crawlItem{{url: root.String()}}
	visited := map[string]bool{}
	maxPages := r.cfg.WebScan.Crawler.MaxPages
	for len(queue) > 0 && task.Summary["requests"] < r.cfg.Active.MaxRequestsPerTask && task.Summary["pages"] < maxPages {
		item := queue[0]
		queue = queue[1:]
		current := item.url
		if visited[current] {
			continue
		}
		if r.blockedPath(current) || (item.depth > 0 && r.excludedSuffix(current)) {
			task.Summary["skipped"]++
			continue
		}
		visited[current] = true
		response, err := r.probeGET(ctx, task.ID, client, current)
		task.Summary["requests"]++
		if err != nil {
			task.Summary["errors"]++
			continue
		}
		task.Summary["pages"]++
		r.record(task, KindCrawl, current, fmt.Sprint(response.status), http.StatusText(response.status), map[string]string{"content_type": response.contentType, "body_bytes": fmt.Sprint(len(response.body))})
		r.engine.Analyze(model.Transaction{Source: "active-crawl", Request: model.Message{Method: http.MethodGet, URL: current, Headers: map[string]string{}}, Response: model.Message{Status: response.status, Headers: map[string]string{"Content-Type": response.contentType}, Body: response.body}})
		if !strings.Contains(strings.ToLower(response.contentType), "text/html") {
			continue
		}
		if item.depth >= r.cfg.WebScan.Crawler.MaxDepth {
			continue
		}
		for _, candidate := range crawlLinks(root, current, response.body, r.cfg.WebScan.HTTP.StrictSameOrigin) {
			if !visited[candidate] {
				queue = append(queue, crawlItem{url: candidate, depth: item.depth + 1})
			}
		}
	}
	return nil
}

func crawlLinks(root *url.URL, current, body string, strictSameOrigin bool) []string {
	base, err := url.Parse(current)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var result []string
	for _, match := range crawlLinkPattern.FindAllStringSubmatch(body, -1) {
		raw := match[1]
		if raw == "" {
			raw = match[2]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "javascript:") || strings.HasPrefix(strings.ToLower(raw), "data:") {
			continue
		}
		candidate, err := base.Parse(raw)
		if err != nil || candidate.Hostname() != root.Hostname() || (candidate.Scheme != "http" && candidate.Scheme != "https") {
			continue
		}
		if strictSameOrigin && (candidate.Scheme != root.Scheme || candidate.Host != root.Host) {
			continue
		}
		candidate.Fragment = ""
		if strings.Contains(strings.ToLower(candidate.Path), "logout") || strings.HasSuffix(strings.ToLower(candidate.Path), "/signout") {
			continue
		}
		if !seen[candidate.String()] {
			seen[candidate.String()] = true
			result = append(result, candidate.String())
		}
	}
	sort.Strings(result)
	return result
}

// headlessCrawl renders one authorized same-origin entry page to discover
// browser-created interfaces. Fetch interception allows only same-origin GET
// requests and blocks form submissions, writes, downloads, logout-like paths,
// external hosts, and all session credentials. It is intentionally separate
// from the static crawler and disabled by default.
func (r *Runner) headlessCrawl(ctx context.Context, task *model.ActiveTask) error {
	root, err := url.Parse(task.Target)
	if err != nil {
		return err
	}
	pinned := r.pinnedIP(task.ID, root.Hostname())
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options,
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("proxy-server", "direct://"),
		chromedp.Flag("proxy-bypass-list", "*"),
	)
	if r.cfg.WebScan.Crawler.ChromePath != "" {
		options = append(options, chromedp.ExecPath(r.cfg.WebScan.Crawler.ChromePath))
	}
	if r.cfg.WebScan.Crawler.NoSandbox {
		options = append(options, chromedp.NoSandbox)
	}
	if r.cfg.WebScan.Crawler.DisableImages {
		options = append(options, chromedp.Flag("blink-settings", "imagesEnabled=false"))
	}
	if r.cfg.WebScan.Crawler.UserAgent != "" {
		options = append(options, chromedp.UserAgent(r.cfg.WebScan.Crawler.UserAgent))
	}
	if pinned != nil {
		options = append(options, chromedp.Flag("host-resolver-rules", "MAP "+root.Hostname()+" "+pinned.String()))
	}
	allocator, cancelAllocator := chromedp.NewExecAllocator(ctx, options...)
	defer cancelAllocator()
	// Some Chromium versions emit harmless protocol-enum warnings for local
	// address-space metadata. Task errors still propagate through chromedp.Run.
	browser, cancelBrowser := chromedp.NewContext(allocator, chromedp.WithErrorf(func(string, ...any) {}))
	defer cancelBrowser()
	browserTimeout := time.Duration(r.cfg.Active.TimeoutSeconds*2) * time.Second
	if browserTimeout < 15*time.Second {
		browserTimeout = 15 * time.Second
	}
	browser, cancelDeadline := context.WithTimeout(browser, browserTimeout)
	defer cancelDeadline()
	var allowedRequests atomic.Int64
	chromedp.ListenTarget(browser, func(event any) {
		paused, ok := event.(*fetch.EventRequestPaused)
		if !ok || paused.Request == nil {
			return
		}
		allowed := paused.Request.Method == http.MethodGet && headlessAllowedURL(root, paused.Request.URL, r.cfg.WebScan.HTTP.StrictSameOrigin) && !r.blockedPath(paused.Request.URL) && !r.excludedSuffix(paused.Request.URL) && allowedRequests.Add(1) <= int64(r.cfg.Active.MaxRequestsPerTask)
		go func() {
			if allowed {
				_ = chromedp.Run(browser, fetch.ContinueRequest(paused.RequestID))
				return
			}
			_ = chromedp.Run(browser, fetch.FailRequest(paused.RequestID, network.ErrorReasonBlockedByClient))
		}()
	})
	var rendered struct {
		HTML      string   `json:"html"`
		Resources []string `json:"resources"`
	}
	script := `({html:(document.documentElement ? document.documentElement.outerHTML : '').slice(0,1048576),resources:performance.getEntriesByType('resource').map(e=>e.name).slice(0,100)})`
	err = chromedp.Run(browser,
		network.Enable(),
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}}),
		chromedp.Navigate(root.String()),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Evaluate(script, &rendered),
	)
	if err != nil {
		return fmt.Errorf("浏览器爬取失败：%w", err)
	}
	task.Summary["requests"] = int(allowedRequests.Load())
	task.Summary["pages"]++
	r.record(task, KindHeadless, root.String(), "discovered", "已获取浏览器渲染的同源页面；已拦截非 GET 与跨域请求", map[string]string{"resources": fmt.Sprint(len(rendered.Resources)), "session": "未使用", "network_policy": "仅同源 GET"})
	r.engine.Analyze(model.Transaction{Source: "active-headless", Request: model.Message{Method: http.MethodGet, URL: root.String()}, Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "text/html"}, Body: rendered.HTML}})
	seen := map[string]bool{}
	for _, raw := range rendered.Resources {
		if !headlessAllowedURL(root, raw, r.cfg.WebScan.HTTP.StrictSameOrigin) || r.blockedPath(raw) || r.excludedSuffix(raw) || seen[raw] {
			continue
		}
		seen[raw] = true
		task.Summary["resources"]++
		r.engine.Analyze(model.Transaction{Source: "active-headless-resource", Request: model.Message{Method: http.MethodGet, URL: raw}, Response: model.Message{Status: 0}})
	}
	return nil
}

func (r *Runner) pinnedIP(taskID, host string) net.IP {
	r.mu.Lock()
	defer r.mu.Unlock()
	ips := r.sessions[taskID].pinned[strings.ToLower(host)]
	if len(ips) == 0 {
		return nil
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return append(net.IP(nil), ipv4...)
		}
	}
	return append(net.IP(nil), ips[0]...)
}

func headlessAllowedURL(root *url.URL, raw string, strictSameOrigin bool) bool {
	candidate, err := root.Parse(raw)
	if err != nil || candidate.Hostname() != root.Hostname() || candidate.User != nil || (candidate.Scheme != "http" && candidate.Scheme != "https") {
		return false
	}
	if strictSameOrigin && (candidate.Scheme != root.Scheme || candidate.Host != root.Host) {
		return false
	}
	path := strings.ToLower(candidate.Path)
	for _, denied := range []string{"logout", "signout", "delete", "remove", "reset", "shutdown", "restart"} {
		if strings.Contains(path, denied) {
			return false
		}
	}
	return true
}

func (r *Runner) basicAuth(ctx context.Context, task *model.ActiveTask) error {
	client := r.probeClient(task.ID)
	baseline, err := r.doBasic(ctx, task.ID, client, task.Target, "", "")
	if err != nil {
		return err
	}
	task.Summary["requests"]++
	if baseline != http.StatusUnauthorized {
		return fmt.Errorf("HTTP Basic 认证检测要求目标对未认证请求返回 HTTP 401（实际为 %d）", baseline)
	}
	users := []string{"admin", "administrator", "root"}
	passwords := []string{"admin", "password", "123456", "root"}
	for _, user := range users {
		for _, password := range passwords {
			if task.Summary["requests"] >= r.cfg.Active.MaxRequestsPerTask {
				return nil
			}
			status, err := r.doBasic(ctx, task.ID, client, task.Target, user, password)
			task.Summary["requests"]++
			if err != nil {
				task.Summary["errors"]++
				continue
			}
			if status >= 200 && status < 400 {
				task.Summary["valid_credentials"]++
				r.record(task, KindBasicAuth, task.Target, "valid", "HTTP Basic 认证检测发现可用账号", map[string]string{"username": user, "password": "[REDACTED]", "status": fmt.Sprint(status)})
				_ = r.audit(task.ID, "basic_auth_check", "credential_accepted", "username="+user)
				return nil
			}
		}
	}
	return nil
}

type probeResponse struct {
	status            int
	body, contentType string
}

func (r *Runner) probeClient(taskID string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = r.dialTask(taskID)
	return &http.Client{Transport: transport, Timeout: time.Duration(r.cfg.WebScan.HTTP.TimeoutSeconds) * time.Second, CheckRedirect: r.redirectPolicy(taskID)}
}
func (r *Runner) redirectPolicy(_ string) func(*http.Request, []*http.Request) error {
	return func(next *http.Request, via []*http.Request) error {
		if len(via) > r.cfg.WebScan.HTTP.MaxRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) == 0 {
			return http.ErrUseLastResponse
		}
		origin := via[0].URL
		if next.URL.Hostname() != origin.Hostname() || next.URL.User != nil || (r.cfg.WebScan.HTTP.StrictSameOrigin && (next.URL.Scheme != origin.Scheme || next.URL.Host != origin.Host)) || r.blockedPath(next.URL.String()) {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// activeGET is the shared request path for all active HTTP tasks.  It keeps
// the request GET-only, applies the configured safe headers, retries only
// transport errors, and stops subsequent requests after consecutive failures.
func (r *Runner) activeGET(ctx context.Context, taskID string, client *http.Client, target, byteRange, user, password string) (*http.Response, error) {
	if r.blockedPath(target) {
		return nil, errors.New("目标路径被 webscan.http.disallowed_scan_path 拦截")
	}
	if !r.httpAllowed(taskID) {
		return nil, fmt.Errorf("连续 %d 次 HTTP 请求失败，已停止", r.cfg.WebScan.HTTP.MaxFailures)
	}
	var lastErr error
	for attempt := 0; attempt <= r.cfg.WebScan.HTTP.Retry; attempt++ {
		if err := r.acquire(ctx); err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err == nil {
			if byteRange != "" {
				request.Header.Set("Range", byteRange)
			}
			request.Header.Set("User-Agent", "EasyScan/0.1 authorized-verification")
			r.applyConfiguredHeaders(request)
			r.applySessionHeaders(taskID, request)
			if user != "" {
				request.SetBasicAuth(user, password)
			}
		}
		var response *http.Response
		if err == nil {
			response, err = client.Do(request)
		}
		r.release()
		if err == nil {
			r.noteHTTPResult(taskID, nil)
			return response, nil
		}
		lastErr = err
		r.noteHTTPResult(taskID, err)
		if !r.httpAllowed(taskID) || attempt == r.cfg.WebScan.HTTP.Retry {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(75 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func (r *Runner) probeGET(ctx context.Context, taskID string, client *http.Client, target string) (probeResponse, error) {
	response, err := r.activeGET(ctx, taskID, client, target, "bytes=0-8191", "", "")
	if err != nil {
		return probeResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil {
		return probeResponse{}, err
	}
	return probeResponse{status: response.StatusCode, body: string(body), contentType: response.Header.Get("Content-Type")}, nil
}
func (r *Runner) doBasic(ctx context.Context, taskID string, client *http.Client, target, user, password string) (int, error) {
	resp, err := r.activeGET(ctx, taskID, client, target, "", user, password)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
func (r *Runner) applySessionHeaders(taskID string, request *http.Request) {
	r.mu.Lock()
	headers := r.sessions[taskID].headers.Clone()
	r.mu.Unlock()
	for name, values := range headers {
		request.Header.Del(name)
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
}

func (r *Runner) applyConfiguredHeaders(request *http.Request) {
	for rawName, value := range r.cfg.WebScan.HTTP.Headers {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rawName))
		if configurableHeader(name) && request.Header.Get(name) == "" {
			request.Header.Set(name, value)
		}
	}
	for rawName, value := range r.cfg.WebScan.HTTP.HeadersForce {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rawName))
		if configurableHeader(name) {
			request.Header.Set(name, value)
		}
	}
}

func configurableHeader(name string) bool {
	switch strings.ToLower(name) {
	case "", "host", "content-length", "connection", "transfer-encoding", "upgrade", "proxy-authorization", "proxy-connection", "te", "trailer":
		return false
	default:
		return true
	}
}

func (r *Runner) dialTask(taskID string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		pinned := append([]net.IP(nil), r.sessions[taskID].pinned[strings.ToLower(host)]...)
		r.mu.Unlock()
		dialer := net.Dialer{Timeout: time.Duration(r.cfg.Active.TimeoutSeconds) * time.Second}
		if len(pinned) == 0 {
			return dialer.DialContext(ctx, network, address)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(pinned[0].String(), port))
	}
}
func flatten(h http.Header) map[string]string {
	result := map[string]string{}
	for k, v := range h {
		result[k] = strings.Join(v, "\n")
	}
	return result
}
func interestingStatus(status int) bool {
	return (status >= 200 && status < 300) || status == 301 || status == 302 || status == 307 || status == 308 || status == 401 || status == 403
}
func serviceName(port int) string {
	known := map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http-alt", 3128: "http-proxy", 3306: "mysql", 3389: "rdp", 5000: "http-alt", 5432: "postgresql", 5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "https-alt", 7001: "weblogic", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt"}
	return known[port]
}
func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
