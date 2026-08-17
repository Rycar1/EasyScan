// Package wafprobe implements the optional active WAF fingerprinting triggered
// by origins observed through the local HTTP proxy or HTTPS MITM. Exactly one
// canary request is sent per new origin using well-formed benign SQLi/XSS
// payloads. Signals in the response (status code, blocked page body, WAF
// headers, connection drop / timeout) are used to decide whether a WAF is
// present, and the shared HFinger database is used to identify the vendor.
package wafprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/fingerprint"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID      = "passive.waf_probe"
	queueCapacity  = 32
	defaultTimeout = 8 * time.Second
	maxBodyBytes   = 1 << 20
	canaryParam    = "id"
	// canarySQLi 与 canaryXSS 属于最经典的 WAF 关键词触发样本；不会造成任何
	// 实际数据变更，只用于观察响应差异。
	canarySQLi = "1' or '1'='1"
	canaryXSS  = "<script>alert(1)</script>"
)

// blockingStatusCodes 是常见 WAF 拦截页返回的状态码，用作"未识别厂商但存
// 在拦截"的兜底信号。仅在同域正常基线响应可用（或缺失时也保守判定）时使用。
var blockingStatusCodes = map[int]bool{
	403: true,
	406: true,
	409: true,
	418: true,
	419: true,
	429: true,
	444: true,
	449: true,
	494: true,
	495: true,
	496: true,
	501: true,
	503: true,
	521: true,
	522: true,
	523: true,
	999: true,
}

// wafBodyPattern 用于响应体中的通用 WAF 关键词匹配。
var wafBodyPattern = regexp.MustCompile(`(?is)(?:web application firewall|blocked by .*firewall|attack detected|malicious request|request.*(?:blocked|denied|rejected)|access denied|suspected attack|security policy|not acceptable|forbidden by|拦截|已被拦截|安全策略|防火墙|非法请求|异常访问|非法访问|已阻断|已阻止|检测到攻击)`)

// wafHeaderNames 命中即视为存在 WAF（部分厂商响应头会主动带出自我标识）。
var wafHeaderNames = []string{
	"x-cdn",
	"x-waf",
	"x-waf-detected",
	"x-sucuri-id",
	"x-sucuri-cache",
	"x-mod-security",
	"x-protected-by",
	"x-akamai-transformed",
	"x-yunjiasu-hash",
	"x-cache-lookup",
	"cf-ray",
	"cf-cache-status",
	"cf-mitigated",
	"server-timing",
}

// Policy 是运行期使用的功能开关表。
type Policy interface {
	Enabled(string) bool
}

// Worker 负责按域名去重地执行主动 WAF 探测。整体结构与 fileprobe 一致：
// Observe 只入队，实际 HTTP 请求由后台协程发送。
type Worker struct {
	cfg    config.Config
	engine *engine.Engine
	policy Policy
	client *http.Client

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan queuedOrigin

	mu             sync.Mutex
	scheduled      map[string]struct{}
	stopped        bool
	hintedDisabled bool
	generation     uint64
	batchCtx       context.Context
	batchCancel    context.CancelFunc
	workers        sync.WaitGroup
}

type queuedOrigin struct {
	origin     string
	referer    string
	generation uint64
}

// New 构造 Worker 并启动后台调度协程。
func New(cfg config.Config, e *engine.Engine, policy Policy) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	batchCtx, batchCancel := context.WithCancel(ctx)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   4 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 目标由 scope 授权，跳过证书校验以覆盖自签场景
		DisableKeepAlives:   true,
	}
	w := &Worker{
		cfg:    cfg,
		engine: e,
		policy: policy,
		client: &http.Client{
			Timeout:   defaultTimeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ctx:         ctx,
		cancel:      cancel,
		queue:       make(chan queuedOrigin, queueCapacity),
		scheduled:   make(map[string]struct{}),
		batchCtx:    batchCtx,
		batchCancel: batchCancel,
	}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe 在观察到一次代理流量时入队。每个 scheme+host+port 只会探测一次。
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) {
		return
	}
	if !w.enabled() {
		w.hintDisabledOnce()
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	method := strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	if method != http.MethodGet && method != http.MethodPost {
		return
	}
	origin := originKey(parsed)
	if origin == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if _, exists := w.scheduled[origin]; exists {
		return
	}
	item := queuedOrigin{origin: origin, referer: parsed.String(), generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[origin] = struct{}{}
		w.engine.Log("info", "waf-probe", fmt.Sprintf("WAF 探测入队：origin=%s", origin))
	default:
		// 队列已满就放弃，避免拖慢 MITM 主链路。
		w.engine.Log("warn", "waf-probe", fmt.Sprintf("WAF 探测跳过：队列已满（静默丢弃）origin=%s", origin))
	}
}

// hintDisabledOnce 在 WAF 检测处于关闭状态且已有代理流量时，输出一次提示，
// 让用户明白"未检测到 WAF"是因为该主动探测默认未开启，而非漏报。
func (w *Worker) hintDisabledOnce() {
	w.mu.Lock()
	if w.stopped || w.hintedDisabled {
		w.mu.Unlock()
		return
	}
	w.hintedDisabled = true
	w.mu.Unlock()
	w.engine.Log("info", "waf-probe", "WAF 检测默认关闭：如需识别 WAF 及厂商，请在高级设置中开启「WAF 检测」并确认目标在主动扫描范围内")
}

// CancelPending 清空当前批次并允许同一 origin 在下一次 MITM 启动后重新入队。
func (w *Worker) CancelPending() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if w.batchCancel != nil {
		w.batchCancel()
	}
	w.generation++
	w.batchCtx, w.batchCancel = context.WithCancel(w.ctx)
	w.scheduled = make(map[string]struct{})
	for {
		select {
		case <-w.queue:
		default:
			return
		}
	}
}

// Shutdown 停止后台协程。
func (w *Worker) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.Lock()
	if !w.stopped {
		w.stopped = true
		if w.batchCancel != nil {
			w.batchCancel()
		}
		w.cancel()
	}
	w.mu.Unlock()
	done := make(chan struct{})
	go func() {
		w.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Worker) run() {
	defer w.workers.Done()
	for {
		select {
		case <-w.ctx.Done():
			return
		case item := <-w.queue:
			batch := w.currentBatch(item.generation)
			if batch != nil {
				w.probeOrigin(batch, item)
			}
		}
	}
}

func (w *Worker) currentBatch(generation uint64) context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped || generation != w.generation {
		return nil
	}
	return w.batchCtx
}

func (w *Worker) enabled() bool {
	return w.policy != nil && w.policy.Enabled(featureID)
}

// probeOrigin 是单次域名探测的完整流程：先取一个基线，再依次发出 SQLi 与
// XSS canary，只要有任一 canary 出现异常即上报。
func (w *Worker) probeOrigin(ctx context.Context, item queuedOrigin) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	base, err := url.Parse(item.origin)
	if err != nil || base.Hostname() == "" || !w.engine.AllowsActiveHost(base.Hostname()) {
		return
	}

	baseline := w.probe(ctx, base, "", "")
	if ctx.Err() != nil {
		return
	}

	for _, canary := range []struct {
		kind    string
		payload string
	}{
		{"sqli", canarySQLi},
		{"xss", canaryXSS},
	} {
		if ctx.Err() != nil {
			return
		}
		attempt := w.probe(ctx, base, canaryParam, canary.payload)
		verdict, vendor, evidence := classify(baseline, attempt)
		if verdict == "" {
			continue
		}
		w.report(item.origin, canary.kind, canary.payload, vendor, evidence, baseline, attempt)
		// 一个域名只需要一次结论，命中即停止。
		return
	}
}

// probeResult 是 canary 请求的观测结果。err != nil 时表示连接层异常（如
// 直接被 WAF drop），此时 status 与 body 都为空。
type probeResult struct {
	requestURL string
	status     int
	headers    http.Header
	body       string
	err        error
	dropped    bool
	tx         model.Transaction
}

func (w *Worker) probe(ctx context.Context, base *url.URL, paramName, paramValue string) probeResult {
	target := *base
	target.Path = "/"
	target.RawPath = ""
	if paramName != "" {
		q := url.Values{}
		q.Set(paramName, paramValue)
		target.RawQuery = q.Encode()
	} else {
		target.RawQuery = ""
	}
	target.Fragment = ""
	requestURL := target.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return probeResult{requestURL: requestURL, err: err}
	}
	ua := strings.TrimSpace(w.cfg.WebScan.Crawler.UserAgent)
	if ua == "" {
		ua = "Mozilla/5.0 (compatible; EasyScan/1.0)"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := w.client.Do(req)
	if err != nil {
		dropped := isDroppedError(err)
		return probeResult{
			requestURL: requestURL,
			err:        err,
			dropped:    dropped,
			tx: model.Transaction{
				Source:  model.SourceMITMProbe,
				Request: model.Message{Method: http.MethodGet, URL: requestURL},
				Response: model.Message{
					Status: 0,
					Body:   "[connection dropped or timeout] " + err.Error(),
				},
			},
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	headers := headersToMap(resp.Header)
	return probeResult{
		requestURL: requestURL,
		status:     resp.StatusCode,
		headers:    resp.Header,
		body:       string(body),
		tx: model.Transaction{
			Source: model.SourceMITMProbe,
			Request: model.Message{
				Method: http.MethodGet,
				URL:    requestURL,
			},
			Response: model.Message{
				Status:  resp.StatusCode,
				Headers: headers,
				Body:    string(body),
			},
		},
	}
}

// classify 依据基线与 canary 探测结果判断 WAF 是否存在及厂商。
//
// 返回 verdict 为空字符串表示"未检测到 WAF"，此时不应上报。
func classify(baseline, attempt probeResult) (verdict, vendor, evidence string) {
	// 若 baseline 也直接被 drop / 超时，说明目标不可达，不做误报。
	if attempt.err != nil && baseline.err != nil {
		return "", "", ""
	}

	// 情况一：canary 请求被 drop 或超时，但基线可正常访问 → 强 WAF 拦截信号。
	if attempt.dropped && baseline.err == nil {
		return "waf-detected", "", "canary 请求被连接层丢弃或超时，基线正常访问：" + trimError(attempt.err)
	}

	// 情况二：canary 响应体或响应头命中通用 WAF 关键词。
	if attempt.body != "" && wafBodyPattern.MatchString(attempt.body) {
		if !baselineHasSameSignal(baseline) {
			return "waf-detected", "", "响应体命中 WAF 关键词特征"
		}
	}
	if hasWAFHeader(attempt.headers) && !hasWAFHeader(baseline.headers) {
		return "waf-detected", "", "响应头出现 WAF/CDN 自我标识"
	}

	// 情况三：canary 触发了明显不同于基线的拦截型状态码。
	if attempt.status > 0 && blockingStatusCodes[attempt.status] {
		if baseline.status == 0 || baseline.status != attempt.status {
			return "waf-detected", "", "触发 WAF 拦截状态码 " + statusText(attempt.status)
		}
	}

	return "", "", ""
}

// IdentifyVendor 使用 HFinger 数据库识别 canary 响应对应的 WAF 厂商。
// 该函数在 report 阶段调用，允许被外部注入替换以便测试。
var IdentifyVendor = func(db *fingerprint.HFingerDatabase, tx model.Transaction) string {
	if db == nil {
		return ""
	}
	matches := db.MatchDetails(tx, false, true)
	for _, m := range matches {
		if strings.EqualFold(m.Category, "waf") {
			// MatchDetails 已经加过 "WAF · " 前缀，报告时保留即可。
			return strings.TrimSpace(m.Name)
		}
	}
	return ""
}

func (w *Worker) report(origin, canaryKind, payload, vendorHint, evidence string, baseline, attempt probeResult) {
	vendor := vendorHint
	if vendor == "" {
		vendor = IdentifyVendor(w.engine.HFinger(), attempt.tx)
	}

	title := "存在 WAF"
	ruleID := "passive.waf-probe.unknown"
	description := "对新出现的域名 " + origin + " 发送了一次 " + canaryKind + " canary 探测（payload：" + payload + "），响应与正常基线存在明显差异，判定该域名前置存在 WAF。"
	if vendor != "" {
		title = "存在 WAF：" + vendor
		ruleID = "passive.waf-probe.identified"
		description += " 通过 HFinger 指纹识别为 " + vendor + "。"
	} else {
		description += " 未能识别具体厂商。"
	}

	finding := model.Finding{
		RuleID:      ruleID,
		Title:       title,
		Severity:    "info",
		Confidence:  "firm",
		URL:         attempt.requestURL,
		Method:      http.MethodGet,
		Description: description,
		Evidence:    evidence,
		Tags:        []string{"waf", "active-probe", canaryKind},
		ObservedAt:  time.Now().UTC(),
	}

	evidenceTxs := []model.Transaction{attempt.tx}
	if baseline.tx.Request.URL != "" {
		evidenceTxs = append([]model.Transaction{baseline.tx}, evidenceTxs...)
	}
	w.engine.ReportFindingWithEvidence(finding, evidenceTxs)
}

// baselineHasSameSignal 用于避免"目标本身就在响应体里带 WAF 关键词"造成
// 的误报（例如目标是一篇 WAF 相关的博客）。
func baselineHasSameSignal(baseline probeResult) bool {
	if baseline.body == "" {
		return false
	}
	return wafBodyPattern.MatchString(baseline.body)
}

func hasWAFHeader(headers http.Header) bool {
	if headers == nil {
		return false
	}
	for _, name := range wafHeaderNames {
		if v := headers.Get(name); strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func isDroppedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	message := strings.ToLower(err.Error())
	needles := []string{
		"connection reset",
		"connection refused",
		"connection aborted",
		"broken pipe",
		"eof",
		"tls: ",
		"i/o timeout",
		"no route to host",
		"unexpected eof",
	}
	for _, needle := range needles {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func trimError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 200 {
		return msg[:200] + "..."
	}
	return msg
}

func statusText(status int) string {
	if text := http.StatusText(status); text != "" {
		return strconv.Itoa(status) + " " + text
	}
	return strconv.Itoa(status)
}

func headersToMap(h http.Header) map[string]string {
	result := make(map[string]string, len(h))
	for key, values := range h {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]:" + port
	}
	return scheme + "://" + host + ":" + port
}
