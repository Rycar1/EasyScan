// Package ssrfprobe implements an optional Server-Side Request Forgery check
// triggered by traffic observed through the local HTTP proxy or HTTPS MITM. It
// targets URL-like request parameters and sends benign probe URLs, including a
// user-configured OOB (out-of-band) domain when one is reserved. Detection is
// primarily local: it compares responses for a non-routable/loopback target
// against a control value to spot server-side fetch behaviour. No exploitation
// or state change is attempted.
package ssrfprobe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID      = "passive.ssrf_probe"
	minimumQPS     = 1
	maximumQPS     = 20
	queueCapacity  = 32
	maxBodyBytes   = 1 << 20
	maxParams      = 4
	defaultTimeout = 10 * time.Second
)

// urlParamHints identifies parameters likely to accept a URL. Names are matched
// case-insensitively as substrings.
var urlParamHints = []string{"url", "uri", "link", "src", "source", "target", "dest", "redirect", "callback", "next", "return", "image", "img", "fetch", "load", "site", "domain", "host", "path", "file", "feed", "proxy", "webhook", "api", "endpoint"}

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveSSRFProbeQPS() int
	// OOBDomain returns the reserved out-of-band callback domain, or an empty
	// string when the user has not configured one.
	OOBDomain() string
}

type Worker struct {
	cfg    config.Config
	engine *engine.Engine
	policy Policy

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan job

	mu          sync.Mutex
	scheduled   map[string]struct{}
	stopped     bool
	generation  uint64
	batchCtx    context.Context
	batchCancel context.CancelFunc
	workers     sync.WaitGroup
}

type job struct {
	tx         model.Transaction
	generation uint64
}

type target struct {
	location string // query | form
	name     string
	value    string
}

// New constructs the worker and starts its single background scheduler.
func New(cfg config.Config, e *engine.Engine, policy Policy) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	batchCtx, batchCancel := context.WithCancel(ctx)
	w := &Worker{
		cfg:         cfg,
		engine:      e,
		policy:      policy,
		ctx:         ctx,
		cancel:      cancel,
		queue:       make(chan job, queueCapacity),
		scheduled:   make(map[string]struct{}),
		batchCtx:    batchCtx,
		batchCancel: batchCancel,
	}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe only queues work. Each endpoint carrying a URL-like parameter is
// scheduled once.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) || !w.enabled() {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	if len(extractTargets(tx)) == 0 {
		return
	}
	key := endpointKey(tx.Request.Method, parsed)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if _, exists := w.scheduled[key]; exists {
		return
	}
	item := job{tx: cloneTransaction(tx), generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[key] = struct{}{}
	default:
	}
}

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
				w.probeJob(batch, item)
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

func (w *Worker) qps() int {
	if w.policy == nil {
		return minimumQPS
	}
	qps := w.policy.PassiveSSRFProbeQPS()
	if qps < minimumQPS {
		return minimumQPS
	}
	if qps > maximumQPS {
		return maximumQPS
	}
	return qps
}

func (w *Worker) waitForTurn(ctx context.Context) error {
	timer := time.NewTimer(time.Second / time.Duration(w.qps()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (w *Worker) probeJob(ctx context.Context, jb job) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	targets := extractTargets(jb.tx)
	if len(targets) > maxParams {
		targets = targets[:maxParams]
	}
	client := w.client()
	for _, tgt := range targets {
		if ctx.Err() != nil {
			return
		}
		if w.probeTarget(ctx, client, jb.tx, tgt) {
			return
		}
	}
}

// probeTarget sends a control probe to a non-routable public host and a test
// probe to a loopback host. When the loopback probe yields a materially
// different (typically fetch-error or metadata) response than the control, the
// parameter is a strong SSRF candidate. When an OOB domain is configured it is
// also injected so an external collector can confirm blind SSRF.
func (w *Worker) probeTarget(ctx context.Context, client *http.Client, tx model.Transaction, tgt target) bool {
	controlURL := "http://" + controlHost + "/easyscan-ssrf"
	loopbackURL := "http://127.0.0.1:80/easyscan-ssrf"
	control, ok1 := w.send(ctx, client, tx, tgt, controlURL)
	loopback, ok2 := w.send(ctx, client, tx, tgt, loopbackURL)
	if oob := oobProbeURL(w.policy.OOBDomain()); oob != "" {
		_, _ = w.send(ctx, client, tx, tgt, oob)
	}
	if !ok1 || !ok2 {
		return false
	}
	if ssrfSignal(control, loopback) {
		w.report(tx, tgt, controlURL, loopbackURL, control, loopback)
		return true
	}
	return false
}

type probeResult struct {
	status int
	body   string
	err    string
}

func (w *Worker) send(ctx context.Context, client *http.Client, tx model.Transaction, tgt target, value string) (probeResult, bool) {
	if err := w.waitForTurn(ctx); err != nil {
		return probeResult{}, false
	}
	request, err := buildRequest(ctx, tx, tgt, value)
	if err != nil {
		return probeResult{}, false
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan ssrf probe)")
	response, err := client.Do(request)
	if err != nil {
		return probeResult{err: err.Error()}, true
	}
	body := drainLimited(response.Body)
	response.Body.Close()
	return probeResult{status: response.StatusCode, body: body}, true
}

// ssrfSignal reports whether the loopback probe response indicates the server
// attempted a fetch to the injected target (connection errors surfaced in the
// body, or a status/length divergence from the control probe).
func ssrfSignal(control, loopback probeResult) bool {
	lower := strings.ToLower(loopback.body)
	for _, marker := range fetchErrorMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if loopback.status != control.status && (loopback.status >= 500 || loopback.status == 0) {
		return true
	}
	// A large divergence in body length against an otherwise-similar control
	// probe suggests the loopback content was actually fetched and inlined.
	if control.status == loopback.status && absDiff(len(control.body), len(loopback.body)) > 256 {
		return true
	}
	return false
}

var fetchErrorMarkers = []string{"connection refused", "econnrefused", "failed to connect", "connect: connection", "no route to host", "dial tcp", "connection reset", "could not resolve", "name resolution", "timeout", "invalid_url"}

const controlHost = "240.0.0.1" // reserved, non-routable IPv4

func oobProbeURL(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Trim(domain, "/")
	return "http://ssrf." + domain + "/easyscan"
}

func (w *Worker) report(tx model.Transaction, tgt target, controlURL, loopbackURL string, control, loopback probeResult) {
	finding := model.Finding{
		RuleID:      "passive.ssrf-probe.candidate",
		Title:       "疑似 SSRF（服务端请求伪造）",
		Severity:    "high",
		Confidence:  "medium",
		URL:         tx.Request.URL,
		Method:      tx.Request.Method,
		Description: "MITM SSRF 探测向 URL 类参数注入内网/回环地址后，服务端响应相较对照探针出现明显差异（连接错误回显或响应结构变化），表明参数可能触发服务端对外/对内发起请求。若已配置 OOB 域名，可结合外带回连进一步确认盲打 SSRF。",
		Evidence:    fmt.Sprintf("参数=%s(%s)；对照=%s(状态%d)；回环=%s(状态%d,err=%s)", tgt.name, tgt.location, controlURL, control.status, loopbackURL, loopback.status, loopback.err),
		Remediation: "对用户可控的 URL 做协议与目标白名单校验，禁止访问内网/回环/云元数据地址，并在服务端出网层做限制。",
		Tags:        []string{"ssrf", "mitm"},
		ObservedAt:  tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{cloneTransaction(tx)})
	if w.engine != nil {
		w.engine.Log("warn", "ssrf-probe", "疑似 SSRF："+tx.Request.URL)
	}
}

func (w *Worker) client() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	timeout := time.Duration(w.cfg.WebScan.HTTP.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(w.cfg.Active.TimeoutSeconds) * time.Second
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func extractTargets(tx model.Transaction) []target {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil {
		return nil
	}
	result := make([]target, 0, 4)
	for name, values := range parsed.Query() {
		if name != "" && len(values) > 0 && looksLikeURLParam(name, values[0]) {
			result = append(result, target{location: "query", name: name, value: values[0]})
		}
	}
	contentType := strings.ToLower(strings.TrimSpace(headerValue(tx.Request.Headers, "Content-Type")))
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if values, parseErr := url.ParseQuery(tx.Request.Body); parseErr == nil {
			for name, vs := range values {
				if name != "" && len(vs) > 0 && looksLikeURLParam(name, vs[0]) {
					result = append(result, target{location: "form", name: name, value: vs[0]})
				}
			}
		}
	}
	return result
}

// looksLikeURLParam keeps only parameters whose name hints at a URL or whose
// value already contains a URL scheme, to avoid noisy false triggers.
func looksLikeURLParam(name, value string) bool {
	lowerValue := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(lowerValue, "http://") || strings.HasPrefix(lowerValue, "https://") || strings.HasPrefix(lowerValue, "//") {
		return true
	}
	lowerName := strings.ToLower(name)
	for _, hint := range urlParamHints {
		if strings.Contains(lowerName, hint) {
			return true
		}
	}
	return false
}

func buildRequest(ctx context.Context, tx model.Transaction, tgt target, payload string) (*http.Request, error) {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil {
		return nil, err
	}
	method := tx.Request.Method
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	if tgt.location == "query" {
		query := parsed.Query()
		query.Set(tgt.name, payload)
		parsed.RawQuery = query.Encode()
	} else {
		values, parseErr := url.ParseQuery(tx.Request.Body)
		if parseErr != nil {
			return nil, parseErr
		}
		values.Set(tgt.name, payload)
		bodyReader = strings.NewReader(values.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	for name, value := range tx.Request.Headers {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Host") {
			continue
		}
		request.Header.Set(name, value)
	}
	return request, nil
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func endpointKey(method string, parsed *url.URL) string {
	names := make([]string, 0, 4)
	for name := range parsed.Query() {
		names = append(names, name)
	}
	return method + " " + parsed.Host + parsed.Path + "?" + strings.Join(names, ",")
}

func cloneTransaction(tx model.Transaction) model.Transaction {
	tx.Request.Headers = cloneHeaderMap(tx.Request.Headers)
	tx.Response.Headers = cloneHeaderMap(tx.Response.Headers)
	return tx
}

func cloneHeaderMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for name, value := range source {
		result[name] = value
	}
	return result
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return value
		}
	}
	return ""
}

func drainLimited(body io.Reader) string {
	limited := io.LimitReader(body, maxBodyBytes)
	data, _ := io.ReadAll(limited)
	return string(data)
}
