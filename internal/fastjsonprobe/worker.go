// Package fastjsonprobe implements the optional Fastjson detection triggered
// by JSON requests observed through the local HTTP proxy or HTTPS MITM. For a
// captured JSON request the worker resends a copy with one brace removed and
// inspects the error response for Fastjson-specific parser signatures. This is
// a technology-detection probe only: it never sends deserialization payloads.
package fastjsonprobe

import (
	"bytes"
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
	featureID      = "passive.fastjson_probe"
	minimumQPS     = 1
	maximumQPS     = 20
	queueCapacity  = 32
	maxBodyBytes   = 1 << 20
	defaultTimeout = 10 * time.Second
)

// fastjsonSignatures are lower-cased substrings that strongly indicate the
// Alibaba Fastjson parser produced the response. They are matched against the
// error response body triggered by a malformed JSON payload.
var fastjsonSignatures = []string{
	"com.alibaba.fastjson",
	"fastjson.jsonexception",
	"fastjson.parser",
	"com.alibaba.fastjson.jsonexception",
	"com.alibaba.fastjson.parser",
}

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveFastjsonProbeQPS() int
}

// Worker schedules Fastjson probes for observed JSON requests. Observe only
// enqueues work; the background goroutine performs the network requests so the
// browser response path is never delayed.
type Worker struct {
	cfg    config.Config
	engine *engine.Engine
	policy Policy

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan queuedTransaction

	mu          sync.Mutex
	scheduled   map[string]struct{}
	stopped     bool
	generation  uint64
	batchCtx    context.Context
	batchCancel context.CancelFunc
	workers     sync.WaitGroup
}

type queuedTransaction struct {
	tx         model.Transaction
	generation uint64
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
		queue:       make(chan queuedTransaction, queueCapacity),
		scheduled:   make(map[string]struct{}),
		batchCtx:    batchCtx,
		batchCancel: batchCancel,
	}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe only queues work. Only state-changing requests that carry a JSON
// object body are eligible, because removing a brace from such a body is what
// provokes a parser error on the server.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) || !w.enabled() {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	method := strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return
	}
	body := tx.Request.Body
	if len(body) == 0 || len(body) > maxBodyBytes || !looksLikeJSONObject(tx.Request.Headers, body) {
		return
	}
	if removeOneBrace(body) == "" {
		return
	}
	key := transactionKey(tx, parsed)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if _, exists := w.scheduled[key]; exists {
		return
	}
	item := queuedTransaction{tx: cloneTransaction(tx), generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[key] = struct{}{}
	default:
		// A full queue is deliberately dropped rather than blocking MITM.
	}
}

// CancelPending stops the current batch and allows the same endpoint to be
// scheduled again after MITM is restarted or the setting is changed.
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

// Shutdown stops the scheduler and waits for in-flight probes to finish.
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
				w.probeTransaction(batch, item.tx)
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
	qps := w.policy.PassiveFastjsonProbeQPS()
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

// probeTransaction resends the captured request with one brace removed and
// reports a finding when the error response carries Fastjson signatures that
// were absent from the original captured response.
func (w *Worker) probeTransaction(ctx context.Context, tx model.Transaction) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	malformed := removeOneBrace(tx.Request.Body)
	if malformed == "" || malformed == tx.Request.Body {
		return
	}
	if err := w.waitForTurn(ctx); err != nil {
		return
	}
	resp, probeTx, err := w.send(ctx, tx, malformed)
	if err != nil {
		return
	}
	signature := matchFastjsonSignature(resp.body)
	if signature == "" {
		return
	}
	// Differential guard: ignore endpoints whose normal response already
	// mentions Fastjson, which would otherwise produce a false positive.
	if matchFastjsonSignature(tx.Response.Body) != "" {
		return
	}
	w.report(tx, probeTx, signature, resp.status)
}

// send issues the malformed request and returns the response together with a
// full evidence transaction for the report.
func (w *Worker) send(ctx context.Context, tx model.Transaction, body string) (probeResult, model.Transaction, error) {
	client := w.client()
	request, err := http.NewRequestWithContext(ctx, strings.ToUpper(strings.TrimSpace(tx.Request.Method)), tx.Request.URL, bytes.NewReader([]byte(body)))
	if err != nil {
		return probeResult{}, model.Transaction{}, err
	}
	for name, value := range tx.Request.Headers {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Host") {
			continue
		}
		request.Header.Set(name, value)
	}
	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return probeResult{}, model.Transaction{}, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return probeResult{}, model.Transaction{}, err
	}
	headers := make(map[string]string, len(response.Header))
	for name, values := range response.Header {
		if len(values) > 0 {
			headers[name] = strings.Join(values, "; ")
		}
	}
	probeTx := model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceMITMProbe,
		Request: model.Message{
			Method:  request.Method,
			URL:     tx.Request.URL,
			Headers: requestHeadersForEvidence(request.Header),
			Body:    body,
		},
		Response: model.Message{
			Status:  response.StatusCode,
			Headers: headers,
			Body:    string(payload),
		},
	}
	return probeResult{status: response.StatusCode, body: string(payload), dur: time.Since(started)}, probeTx, nil
}

func (w *Worker) report(tx, probeTx model.Transaction, signature string, status int) {
	finding := model.Finding{
		RuleID:      "passive.fastjson-probe.detected",
		Title:       "检测到 Fastjson",
		Severity:    "low",
		Confidence:  "medium",
		URL:         tx.Request.URL,
		Method:      tx.Request.Method,
		Description: "MITM Fastjson 探测发送了一个缺少大括号的 JSON 请求，服务端返回了 Fastjson 解析器特征，说明后端使用了 Alibaba Fastjson。Fastjson 历史版本存在反序列化漏洞，建议确认其版本。",
		Evidence:    fmt.Sprintf("状态码=%d；命中特征=%s", status, signature),
		Remediation: "确认 Fastjson 版本并升级到最新安全版本，或关闭 autoType；如无必要避免直接解析不可信 JSON。",
		Tags:        []string{"fastjson", "technology", "mitm"},
		ObservedAt:  tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{cloneTransaction(tx), cloneTransaction(probeTx)})
	if w.engine != nil {
		w.engine.Log("info", "fastjson-probe", fmt.Sprintf("检测到 Fastjson：%s", tx.Request.URL))
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

type probeResult struct {
	status int
	body   string
	dur    time.Duration
}

// looksLikeJSONObject reports whether the body is a JSON object worth probing.
// It accepts an explicit JSON content type, or a body that begins with '{'.
func looksLikeJSONObject(headers map[string]string, body string) bool {
	contentType := strings.ToLower(headerValue(headers, "Content-Type"))
	trimmed := strings.TrimSpace(body)
	if strings.Contains(contentType, "json") {
		return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	}
	return strings.HasPrefix(trimmed, "{")
}

// removeOneBrace removes a single brace to produce malformed JSON. It prefers
// dropping the last closing brace, which reliably breaks object parsing.
func removeOneBrace(body string) string {
	if idx := strings.LastIndex(body, "}"); idx >= 0 {
		return body[:idx] + body[idx+1:]
	}
	if idx := strings.Index(body, "{"); idx >= 0 {
		return body[:idx] + body[idx+1:]
	}
	return ""
}

// matchFastjsonSignature returns the first Fastjson signature present in body.
func matchFastjsonSignature(body string) string {
	if body == "" {
		return ""
	}
	lower := strings.ToLower(body)
	for _, signature := range fastjsonSignatures {
		if strings.Contains(lower, signature) {
			return signature
		}
	}
	return ""
}

func transactionKey(tx model.Transaction, parsed *url.URL) string {
	return strings.ToUpper(strings.TrimSpace(tx.Request.Method)) + "\x00" + parsed.Host + parsed.EscapedPath()
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

func requestHeadersForEvidence(header http.Header) map[string]string {
	result := make(map[string]string, len(header))
	for name, values := range header {
		if len(values) > 0 {
			result[name] = strings.Join(values, "; ")
		}
	}
	return result
}
