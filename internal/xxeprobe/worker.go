// Package xxeprobe implements an optional XML External Entity check triggered
// when the local HTTP proxy or HTTPS MITM observes an XML request. When a
// request carries an XML body, the worker replays it with an injected DOCTYPE
// declaring an external entity. Detection is error-based: a response that
// echoes the entity value or leaks XML-parser/entity errors indicates the
// parser resolved external entities. A reserved OOB domain is used for
// out-of-band confirmation when configured. No local files are exfiltrated
// beyond a harmless probe path.
package xxeprobe

import (
	"context"
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
	featureID      = "passive.xxe_probe"
	minimumQPS     = 1
	maximumQPS     = 20
	queueCapacity  = 32
	maxBodyBytes   = 1 << 20
	defaultTimeout = 10 * time.Second
	// marker is a unique token echoed via an internal entity so we can confirm
	// entity expansion happened regardless of file access.
	marker = "easyscan-xxe-9f31a7c2"
)

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveXXEProbeQPS() int
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

// Observe only queues work. An endpoint is scheduled once when it carries an
// XML request body — the trigger the user asked for.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) || !w.enabled() {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	if !isXMLRequest(tx) {
		return
	}
	key := tx.Request.Method + " " + parsed.Host + parsed.Path
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
	qps := w.policy.PassiveXXEProbeQPS()
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
	client := w.client()
	for _, payload := range w.payloads() {
		if ctx.Err() != nil {
			return
		}
		if err := w.waitForTurn(ctx); err != nil {
			return
		}
		body := w.replay(ctx, client, jb.tx, payload.body)
		if body == "" {
			continue
		}
		if strings.Contains(body, marker) {
			w.report(jb.tx, payload.kind, "响应回显了注入的实体标记（"+marker+"），确认 XML 解析器展开了外部/内部实体。")
			return
		}
		if signal, hit := xxeErrorSignal(body); hit {
			w.report(jb.tx, payload.kind, "响应出现实体解析相关报错："+signal)
			return
		}
	}
}

type xxePayload struct {
	kind string
	body string
}

// payloads builds the XXE test documents. The internal-entity variant is safe
// and confirms entity expansion; the file variant reads a harmless
// non-sensitive path to elicit parser errors; the OOB variant is only added
// when a callback domain is reserved.
func (w *Worker) payloads() []xxePayload {
	internal := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe "` + marker + `">]><r>&xxe;</r>`
	file := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///nonexistent/` + marker + `">]><r>&xxe;</r>`
	list := []xxePayload{
		{kind: "internal-entity", body: internal},
		{kind: "file-entity", body: file},
	}
	if domain := oobEntity(w.policy.OOBDomain()); domain != "" {
		list = append(list, xxePayload{kind: "oob-entity", body: domain})
	}
	return list
}

func oobEntity(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Trim(domain, "/")
	return `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://xxe.` + domain + `/easyscan">]><r>&xxe;</r>`
}

func (w *Worker) replay(ctx context.Context, client *http.Client, tx model.Transaction, xml string) string {
	method := tx.Request.Method
	if method == "" || method == http.MethodGet {
		method = http.MethodPost
	}
	request, err := http.NewRequestWithContext(ctx, method, tx.Request.URL, strings.NewReader(xml))
	if err != nil {
		return ""
	}
	for name, value := range tx.Request.Headers {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Host") {
			continue
		}
		request.Header.Set(name, value)
	}
	if headerValue(tx.Request.Headers, "Content-Type") == "" {
		request.Header.Set("Content-Type", "application/xml")
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan xxe probe)")
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	body := drainLimited(response.Body)
	response.Body.Close()
	return body
}

// xxeErrorSignal reports whether the response body carries a marker consistent
// with a server-side XML parser attempting to resolve an external entity.
func xxeErrorSignal(body string) (string, bool) {
	lower := strings.ToLower(body)
	for _, marker := range xxeErrorMarkers {
		if strings.Contains(lower, marker) {
			return marker, true
		}
	}
	return "", false
}

var xxeErrorMarkers = []string{"failed to load external entity", "external entity", "entity reference", "no such file or directory", "file:///nonexistent", "docytype is not allowed", "doctype is not allowed", "xmlparseentityref", "undefined entity", "systemid unknown", "simplexml_load", "domdocument", "org.xml.sax", "saxparseexception", "xmlreader"}

func (w *Worker) report(tx model.Transaction, kind, detail string) {
	finding := model.Finding{
		RuleID:      "passive.xxe-probe.entity",
		Title:       "XXE（XML 外部实体注入）",
		Severity:    "high",
		Confidence:  "high",
		URL:         tx.Request.URL,
		Method:      tx.Request.Method,
		Description: "MITM 检测到 XML 流量后，重放请求并注入声明外部/内部实体的 DOCTYPE。" + detail + " 说明服务端 XML 解析器未禁用外部实体解析，存在 XXE 风险。",
		Evidence:    "Payload 类型=" + kind,
		Remediation: "在 XML 解析器中禁用 DTD 与外部实体（如设置 FEATURE_SECURE_PROCESSING、禁用 external-general-entities），或改用不解析实体的解析库。",
		Tags:        []string{"xxe", "xml", "mitm"},
		ObservedAt:  tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{cloneTransaction(tx)})
	if w.engine != nil {
		w.engine.Log("warn", "xxe-probe", "XXE 命中（"+kind+"）："+tx.Request.URL)
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

// isXMLRequest reports whether the observed request body is XML, by Content-Type
// or by leading document markers.
func isXMLRequest(tx model.Transaction) bool {
	body := strings.TrimSpace(tx.Request.Body)
	if body == "" {
		return false
	}
	contentType := strings.ToLower(headerValue(tx.Request.Headers, "Content-Type"))
	if strings.Contains(contentType, "xml") {
		return true
	}
	if strings.HasPrefix(body, "<?xml") {
		return true
	}
	if strings.HasPrefix(body, "<") && strings.Contains(body, "</") {
		return true
	}
	return false
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
