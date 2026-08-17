// Package shiroprobe implements the optional Apache Shiro checks triggered by
// traffic observed through the local HTTP proxy or HTTPS MITM. It detects the
// Shiro rememberMe fingerprint and, when a real rememberMe cookie is captured,
// attempts to decrypt it offline with a dictionary of well-known keys. The
// probe never sends deserialization payloads; key verification is performed by
// decrypting the target's own cookie, so it is safe and non-intrusive.
package shiroprobe

import (
	"context"
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
	featureID      = "passive.shiro_probe"
	minimumQPS     = 1
	maximumQPS     = 20
	queueCapacity  = 32
	maxBodyBytes   = 1 << 20
	defaultTimeout = 10 * time.Second
	// rememberMeCookieName is the cookie Shiro uses for remember-me identity.
	rememberMeCookieName = "rememberMe"
	// deleteMeValue is the sentinel Shiro sets when a rememberMe cookie is
	// missing or cannot be decrypted.
	deleteMeValue = "deleteMe"
)

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveShiroProbeQPS() int
	// ShiroKeys returns the user-supplied key dictionary appended to the
	// built-in list.
	ShiroKeys() []string
}

// Worker schedules Shiro probes for observed hosts. Observe only enqueues work;
// the background goroutine performs the network requests so the browser
// response path is never delayed.
type Worker struct {
	cfg    config.Config
	engine *engine.Engine
	policy Policy

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan shiroJob

	mu          sync.Mutex
	scheduled   map[string]struct{}
	stopped     bool
	generation  uint64
	batchCtx    context.Context
	batchCancel context.CancelFunc
	workers     sync.WaitGroup
}

type shiroJob struct {
	tx               model.Transaction
	rememberMeCookie string
	generation       uint64
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
		queue:       make(chan shiroJob, queueCapacity),
		scheduled:   make(map[string]struct{}),
		batchCtx:    batchCtx,
		batchCancel: batchCancel,
	}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe only queues work. A host is scheduled once when it shows any Shiro
// rememberMe fingerprint or carries a real rememberMe cookie.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) || !w.enabled() {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	rememberMeCookie := extractCookieValue(headerValue(tx.Request.Headers, "Cookie"), rememberMeCookieName)
	shiroSignal := rememberMeCookie != "" && rememberMeCookie != deleteMeValue
	if !shiroSignal {
		shiroSignal = responseHasRememberMe(tx.Response.Headers)
	}
	if !shiroSignal {
		return
	}
	key := parsed.Host
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if _, exists := w.scheduled[key]; exists {
		return
	}
	item := shiroJob{tx: cloneTransaction(tx), rememberMeCookie: rememberMeCookie, generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[key] = struct{}{}
	default:
		// A full queue is deliberately dropped rather than blocking MITM.
	}
}

// CancelPending stops the current batch and allows the same host to be
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
	qps := w.policy.PassiveShiroProbeQPS()
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

// probeJob confirms the Shiro fingerprint with an active rememberMe probe and,
// when a real rememberMe cookie was captured, attempts offline key decryption.
func (w *Worker) probeJob(ctx context.Context, job shiroJob) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	confirmed := w.confirmShiro(ctx, job)
	if confirmed {
		w.reportShiroPresence(job)
	}
	// Offline key verification only needs the captured cookie; it is pure
	// cryptography and runs even when the active probe was inconclusive.
	if job.rememberMeCookie != "" && job.rememberMeCookie != deleteMeValue {
		w.verifyKeys(job)
	}
}

// confirmShiro sends a request with an invalid rememberMe cookie and reports
// whether the response sets rememberMe=deleteMe, the canonical Shiro signal.
func (w *Worker) confirmShiro(ctx context.Context, job shiroJob) bool {
	if responseHasRememberMe(job.tx.Response.Headers) {
		return true
	}
	if err := w.waitForTurn(ctx); err != nil {
		return false
	}
	client := w.client()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, job.tx.Request.URL, nil)
	if err != nil {
		return false
	}
	request.Header.Set("Cookie", rememberMeCookieName+"=1")
	request.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan shiro probe)")
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	// Drain a bounded amount so the connection can be reused.
	drainLimited(response.Body)
	headers := make(map[string]string, len(response.Header))
	for name, values := range response.Header {
		if len(values) > 0 {
			headers[name] = strings.Join(values, "; ")
		}
	}
	return responseHasRememberMe(headers)
}

// verifyKeys attempts to decrypt the captured rememberMe cookie with every key
// in the combined built-in + user dictionary and reports each match.
func (w *Worker) verifyKeys(job shiroJob) {
	for _, key := range w.candidateKeys() {
		if result, ok := tryDecryptCookie(job.rememberMeCookie, key); ok {
			w.reportShiroKey(job, result)
		}
	}
}

// candidateKeys merges the built-in dictionary with the user-supplied keys,
// de-duplicated and trimmed.
func (w *Worker) candidateKeys() []string {
	seen := make(map[string]struct{})
	keys := make([]string, 0, len(builtinKeys))
	add := func(k string) {
		k = strings.TrimSpace(k)
		if k == "" {
			return
		}
		if _, exists := seen[k]; exists {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for _, k := range builtinKeys {
		add(k)
	}
	if w.policy != nil {
		for _, k := range w.policy.ShiroKeys() {
			add(k)
		}
	}
	return keys
}

func (w *Worker) reportShiroPresence(job shiroJob) {
	finding := model.Finding{
		RuleID:      "passive.shiro-probe.detected",
		Title:       "检测到 Apache Shiro",
		Severity:    "low",
		Confidence:  "high",
		URL:         job.tx.Request.URL,
		Method:      job.tx.Request.Method,
		Description: "MITM Shiro 探测观察到 rememberMe 指纹（响应设置 rememberMe=deleteMe 或请求携带 rememberMe Cookie），说明目标使用了 Apache Shiro 框架。",
		Evidence:    "rememberMe 指纹命中",
		Remediation: "确认 Shiro 版本并升级；避免使用默认或泄露的 rememberMe 密钥。",
		Tags:        []string{"shiro", "technology", "mitm"},
		ObservedAt:  job.tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{cloneTransaction(job.tx)})
	if w.engine != nil {
		w.engine.Log("info", "shiro-probe", "检测到 Apache Shiro："+job.tx.Request.URL)
	}
}

func (w *Worker) reportShiroKey(job shiroJob, result decryptResult) {
	finding := model.Finding{
		RuleID:      "passive.shiro-probe.weak-key",
		Title:       "Shiro rememberMe 密钥可被识别",
		Severity:    "high",
		Confidence:  "high",
		URL:         job.tx.Request.URL,
		Method:      job.tx.Request.Method,
		Description: "使用常见 Shiro 密钥成功解密了捕获的 rememberMe Cookie，说明目标使用了已知/默认密钥。攻击者可据此伪造 rememberMe 身份，存在认证绕过乃至反序列化风险。",
		Evidence:    "加密模式=" + result.mode + "；密钥=" + result.key,
		Remediation: "立即更换 rememberMe 密钥为随机生成的高强度密钥，并升级 Shiro 至最新安全版本。",
		Tags:        []string{"shiro", "weak-key", "mitm"},
		ObservedAt:  job.tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{cloneTransaction(job.tx)})
	if w.engine != nil {
		w.engine.Log("warn", "shiro-probe", "识别到 Shiro 密钥（"+result.mode+"）："+job.tx.Request.URL)
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

// responseHasRememberMe reports whether any Set-Cookie header carries the
// rememberMe cookie (including the deleteMe sentinel).
func responseHasRememberMe(headers map[string]string) bool {
	for name, value := range headers {
		if !strings.EqualFold(strings.TrimSpace(name), "Set-Cookie") {
			continue
		}
		if strings.Contains(strings.ToLower(value), strings.ToLower(rememberMeCookieName)) {
			return true
		}
	}
	return false
}

// extractCookieValue parses a Cookie header and returns the value of the named
// cookie, or an empty string when absent.
func extractCookieValue(cookieHeader, name string) string {
	if cookieHeader == "" {
		return ""
	}
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx > 0 {
			if strings.EqualFold(strings.TrimSpace(part[:idx]), name) {
				return strings.TrimSpace(part[idx+1:])
			}
		}
	}
	return ""
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

func drainLimited(body interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	total := 0
	for total < maxBodyBytes {
		n, err := body.Read(buf)
		total += n
		if err != nil {
			return
		}
	}
}
