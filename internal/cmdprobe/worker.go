// Package cmdprobe implements an optional command-injection check triggered by
// traffic observed through the local HTTP proxy or HTTPS MITM. It injects a
// harmless arithmetic expression (e.g. expr 41567+82431) into request
// parameters and reports the endpoint as vulnerable only when the response
// echoes back the exact computed sum, which is a strong, low-false-positive
// signal that the input reached an OS command or eval context. No destructive
// commands are ever submitted.
package cmdprobe

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID      = "passive.cmd_probe"
	minimumQPS     = 1
	maximumQPS     = 20
	queueCapacity  = 32
	maxBodyBytes   = 1 << 20
	maxParams      = 4
	defaultTimeout = 10 * time.Second
)

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveCmdProbeQPS() int
}

// Worker schedules command-injection probes for observed endpoints. Observe
// only enqueues work; the background goroutine performs the network requests so
// the browser response path is never delayed.
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

// Observe only queues work. Each endpoint carrying at least one injectable
// parameter is scheduled once.
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
	qps := w.policy.PassiveCmdProbeQPS()
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

// probeTarget injects an arithmetic expression whose operands are randomised so
// the expected sum cannot pre-exist in the page, then confirms the sum is
// echoed back. A confirmation payload with different operands guards against a
// coincidental match.
func (w *Worker) probeTarget(ctx context.Context, client *http.Client, tx model.Transaction, tgt target) bool {
	left := 100000 + rand.Intn(800000)
	right := 100000 + rand.Intn(800000)
	sum := left + right
	if w.injectAndCheck(ctx, client, tx, tgt, left, right, sum) {
		// Second, independent operand pair confirms the echo is dynamic.
		l2 := 100000 + rand.Intn(800000)
		r2 := 100000 + rand.Intn(800000)
		if w.injectAndCheck(ctx, client, tx, tgt, l2, r2, l2+r2) {
			w.report(tx, tgt, left, right, sum)
			return true
		}
	}
	return false
}

func (w *Worker) injectAndCheck(ctx context.Context, client *http.Client, tx model.Transaction, tgt target, left, right, sum int) bool {
	if err := w.waitForTurn(ctx); err != nil {
		return false
	}
	sumText := strconv.Itoa(sum)
	for _, payload := range commandPayloads(tgt.value, left, right) {
		if ctx.Err() != nil {
			return false
		}
		request, err := buildRequest(ctx, tx, tgt, payload)
		if err != nil {
			continue
		}
		request.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan cmd probe)")
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		body := drainLimited(response.Body)
		response.Body.Close()
		if strings.Contains(body, sumText) && !strings.Contains(tgt.value, sumText) {
			return true
		}
	}
	return false
}

// commandPayloads returns candidate injection strings for a base value. They
// cover shell command substitution, chaining, and template/eval echo contexts.
func commandPayloads(base string, left, right int) []string {
	l := strconv.Itoa(left)
	r := strconv.Itoa(right)
	expr := "expr " + l + " + " + r
	arith := "$((" + l + "+" + r + "))"
	return []string{
		base + ";" + expr,
		base + "|" + expr,
		base + "`" + expr + "`",
		base + "$(" + expr + ")",
		base + "&&" + expr,
		base + arith,
		base + "${" + l + "+" + r + "}",
	}
}

func (w *Worker) report(tx model.Transaction, tgt target, left, right, sum int) {
	finding := model.Finding{
		RuleID:      "passive.cmd-probe.echo",
		Title:       "命令/代码执行（算术回显）",
		Severity:    "critical",
		Confidence:  "high",
		URL:         tx.Request.URL,
		Method:      tx.Request.Method,
		Description: "MITM 命令执行探测向参数注入算术表达式（如 expr X+Y），响应中回显了精确计算结果，说明输入被目标当作系统命令或表达式执行。这是命令/代码注入的高置信度证据。",
		Evidence:    fmt.Sprintf("参数=%s(%s)；表达式=%d+%d；回显结果=%d", tgt.name, tgt.location, left, right, sum),
		Remediation: "对进入命令/表达式上下文的输入做严格白名单校验，避免拼接执行；使用参数化 API 替代 shell 调用。",
		Tags:        []string{"command-injection", "rce", "mitm"},
		ObservedAt:  tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{cloneTransaction(tx)})
	if w.engine != nil {
		w.engine.Log("warn", "cmd-probe", "命令执行回显命中："+tx.Request.URL)
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

// extractTargets returns injectable query and form parameters for a request.
func extractTargets(tx model.Transaction) []target {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil {
		return nil
	}
	result := make([]target, 0, 8)
	for name, values := range parsed.Query() {
		if name != "" && len(values) > 0 {
			result = append(result, target{location: "query", name: name, value: values[0]})
		}
	}
	contentType := strings.ToLower(strings.TrimSpace(headerValue(tx.Request.Headers, "Content-Type")))
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if values, parseErr := url.ParseQuery(tx.Request.Body); parseErr == nil {
			for name, vs := range values {
				if name != "" && len(vs) > 0 {
					result = append(result, target{location: "form", name: name, value: vs[0]})
				}
			}
		}
	}
	return result
}

// buildRequest clones the observed request and replaces the target parameter
// value with the payload, preserving the original method, headers, and body
// shape.
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
