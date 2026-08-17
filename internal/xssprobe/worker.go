// Package xssprobe implements the optional reflected-XSS checks triggered by
// requests observed through the local HTTP proxy or HTTPS MITM. It only sends
// inert special-character markers and confirms repeatable unencoded
// reflection in script, tag, or attribute context; no script, event handler,
// or payload is ever executed.
package xssprobe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID       = "passive.xss_probe"
	minimumQPS      = 1
	maximumQPS      = 20
	minimumRequests = 2
	maximumRequests = 100
	minimumParams   = 1
	maximumParams   = 20
	queueCapacity   = 32
	activeProbeBodyLimit = 4 << 20
)

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveXSSProbeQPS() int
	PassiveXSSMaxRequests() int
	PassiveXSSMaxParameters() int
}

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

// parameter is one controllable input location whose value can be replaced
// with a reflection marker.
type parameter struct {
	name          string
	location      string // query | form | json | cookie | header | path
	value         string
	containerName string
	jsonPath      []jsonPathPart
	headerName    string
}

type jsonPathPart struct {
	key     string
	index   int
	isIndex bool
}

type probeResponse struct {
	status      int
	body        string
	contentType string
	marker      string
	transaction model.Transaction
}

type requestBudget struct {
	limit int
	used  int
}

func (b *requestBudget) canSpend(count int) bool { return b.used+count <= b.limit }

func (b *requestBudget) spend() bool {
	if b.used >= b.limit {
		return false
	}
	b.used++
	return true
}

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

// Observe only queues work. Network requests are made by the background
// worker so the browser response path is never delayed by probing.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) || !w.enabled() {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	method := strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return
	}
	if len(extractParameters(tx)) == 0 {
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
	qps := w.policy.PassiveXSSProbeQPS()
	if qps < minimumQPS {
		return minimumQPS
	}
	if qps > maximumQPS {
		return maximumQPS
	}
	return qps
}

func (w *Worker) maxRequests() int {
	value := w.policy.PassiveXSSMaxRequests()
	if value < minimumRequests {
		return minimumRequests
	}
	if value > maximumRequests {
		return maximumRequests
	}
	return value
}

func (w *Worker) maxParameters() int {
	value := w.policy.PassiveXSSMaxParameters()
	if value < minimumParams {
		return minimumParams
	}
	if value > maximumParams {
		return maximumParams
	}
	return value
}

func (w *Worker) waitForTurn(ctx context.Context) error {
	delay := time.Second / time.Duration(w.qps())
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (w *Worker) probeTransaction(ctx context.Context, tx model.Transaction) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	if tx.Response.Status == http.StatusTooManyRequests || tx.Response.Status >= 500 {
		return
	}
	candidates := extractParameters(tx)
	if len(candidates) == 0 {
		return
	}
	if len(candidates) > w.maxParameters() {
		candidates = candidates[:w.maxParameters()]
	}
	client := w.client()
	defer client.CloseIdleConnections()
	budget := requestBudget{limit: w.maxRequests()}
	for _, item := range candidates {
		if ctx.Err() != nil || !w.enabled() || !budget.canSpend(2) {
			return
		}
		// First marker: look for an unencoded reflection in an executable
		// HTML context. The marker carries only HTML-significant characters.
		first, firstErr := w.probe(ctx, client, tx, item, newMarker(), &budget)
		if firstErr != nil {
			continue
		}
		contextName := reflectionContext(first.body, first.marker)
		if !isRenderableHTML(first.contentType) || first.status < 200 || first.status >= 400 || contextName == "" || contextName == "HTML comment context" {
			continue
		}
		// Second marker: the reflection must reproduce with different marker
		// bytes in the same context before anything is reported.
		if !budget.canSpend(1) {
			return
		}
		replay, replayErr := w.probe(ctx, client, tx, item, newMarker(), &budget)
		if replayErr != nil {
			continue
		}
		if reflectionContext(replay.body, replay.marker) != contextName || !reproducibleReflection(first, replay) {
			continue
		}
		confidence := "medium"
		if !isExecutableHTMLContext(contextName) {
			confidence = "low"
		}
		w.report(tx, item, contextName, confidence, first, replay)
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
		timeout = 5 * time.Second
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (w *Worker) probe(ctx context.Context, client *http.Client, tx model.Transaction, item parameter, marker string, budget *requestBudget) (probeResponse, error) {
	if !w.enabled() {
		return probeResponse{}, errors.New("XSS probe is disabled")
	}
	if !budget.spend() {
		return probeResponse{}, errors.New("XSS probe request budget exhausted")
	}
	if err := w.waitForTurn(ctx); err != nil {
		return probeResponse{}, err
	}
	request, err := buildRequest(ctx, tx, item, marker)
	if err != nil {
		return probeResponse{}, err
	}
	requestBody, err := snapshotRequestBody(request)
	if err != nil {
		return probeResponse{}, err
	}
	startedAt := time.Now().UTC()
	response, err := client.Do(request)
	if err != nil {
		return probeResponse{}, err
	}
	defer response.Body.Close()
	limit := w.cfg.Proxy.MaxBodyBytes
	if limit < activeProbeBodyLimit {
		limit = activeProbeBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return probeResponse{}, err
	}
	transaction := model.Transaction{
		Observed: startedAt,
		Source:   "xss-probe",
		Request: model.Message{
			Method:  request.Method,
			URL:     request.URL.String(),
			Headers: httpHeaderMap(request.Header),
			Body:    requestBody,
		},
		Response: model.Message{
			Status:  response.StatusCode,
			Headers: httpHeaderMap(response.Header),
			Body:    string(body),
		},
	}
	return probeResponse{
		status:      response.StatusCode,
		body:        string(body),
		contentType: response.Header.Get("Content-Type"),
		marker:      marker,
		transaction: transaction,
	}, nil
}

func (w *Worker) report(tx model.Transaction, item parameter, contextName string, confidence string, first, replay probeResponse) {
	ruleID := "passive.xss-probe." + item.location + "." + stableToken(item.name)
	finding := model.Finding{
		RuleID:      ruleID,
		Title:       "疑似反射型 XSS",
		Severity:    "medium",
		Confidence:  confidence,
		URL:         tx.Request.URL,
		Method:      tx.Request.Method,
		Description: "MITM XSS 探测在受控参数中观察到可重复的未编码特殊字符反射，未执行任何脚本，需人工复核反射上下文。",
		Evidence:    fmt.Sprintf("参数=%s；位置=%s；反射上下文=%s；状态码=%d/%d；两次不同标记反射一致。", item.name, item.location, contextName, first.status, replay.status),
		Remediation: "按输出上下文对不可信数据进行编码（HTML 实体、属性或脚本字符串转义），并设置 Content-Security-Policy。",
		Tags:        []string{"xss", "mitm", "candidate"},
		ObservedAt:  tx.Observed,
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, []model.Transaction{
		cloneTransaction(tx),
		first.transaction,
		replay.transaction,
	})
	w.engine.Log("info", "xssprobe", fmt.Sprintf("MITM XSS 探测：参数 %s 在 %s 发现可复现的未编码反射", item.name, contextName))
}

// newMarker returns an inert marker containing only HTML-significant
// characters plus a random token so reflections can be correlated.
func newMarker() string {
	buffer := make([]byte, 4)
	if _, err := rand.Read(buffer); err != nil {
		return "ezxss_00000000_\"'<>"
	}
	return "ezxss_" + hex.EncodeToString(buffer) + "_\"'<>"
}

var volatileBodyPattern = regexp.MustCompile(`(?i)\b(?:ezxss_[a-f0-9]{8,}|[a-f0-9]{8}-[a-f0-9-]{27,}|\d{4}-\d{2}-\d{2}[t ][0-9:.+-]{8,}|\b\d{10,}\b|\b[a-f0-9]{20,}\b)\b`)

// normalizeProbeBody removes common volatile values before comparing two
// bounded responses. It deliberately leaves page structure intact.
func normalizeProbeBody(body string) string {
	body = strings.ToLower(body)
	body = volatileBodyPattern.ReplaceAllString(body, "[volatile]")
	return strings.Join(strings.Fields(body), " ")
}

func bodySimilarity(a, b string) float64 {
	if a == b {
		return 1
	}
	if len(a) < 3 || len(b) < 3 {
		return 0
	}
	grams := func(value string) map[string]struct{} {
		result := make(map[string]struct{}, len(value)-2)
		for i := 0; i+3 <= len(value); i++ {
			result[value[i:i+3]] = struct{}{}
		}
		return result
	}
	left, right := grams(a), grams(b)
	intersection := 0
	for gram := range left {
		if _, ok := right[gram]; ok {
			intersection++
		}
	}
	union := len(left) + len(right) - intersection
	if union == 0 {
		return 1
	}
	return float64(intersection) / float64(union)
}

func reproducibleReflection(first, replay probeResponse) bool {
	return first.status == replay.status && bodySimilarity(normalizeProbeBody(first.body), normalizeProbeBody(replay.body)) >= 0.90
}

// reflectionContext classifies the HTML context around a reflected marker.
func reflectionContext(body, marker string) string {
	at := strings.Index(body, marker)
	if at < 0 {
		return ""
	}
	start := at - 180
	if start < 0 {
		start = 0
	}
	prefix := strings.ToLower(body[start:at])
	if strings.LastIndex(prefix, "<!--") > strings.LastIndex(prefix, "-->") {
		return "HTML comment context"
	}
	if strings.LastIndex(prefix, "<script") > strings.LastIndex(prefix, "</script") {
		return "script context"
	}
	if strings.LastIndex(prefix, "=") > strings.LastIndex(prefix, "<") {
		return "HTML attribute context"
	}
	if strings.LastIndex(prefix, "<") > strings.LastIndex(prefix, ">") {
		return "HTML tag context"
	}
	return "HTML text context"
}

func isRenderableHTML(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml")
}

func isExecutableHTMLContext(context string) bool {
	return context == "script context" || context == "HTML attribute context" || context == "HTML tag context"
}

// extractParameters collects controllable query, form, and JSON scalar
// parameters in a deterministic order.
func extractParameters(tx model.Transaction) []parameter {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil {
		return nil
	}
	result := make([]parameter, 0, 16)
	names := make([]string, 0, len(parsed.Query()))
	for name := range parsed.Query() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := parsed.Query()[name]
		if name != "" && len(values) > 0 {
			result = append(result, parameter{name: name, location: "query", value: values[0]})
		}
	}
	contentType := strings.ToLower(strings.TrimSpace(headerValue(tx.Request.Headers, "Content-Type")))
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if values, parseErr := url.ParseQuery(tx.Request.Body); parseErr == nil {
			formNames := make([]string, 0, len(values))
			for name := range values {
				formNames = append(formNames, name)
			}
			sort.Strings(formNames)
			for _, name := range formNames {
				if name != "" && len(values[name]) > 0 {
					result = append(result, parameter{name: name, location: "form", value: values[name][0]})
				}
			}
		}
	}
	if strings.HasPrefix(contentType, "application/json") {
		var value any
		if json.Unmarshal([]byte(tx.Request.Body), &value) == nil {
			appendJSONParameters(&result, value, nil)
		}
	}
	hasExplicitParameters := len(result) > 0
	for _, pair := range strings.Split(headerValue(tx.Request.Headers, "Cookie"), ";") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" {
			name := strings.TrimSpace(parts[0])
			result = append(result, parameter{name: name, location: "cookie", value: strings.TrimSpace(parts[1])})
		}
	}
	if !hasExplicitParameters {
		for _, name := range []string{"Referer", "X-Forwarded-For", "X-Real-IP", "Client-IP"} {
			if value := strings.TrimSpace(headerValue(tx.Request.Headers, name)); value != "" {
				result = append(result, parameter{name: name, location: "header", value: value, headerName: name})
			}
		}
	}
	if len(result) == 0 {
		if item, ok := lastPathParameter(parsed); ok {
			result = append(result, item)
		}
	}
	return result
}

// lastPathParameter extracts the final path segment as a candidate parameter
// when no query/form/json/cookie/header parameters are present. This covers
// RESTful endpoints where the identifier is in the URL path.
func lastPathParameter(parsed *url.URL) (parameter, bool) {
	if parsed == nil {
		return parameter{}, false
	}
	trimmed := strings.Trim(parsed.Path, "/")
	segments := strings.Split(trimmed, "/")
	if len(segments) < 2 {
		return parameter{}, false
	}
	value := segments[len(segments)-1]
	if value == "" || len(value) > 128 || strings.Contains(value, ".") {
		return parameter{}, false
	}
	switch strings.ToLower(value) {
	case "api", "login", "logout", "user", "users", "index", "home", "health", "metrics", "swagger", "openapi":
		return parameter{}, false
	}
	return parameter{name: "path.segment", location: "path", value: value}, true
}

func replaceCookieValue(raw, name, value string) string {
	parts := strings.Split(raw, ";")
	for index, part := range parts {
		pair := strings.SplitN(part, "=", 2)
		if len(pair) == 2 && strings.TrimSpace(pair[0]) == name {
			parts[index] = strings.TrimSpace(pair[0]) + "=" + value
		}
	}
	return strings.Join(parts, "; ")
}

func appendJSONParameters(result *[]parameter, value any, path []jsonPathPart) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			next := append(append([]jsonPathPart(nil), path...), jsonPathPart{key: key})
			appendJSONParameters(result, typed[key], next)
		}
	case []any:
		for index, child := range typed {
			next := append(append([]jsonPathPart(nil), path...), jsonPathPart{index: index, isIndex: true})
			appendJSONParameters(result, child, next)
		}
	case string:
		if len(path) == 0 {
			return
		}
		*result = append(*result, parameter{
			name:     jsonPathName(path),
			location: "json",
			value:    typed,
			jsonPath: append([]jsonPathPart(nil), path...),
		})
	}
}

func jsonPathName(path []jsonPathPart) string {
	var builder strings.Builder
	for index, part := range path {
		if part.isIndex {
			fmt.Fprintf(&builder, "[%d]", part.index)
			continue
		}
		if index > 0 {
			builder.WriteByte('.')
		}
		builder.WriteString(part.key)
	}
	return builder.String()
}

// buildRequest clones the observed request and replaces only the probed
// parameter value with the marker.
func buildRequest(ctx context.Context, tx model.Transaction, item parameter, value string) (*http.Request, error) {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil {
		return nil, err
	}
	headers := cloneHeaderMap(tx.Request.Headers)
	var body string
	switch item.location {
	case "query":
		values := parsed.Query()
		values.Set(item.name, value)
		parsed.RawQuery = values.Encode()
		body = tx.Request.Body
	case "form":
		values, parseErr := url.ParseQuery(tx.Request.Body)
		if parseErr != nil {
			return nil, parseErr
		}
		values.Set(item.name, value)
		body = values.Encode()
		if headers != nil {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
	case "json":
		var document any
		if err := json.Unmarshal([]byte(tx.Request.Body), &document); err != nil {
			return nil, err
		}
		mutated, ok := setJSONValue(document, item.jsonPath, value)
		if !ok {
			return nil, errors.New("json path no longer present")
		}
		encoded, marshalErr := json.Marshal(mutated)
		if marshalErr != nil {
			return nil, marshalErr
		}
		body = string(encoded)
		if headers != nil {
			headers["Content-Type"] = "application/json"
		}
	case "cookie":
		updated := replaceCookieValue(headerValue(tx.Request.Headers, "Cookie"), item.name, value)
		if headers != nil {
			headers["Cookie"] = updated
		}
		body = tx.Request.Body
	case "header":
		if item.headerName == "" {
			return nil, fmt.Errorf("header parameter %q missing header name", item.name)
		}
		if headers != nil {
			headers[item.headerName] = value
		}
		body = tx.Request.Body
	case "path":
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(segments) < 2 {
			return nil, errors.New("path segment no longer present")
		}
		segments[len(segments)-1] = value
		parsed.Path = "/" + strings.Join(segments, "/")
		body = tx.Request.Body
	default:
		return nil, fmt.Errorf("unsupported parameter location %q", item.location)
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, tx.Request.Method, parsed.String(), reader)
	if err != nil {
		return nil, err
	}
	for name, raw := range headers {
		for _, value := range strings.Split(raw, "\n") {
			request.Header.Add(name, value)
		}
	}
	request.Header.Set("User-Agent", "EasyScan/0.1 authorized-verification")
	request.Header.Del("Accept-Encoding")
	return request, nil
}

func setJSONValue(document any, path []jsonPathPart, value string) (any, bool) {
	if len(path) == 0 {
		return value, true
	}
	switch typed := document.(type) {
	case map[string]any:
		part := path[0]
		if part.isIndex {
			return nil, false
		}
		child, ok := typed[part.key]
		if !ok {
			return nil, false
		}
		if len(path) == 1 {
			typed[part.key] = value
			return typed, true
		}
		mutated, ok := setJSONValue(child, path[1:], value)
		if !ok {
			return nil, false
		}
		typed[part.key] = mutated
		return typed, true
	case []any:
		part := path[0]
		if !part.isIndex || part.index < 0 || part.index >= len(typed) {
			return nil, false
		}
		if len(path) == 1 {
			typed[part.index] = value
			return typed, true
		}
		mutated, ok := setJSONValue(typed[part.index], path[1:], value)
		if !ok {
			return nil, false
		}
		typed[part.index] = mutated
		return typed, true
	}
	return nil, false
}

func transactionKey(tx model.Transaction, parsed *url.URL) string {
	items := extractParameters(tx)
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, item.location+"="+item.name)
	}
	sort.Strings(parts)
	raw := strings.ToUpper(strings.TrimSpace(tx.Request.Method)) + "\x00" + parsed.Host + parsed.EscapedPath() + "\x00" + strings.Join(parts, "&")
	return stableToken(raw)
}

func stableToken(value string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(value))))
	return hex.EncodeToString(digest[:])[:16]
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

func httpHeaderMap(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for name, values := range headers {
		result[name] = strings.Join(values, "\n")
	}
	return result
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func snapshotRequestBody(request *http.Request) (string, error) {
	if request == nil || request.Body == nil || request.GetBody == nil {
		return "", nil
	}
	body, err := request.GetBody()
	if err != nil {
		return "", err
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	return string(data), err
}
