// Package sqlprobe implements the optional SQL injection checks triggered by
// requests observed through the local HTTP proxy or HTTPS MITM.
package sqlprobe

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	featureID        = "passive.sqli_probe"
	minimumQPS       = 1
	maximumQPS       = 20
	minimumRequests  = 3
	maximumRequests  = 200
	minimumParams    = 1
	maximumParams    = 20
	queueCapacity    = 32
	timeProbeDelay   = 2 * time.Second
	minimumTimeDelta = 1 * time.Second
	activeProbeBodyLimit = 4 << 20
)

var (
	sqlErrorPattern     = regexp.MustCompile(`(?is)(?:sql syntax|sqlstate|sql error|sql syntax error|sqlstatementexception|sqlsyntaxerrorexception|mysql(?: server| error|_fetch_|i?sql)|mariadb|postgres(?:ql)?|psql(?:exception|:)|pg_query|oracle|ora-\d{5}|unclosed quotation mark|quoted string not properly terminated|incorrect syntax near|invalid object name|odbc (?:sql|microsoft)|sqlite(?:_exception| error)|jdbc|database error|xpath syntax error|unknown column ['"]|unterminated quoted string|unrecognized token|syntax error at or near|order by position|ordinal position|not in select list|unknown column .+ in .?order clause|microsoft sql server|microsoft ole db provider|microsoft jet database|microsoft access (?:driver|database)|ole db provider|native client|\[sql server\]|\[sqlserver jdbc driver\]|\[microsoft\]\[odbc|mssql_(?:query|fetch|num_rows|connect)|sqlserverexception|sqlservererror|system\.data\.sqlclient\.sqlexception|msg \d+, level \d+, state \d+|line \d+: incorrect syntax|conversion failed when converting|conversion failed converting|arithmetic overflow error|must declare the (?:scalar |table )?variable|procedure or function .+ expects parameter|invalid column name|the multi-part identifier|cannot insert (?:the value |explicit value )|the conversion of (?:a |the )|string or binary data would be truncated|cannot resolve the collation conflict|divide by zero error encountered|xp_cmdshell|openrowset|opendatasource)`)
	wafPattern          = regexp.MustCompile(`(?is)(?:\bwaf\b|web application firewall|blocked by .*firewall|request.*(?:blocked|denied)|suspected attack)`)
	numericPattern      = regexp.MustCompile(`^[+-]?\d+(?:\.\d+)?$`)
	volatileBodyPattern = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{8}-[a-f0-9-]{27,}|\d{4}-\d{2}-\d{2}[t ][0-9:.+-]{8,}|\b\d{10,}\b|\b[a-f0-9]{20,}\b)\b`)
	// volatileValuePattern 匹配 key="value" / key:'value' / key=value 形式的动态
	// 赋值，将值部分替换为占位符，覆盖 csrf/session/nonce/token 等常见字段，避免
	// 动态内容导致 baseline vs control 闸门误判。仅针对字段赋值形式，不会破坏
	// SQL 错误信息或正常文本内容。
	volatileValuePattern = regexp.MustCompile(`(?i)\b(?:csrf|csrf[_\-]?token|nonce|token|session(?:id)?|sid|auth|captcha|verify|nonce_str|_token|x[-_]?csrf[-_]?token|jwt|bearer)\b\s*[:=]\s*['"]?[a-z0-9_\-+/=]{6,128}['"]?`)
)

// Parser probes cover quoted, unquoted, and parenthesized SQL contexts. The
// response delta is also used to prioritize boolean and timing templates.
var errorPayloads = []errorPayload{
	{context: "single-quoted", suffix: "'"},
	{context: "double-quoted", suffix: `"`},
	{context: "numeric-parenthesized", suffix: ")"},
	{context: "numeric-double-parenthesized", suffix: "))"},
	{context: "single-quoted-parenthesized", suffix: "')"},
	{context: "double-quoted-parenthesized", suffix: `")`},
	{context: "escape", suffix: `\`},
	{context: "backtick", suffix: "`"},
}

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	SQLiErrorEnabled() bool
	SQLiBooleanEnabled() bool
	SQLiTimeEnabled() bool
	PassiveSQLiProbeQPS() int
	PassiveSQLiMaxRequests() int
	PassiveSQLiMaxParameters() int
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

type candidate struct {
	name          string
	location      string
	value         string
	containerName string
	jsonPath      []jsonPathPart
	headerName    string
	contextHint   string
	priority      int
}

type jsonPathPart struct {
	key     string
	index   int
	isIndex bool
}

type errorPayload struct {
	context string
	suffix  string
}

type probeResponse struct {
	status      int
	body        string
	dur         time.Duration
	transaction model.Transaction
}

type requestBudget struct {
	limit int
	used  int
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
	if w == nil || w.engine == nil || w.policy == nil {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：worker 未初始化 url=%s", tx.Request.URL))
		return
	}
	if !model.IsObservedProxySource(tx.Source) {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：source=%q 非代理来源 url=%s", tx.Source, tx.Request.URL))
		return
	}
	if !w.enabled() {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：passive.sqli_probe 未启用 url=%s", tx.Request.URL))
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：URL 解析失败 url=%s", tx.Request.URL))
		return
	}
	if !w.engine.AllowsActiveHost(parsed.Hostname()) {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：AllowsActiveHost 拒绝 host=%s url=%s", parsed.Hostname(), tx.Request.URL))
		return
	}
	method := strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：method=%s 不支持 url=%s", method, tx.Request.URL))
		return
	}
	if len(extractCandidates(tx)) == 0 {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：无候选参数 url=%s", tx.Request.URL))
		return
	}
	key := transactionKey(tx, parsed)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：worker 已停止 url=%s", tx.Request.URL))
		return
	}
	if _, exists := w.scheduled[key]; exists {
		w.engine.Log("debug", "sqli-probe", fmt.Sprintf("Observe 跳过：已调度过（去重）key=%s url=%s", key[:8], tx.Request.URL))
		return
	}
	item := queuedTransaction{tx: cloneTransaction(tx), generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[key] = struct{}{}
		w.engine.Log("info", "sqli-probe", fmt.Sprintf("Observe 入队：key=%s url=%s method=%s", key[:8], tx.Request.URL, method))
	default:
		w.engine.Log("warn", "sqli-probe", fmt.Sprintf("Observe 跳过：队列已满（静默丢弃）url=%s", tx.Request.URL))
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
	qps := w.policy.PassiveSQLiProbeQPS()
	if qps < minimumQPS {
		return minimumQPS
	}
	if qps > maximumQPS {
		return maximumQPS
	}
	return qps
}

func (w *Worker) maxRequests() int {
	value := w.policy.PassiveSQLiMaxRequests()
	if value < minimumRequests {
		return minimumRequests
	}
	if value > maximumRequests {
		return maximumRequests
	}
	return value
}

func (w *Worker) maxParameters() int {
	value := w.policy.PassiveSQLiMaxParameters()
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
	if tx.Response.Status == http.StatusTooManyRequests || tx.Response.Status == http.StatusBadGateway || tx.Response.Status >= 500 {
		return
	}
	errorEnabled := w.policy.SQLiErrorEnabled()
	booleanEnabled := w.policy.SQLiBooleanEnabled()
	timeEnabled := w.policy.SQLiTimeEnabled()
	if !errorEnabled && !booleanEnabled && !timeEnabled {
		return
	}
	candidates := extractCandidates(tx)
	if len(candidates) == 0 {
		return
	}
	if len(candidates) > w.maxParameters() {
		candidates = candidates[:w.maxParameters()]
	}
	client := w.client()
	defer client.CloseIdleConnections()
	endpointBudget := w.maxRequests()
	perParam := perParameterBudget(endpointBudget, len(candidates))
	baseline := observedResponse(tx.Response)
	for _, item := range candidates {
		if ctx.Err() != nil || !w.enabled() || perParam < minimumRequests {
			return
		}
		budget := requestBudget{limit: perParam}
		// Replay the original value as the control. Replacing a numeric parameter
		// with an alphabetic marker can be rejected by application validation
		// before the value reaches SQL, hiding otherwise detectable behavior.
		controlValue := item.value
		control, err := w.probe(ctx, client, tx, item, controlValue, "sqli-probe.control", &budget)
		if err != nil {
			continue
		}

		preferredContexts := make([]string, 0, 4)
		findingReported := false
		if errorEnabled {
			for _, payload := range errorPayloads {
				if !budget.canSpend(1) {
					break
				}
				probeValue := item.value + payload.suffix
				first, firstErr := w.probe(ctx, client, tx, item, probeValue, "sqli-probe.error."+payload.context+".probe", &budget)
				if firstErr != nil {
					continue
				}
				if materialDelta(first, baseline, control) {
					preferredContexts = appendUnique(preferredContexts, payload.context)
				}
				if !sqlErrorOnlyIn(first, baseline, control) || !budget.canSpend(1) {
					continue
				}
				replay, replayErr := w.probe(ctx, client, tx, item, probeValue, "sqli-probe.error."+payload.context+".replay", &budget)
				if replayErr == nil && reproducibleSQLError(first, replay) {
					w.report(tx, item, "sql-error-"+payload.context, "high", first, fmt.Sprintf("%s 参数出现新的 SQL 错误特征，%s 上下文复测结果一致。", item.location, payload.context), control, first, replay)
					findingReported = true
					break
				}
			}
		}
		if findingReported {
			continue
		}
		if !responsesSimilar(baseline, control) {
			continue
		}

		booleanDetected := false
		var booleanPair booleanValuePair
		var booleanTrue, booleanFalse, booleanReplay probeResponse
		if booleanEnabled {
			for _, pair := range orderedBooleanValuePairs(item, preferredContexts) {
				reservedForTiming := 0
				if timeEnabled {
					reservedForTiming = 3
				}
				if !budget.canSpend(2 + reservedForTiming) {
					break
				}
				trueResponse, trueErr := w.probe(ctx, client, tx, item, pair.trueValue, "sqli-probe.boolean."+pair.context+".true", &budget)
				falseResponse, falseErr := w.probe(ctx, client, tx, item, pair.falseValue, "sqli-probe.boolean."+pair.context+".false", &budget)
				if trueErr != nil || falseErr != nil || looksLikeWAF(trueResponse.body) || looksLikeWAF(falseResponse.body) {
					continue
				}
				candidateDetected := responsesSimilar(baseline, trueResponse) && responsesSimilar(control, trueResponse) && substantiallyDifferent(baseline, falseResponse) && substantiallyDifferent(control, falseResponse) && substantiallyDifferent(trueResponse, falseResponse)
				if !candidateDetected || !budget.canSpend(1+reservedForTiming) {
					continue
				}
				falseReplay, replayErr := w.probe(ctx, client, tx, item, pair.falseValue, "sqli-probe.boolean."+pair.context+".replay", &budget)
				if replayErr == nil && reproducibleResponse(falseResponse, falseReplay) {
					booleanDetected = true
					booleanPair = pair
					booleanTrue, booleanFalse, booleanReplay = trueResponse, falseResponse, falseReplay
					break
				}
			}
		}
		if booleanDetected && !timeEnabled {
			w.report(tx, item, "boolean-differential-"+booleanPair.context, "medium", booleanFalse, fmt.Sprintf("%s 参数的真假条件响应差异可复现（%s）。", item.location, booleanPair.context), control, booleanTrue, booleanFalse, booleanReplay)
			continue
		}

		if booleanEnabled && !booleanDetected {
			for _, pair := range orderedOrderByValuePairs(item, preferredContexts) {
				reservedForTiming := 0
				if timeEnabled {
					reservedForTiming = 3
				}
				if !budget.canSpend(3 + reservedForTiming) {
					break
				}
				validResponse, validErr := w.probe(ctx, client, tx, item, pair.validValue, "sqli-probe.order-by."+pair.context+".valid", &budget)
				invalidResponse, invalidErr := w.probe(ctx, client, tx, item, pair.invalidValue, "sqli-probe.order-by."+pair.context+".invalid", &budget)
				invalidReplay, replayErr := w.probe(ctx, client, tx, item, pair.invalidValue, "sqli-probe.order-by."+pair.context+".replay", &budget)
				if validErr == nil && invalidErr == nil && replayErr == nil && reproducibleOrderByDifferential(baseline, control, validResponse, invalidResponse, invalidReplay) {
					w.report(tx, item, "order-by-differential-"+pair.context, "high", invalidResponse, fmt.Sprintf("%s 参数在 ORDER BY 有效序号与越界序号之间出现可复现差异（%s）。", item.location, pair.context), control, validResponse, invalidResponse, invalidReplay)
					findingReported = true
					break
				}
			}
		}
		if findingReported {
			continue
		}

		if timeEnabled {
			timingContexts := preferredContexts
			if booleanDetected {
				timingContexts = append([]string{booleanPair.context}, timingContexts...)
			}
			for _, pair := range orderedTimeValuePairs(item, timingContexts) {
				if !budget.canSpend(3) {
					break
				}
				fastResponse, fastErr := w.probe(ctx, client, tx, item, pair.fastValue, "sqli-probe.time."+pair.context+".fast", &budget)
				slowResponse, slowErr := w.probe(ctx, client, tx, item, pair.slowValue, "sqli-probe.time."+pair.context+".slow", &budget)
				slowReplay, replayErr := w.probe(ctx, client, tx, item, pair.slowValue, "sqli-probe.time."+pair.context+".replay", &budget)
				if fastErr == nil && slowErr == nil && replayErr == nil && reproducibleTimeDelay(fastResponse, slowResponse, slowReplay) {
					w.report(tx, item, "time-differential-"+pair.context, "high", slowResponse, fmt.Sprintf("%s 参数的延时条件在两次复测中稳定增加至少 %s（%s）。", item.location, minimumTimeDelta, pair.context), control, fastResponse, slowResponse, slowReplay)
					findingReported = true
					break
				}
			}
		}
		if findingReported {
			continue
		}
		if booleanDetected {
			w.report(tx, item, "boolean-differential-"+booleanPair.context, "medium", booleanFalse, fmt.Sprintf("%s 参数的真假条件响应差异可复现（%s）。", item.location, booleanPair.context), control, booleanTrue, booleanFalse, booleanReplay)
		}
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

func (w *Worker) probe(ctx context.Context, client *http.Client, tx model.Transaction, item candidate, value, label string, budget *requestBudget) (probeResponse, error) {
	if !w.enabled() {
		return probeResponse{}, errors.New("SQL probe is disabled")
	}
	if !budget.spend() {
		return probeResponse{}, errors.New("SQL probe request budget exhausted")
	}
	if err := w.waitForTurn(ctx); err != nil {
		return probeResponse{}, err
	}
	request, err := buildRequest(ctx, tx, item, value)
	if err != nil {
		return probeResponse{}, err
	}
	requestBody, err := snapshotRequestBody(request)
	if err != nil {
		return probeResponse{}, err
	}
	startedAt := time.Now().UTC()
	started := time.Now()
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
		Source:   label,
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
	return probeResponse{status: response.StatusCode, body: string(body), dur: time.Since(started), transaction: transaction}, nil
}

func (w *Worker) report(tx model.Transaction, item candidate, technique, severity string, response probeResponse, detail string, probes ...probeResponse) {
	ruleID := "passive.sqli-probe." + item.location + "." + stableToken(item.name)
	finding := model.Finding{
		RuleID:      ruleID,
		Title:       "疑似 SQL 注入",
		Severity:    severity,
		Confidence:  "candidate",
		URL:         tx.Request.URL,
		Method:      tx.Request.Method,
		Description: "MITM SQL 探测对受控参数值观察到可重复的异常响应，未读取数据。",
		Evidence:    fmt.Sprintf("参数=%s；技术=%s；状态码=%d；耗时=%s；%s", item.name, technique, response.status, response.dur.Round(time.Millisecond), detail),
		Remediation: "使用参数化查询或预编译语句，并严格校验输入类型。",
		Tags:        []string{"sql-injection", "mitm", "candidate"},
		ObservedAt:  tx.Observed,
	}
	transactions := make([]model.Transaction, 0, len(probes)+1)
	transactions = append(transactions, cloneTransaction(tx))
	for _, probe := range probes {
		if strings.TrimSpace(probe.transaction.Request.URL) != "" {
			transactions = append(transactions, cloneTransaction(probe.transaction))
		}
	}
	_, _ = w.engine.ReportFindingWithEvidence(finding, transactions)
}

func snapshotRequestBody(request *http.Request) (string, error) {
	if request == nil || request.Body == nil {
		return "", nil
	}
	if request.GetBody == nil {
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

func httpHeaderMap(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for name, values := range headers {
		result[name] = strings.Join(values, "\n")
	}
	return result
}

func extractCandidates(tx model.Transaction) []candidate {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil {
		return nil
	}
	result := make([]candidate, 0, 16)
	for name, values := range parsed.Query() {
		if name != "" && len(values) > 0 {
			appendEncodedCandidates(&result, "query", name, values[0])
		}
	}
	contentType := strings.ToLower(strings.TrimSpace(headerValue(tx.Request.Headers, "Content-Type")))
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if values, parseErr := url.ParseQuery(tx.Request.Body); parseErr == nil {
			for name, values := range values {
				if name != "" && len(values) > 0 {
					appendEncodedCandidates(&result, "form", name, values[0])
				}
			}
		}
	}
	if strings.HasPrefix(contentType, "application/json") {
		var value any
		if json.Unmarshal([]byte(tx.Request.Body), &value) == nil {
			appendJSONCandidates(&result, "json", "", value, nil)
		}
	}
	hasExplicitParameters := len(result) > 0
	for _, pair := range strings.Split(headerValue(tx.Request.Headers, "Cookie"), ";") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" {
			name := strings.TrimSpace(parts[0])
			result = append(result, candidate{name: name, location: "cookie", value: strings.TrimSpace(parts[1]), priority: parameterPriority(name, "cookie")})
		}
	}
	if !hasExplicitParameters {
		for _, name := range []string{"Referer", "X-Forwarded-For", "X-Real-IP", "Client-IP"} {
			if value := strings.TrimSpace(headerValue(tx.Request.Headers, name)); value != "" {
				result = append(result, candidate{name: name, location: "header", value: value, headerName: name, priority: parameterPriority(name, "header")})
			}
		}
	}
	if len(result) == 0 {
		if item, ok := lastPathCandidate(parsed); ok {
			result = append(result, item)
		}
	}
	if strings.Contains(strings.ToLower(parsed.Path), "/like") {
		for index := range result {
			result[index].contextHint = "like"
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].priority != result[j].priority {
			return result[i].priority > result[j].priority
		}
		left := result[i].location + "\x00" + result[i].name
		right := result[j].location + "\x00" + result[j].name
		return left < right
	})
	return result
}

func appendEncodedCandidates(result *[]candidate, location, name, value string) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var decoded any
		if json.Unmarshal([]byte(trimmed), &decoded) == nil {
			before := len(*result)
			appendJSONCandidates(result, location+"-json", name, decoded, nil)
			if len(*result) > before {
				return
			}
		}
	}
	if decoded, ok := decodeBase64(value); ok {
		var document any
		if json.Unmarshal(decoded, &document) == nil {
			before := len(*result)
			appendJSONCandidates(result, location+"-base64-json", name, document, nil)
			if len(*result) > before {
				return
			}
		}
		lowerName := strings.ToLower(name)
		if (strings.Contains(lowerName, "b64") || strings.Contains(lowerName, "base64")) && printableText(decoded) {
			*result = append(*result, candidate{
				name:          name,
				location:      location + "-base64",
				value:         string(decoded),
				containerName: name,
				priority:      parameterPriority(name, location+"-base64"),
			})
			return
		}
	}
	*result = append(*result, candidate{name: name, location: location, value: value, priority: parameterPriority(name, location)})
}

func appendJSONCandidates(result *[]candidate, location, container string, value any, path []jsonPathPart) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			next := append(append([]jsonPathPart(nil), path...), jsonPathPart{key: key})
			appendJSONCandidates(result, location, container, typed[key], next)
		}
	case []any:
		for index, child := range typed {
			next := append(append([]jsonPathPart(nil), path...), jsonPathPart{index: index, isIndex: true})
			appendJSONCandidates(result, location, container, child, next)
		}
	default:
		scalar, ok := jsonScalarText(typed)
		if !ok || len(path) == 0 {
			return
		}
		pathName := jsonPathName(path)
		name := pathName
		if container != "" {
			name = container + "." + pathName
		}
		*result = append(*result, candidate{
			name:          name,
			location:      location,
			value:         scalar,
			containerName: container,
			jsonPath:      append([]jsonPathPart(nil), path...),
			priority:      parameterPriority(lastJSONPathName(path), location),
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

func lastJSONPathName(path []jsonPathPart) string {
	for index := len(path) - 1; index >= 0; index-- {
		if !path[index].isIndex {
			return path[index].key
		}
	}
	return "json"
}

func parameterPriority(name, location string) int {
	name = strings.ToLower(strings.TrimSpace(name))
	priority := 10
	switch name {
	case "id", "uid", "user_id", "userid":
		priority = 100
	case "name", "username", "user", "login":
		priority = 95
	case "orderby", "order_by", "order", "sort", "sortby":
		priority = 90
	case "limit", "offset", "page", "pagesize":
		priority = 80
	case "referer", "x-forwarded-for", "x-real-ip", "client-ip", "user-agent":
		priority = 75
	case "password", "passwd", "email", "search", "query", "keyword", "q":
		priority = 70
	}
	if strings.Contains(location, "base64") {
		priority += 20
	} else if strings.Contains(location, "json") {
		priority += 10
	}
	return priority
}

func decodeBase64(value string) ([]byte, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 4 || len(value) > 32<<10 {
		return nil, false
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}
	return nil, false
}

func printableText(value []byte) bool {
	if len(value) == 0 || len(value) > 32<<10 {
		return false
	}
	for _, character := range string(value) {
		if character == '\r' || character == '\n' || character == '\t' {
			continue
		}
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func lastPathCandidate(parsed *url.URL) (candidate, bool) {
	if parsed == nil {
		return candidate{}, false
	}
	trimmed := strings.Trim(parsed.Path, "/")
	segments := strings.Split(trimmed, "/")
	if len(segments) < 2 {
		return candidate{}, false
	}
	value := segments[len(segments)-1]
	if value == "" || len(value) > 128 || strings.Contains(value, ".") {
		return candidate{}, false
	}
	switch strings.ToLower(value) {
	case "api", "login", "logout", "user", "users", "index", "home", "health", "metrics", "swagger", "openapi":
		return candidate{}, false
	}
	return candidate{name: "path.segment", location: "path", value: value, priority: 60}, true
}

func buildRequest(ctx context.Context, tx model.Transaction, item candidate, value string) (*http.Request, error) {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil {
		return nil, err
	}
	headers := cloneRequestHeaders(tx.Request.Headers)
	var body io.Reader
	switch item.location {
	case "query":
		values := parsed.Query()
		values.Set(item.name, value)
		parsed.RawQuery = values.Encode()
		if tx.Request.Body != "" {
			body = strings.NewReader(tx.Request.Body)
		}
	case "query-json", "query-base64-json", "query-base64":
		values := parsed.Query()
		encoded, mutateErr := mutateEncodedValue(values.Get(item.containerName), item, value)
		if mutateErr != nil {
			return nil, mutateErr
		}
		values.Set(item.containerName, encoded)
		parsed.RawQuery = values.Encode()
		if tx.Request.Body != "" {
			body = strings.NewReader(tx.Request.Body)
		}
	case "form":
		values, parseErr := url.ParseQuery(tx.Request.Body)
		if parseErr != nil {
			return nil, parseErr
		}
		values.Set(item.name, value)
		body = strings.NewReader(values.Encode())
	case "form-json", "form-base64-json", "form-base64":
		values, parseErr := url.ParseQuery(tx.Request.Body)
		if parseErr != nil {
			return nil, parseErr
		}
		encoded, mutateErr := mutateEncodedValue(values.Get(item.containerName), item, value)
		if mutateErr != nil {
			return nil, mutateErr
		}
		values.Set(item.containerName, encoded)
		body = strings.NewReader(values.Encode())
	case "json":
		payload, err := mutateJSONDocument([]byte(tx.Request.Body), item.jsonPath, value)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(payload))
	case "cookie":
		headers.Set("Cookie", replaceCookieValue(headerValue(tx.Request.Headers, "Cookie"), item.name, value))
		if tx.Request.Body != "" {
			body = strings.NewReader(tx.Request.Body)
		}
	case "header":
		headers.Set(item.headerName, value)
		if tx.Request.Body != "" {
			body = strings.NewReader(tx.Request.Body)
		}
	case "path":
		trimmed := strings.TrimSuffix(parsed.Path, "/")
		separator := strings.LastIndex(trimmed, "/")
		if separator < 0 {
			return nil, errors.New("path parameter segment not found")
		}
		parsed.Path = trimmed[:separator+1] + value
		parsed.RawPath = ""
		if tx.Request.Body != "" {
			body = strings.NewReader(tx.Request.Body)
		}
	default:
		return nil, errors.New("unsupported parameter location")
	}
	method := strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return nil, err
	}
	for name, values := range headers {
		for _, headerValue := range values {
			request.Header.Add(name, headerValue)
		}
	}
	if body != nil && strings.HasPrefix(item.location, "form") && request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return request, nil
}

func mutateEncodedValue(original string, item candidate, value string) (string, error) {
	switch {
	case strings.HasSuffix(item.location, "-json") && !strings.Contains(item.location, "base64"):
		payload, err := mutateJSONDocument([]byte(original), item.jsonPath, value)
		return string(payload), err
	case strings.Contains(item.location, "base64-json"):
		decoded, ok := decodeBase64(original)
		if !ok {
			return "", errors.New("invalid base64 JSON parameter")
		}
		payload, err := mutateJSONDocument(decoded, item.jsonPath, value)
		if err != nil {
			return "", err
		}
		return encodeBase64Like(original, payload), nil
	case strings.HasSuffix(item.location, "-base64"):
		return encodeBase64Like(original, []byte(value)), nil
	default:
		return "", errors.New("unsupported encoded parameter")
	}
}

func mutateJSONDocument(raw []byte, path []jsonPathPart, value string) ([]byte, error) {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if err := setJSONPath(document, path, value); err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

func setJSONPath(document any, path []jsonPathPart, value string) error {
	if len(path) == 0 {
		return errors.New("empty JSON path")
	}
	current := document
	for index, part := range path {
		last := index == len(path)-1
		if part.isIndex {
			array, ok := current.([]any)
			if !ok || part.index < 0 || part.index >= len(array) {
				return errors.New("JSON array path not found")
			}
			if last {
				array[part.index] = value
				return nil
			}
			current = array[part.index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return errors.New("JSON object path not found")
		}
		if _, exists := object[part.key]; !exists {
			return errors.New("JSON key path not found")
		}
		if last {
			object[part.key] = value
			return nil
		}
		current = object[part.key]
	}
	return nil
}

func encodeBase64Like(original string, value []byte) string {
	urlAlphabet := strings.ContainsAny(original, "-_")
	padded := strings.Contains(original, "=")
	if urlAlphabet {
		if padded {
			return base64.URLEncoding.EncodeToString(value)
		}
		return base64.RawURLEncoding.EncodeToString(value)
	}
	if padded {
		return base64.StdEncoding.EncodeToString(value)
	}
	return base64.RawStdEncoding.EncodeToString(value)
}

func cloneRequestHeaders(source map[string]string) http.Header {
	result := make(http.Header, len(source))
	for name, value := range source {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host", "content-length", "connection", "proxy-connection", "proxy-authorization", "accept-encoding", "upgrade", "te", "trailer":
			continue
		}
		result.Set(name, value)
	}
	return result
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

func transactionKey(tx model.Transaction, parsed *url.URL) string {
	items := extractCandidates(tx)
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, item.location+"="+item.name)
	}
	sort.Strings(parts)
	raw := strings.ToUpper(strings.TrimSpace(tx.Request.Method)) + "\x00" + parsed.Host + parsed.EscapedPath() + "\x00" + strings.Join(parts, "&")
	return stableToken(raw)
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

func observedResponse(message model.Message) probeResponse {
	return probeResponse{status: message.Status, body: message.Body}
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return value
		}
	}
	return ""
}

func jsonScalarText(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case float64:
		return fmt.Sprint(typed), true
	case bool:
		return fmt.Sprint(typed), true
	default:
		return "", false
	}
}

func sqlErrorOnlyIn(probe, baseline, control probeResponse) bool {
	return !hasSQLError(baseline.body) && hasSQLError(probe.body) && !hasSQLError(control.body) && !looksLikeWAF(probe.body)
}

func reproducibleSQLError(first, second probeResponse) bool {
	return hasSQLError(first.body) && hasSQLError(second.body) && responsesSimilar(first, second)
}

func hasSQLError(body string) bool { return sqlErrorPattern.MatchString(body) }

func looksLikeWAF(body string) bool { return wafPattern.MatchString(body) }

func materialDelta(first, baseline, control probeResponse) bool {
	if first.status != baseline.status || first.status != control.status {
		return true
	}
	return substantiallyDifferent(first, baseline) || substantiallyDifferent(first, control)
}

func responsesSimilar(first, second probeResponse) bool {
	return first.status == second.status && !substantiallyDifferent(first, second)
}

func reproducibleResponse(first, second probeResponse) bool {
	return responsesSimilar(first, second)
}

func substantiallyDifferent(first, second probeResponse) bool {
	if first.status != second.status {
		return true
	}
	left, right := normalizeProbeBody(first.body), normalizeProbeBody(second.body)
	if left == right {
		return false
	}
	delta := len(left) - len(right)
	if delta < 0 {
		delta = -delta
	}
	// 阈值从 0.985 放宽到 0.90：动态页面（CSRF token、session id、时间戳、
	// 推荐位等）的轻微内容差异不应导致整个参数的 boolean/time 检测被跳过。
	// 只有当响应体相似度低于 90% 时才认为是实质性差异。
	return delta >= 16 && bodySimilarity(left, right) < 0.90
}

type booleanValuePair struct {
	context    string
	trueValue  string
	falseValue string
}

func booleanValuePairs(original string) []booleanValuePair {
	pairs := make([]booleanValuePair, 0, 7)
	if numericPattern.MatchString(strings.TrimSpace(original)) {
		pairs = append(pairs,
			booleanValuePair{context: "numeric", trueValue: original + " AND 1=1", falseValue: original + " AND 1=2"},
			booleanValuePair{context: "numeric-parenthesized", trueValue: original + ") AND (1=1) -- ", falseValue: original + ") AND (1=2) -- "},
			booleanValuePair{context: "numeric-double-parenthesized", trueValue: original + ")) AND ((1=1)) -- ", falseValue: original + ")) AND ((1=2)) -- "},
		)
	}
	return append(pairs,
		booleanValuePair{context: "single-quoted", trueValue: original + "' AND '1'='1' -- ", falseValue: original + "' AND '1'='2' -- "},
		booleanValuePair{context: "single-quoted-parenthesized", trueValue: original + "') AND ('1'='1' -- ", falseValue: original + "') AND ('1'='2' -- "},
		booleanValuePair{context: "double-quoted", trueValue: original + `" AND "1"="1" -- `, falseValue: original + `" AND "1"="2" -- `},
		booleanValuePair{context: "double-quoted-parenthesized", trueValue: original + `") AND ("1"="1" -- `, falseValue: original + `") AND ("1"="2" -- `},
	)
}

func orderedBooleanValuePairs(item candidate, preferred []string) []booleanValuePair {
	pairs := booleanValuePairs(item.value)
	if item.contextHint == "like" {
		pairs = append([]booleanValuePair{
			{context: "like-single-quoted", trueValue: item.value + "%' AND '1'='1' -- ", falseValue: item.value + "%' AND '1'='2' -- "},
			{context: "like-single-quoted-parenthesized", trueValue: item.value + "%') AND (1=1) -- ", falseValue: item.value + "%') AND (1=2) -- "},
		}, pairs...)
	}
	result := make([]booleanValuePair, 0, len(pairs))
	used := make(map[string]struct{}, len(pairs))
	appendContext := func(context string) {
		for _, pair := range pairs {
			if pair.context != context {
				continue
			}
			if _, exists := used[pair.context]; exists {
				return
			}
			used[pair.context] = struct{}{}
			result = append(result, pair)
			return
		}
	}
	for _, context := range preferred {
		appendContext(context)
		if context == "single-quoted" {
			appendContext("single-quoted-parenthesized")
		}
		if context == "double-quoted" {
			appendContext("double-quoted-parenthesized")
		}
	}
	if item.contextHint == "like" {
		appendContext("like-single-quoted")
		appendContext("like-single-quoted-parenthesized")
	}
	for _, pair := range pairs {
		appendContext(pair.context)
	}
	return result
}

type orderByValuePair struct {
	context      string
	validValue   string
	invalidValue string
}

func orderByValuePairs(original string) []orderByValuePair {
	pairs := make([]orderByValuePair, 0, 7)
	if numericPattern.MatchString(strings.TrimSpace(original)) {
		pairs = append(pairs,
			orderByValuePair{context: "numeric", validValue: original + " ORDER BY 1 -- ", invalidValue: original + " ORDER BY 999999 -- "},
			orderByValuePair{context: "numeric-parenthesized", validValue: original + ") ORDER BY 1 -- ", invalidValue: original + ") ORDER BY 999999 -- "},
			orderByValuePair{context: "numeric-double-parenthesized", validValue: original + ")) ORDER BY 1 -- ", invalidValue: original + ")) ORDER BY 999999 -- "},
		)
	}
	return append(pairs,
		orderByValuePair{context: "single-quoted", validValue: original + "' ORDER BY 1 -- ", invalidValue: original + "' ORDER BY 999999 -- "},
		orderByValuePair{context: "single-quoted-parenthesized", validValue: original + "') ORDER BY 1 -- ", invalidValue: original + "') ORDER BY 999999 -- "},
		orderByValuePair{context: "double-quoted", validValue: original + `" ORDER BY 1 -- `, invalidValue: original + `" ORDER BY 999999 -- `},
		orderByValuePair{context: "double-quoted-parenthesized", validValue: original + `") ORDER BY 1 -- `, invalidValue: original + `") ORDER BY 999999 -- `},
	)
}

func orderedOrderByValuePairs(item candidate, preferred []string) []orderByValuePair {
	pairs := orderByValuePairs(item.value)
	parameterName := strings.ToLower(item.name)
	if dot := strings.LastIndex(parameterName, "."); dot >= 0 {
		parameterName = parameterName[dot+1:]
	}
	switch parameterName {
	case "orderby", "order_by", "sortby":
		pairs = append([]orderByValuePair{{
			context:      "orderby-field",
			validValue:   item.value,
			invalidValue: "__easyscan_missing_column__",
		}}, pairs...)
	case "order", "sort":
		pairs = append([]orderByValuePair{{
			context:      "order-direction",
			validValue:   item.value + ", id",
			invalidValue: item.value + ", __easyscan_missing_column__",
		}}, pairs...)
	}
	result := make([]orderByValuePair, 0, len(pairs))
	used := make(map[string]struct{}, len(pairs))
	appendContext := func(context string) {
		for _, pair := range pairs {
			if pair.context != context {
				continue
			}
			if _, exists := used[pair.context]; exists {
				return
			}
			used[pair.context] = struct{}{}
			result = append(result, pair)
			return
		}
	}
	for _, context := range preferred {
		appendContext(context)
	}
	for _, pair := range pairs {
		appendContext(pair.context)
	}
	return result
}

func reproducibleOrderByDifferential(baseline, control, valid, invalid, invalidReplay probeResponse) bool {
	if looksLikeWAF(valid.body) || looksLikeWAF(invalid.body) || looksLikeWAF(invalidReplay.body) {
		return false
	}
	if !responsesSimilar(baseline, control) || !responsesSimilar(baseline, valid) || !responsesSimilar(control, valid) {
		return false
	}
	errorDelta := !hasSQLError(baseline.body) && !hasSQLError(control.body) && !hasSQLError(valid.body) && hasSQLError(invalid.body)
	responseDelta := substantiallyDifferent(baseline, invalid) && substantiallyDifferent(control, invalid) && substantiallyDifferent(valid, invalid)
	return (errorDelta || responseDelta) && reproducibleResponse(invalid, invalidReplay)
}

type timeValuePair struct {
	context   string
	fastValue string
	slowValue string
}

func timeValuePairs(original string) []timeValuePair {
	sleep := fmt.Sprintf("%.1f", timeProbeDelay.Seconds())
	pairs := make([]timeValuePair, 0, 7)
	if numericPattern.MatchString(strings.TrimSpace(original)) {
		pairs = append(pairs,
			timeValuePair{context: "numeric", fastValue: original + " AND IF(1=2,SLEEP(" + sleep + "),0)", slowValue: original + " AND IF(1=1,SLEEP(" + sleep + "),0)"},
			timeValuePair{context: "numeric-parenthesized", fastValue: original + ") AND IF(1=2,SLEEP(" + sleep + "),0) -- ", slowValue: original + ") AND IF(1=1,SLEEP(" + sleep + "),0) -- "},
			timeValuePair{context: "numeric-double-parenthesized", fastValue: original + ")) AND IF(1=2,SLEEP(" + sleep + "),0) -- ", slowValue: original + ")) AND IF(1=1,SLEEP(" + sleep + "),0) -- "},
		)
	}
	return append(pairs,
		timeValuePair{context: "single-quoted", fastValue: original + "' AND IF('1'='2',SLEEP(" + sleep + "),0) -- ", slowValue: original + "' AND IF('1'='1',SLEEP(" + sleep + "),0) -- "},
		timeValuePair{context: "single-quoted-parenthesized", fastValue: original + "') AND IF('1'='2',SLEEP(" + sleep + "),0) -- ", slowValue: original + "') AND IF('1'='1',SLEEP(" + sleep + "),0) -- "},
		timeValuePair{context: "double-quoted", fastValue: original + `" AND IF("1"="2",SLEEP(` + sleep + `),0) -- `, slowValue: original + `" AND IF("1"="1",SLEEP(` + sleep + `),0) -- `},
		timeValuePair{context: "double-quoted-parenthesized", fastValue: original + `") AND IF("1"="2",SLEEP(` + sleep + `),0) -- `, slowValue: original + `") AND IF("1"="1",SLEEP(` + sleep + `),0) -- `},
	)
}

func orderedTimeValuePairs(item candidate, preferred []string) []timeValuePair {
	pairs := timeValuePairs(item.value)
	if item.contextHint == "like" {
		sleep := fmt.Sprintf("%.1f", timeProbeDelay.Seconds())
		pairs = append([]timeValuePair{
			{context: "like-single-quoted", fastValue: item.value + "%' AND IF('1'='2',SLEEP(" + sleep + "),0) -- ", slowValue: item.value + "%' AND IF('1'='1',SLEEP(" + sleep + "),0) -- "},
			{context: "like-single-quoted-parenthesized", fastValue: item.value + "%') AND IF(1=2,SLEEP(" + sleep + "),0) -- ", slowValue: item.value + "%') AND IF(1=1,SLEEP(" + sleep + "),0) -- "},
		}, pairs...)
	}
	result := make([]timeValuePair, 0, len(pairs))
	used := make(map[string]struct{}, len(pairs))
	appendContext := func(context string) {
		for _, pair := range pairs {
			if pair.context != context {
				continue
			}
			if _, exists := used[pair.context]; exists {
				return
			}
			used[pair.context] = struct{}{}
			result = append(result, pair)
			return
		}
	}
	for _, context := range preferred {
		appendContext(context)
	}
	if item.contextHint == "like" {
		appendContext("like-single-quoted")
		appendContext("like-single-quoted-parenthesized")
	}
	for _, pair := range pairs {
		appendContext(pair.context)
	}
	return result
}

func reproducibleTimeDelay(fast, slow, slowReplay probeResponse) bool {
	if fast.status != slow.status || slow.status != slowReplay.status || looksLikeWAF(fast.body) || looksLikeWAF(slow.body) || looksLikeWAF(slowReplay.body) {
		return false
	}
	// 时序检测只关心响应时间差，不要求响应体高度相似。SLEEP 期间页面可能
	// 有时间戳/session 变化，但这些不影响时序判断。只需状态码一致且响应体
	// 长度差异不大即可。
	if !timeResponseCompatible(fast, slow) || !timeResponseCompatible(slow, slowReplay) {
		return false
	}
	return slow.dur-fast.dur >= minimumTimeDelta && slowReplay.dur-fast.dur >= minimumTimeDelta
}

// timeResponseCompatible 检查时序检测的两次响应是否可比：状态码一致且归一化
// 后的响应体长度差异不超过 15%（容忍 SLEEP 期间的轻微动态内容变化）。
func timeResponseCompatible(first, second probeResponse) bool {
	left := normalizeProbeBody(first.body)
	right := normalizeProbeBody(second.body)
	if left == right {
		return true
	}
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	delta := len(left) - len(right)
	if delta < 0 {
		delta = -delta
	}
	maxLen := len(left)
	if len(right) > maxLen {
		maxLen = len(right)
	}
	return float64(delta)/float64(maxLen) < 0.15
}

func appendUnique(items []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func normalizeProbeBody(body string) string {
	body = strings.ToLower(body)
	body = volatileValuePattern.ReplaceAllString(body, "[volatile]")
	body = volatileBodyPattern.ReplaceAllString(body, "[volatile]")
	return strings.Join(strings.Fields(body), " ")
}

func bodySimilarity(left, right string) float64 {
	if left == right {
		return 1
	}
	if len(left) < 3 || len(right) < 3 {
		return 0
	}
	grams := func(value string) map[string]struct{} {
		result := make(map[string]struct{}, len(value)-2)
		for index := 0; index+3 <= len(value); index++ {
			result[value[index:index+3]] = struct{}{}
		}
		return result
	}
	leftGrams, rightGrams := grams(left), grams(right)
	intersection := 0
	for gram := range leftGrams {
		if _, ok := rightGrams[gram]; ok {
			intersection++
		}
	}
	union := len(leftGrams) + len(rightGrams) - intersection
	if union == 0 {
		return 1
	}
	return float64(intersection) / float64(union)
}

func (b *requestBudget) canSpend(count int) bool { return b.used+count <= b.limit }

// perParameterBudget distributes the endpoint-level request budget across the
// candidate parameters. 参数少时每个参数分到更多预算，确保 boolean/time 检测
// 有足够请求跑完全部分支。每个参数至少获得 minimumRequests。
func perParameterBudget(totalBudget, paramCount int) int {
	if paramCount <= 0 || totalBudget <= 0 {
		return 0
	}
	share := totalBudget / paramCount
	// 单参数检测全部分支约需 80 个请求（control 1 + error 16 + boolean 21 +
	// order-by 21 + time 21）。参数少时给满预算，避免 budget 不足导致
	// boolean/time 检测被 canSpend 跳过。
	if share > maximumRequests {
		share = maximumRequests
	}
	if share < minimumRequests {
		return minimumRequests
	}
	return share
}

func (b *requestBudget) spend() bool {
	if b.used >= b.limit {
		return false
	}
	b.used++
	return true
}

func stableToken(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:12]
}
