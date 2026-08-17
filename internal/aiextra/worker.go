// Package aiextra implements three optional AI-powered analysis roles that
// extend the core pipeline:
//
//   - Fingerprint inference: when HFinger returns no match, ask the AI to
//     infer the likely technology stack from response headers and HTML.
//   - Secret context enhancement: when a secret-exposure finding is detected,
//     ask the AI whether the value is a real credential or a placeholder.
//   - Traffic anomaly detection: once a site's traffic settles, ask the AI to
//     identify unusual endpoints, status patterns or version mismatches.
//
// All three roles share the same OpenAI-compatible client and feature-policy
// infrastructure as aiprobe / aiinsight. They are non-blocking: AI calls happen
// in background goroutines so the browser response path is never delayed.
package aiextra

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/aiclient"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	// FeatureFingerprint gates the AI fingerprint-inference role.
	FeatureFingerprint = "passive.ai_fingerprint"
	// FeatureSecretContext gates the AI secret-context-enhancement role.
	FeatureSecretContext = "passive.ai_secret_context"
	// FeatureTrafficAnomaly gates the AI traffic-anomaly-detection role.
	FeatureTrafficAnomaly = "passive.ai_traffic_anomaly"

	systemPrompt = "你是一名资深 Web 安全分析师。你只输出 JSON，不输出任何解释、注释或 Markdown 标记。"

	aiTimeout         = 90 * time.Second
	settleDelay       = 12 * time.Second
	maxCollectWait    = 3 * time.Minute
	tickInterval      = 3 * time.Second
	maxTrafficEntries = 200
	maxHeadersChars   = 2000
	maxHTMLChars      = 3000
	maxEvidenceChars  = 3000
	maxAnomalyChars   = 8000
)

// Policy exposes the feature switches and AI endpoint configuration.
type Policy interface {
	Enabled(id string) bool
	AIBaseURL() string
	AIModel() string
	AIAPIKey() string
}

// chatClient abstracts aiclient.Chat so the worker can be unit-tested with a
// stub implementation.
type chatClient interface {
	Chat(ctx context.Context, system, user string) (string, error)
}

// Worker observes analyzed transactions and runs the three optional AI roles
// in background goroutines. Observe only records state; AI calls never block
// the browser response path.
type Worker struct {
	engine *engine.Engine
	policy Policy

	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.Mutex
	fingerprintMu sync.Mutex
	fpSeen        map[string]bool
	trafficSites  map[string]*trafficState
	stopped       bool
	workers       sync.WaitGroup

	// newClient builds the chat client for a call. It defaults to
	// aiclient.New and is overridable in tests to inject a stub.
	newClient func(baseURL, model, apiKey string) chatClient
}

type trafficState struct {
	origin    string
	entries   []trafficEntry
	firstSeen time.Time
	lastSeen  time.Time
	analyzed  bool
}

type trafficEntry struct {
	Method      string
	URL         string
	Status      int
	ContentType string
	tx          model.Transaction
}

// New builds the worker and starts its background ticker for traffic-anomaly
// detection.
func New(eng *engine.Engine, policy Policy) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Worker{
		engine:       eng,
		policy:       policy,
		ctx:          ctx,
		cancel:       cancel,
		fpSeen:       make(map[string]bool),
		trafficSites: make(map[string]*trafficState),
		newClient: func(baseURL, model, apiKey string) chatClient {
			return aiclient.New(baseURL, model, apiKey)
		},
	}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe records transactions for the three AI roles. It is invoked
// synchronously by the analysis pipeline and therefore never blocks.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) {
		return
	}
	if !w.configured() {
		return
	}
	if w.policy.Enabled(FeatureFingerprint) {
		w.observeFingerprint(tx)
	}
	if w.policy.Enabled(FeatureTrafficAnomaly) {
		w.observeTraffic(tx)
	}
}

// EnrichSecretContext asks the AI to classify a secret-exposure finding as a
// real credential or a placeholder. It is called by the engine's finding
// enricher hook for secret-type findings.
func (w *Worker) EnrichSecretContext(ctx context.Context, finding model.Finding) (model.Finding, bool) {
	if w == nil || w.policy == nil {
		return finding, false
	}
	if !w.policy.Enabled(FeatureSecretContext) {
		return finding, false
	}
	if !w.configured() {
		return finding, false
	}
	if !isSecretFinding(finding) {
		return finding, false
	}
	if alreadyEnhanced(finding) {
		return finding, false
	}

	callCtx, cancel := context.WithTimeout(ctx, aiTimeout)
	defer cancel()
	raw, err := w.chat(callCtx, systemPrompt, buildSecretPrompt(finding))
	if err != nil {
		return finding, false
	}
	result, err := parseSecretContext(raw)
	if err != nil {
		return finding, false
	}

	enriched := finding
	enriched.Description = appendEnhanced(finding.Description, formatSecretContext(result))
	return enriched, true
}

// observeFingerprint checks whether HFinger returned matches; if not, it
// triggers an async AI inference call.
func (w *Worker) observeFingerprint(tx model.Transaction) {
	if tx.Response.Status < 200 || tx.Response.Status >= 400 {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" {
		return
	}
	contentType := strings.ToLower(headerValue(tx.Response.Headers, "Content-Type"))
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml") {
		return
	}
	origin := parsed.Scheme + "://" + parsed.Host
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	w.fingerprintMu.Lock()
	seenKey := origin + path
	if w.fpSeen[seenKey] {
		w.fingerprintMu.Unlock()
		return
	}
	w.fpSeen[seenKey] = true
	w.fingerprintMu.Unlock()

	body := truncateChars(tx.Response.Body, maxHTMLChars)
	headers := truncateChars(buildHeaderSummary(tx.Response.Headers), maxHeadersChars)

	serverHeader := headerValue(tx.Response.Headers, "Server")

	w.workers.Add(1)
	go func() {
		defer w.workers.Done()
		w.inferFingerprint(origin, parsed.Host, path, tx.Response.Status, headers, body, serverHeader)
	}()
}

// inferFingerprint calls the AI to infer the technology stack.
func (w *Worker) inferFingerprint(origin, host, path string, status int, headers, html, serverHeader string) {
	prompt := fmt.Sprintf(
		"请根据以下 HTTP 响应信息推断目标站点使用的技术栈（框架、语言、CMS、服务器等）。\n"+
			"URL: %s%s\n状态码: %d\n响应头:\n%s\nHTML 片段:\n%s\n\n"+
			"请优先从以下高价值特征中寻找证据（这些比 Server 响应头更有价值）：\n"+
			"- Cookie 名：laravel_session→Laravel/PHP，JSESSIONID→Java，PHPSESSID→PHP，csrftoken/sessionid→Django/Python，ci_session→CodeIgniter，wordpress_*/wp-*→WordPress，rack.session→Ruby/Rack，connect.sid→Express/Node.js，ASP.NET_SessionId/.ASPXAUTH→ASP.NET。\n"+
			"- 响应头：X-Powered-By、X-Generator、X-Drupal-Cache、X-Redirect-By、X-AspNet-Version、Liferay-Portal 等专属头。\n"+
			"- HTML 标记：<meta name=\"generator\">（WordPress/Drupal/Joomla/Hexo 等）、专属静态资源路径（/wp-content/、/sites/default/、/_next/、/static/admin/）、专属 JS 全局变量或注释。\n"+
			"- 资源指纹：favicon、专属 CSS/JS 文件名、构建产物路径可揭示前端框架（Next.js、Nuxt、Vue、React）。\n\n"+
			"严格要求：\n"+
			"1. 只有当你有明确证据（响应头、Cookie 名、指纹特征、框架专属路径或 HTML 标记）时才填写对应字段；没有把握一律留空字符串 \"\"。\n"+
			"2. 禁止猜测。禁止输出 \"unknown\"、\"未知\"、\"N/A\"、\"静态站点\"、\"static\"、\"none\"、\"无\" 等占位或兜底值——遇到这些情况请直接留空。\n"+
			"3. 不要只填写 server 字段去复述 Server 响应头（如 nginx、apache）——这没有价值；请尽力从上述高价值特征中推断 framework/language/CMS/version。若确实只能读到 Server 头而无其它证据，则所有字段留空。\n"+
			"4. confidence 表示整体推断可信度：只有当至少有一个字段基于确凿证据时才可为 \"high\"；证据薄弱时用 \"low\"。\n"+
			"5. evidence 必须给出具体依据（如某响应头的值、某个 Cookie 名、某段 HTML 标记），不能空泛。\n"+
			"只输出一个 JSON 对象，格式：{\"framework\": \"\", \"version\": \"\", \"language\": \"\", \"server\": \"\", \"evidence\": [\"依据1\"], \"confidence\": \"high|medium|low\"}。",
		origin, path, status, headers, html)

	callCtx, cancel := context.WithTimeout(w.ctx, aiTimeout)
	defer cancel()
	raw, err := w.chat(callCtx, systemPrompt, prompt)
	if err != nil {
		w.logf("warn", fmt.Sprintf("AI 指纹推断失败（%s）：%v", origin, err))
		return
	}
	result, err := parseFingerprintInference(raw)
	if err != nil {
		w.logf("warn", fmt.Sprintf("AI 指纹推断响应解析失败（%s）：%v", origin, err))
		return
	}
	if result.Framework == "" && result.Server == "" && result.Language == "" {
		return
	}
	if isLowValueFingerprint(result, serverHeader) {
		w.logf("info", fmt.Sprintf("AI 指纹无增量价值（%s，仅复述 Server 响应头=%q），不上报", origin, serverHeader))
		return
	}

	description := fmt.Sprintf("AI 推断 %s 的技术栈：", origin)
	parts := []string{}
	if result.Framework != "" {
		parts = append(parts, fmt.Sprintf("框架=%s", result.Framework))
	}
	if result.Version != "" {
		parts = append(parts, fmt.Sprintf("版本=%s", result.Version))
	}
	if result.Language != "" {
		parts = append(parts, fmt.Sprintf("语言=%s", result.Language))
	}
	if result.Server != "" {
		parts = append(parts, fmt.Sprintf("服务器=%s", result.Server))
	}
	description += strings.Join(parts, "、")
	if len(result.Evidence) > 0 {
		description += "\n判断依据：" + strings.Join(result.Evidence, "；")
	}
	if result.Confidence != "" {
		description += fmt.Sprintf("\n置信度：%s", result.Confidence)
	}

	w.engine.ReportFinding(model.Finding{
		RuleID:      "passive.ai.fingerprint",
		Severity:    "info",
		Title:       "AI 识别 技术栈推断",
		Description: description,
		URL:         origin + path,
		Method:      http.MethodGet,
		Remediation: "确认技术栈版本是否存在已知漏洞，及时升级到安全版本。",
		Evidence:    fmt.Sprintf("AI 推断：%s", strings.Join(parts, "、")),
		Tags:        []string{"ai", "fingerprint"},
		ObservedAt:  time.Now().UTC(),
	}, nil)
	w.logf("info", fmt.Sprintf("AI 指纹推断完成（%s）：%s", origin, strings.Join(parts, "、")))

	if w.engine != nil {
		if aiFingerprintConfidence(result.Confidence) != "high" {
			w.logf("info", fmt.Sprintf("AI 指纹置信度不足（%s，confidence=%s），不写入指纹集合", origin, result.Confidence))
			return
		}
		names := fingerprintNames(result)
		for _, name := range names {
			if w.engine.AddInferredFingerprint(host, name, []string{"AI 推断", result.Confidence}, "high") {
				w.logf("info", fmt.Sprintf("AI 指纹写入资产（%s）：%s", host, name))
			}
		}
	}
}

// isLowValueFingerprint reports whether an AI inference carries no incremental
// value over the raw response. The most common noise case is the model merely
// echoing the "Server" response header (e.g. "nginx") without inferring any
// framework, language, version, or CMS. Such a result is not an inference — it
// restates a header the operator can already read — so it must not surface as a
// finding. A result is dropped only when framework/language/version are all
// empty AND the reported server equals the Server header value (case- and
// version-insensitive: "nginx" vs "nginx/1.25" both count as an echo).
func isLowValueFingerprint(result fingerprintInference, serverHeader string) bool {
	if strings.TrimSpace(result.Framework) != "" ||
		strings.TrimSpace(result.Language) != "" ||
		strings.TrimSpace(result.Version) != "" {
		return false
	}
	server := strings.TrimSpace(result.Server)
	if server == "" {
		return true
	}
	header := strings.TrimSpace(serverHeader)
	if header == "" {
		return false
	}
	return serverToken(header) == serverToken(server)
}

// serverToken normalizes a Server value to its bare product token for echo
// comparison: it lowercases the string and strips any "/version" suffix, so
// "nginx/1.25.3" and "Nginx" both reduce to "nginx".
func serverToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if index := strings.IndexByte(value, '/'); index >= 0 {
		value = value[:index]
	}
	if index := strings.IndexByte(value, ' '); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

// fingerprintNames turns an AI inference result into a list of fingerprint
// labels suitable for the asset inventory. A version, when known, is appended
// to the framework/server label so the UI shows e.g. "Nginx 1.25".
func fingerprintNames(result fingerprintInference) []string {
	seen := map[string]struct{}{}
	names := make([]string, 0, 4)
	add := func(base string, withVersion bool) {
		base = strings.TrimSpace(base)
		if base == "" {
			return
		}
		name := base
		if withVersion && strings.TrimSpace(result.Version) != "" {
			name = base + " " + strings.TrimSpace(result.Version)
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		names = append(names, name)
	}
	add(result.Framework, true)
	add(result.Server, true)
	add(result.Language, false)
	return names
}

// aiFingerprintConfidence maps the AI-reported confidence to the shared
// fingerprint confidence vocabulary.
func aiFingerprintConfidence(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// observeTraffic records a traffic summary entry for the origin.
func (w *Worker) observeTraffic(tx model.Transaction) {
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" {
		return
	}
	origin := parsed.Scheme + "://" + parsed.Host
	entry := trafficEntry{
		Method:      tx.Request.Method,
		URL:         tx.Request.URL,
		Status:      tx.Response.Status,
		ContentType: headerValue(tx.Response.Headers, "Content-Type"),
		tx:          tx,
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	site, ok := w.trafficSites[origin]
	if !ok {
		site = &trafficState{origin: origin, firstSeen: time.Now(), lastSeen: time.Now()}
		w.trafficSites[origin] = site
	}
	site.lastSeen = time.Now()
	if site.analyzed {
		return
	}
	if len(site.entries) >= maxTrafficEntries {
		return
	}
	site.entries = append(site.entries, entry)
}

// run triggers traffic-anomaly analysis for sites whose stream has settled.
func (w *Worker) run() {
	defer w.workers.Done()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.triggerReadySites()
		}
	}
}

func (w *Worker) triggerReadySites() {
	if w.policy == nil || !w.policy.Enabled(FeatureTrafficAnomaly) || !w.configured() {
		return
	}
	now := time.Now()
	var ready []*trafficState
	w.mu.Lock()
	for _, site := range w.trafficSites {
		if site.analyzed || len(site.entries) < 5 {
			continue
		}
		if now.Sub(site.lastSeen) >= settleDelay || now.Sub(site.firstSeen) >= maxCollectWait {
			site.analyzed = true
			ready = append(ready, site)
		}
	}
	w.mu.Unlock()
	for _, site := range ready {
		site := site
		w.workers.Add(1)
		go func() {
			defer w.workers.Done()
			w.analyzeTraffic(site)
		}()
	}
}

// analyzeTraffic calls the AI to detect anomalous patterns in the traffic.
func (w *Worker) analyzeTraffic(site *trafficState) {
	summary := buildTrafficSummary(site.entries)
	prompt := fmt.Sprintf(
		"请分析以下站点 %s 的流量摘要，识别异常模式与潜在安全风险。\n"+
			"关注：调试端点暴露、异常状态码分布、版本混用、未授权接口、敏感路径等。\n\n%s\n\n"+
			"只输出一个 JSON 对象，格式：{\"anomalies\": [{\"type\": \"类型\", \"path\": \"相关路径\", \"reason\": \"原因\"}], \"risk_level\": \"high|medium|low\", \"summary\": \"整体评估\"}。没有异常时输出 {\"anomalies\": [], \"risk_level\": \"low\", \"summary\": \"未发现异常\"}。",
		site.origin, summary)

	callCtx, cancel := context.WithTimeout(w.ctx, aiTimeout)
	defer cancel()
	raw, err := w.chat(callCtx, systemPrompt, prompt)
	if err != nil {
		w.logf("warn", fmt.Sprintf("AI 流量异常检测失败（%s）：%v", site.origin, err))
		return
	}
	result, err := parseTrafficAnomaly(raw)
	if err != nil {
		w.logf("warn", fmt.Sprintf("AI 流量异常检测响应解析失败（%s）：%v", site.origin, err))
		return
	}
	if len(result.Anomalies) == 0 && (result.RiskLevel == "" || result.RiskLevel == "low") {
		return
	}

	severity := "info"
	if result.RiskLevel == "high" {
		severity = "medium"
	} else if result.RiskLevel == "medium" {
		severity = "low"
	}

	description := fmt.Sprintf("AI 对 %s 的 %d 条流量进行异常分析。", site.origin, len(site.entries))
	if result.Summary != "" {
		description += "\n整体评估：" + result.Summary
	}
	if len(result.Anomalies) > 0 {
		var b strings.Builder
		for i, a := range result.Anomalies {
			fmt.Fprintf(&b, "%d. [%s] %s", i+1, a.Type, a.Reason)
			if a.Path != "" {
				fmt.Fprintf(&b, "（路径：%s）", a.Path)
			}
			b.WriteString("\n")
		}
		description += "\n异常项：\n" + truncateChars(b.String(), maxAnomalyChars)
	}

	finding := model.Finding{
		RuleID:      "passive.ai.traffic-anomaly",
		Severity:    severity,
		Title:       "AI 识别 流量异常检测",
		Description: description,
		URL:         site.origin + "/",
		Method:      http.MethodGet,
		Remediation: "核查异常端点是否应暴露，移除调试接口，统一 API 版本，补充鉴权。",
		Evidence:    fmt.Sprintf("AI 从 %d 条流量中检测到 %d 个异常项", len(site.entries), len(result.Anomalies)),
		Tags:        []string{"ai", "traffic-anomaly"},
		ObservedAt:  time.Now().UTC(),
	}
	if evidence := matchAnomalyTransactions(site.entries, result.Anomalies); len(evidence) > 0 {
		w.engine.ReportFindingWithEvidence(finding, evidence)
	} else {
		w.engine.ReportFinding(finding, nil)
	}
	w.logf("info", fmt.Sprintf("AI 流量异常检测完成（%s）：%d 个异常项", site.origin, len(result.Anomalies)))
}

// matchAnomalyTransactions returns the original exchanges whose path matches an
// AI-reported anomaly path, so the finding can display the exact traffic that
// triggered each anomaly. Duplicate transactions are returned only once.
func matchAnomalyTransactions(entries []trafficEntry, anomalies []trafficAnomaly) []model.Transaction {
	if len(entries) == 0 || len(anomalies) == 0 {
		return nil
	}
	wanted := make(map[string]struct{}, len(anomalies))
	for _, a := range anomalies {
		p := anomalyPathKey(a.Path)
		if p != "" {
			wanted[p] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(entries))
	matched := make([]model.Transaction, 0, len(anomalies))
	for _, entry := range entries {
		parsed, err := url.Parse(entry.URL)
		if err != nil {
			continue
		}
		if _, ok := wanted[anomalyPathKey(parsed.Path)]; !ok {
			continue
		}
		key := entry.Method + " " + entry.URL
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		matched = append(matched, entry.tx)
	}
	return matched
}

// anomalyPathKey normalizes a path for comparison by trimming a single
// trailing slash (but keeping the root "/") and lowercasing.
func anomalyPathKey(path string) string {
	path = strings.TrimSpace(strings.ToLower(path))
	if path == "" {
		return ""
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
		if path == "" {
			path = "/"
		}
	}
	return path
}

// CancelPending drops all collected, not-yet-analysed traffic sites so
// collection restarts cleanly after MITM is restarted.
func (w *Worker) CancelPending() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for origin, site := range w.trafficSites {
		if !site.analyzed {
			delete(w.trafficSites, origin)
		}
	}
}

// Shutdown stops the ticker and waits for in-flight AI analyses to finish.
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

func (w *Worker) configured() bool {
	return w.policy != nil && aiclient.Configured(w.policy.AIBaseURL(), w.policy.AIModel(), w.policy.AIAPIKey())
}

// chat builds a client via the (test-overridable) factory and issues a chat
// request using the configured AI endpoint.
func (w *Worker) chat(ctx context.Context, system, user string) (string, error) {
	newClient := w.newClient
	if newClient == nil {
		newClient = func(baseURL, model, apiKey string) chatClient {
			return aiclient.New(baseURL, model, apiKey)
		}
	}
	client := newClient(w.policy.AIBaseURL(), w.policy.AIModel(), w.policy.AIAPIKey())
	return client.Chat(ctx, system, user)
}

func (w *Worker) logf(level, message string) {
	if w.engine != nil {
		w.engine.Log(level, "ai", message)
	}
}

// ---- Secret context enhancement helpers ----

type secretContextResult struct {
	IsRealSecret bool   `json:"is_real_secret"`
	SecretType   string `json:"secret_type"`
	Reason       string `json:"reason"`
	RotationUrgency string `json:"rotation_urgency"`
}

func buildSecretPrompt(f model.Finding) string {
	var b strings.Builder
	b.WriteString("请判断以下检测到的敏感信息是真实凭据还是示例/占位符。\n")
	fmt.Fprintf(&b, "漏洞类型：%s\n", f.RuleID)
	if f.Title != "" {
		fmt.Fprintf(&b, "标题：%s\n", f.Title)
	}
	if f.URL != "" {
		fmt.Fprintf(&b, "URL：%s\n", f.URL)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "描述：%s\n", f.Description)
	}
	if f.Evidence != "" {
		evidence := f.Evidence
		if len(evidence) > maxEvidenceChars {
			evidence = evidence[:maxEvidenceChars] + "...（已截断）"
		}
		fmt.Fprintf(&b, "证据：%s\n", evidence)
	}
	b.WriteString("\n只输出一个 JSON 对象，格式：{\"is_real_secret\": true|false, \"secret_type\": \"类型\", \"reason\": \"判断理由\", \"rotation_urgency\": \"立即|尽快|低\"}。")
	return b.String()
}

func parseSecretContext(raw string) (secretContextResult, error) {
	body := extractJSONObject(raw)
	if body == "" {
		return secretContextResult{}, fmt.Errorf("未找到 JSON 对象")
	}
	var result secretContextResult
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return secretContextResult{}, fmt.Errorf("解析 AI 响应失败: %w", err)
	}
	return result, nil
}

func formatSecretContext(r secretContextResult) string {
	var b strings.Builder
	b.WriteString("--- AI 敏感信息研判 ---\n")
	if r.IsRealSecret {
		b.WriteString("研判结果：疑似真实凭据\n")
	} else {
		b.WriteString("研判结果：疑似示例/占位符\n")
	}
	if r.SecretType != "" {
		fmt.Fprintf(&b, "凭据类型：%s\n", r.SecretType)
	}
	if r.Reason != "" {
		fmt.Fprintf(&b, "研判理由：%s\n", r.Reason)
	}
	if r.RotationUrgency != "" {
		fmt.Fprintf(&b, "轮换建议：%s\n", r.RotationUrgency)
	}
	return strings.TrimRight(b.String(), "\n")
}

func isSecretFinding(f model.Finding) bool {
	lower := strings.ToLower(f.RuleID)
	if strings.HasPrefix(lower, "passive.exposure.") {
		if strings.Contains(lower, "key") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "private") || strings.Contains(lower, "password") || strings.Contains(lower, "connection") || strings.Contains(lower, "jwt") {
			return true
		}
	}
	if lower == "passive.ai.secrets" {
		return true
	}
	return false
}

func alreadyEnhanced(f model.Finding) bool {
	return strings.Contains(f.Description, "--- AI 敏感信息研判 ---")
}

func appendEnhanced(original, aiText string) string {
	if strings.TrimSpace(aiText) == "" {
		return original
	}
	if original == "" {
		return aiText
	}
	return original + "\n\n" + aiText
}

// ---- Fingerprint inference helpers ----

type fingerprintInference struct {
	Framework  string   `json:"framework"`
	Version    string   `json:"version"`
	Language   string   `json:"language"`
	Server     string   `json:"server"`
	Evidence   []string `json:"evidence"`
	Confidence string   `json:"confidence"`
}

func parseFingerprintInference(raw string) (fingerprintInference, error) {
	body := extractJSONObject(raw)
	if body == "" {
		return fingerprintInference{}, fmt.Errorf("未找到 JSON 对象")
	}
	var result fingerprintInference
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return fingerprintInference{}, fmt.Errorf("解析 AI 响应失败: %w", err)
	}
	result.Framework = sanitizeFingerprintValue(result.Framework)
	result.Version = sanitizeFingerprintValue(result.Version)
	result.Language = sanitizeFingerprintValue(result.Language)
	result.Server = sanitizeFingerprintValue(result.Server)
	return result, nil
}

// invalidFingerprintValues holds placeholder / fallback words the AI may emit
// when it has no real conclusion. Any field equal to one of these is treated
// as empty so it never becomes a bogus fingerprint like "unknown" or "未知（静态站点）".
var invalidFingerprintValues = map[string]struct{}{
	"unknown": {}, "未知": {}, "n/a": {}, "na": {}, "none": {}, "null": {}, "nil": {},
	"无": {}, "无法确定": {}, "无法识别": {}, "不确定": {}, "不详": {}, "暂无": {},
	"static": {}, "静态": {}, "静态站点": {}, "静态网站": {}, "static site": {},
	"未知（静态站点）": {}, "未知(静态站点)": {}, "-": {}, "—": {}, "待定": {},
}

// sanitizeFingerprintValue trims a fingerprint field and drops placeholder /
// fallback values so only concrete technology names survive.
func sanitizeFingerprintValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	key := strings.ToLower(trimmed)
	if _, bad := invalidFingerprintValues[key]; bad {
		return ""
	}
	if strings.Contains(key, "unknown") || strings.Contains(key, "未知") || strings.Contains(key, "静态站点") {
		return ""
	}
	return trimmed
}

// ---- Traffic anomaly helpers ----

type trafficAnomalyResult struct {
	Anomalies []trafficAnomaly `json:"anomalies"`
	RiskLevel string           `json:"risk_level"`
	Summary   string           `json:"summary"`
}

type trafficAnomaly struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func parseTrafficAnomaly(raw string) (trafficAnomalyResult, error) {
	body := extractJSONObject(raw)
	if body == "" {
		return trafficAnomalyResult{}, fmt.Errorf("未找到 JSON 对象")
	}
	var result trafficAnomalyResult
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return trafficAnomalyResult{}, fmt.Errorf("解析 AI 响应失败: %w", err)
	}
	return result, nil
}

func buildTrafficSummary(entries []trafficEntry) string {
	var b strings.Builder
	for i, e := range entries {
		fmt.Fprintf(&b, "%d. %s %s -> %d (%s)\n", i+1, e.Method, e.URL, e.Status, e.ContentType)
	}
	return b.String()
}

// ---- Shared helpers ----

func buildHeaderSummary(headers map[string]string) string {
	var b strings.Builder
	for name, value := range headers {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "authorization") {
			continue
		}
		if strings.Contains(lower, "cookie") {
			names := cookieNames(value)
			if len(names) == 0 {
				continue
			}
			fmt.Fprintf(&b, "%s: %s\n", name, strings.Join(names, "; "))
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", name, value)
	}
	return b.String()
}

// cookieNames extracts only the cookie names from a Cookie / Set-Cookie header
// value, discarding the (sensitive) values. Cookie names such as
// laravel_session, JSESSIONID, PHPSESSID, csrftoken, ci_session, or wordpress_*
// are among the strongest framework/language fingerprint signals, so they are
// safe and valuable to expose to the AI while the secret values are dropped.
func cookieNames(value string) []string {
	var names []string
	seen := make(map[string]struct{})
	for _, part := range strings.Split(value, "\n") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pair := part
		if idx := strings.IndexByte(pair, ';'); idx >= 0 {
			pair = pair[:idx]
		}
		name := pair
		if idx := strings.IndexByte(pair, '='); idx >= 0 {
			name = pair[:idx]
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		switch strings.ToLower(name) {
		case "path", "domain", "expires", "max-age", "secure", "httponly", "samesite":
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func headerValue(headers map[string]string, name string) string {
	if value, ok := headers[name]; ok {
		return value
	}
	lower := strings.ToLower(name)
	for key, value := range headers {
		if strings.ToLower(key) == lower {
			return value
		}
	}
	return ""
}

func extractJSONObject(raw string) string {
	start := strings.IndexByte(raw, '{')
	if start < 0 {
		return ""
	}
	end := strings.LastIndexByte(raw, '}')
	if end <= start {
		return ""
	}
	return raw[start : end+1]
}

func truncateChars(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "...（已截断）"
}
