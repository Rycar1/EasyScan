// Package aiprobe implements the two-stage AI analysis pipeline for captured
// MITM JavaScript assets. Stage one collects every JavaScript file observed
// for an origin until the stream settles, then asks the AI to pick the
// valuable files. Stage two forwards the selected file contents to two more
// AI roles: a route extractor and a sensitive-credential detector.
package aiprobe

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
	// FeatureAnalysis gates the whole AI pipeline.
	FeatureAnalysis = "passive.ai_analysis"
	// FeatureRoutes gates the route-extraction role (AI #2).
	FeatureRoutes = "passive.ai_analysis.routes"
	// FeatureSecrets gates the sensitive-information role (AI #3).
	FeatureSecrets = "passive.ai_analysis.secrets"

	// settleDelay is how long the JS stream must stay quiet before the site
	// is considered "all JS loaded".
	settleDelay = 10 * time.Second
	// maxCollectWait caps the collection window for busy sites.
	maxCollectWait = 2 * time.Minute
	tickInterval   = 2 * time.Second

	maxFilesPerSite = 64
	maxStoredBody   = 512 << 10 // per-file capture kept in memory
	maxPromptChars  = 45000     // per-file content sent to the AI
	maxSelected     = 8         // cap on files analysed by AI #2/#3
	maxRoutes       = 200
	maxDescription  = 6000 // finding description budget for the AI output
	aiTimeout       = 180 * time.Second
)

const (
	selectorSystemPrompt = "你是一名前端安全分析助手。你只输出 JSON，不输出任何解释、注释或 Markdown 标记。"
	analysisSystemPrompt = "你是一名前端安全分析助手。你只输出 JSON，不输出任何解释、注释或 Markdown 标记。"
)

// Policy exposes the feature switches and AI endpoint configuration.
type Policy interface {
	Enabled(id string) bool
	AIBaseURL() string
	AIModel() string
	AIAPIKey() string
}

type jsFile struct {
	URL  string
	Body string
}

type siteState struct {
	origin    string
	files     map[string]*jsFile
	order     []string
	firstSeen time.Time
	lastSeen  time.Time
	analyzed  bool
}

// Worker observes analyzed transactions, collects JavaScript assets per
// origin, and runs the two-stage AI pipeline once the JS stream settles.
// Observe only records state; all AI calls happen in background goroutines so
// the browser response path is never delayed.
type Worker struct {
	engine *engine.Engine
	policy Policy

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	sites   map[string]*siteState
	stopped bool
	workers sync.WaitGroup
}

// New builds the AI analysis worker and starts its background ticker.
func New(eng *engine.Engine, policy Policy) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Worker{engine: eng, policy: policy, ctx: ctx, cancel: cancel, sites: make(map[string]*siteState)}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe records JavaScript responses for the owning origin while the site
// has not been analysed yet. It is invoked synchronously by the analysis
// pipeline and therefore never blocks.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) {
		return
	}
	if !w.policy.Enabled(FeatureAnalysis) || !w.configured() {
		return
	}
	if tx.Response.Status != http.StatusOK || strings.TrimSpace(tx.Response.Body) == "" {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" {
		return
	}
	if !isJavaScript(tx, parsed) {
		return
	}
	origin := parsed.Scheme + "://" + parsed.Host
	body := tx.Response.Body
	if len(body) > maxStoredBody {
		body = body[:maxStoredBody]
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	site, ok := w.sites[origin]
	if !ok {
		site = &siteState{origin: origin, files: make(map[string]*jsFile), firstSeen: time.Now(), lastSeen: time.Now()}
		w.sites[origin] = site
	}
	site.lastSeen = time.Now()
	if site.analyzed {
		return
	}
	if _, exists := site.files[tx.Request.URL]; exists {
		return
	}
	if len(site.files) >= maxFilesPerSite {
		return
	}
	site.files[tx.Request.URL] = &jsFile{URL: tx.Request.URL, Body: body}
	site.order = append(site.order, tx.Request.URL)
}

// CancelPending drops all collected, not-yet-analysed sites so collection
// restarts cleanly after MITM is restarted or the AI settings change.
func (w *Worker) CancelPending() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for origin, site := range w.sites {
		if !site.analyzed {
			delete(w.sites, origin)
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

// run triggers the pipeline for every site whose JS stream has settled.
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
	if w.policy == nil || !w.policy.Enabled(FeatureAnalysis) || !w.configured() {
		return
	}
	now := time.Now()
	var ready []*siteState
	w.mu.Lock()
	for _, site := range w.sites {
		if site.analyzed || len(site.files) == 0 {
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
			w.analyzeSite(site)
		}()
	}
}

// analyzeSite runs the two-stage pipeline: AI #1 selects valuable JS files,
// then AI #2 (routes) and AI #3 (secrets) analyse each selected file.
func (w *Worker) analyzeSite(site *siteState) {
	files := make([]*jsFile, 0, len(site.order))
	for _, fileURL := range site.order {
		files = append(files, site.files[fileURL])
	}
	w.logf("info", fmt.Sprintf("AI 分析开始：%s 的 JS 加载已稳定，共收集 %d 个 JS 文件，正在交给 AI 筛选", site.origin, len(files)))

	client := aiclient.New(w.policy.AIBaseURL(), w.policy.AIModel(), w.policy.AIAPIKey())
	selected, err := w.selectJS(client, site.origin, files)
	if err != nil {
		w.logf("error", fmt.Sprintf("AI 筛选 JS 文件失败（%s）：%v", site.origin, err))
		return
	}
	if len(selected) == 0 {
		w.logf("info", fmt.Sprintf("AI 判定 %s 没有需要深入分析的 JS 文件", site.origin))
		return
	}
	w.logf("info", fmt.Sprintf("AI 选出 %d 个有价值的 JS 文件（%s），开始路由提取与敏感信息检测", len(selected), site.origin))

	routesEnabled := w.policy.Enabled(FeatureRoutes)
	secretsEnabled := w.policy.Enabled(FeatureSecrets)
	var routes []routeEntry
	var secrets []secretEntry
	for _, file := range selected {
		if w.ctx.Err() != nil {
			return
		}
		var fileRoutes []routeEntry
		var fileSecrets []secretEntry
		var routeErr, secretErr error
		var wg sync.WaitGroup
		if routesEnabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fileRoutes, routeErr = w.extractRoutes(client, file)
			}()
		}
		if secretsEnabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fileSecrets, secretErr = w.detectSecrets(client, file)
			}()
		}
		wg.Wait()
		if routeErr != nil {
			w.logf("warn", fmt.Sprintf("AI 路由提取失败（%s）：%v", file.URL, routeErr))
		}
		if secretErr != nil {
			w.logf("warn", fmt.Sprintf("AI 敏感信息检测失败（%s）：%v", file.URL, secretErr))
		}
		routes = append(routes, fileRoutes...)
		secrets = append(secrets, fileSecrets...)
	}

	routes = dedupeRoutes(routes)
	w.logf("info", fmt.Sprintf("AI 分析完成：%s 提取到 %d 条路由/接口，%d 条敏感信息", site.origin, len(routes), len(secrets)))
	w.reportRoutes(site, selected, routes)
	w.reportSecrets(site, selected, secrets)
}

// selectJS asks AI #1 to pick the valuable files from the captured JS list.
func (w *Worker) selectJS(client *aiclient.Client, origin string, files []*jsFile) ([]*jsFile, error) {
	var list strings.Builder
	for index, file := range files {
		fmt.Fprintf(&list, "%d. %s\n", index+1, file.URL)
	}
	prompt := fmt.Sprintf(
		"站点 %s 共捕获 %d 个 JavaScript 文件：\n%s\n"+
			"请挑选出最可能包含业务逻辑代码的文件（应用入口、路由配置、API 请求封装、业务 chunk 等），"+
			"排除第三方库和工具库（react、vue、angular、jquery、lodash、moment、echarts、polyfill、统计/监控 SDK 等）。"+
			"只输出一个 JSON 数组，元素为选中的完整 URL 字符串，最多 %d 个。",
		origin, len(files), list.String(), maxSelected)

	callCtx, cancel := context.WithTimeout(w.ctx, aiTimeout)
	defer cancel()
	raw, err := client.Chat(callCtx, selectorSystemPrompt, prompt)
	if err != nil {
		return nil, err
	}
	picked, err := parseStringArray(raw)
	if err != nil {
		return nil, fmt.Errorf("AI 返回格式无效: %w", err)
	}
	byURL := make(map[string]*jsFile, len(files))
	for _, file := range files {
		byURL[file.URL] = file
	}
	selected := make([]*jsFile, 0, len(picked))
	seen := make(map[string]struct{}, len(picked))
	for _, pickedURL := range picked {
		file, ok := byURL[strings.TrimSpace(pickedURL)]
		if !ok {
			continue
		}
		if _, dup := seen[file.URL]; dup {
			continue
		}
		seen[file.URL] = struct{}{}
		selected = append(selected, file)
	}
	if len(selected) > maxSelected {
		selected = selected[:maxSelected]
	}
	return selected, nil
}

type routeEntry struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

// extractRoutes asks AI #2 to list every route/API path defined in the file.
func (w *Worker) extractRoutes(client *aiclient.Client, file *jsFile) ([]routeEntry, error) {
	prompt := fmt.Sprintf(
		"分析以下 JavaScript 文件（%s）的内容，提取其中定义的所有前端路由和 API 接口路径"+
			"（包括 router 路由配置、axios/fetch/XHR 请求地址等）。\n"+
			"只输出 JSON 数组，元素格式：{\"method\": \"GET|POST|PUT|DELETE|UNKNOWN\", \"path\": \"/xxx\", \"description\": \"用途说明\"}。\n"+
			"结果去重，最多 %d 条。\n\n文件内容：\n%s",
		file.URL, maxRoutes, truncateChars(file.Body, maxPromptChars))

	callCtx, cancel := context.WithTimeout(w.ctx, aiTimeout)
	defer cancel()
	raw, err := client.Chat(callCtx, analysisSystemPrompt, prompt)
	if err != nil {
		return nil, err
	}
	var entries []routeEntry
	if err := parseJSONArray(raw, &entries); err != nil {
		return nil, fmt.Errorf("AI 返回格式无效: %w", err)
	}
	cleaned := make([]routeEntry, 0, len(entries))
	for _, entry := range entries {
		path := strings.TrimSpace(entry.Path)
		if path == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(entry.Method))
		if method == "" {
			method = "UNKNOWN"
		}
		cleaned = append(cleaned, routeEntry{Method: method, Path: path, Description: strings.TrimSpace(entry.Description)})
	}
	return cleaned, nil
}

type secretEntry struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}

// detectSecrets asks AI #3 to surface credentials and other sensitive data.
func (w *Worker) detectSecrets(client *aiclient.Client, file *jsFile) ([]secretEntry, error) {
	prompt := fmt.Sprintf(
		"分析以下 JavaScript 文件（%s）的内容，提取其中的敏感信息，"+
			"包括：API Key、AccessKey/SecretKey、访问令牌、密码、私钥、数据库连接串、内网地址、云存储凭据等。\n"+
			"只输出 JSON 数组，元素格式：{\"type\": \"类型\", \"value\": \"敏感内容\", \"context\": \"出现的上下文\"}。\n"+
			"没有发现时输出空数组 []。\n\n文件内容：\n%s",
		file.URL, truncateChars(file.Body, maxPromptChars))

	callCtx, cancel := context.WithTimeout(w.ctx, aiTimeout)
	defer cancel()
	raw, err := client.Chat(callCtx, analysisSystemPrompt, prompt)
	if err != nil {
		return nil, err
	}
	var entries []secretEntry
	if err := parseJSONArray(raw, &entries); err != nil {
		return nil, fmt.Errorf("AI 返回格式无效: %w", err)
	}
	cleaned := make([]secretEntry, 0, len(entries))
	for _, entry := range entries {
		value := strings.TrimSpace(entry.Value)
		if value == "" {
			continue
		}
		cleaned = append(cleaned, secretEntry{Type: strings.TrimSpace(entry.Type), Value: value, Context: strings.TrimSpace(entry.Context)})
	}
	return cleaned, nil
}

// reportRoutes emits one aggregated route-extraction finding for the origin.
func (w *Worker) reportRoutes(site *siteState, selected []*jsFile, routes []routeEntry) {
	if w.engine == nil || len(routes) == 0 || !w.policy.Enabled(FeatureRoutes) {
		return
	}
	detail, err := json.MarshalIndent(routes, "", "  ")
	if err != nil {
		return
	}
	description := fmt.Sprintf("AI 从 %d 个有价值的 JS 文件中提取到 %d 条前端路由/接口路径，可用于梳理攻击面与越权测试。\n分析的 JS 文件：%s\n\n%s",
		len(selected), len(routes), joinURLs(selected), truncateChars(string(detail), maxDescription))
	w.engine.ReportFinding(model.Finding{
		RuleID:      "passive.ai.routes",
		Severity:    "info",
		Title:       "AI 识别 前端路由提取",
		Description: description,
		URL:         site.origin + "/",
		Method:      http.MethodGet,
		Remediation: "核对暴露的路由与接口是否都应公开访问，敏感接口应补充认证与鉴权。",
		Evidence:    fmt.Sprintf("AI 从 %d 个 JS 文件中提取到 %d 条路由/接口", len(selected), len(routes)),
		Tags:        []string{"ai", "route-extraction"},
		ObservedAt:  time.Now().UTC(),
	}, nil)
}

// reportSecrets emits one aggregated sensitive-credential finding per origin.
func (w *Worker) reportSecrets(site *siteState, selected []*jsFile, secrets []secretEntry) {
	if w.engine == nil || len(secrets) == 0 || !w.policy.Enabled(FeatureSecrets) {
		return
	}
	detail, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return
	}
	description := fmt.Sprintf("AI 在 %d 个有价值的 JS 文件中发现 %d 处疑似敏感凭据/敏感信息，泄露的凭据可能被直接利用。\n分析的 JS 文件：%s\n\n%s",
		len(selected), len(secrets), joinURLs(selected), truncateChars(string(detail), maxDescription))
	w.engine.ReportFinding(model.Finding{
		RuleID:      "passive.ai.secrets",
		Severity:    "high",
		Title:       "AI 识别 敏感凭据检测",
		Description: description,
		URL:         site.origin + "/",
		Method:      http.MethodGet,
		Remediation: "立即轮换泄露的密钥/凭据，避免在前端代码中硬编码任何秘密，改用后端代理或运行时下发。",
		Evidence:    fmt.Sprintf("AI 在 %d 个 JS 文件中发现 %d 处敏感信息", len(selected), len(secrets)),
		Tags:        []string{"ai", "sensitive-info", "credentials"},
		ObservedAt:  time.Now().UTC(),
	}, nil)
}

func (w *Worker) configured() bool {
	return w.policy != nil && aiclient.Configured(w.policy.AIBaseURL(), w.policy.AIModel(), w.policy.AIAPIKey())
}

func (w *Worker) logf(level, message string) {
	if w.engine != nil {
		w.engine.Log(level, "ai", message)
	}
}

func isJavaScript(tx model.Transaction, parsed *url.URL) bool {
	contentType := strings.ToLower(headerValue(tx.Response.Headers, "Content-Type"))
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "ecmascript") {
		return true
	}
	path := strings.ToLower(parsed.Path)
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")
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

func joinURLs(files []*jsFile) string {
	urls := make([]string, 0, len(files))
	for _, file := range files {
		urls = append(urls, file.URL)
	}
	return strings.Join(urls, "、")
}

func dedupeRoutes(routes []routeEntry) []routeEntry {
	seen := make(map[string]struct{}, len(routes))
	result := make([]routeEntry, 0, len(routes))
	for _, route := range routes {
		key := route.Method + " " + route.Path
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, route)
	}
	if len(result) > maxRoutes {
		result = result[:maxRoutes]
	}
	return result
}

func truncateChars(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n...（内容过长已截断）"
}

// parseJSONArray strips markdown fences and extracts the outermost JSON array
// into target.
func parseJSONArray(raw string, target any) error {
	body := extractJSONFragment(raw, '[', ']')
	if body == "" {
		return fmt.Errorf("未找到 JSON 数组")
	}
	return json.Unmarshal([]byte(body), target)
}

// parseStringArray accepts either a JSON array of strings or an object whose
// first array-valued field holds the strings (some models wrap the list).
func parseStringArray(raw string) ([]string, error) {
	body := extractJSONFragment(raw, '[', ']')
	if body != "" {
		var direct []string
		if err := json.Unmarshal([]byte(body), &direct); err == nil {
			return direct, nil
		}
	}
	objectBody := extractJSONFragment(raw, '{', '}')
	if objectBody == "" {
		return nil, fmt.Errorf("未找到 JSON 数组")
	}
	var wrapped map[string]json.RawMessage
	if err := json.Unmarshal([]byte(objectBody), &wrapped); err != nil {
		return nil, err
	}
	for _, value := range wrapped {
		var candidate []string
		if err := json.Unmarshal(value, &candidate); err == nil {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("JSON 中未找到字符串数组")
}

func extractJSONFragment(raw string, open, close byte) string {
	start := strings.IndexByte(raw, open)
	if start < 0 {
		return ""
	}
	end := strings.LastIndexByte(raw, close)
	if end <= start {
		return ""
	}
	return raw[start : end+1]
}
