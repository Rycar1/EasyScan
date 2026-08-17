// Package fileprobe implements the optional sensitive-file probing triggered
// by origins observed through the local HTTP proxy or HTTPS MITM. When a new
// in-scope origin is observed, the worker issues a bounded set of read-only
// GET requests against well-known sensitive file paths and validates each
// response with the same path + content-signature checks used by the passive
// engine. No state-changing requests are ever sent.
package fileprobe

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID      = "passive.file_probe"
	swaggerCatID   = "swagger"
	customCatID    = "custom"
	queueCapacity  = 32
	defaultQPS     = 2
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 4 << 20
	// scheduledLimit bounds the per-worker bookkeeping so a chatty origin
	// cannot grow the scheduled set without limit. Each (origin, prefix)
	// pair counts as one entry; root prefixes share the origin's namespace.
	scheduledLimit = 256
	// maxPrefixDepth caps how many ancestor directories are extracted from a
	// single observed URL so a deeply nested path cannot flood the queue.
	maxPrefixDepth = 4
)

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
	PassiveFileProbeQPS() int
	// SwaggerExcludedPath reports whether a captured path prefix should be
	// skipped by the swagger documentation probe. Root ("") is never
	// excluded.
	SwaggerExcludedPath(prefix string) bool
	// CustomProbePaths returns the user-supplied paths probed at the site
	// root by the custom sensitive-file detector.
	CustomProbePaths() []string
	// FileProbeMaxPrefixes bounds how many captured path prefixes are probed
	// for a single origin. Zero or negative means no per-origin cap; the
	// global scheduledLimit still applies. The root prefix is always probed
	// and is not counted against this budget.
	FileProbeMaxPrefixes() int
}

// category groups probe paths so each can be toggled independently.
type category struct {
	id    string
	paths []string
}

// probeCategories mirrors the passive sensitive-file detectors. Each category
// is gated by a "passive.file_probe.<key>" feature switch. Categories probe
// well-known paths at the site root and against every captured path prefix
// (e.g. /admin/.git/HEAD), mirroring the swagger documentation probe.
var probeCategories = []category{
	{
		id: "git",
		paths: []string{
			"/.git/HEAD",
			"/.git/config",
			"/.git/index",
			"/.git/packed-refs",
			"/.git/logs/HEAD",
		},
	},
	{
		id: "springboot",
		paths: []string{
			"/actuator",
			"/actuator/env",
			"/actuator/heapdump",
			"/actuator/configprops",
			"/actuator/mappings",
			"/actuator/beans",
			"/actuator/threaddump",
			"/actuator/httptrace",
			"/actuator/trace",
			"/env",
			"/heapdump",
			"/configprops",
			"/mappings",
			"/beans",
			"/trace",
			"/dump",
		},
	},
	{
		id: "svn",
		paths: []string{
			"/.svn/wc.db",
			"/.svn/entries",
		},
	},
	{
		id: "idea",
		paths: []string{
			"/.idea/workspace.xml",
			"/.idea/modules.xml",
			"/.idea/.name",
		},
	},
	{
		id: "ds_store",
		paths: []string{
			"/.DS_Store",
		},
	},
	{
		id: "environment",
		paths: []string{
			"/.env",
			"/.env.local",
			"/.env.production",
			"/.env.development",
		},
	},
	{
		id: "backup",
		paths: []string{
			"/backup.zip",
			"/backup.tar.gz",
			"/web.zip",
			"/www.zip",
			"/site.zip",
			"/backup.sql",
			"/db.sql",
			"/database.sql",
		},
	},
	{
		id: "database_dump",
		paths: []string{
			"/dump.sql",
			"/database.dump",
		},
	},
}

// swaggerProbePaths are the common API documentation routes appended to the
// site root and to each captured path prefix. The leading slash is required;
// it is concatenated as prefix + path (e.g. "/admin" + "/v1/swagger.json").
var swaggerProbePaths = []string{
	"/v1/swagger.json",
	"/v2/swagger.json",
	"/v3/swagger.json",
	"/swagger.json",
	"/openapi.json",
	"/api-docs",
}

type Worker struct {
	cfg    config.Config
	engine *engine.Engine
	policy Policy
	client *http.Client

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan queuedProbe

	mu          sync.Mutex
	scheduled   map[string]struct{}
	htmlSeen    map[string]struct{}
	stopped     bool
	generation  uint64
	batchCtx    context.Context
	batchCancel context.CancelFunc
	workers     sync.WaitGroup
}

func New(cfg config.Config, e *engine.Engine, policy Policy) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	batchCtx, batchCancel := context.WithCancel(ctx)
	w := &Worker{
		cfg:         cfg,
		engine:      e,
		policy:      policy,
		client:      &http.Client{Timeout: defaultTimeout},
		ctx:         ctx,
		cancel:      cancel,
		queue:       make(chan queuedProbe, queueCapacity),
		scheduled:   make(map[string]struct{}),
		htmlSeen:    make(map[string]struct{}),
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
	if method != http.MethodGet && method != http.MethodPost {
		return
	}
	origin := originKey(parsed)
	prefixes := extractPrefixes(parsed.Path)
	if budget := w.policy.FileProbeMaxPrefixes(); budget > 0 && len(prefixes) > budget {
		prefixes = capPrefixesByBudget(prefixes, budget)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	// Root prefix is always probed once per origin so common documentation
	// paths at the site root (e.g. /v1/swagger.json) are covered even when
	// the first observed request is a nested page.
	w.enqueueLocked(origin, "")
	for _, prefix := range prefixes {
		w.enqueueLocked(origin, prefix)
	}
}

// enqueueLocked deduplicates and enqueues a single (origin, prefix) probe.
// Non-root prefixes that match the swagger exclusion config are skipped so
// the user can suppress noisy subtrees such as /js or /assets.
func (w *Worker) enqueueLocked(origin, prefix string) {
	if prefix != "" && w.policy.SwaggerExcludedPath(prefix) {
		return
	}
	key := origin + "\x00" + prefix
	if _, exists := w.scheduled[key]; exists {
		return
	}
	if len(w.scheduled) >= scheduledLimit {
		return
	}
	item := queuedProbe{origin: origin, prefix: prefix, generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[key] = struct{}{}
	default:
		// A full queue is deliberately dropped rather than blocking MITM.
	}
}

// CancelPending stops the current batch and allows the same origin to be
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
	w.htmlSeen = make(map[string]struct{})
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
				w.probeProbe(batch, item.origin, item.prefix)
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

func (w *Worker) categoryEnabled(id string) bool {
	return w.policy != nil && w.policy.Enabled(featureID+"."+id)
}

func (w *Worker) waitForTurn(ctx context.Context) error {
	qps := defaultQPS
	if w.policy != nil {
		if configured := w.policy.PassiveFileProbeQPS(); configured >= 1 && configured <= 20 {
			qps = configured
		}
	}
	timer := time.NewTimer(time.Second / time.Duration(qps))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// probeProbe runs the file-category probes and the swagger documentation
// probes at the site root and against every captured path prefix.
func (w *Worker) probeProbe(ctx context.Context, origin, prefix string) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	base, err := url.Parse(origin)
	if err != nil || base.Hostname() == "" || !w.engine.AllowsActiveHost(base.Hostname()) {
		return
	}
	// Sensitive file categories probe at the site root and against every
	// captured path prefix (e.g. /admin/.git/HEAD), mirroring the swagger
	// documentation probe. Non-root prefixes are filtered by the exclusion
	// config in enqueueLocked before the work is queued.
	for _, cat := range probeCategories {
		if ctx.Err() != nil {
			return
		}
		if !w.categoryEnabled(cat.id) {
			continue
		}
		for _, p := range cat.paths {
			if ctx.Err() != nil {
				return
			}
			if err := w.waitForTurn(ctx); err != nil {
				return
			}
			w.probeFile(ctx, base, joinPrefixPath(prefix, p))
		}
	}
	// Swagger documentation probing runs at the root and against every
	// captured path prefix (e.g. /admin/v1/swagger.json).
	if w.categoryEnabled(swaggerCatID) {
		for _, sp := range swaggerProbePaths {
			if ctx.Err() != nil {
				return
			}
			if err := w.waitForTurn(ctx); err != nil {
				return
			}
			w.probeSwagger(ctx, base, joinPrefixPath(prefix, sp))
		}
	}
	// Custom user-supplied paths are probed at the site root only. The user
	// specifies the exact path to check, so prefix expansion is intentionally
	// skipped to keep the behaviour predictable and bounded.
	if prefix == "" && w.categoryEnabled(customCatID) {
		for _, cp := range w.policy.CustomProbePaths() {
			if ctx.Err() != nil {
				return
			}
			if err := w.waitForTurn(ctx); err != nil {
				return
			}
			w.probeCustomFile(ctx, base, cp)
		}
	}
}

func (w *Worker) probeFile(ctx context.Context, base *url.URL, relativePath string) {
	target := *base
	target.Path = relativePath
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	requestURL := target.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", w.cfg.WebScan.Crawler.UserAgent)
	resp, err := w.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	tx := model.Transaction{
		Source: model.SourceMITMProbe,
		Request: model.Message{
			Method: http.MethodGet,
			URL:    requestURL,
		},
		Response: model.Message{
			Status:  resp.StatusCode,
			Headers: headersToMap(resp.Header),
			Body:    string(body),
		},
	}
	parsed, _ := url.Parse(requestURL)
	for _, finding := range engine.SensitiveFileFindings(tx, parsed) {
		finding.URL = requestURL
		finding.Method = http.MethodGet
		finding.ObservedAt = time.Now().UTC()
		w.engine.ReportFindingWithEvidence(finding, []model.Transaction{tx})
	}
}

// probeCustomFile issues a read-only GET for a user-supplied path and reports
// it when the server answers with a populated 200/206 response. Unlike the
// signature-backed builtin categories there is no known-good content marker
// for arbitrary paths, so HTML answers are downgraded to tentative confidence
// to flag possible SPA fallback pages for manual review.
func (w *Worker) probeCustomFile(ctx context.Context, base *url.URL, relativePath string) {
	target := *base
	target.Path = relativePath
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	requestURL := target.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", w.cfg.WebScan.Crawler.UserAgent)
	resp, err := w.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return
	}
	headers := headersToMap(resp.Header)
	confidence := "firm"
	isHTMLFallback := isHTMLContentType(headers)
	if isHTMLFallback {
		confidence = "tentative"
	}
	tx := model.Transaction{
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
	}
	finding := model.Finding{
		RuleID:      "passive.exposure.custom-file",
		Title:       "自定义探测文件可访问",
		Severity:    "medium",
		Confidence:  confidence,
		URL:         requestURL,
		Method:      http.MethodGet,
		Description: "用户自定义探测路径返回了 200 响应且内容非空，该文件可能可被公开访问。HTML 响应可能是前端路由回退页，请结合证据人工确认。",
		Remediation: "确认该文件是否应公开访问；如不应公开，请通过访问控制、移除路径或网关规则限制访问。",
		Evidence:    relativePath,
		Tags:        []string{"information-disclosure", "custom-probe"},
		ObservedAt:  time.Now().UTC(),
	}
	if isHTMLFallback {
		origin := ""
		if parsed, err := url.Parse(requestURL); err == nil && parsed != nil {
			origin = parsed.Scheme + "://" + parsed.Host
		}
		if w.htmlFallbackAlreadyReported(origin) {
			return
		}
	}
	w.engine.ReportFindingWithEvidence(finding, []model.Transaction{tx})
}

func (w *Worker) htmlFallbackAlreadyReported(origin string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.htmlSeen == nil {
		w.htmlSeen = make(map[string]struct{})
	}
	if _, ok := w.htmlSeen[origin]; ok {
		return true
	}
	if len(w.htmlSeen) < scheduledLimit {
		w.htmlSeen[origin] = struct{}{}
	}
	return false
}

func isHTMLContentType(headers map[string]string) bool {
	contentType := strings.ToLower(headerValue(headers, "Content-Type"))
	return strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml")
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// probeSwagger issues a read-only GET for one documentation path and only
// reports a finding when the response carries the swagger/openapi structure
// marker, so SPA fallback pages and unrelated JSON endpoints are ignored.
func (w *Worker) probeSwagger(ctx context.Context, base *url.URL, relativePath string) {
	target := *base
	target.Path = relativePath
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	requestURL := target.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", w.cfg.WebScan.Crawler.UserAgent)
	resp, err := w.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	tx := model.Transaction{
		Source: model.SourceMITMProbe,
		Request: model.Message{
			Method: http.MethodGet,
			URL:    requestURL,
		},
		Response: model.Message{
			Status:  resp.StatusCode,
			Headers: headersToMap(resp.Header),
			Body:    string(body),
		},
	}
	parsed, _ := url.Parse(requestURL)
	finding := engine.APIDocumentationFinding(tx, parsed)
	if finding == nil {
		return
	}
	finding.URL = requestURL
	finding.Method = http.MethodGet
	finding.ObservedAt = time.Now().UTC()
	w.engine.ReportFindingWithEvidence(*finding, []model.Transaction{tx})
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

type queuedProbe struct {
	origin     string
	prefix     string
	generation uint64
}

// extractPrefixes returns the ancestor directory prefixes of a captured URL
// path, excluding the root. For "/admin/index.html" it returns ["/admin"];
// for "/js/123/file.js" it returns ["/js/123", "/js"]. The leaf segment
// (file name) is always stripped so a static asset such as
// "/assets/index-C_HOOOpe.js" yields "/assets" rather than the file path.
func extractPrefixes(urlPath string) []string {
	cleaned := path.Clean("/" + strings.TrimSpace(urlPath))
	if cleaned == "/" || cleaned == "" || cleaned == "." {
		return nil
	}
	var prefixes []string
	dir := path.Dir(cleaned)
	for dir != "/" && dir != "" && dir != "." {
		prefixes = append(prefixes, dir)
		if len(prefixes) >= maxPrefixDepth {
			break
		}
		dir = path.Dir(dir)
	}
	return prefixes
}

// joinPrefixPath concatenates a captured prefix with a relative probe path.
// An empty prefix (site root) yields the path unchanged. Used by both the
// sensitive file categories and the swagger documentation probe so that
// e.g. "/admin" + "/.git/HEAD" becomes "/admin/.git/HEAD".

// capPrefixesByBudget keeps the deepest budget prefixes. extractPrefixes
// returns ancestors from deepest to shallowest, so a budget of N keeps the
// first N entries. budget <= 0 means no cap and returns the input unchanged.
func capPrefixesByBudget(prefixes []string, budget int) []string {
	if budget <= 0 || len(prefixes) <= budget {
		return prefixes
	}
	out := make([]string, budget)
	copy(out, prefixes[:budget])
	return out
}

func joinPrefixPath(prefix, relativePath string) string {
	if prefix == "" {
		return relativePath
	}
	if !strings.HasPrefix(relativePath, "/") {
		relativePath = "/" + relativePath
	}
	return strings.TrimSuffix(prefix, "/") + relativePath
}

func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	port := u.Port()
	host := u.Hostname()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme + "://" + net_join_host_port(host, port)
}

func net_join_host_port(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
