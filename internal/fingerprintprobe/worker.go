// Package fingerprintprobe implements optional active fingerprint probing
// triggered by origins observed through the local HTTP proxy or HTTPS MITM.
//
// Passive fingerprint matching only ever sees the single response the user
// happened to load, so favicon-hash, path-based and error-page rules almost
// never fire. For each new in-scope origin this worker actively fetches a small
// fixed set of resources — the site root, /favicon.ico and one random 404 path
// — and feeds them together into the shared fingerprint database. The
// aggregated evidence lets favicon and error-page rules match without sending
// any attack payload. Exactly one probe batch is sent per origin.
package fingerprintprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID      = "passive.fingerprint_probe"
	cdnFeatureID   = "passive.cdn_detection"
	queueCapacity  = 32
	defaultTimeout = 8 * time.Second
	maxBodyBytes   = 1 << 20
	probePaceMS    = 300
)

// Policy is the live feature-switch surface used by the worker.
type Policy interface {
	Enabled(string) bool
}

// Worker probes each newly observed in-scope origin exactly once. Observe only
// enqueues; the background goroutine performs the network requests so the MITM
// response path is never delayed.
type Worker struct {
	cfg    config.Config
	engine *engine.Engine
	policy Policy
	client *http.Client

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan queuedOrigin

	mu          sync.Mutex
	scheduled   map[string]struct{}
	stopped     bool
	generation  uint64
	batchCtx    context.Context
	batchCancel context.CancelFunc
	workers     sync.WaitGroup
}

type queuedOrigin struct {
	origin     string
	host       string
	generation uint64
}

// New constructs the worker and starts its background scheduler.
func New(cfg config.Config, e *engine.Engine, policy Policy) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	batchCtx, batchCancel := context.WithCancel(ctx)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   4 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 目标由 scope 授权，跳过证书校验以覆盖自签场景
		DisableKeepAlives:   true,
	}
	timeout := time.Duration(cfg.WebScan.HTTP.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(cfg.Active.TimeoutSeconds) * time.Second
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	w := &Worker{
		cfg:    cfg,
		engine: e,
		policy: policy,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ctx:         ctx,
		cancel:      cancel,
		queue:       make(chan queuedOrigin, queueCapacity),
		scheduled:   make(map[string]struct{}),
		batchCtx:    batchCtx,
		batchCancel: batchCancel,
	}
	w.workers.Add(1)
	go w.run()
	return w
}

// Observe enqueues one probe per scheme+host+port. Only in-scope origins that
// arrive through the proxy are eligible.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || !model.IsObservedProxySource(tx.Source) || !w.enabled() {
		return
	}
	parsed, err := url.Parse(tx.Request.URL)
	if err != nil || parsed.Hostname() == "" || !w.engine.AllowsActiveHost(parsed.Hostname()) {
		return
	}
	origin := originKey(parsed)
	if origin == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	if _, exists := w.scheduled[origin]; exists {
		return
	}
	item := queuedOrigin{origin: origin, host: parsed.Hostname(), generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[origin] = struct{}{}
	default:
		// 队列已满就放弃，避免拖慢 MITM 主链路。
	}
}

// CancelPending clears the current batch and allows the same origin to be
// probed again after MITM is restarted or the setting is changed.
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
				w.probeOrigin(batch, item)
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

func (w *Worker) cdnEnabled() bool {
	return w.policy != nil && w.policy.Enabled(cdnFeatureID)
}

// probeOrigin fetches the fixed resource set for one origin and feeds the
// responses into the shared fingerprint database together.
func (w *Worker) probeOrigin(ctx context.Context, item queuedOrigin) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	base, err := url.Parse(item.origin)
	if err != nil || base.Hostname() == "" || !w.engine.AllowsActiveHost(base.Hostname()) {
		return
	}

	paths := []string{"/", "/favicon.ico", "/easyscan-" + randomToken() + "-not-found"}
	txs := make([]model.Transaction, 0, len(paths)+1)
	var declaredFavicon string
	for i, p := range paths {
		if ctx.Err() != nil {
			return
		}
		if i > 0 {
			w.pace(ctx)
			if ctx.Err() != nil {
				return
			}
		}
		if tx, ok := w.fetch(ctx, base, p); ok {
			txs = append(txs, tx)
			// The root page frequently declares its favicon at a non-default
			// path via <link rel="icon">. Capturing that path lets the
			// favicon.hash rules (the largest rule family) fire on sites that
			// do not serve /favicon.ico.
			if p == "/" {
				declaredFavicon = declaredFaviconPath(base, tx.Response.Body)
			}
		}
	}
	// Probe the declared favicon only when it resolves to a same-origin path
	// distinct from the default /favicon.ico already fetched above
	// (declaredFaviconPath enforces that invariant and returns "" otherwise).
	if declaredFavicon != "" {
		if ctx.Err() != nil {
			return
		}
		w.pace(ctx)
		if ctx.Err() != nil {
			return
		}
		if tx, ok := w.fetch(ctx, base, declaredFavicon); ok {
			txs = append(txs, tx)
		}
	}
	if len(txs) == 0 {
		return
	}

	db := w.engine.HFinger()
	if db == nil {
		return
	}
	matches := db.MatchDetailsMulti(txs, w.cdnEnabled(), true)
	added := 0
	for _, m := range matches {
		if w.engine.AddInferredFingerprint(item.host, m.Name, appendSource(m.Sources), inferredConfidence(m.Reliability)) {
			added++
		}
	}
	if added > 0 {
		w.engine.Log("info", "fingerprint-probe", fmt.Sprintf("主动指纹探测在 %s 上新增 %d 条指纹", item.host, added))
	}
}

// fetch issues one GET request and maps it into a synthesized transaction. The
// favicon body is preserved so the fingerprint database can compute its hash.
func (w *Worker) fetch(ctx context.Context, base *url.URL, path string) (model.Transaction, bool) {
	target := *base
	target.Path = path
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	requestURL := target.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return model.Transaction{}, false
	}
	ua := strings.TrimSpace(w.cfg.WebScan.Crawler.UserAgent)
	if ua == "" {
		ua = "Mozilla/5.0 (compatible; EasyScan/1.0)"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := w.client.Do(req)
	if err != nil {
		return model.Transaction{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	headers := make(map[string]string, len(resp.Header))
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[name] = strings.Join(values, "\n")
		}
	}
	return model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceMITMProbe,
		Request: model.Message{
			Method: http.MethodGet,
			URL:    requestURL,
		},
		Response: model.Message{
			Status:  resp.StatusCode,
			Headers: headers,
			Body:    string(body),
		},
	}, true
}

func (w *Worker) pace(ctx context.Context) {
	timer := time.NewTimer(probePaceMS * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func appendSource(sources []string) []string {
	result := append([]string(nil), sources...)
	return append(result, "主动指纹探测")
}

func inferredConfidence(reliability int) string {
	switch {
	case reliability >= 80:
		return "high"
	case reliability >= 50:
		return "medium"
	default:
		return "low"
	}
}

func randomToken() string {
	return strconv.FormatInt(time.Now().UnixNano()%1_000_000, 36)
}

// faviconLinkPattern matches <link ... rel="...icon..."> tags regardless of
// attribute order, capturing the whole tag for a follow-up href extraction.
var faviconLinkPattern = regexp.MustCompile(`(?is)<link\b[^>]*rel\s*=\s*["'][^"']*icon[^"']*["'][^>]*>`)

// hrefPattern extracts the href value from a single <link> tag.
var hrefPattern = regexp.MustCompile(`(?is)href\s*=\s*["']([^"']+)["']`)

// declaredFaviconPath extracts a same-origin favicon path declared in the root
// HTML via <link rel="icon">. It returns "" when no usable declaration exists,
// when the reference points at another origin, or when it resolves back to the
// default /favicon.ico (already probed separately). Only the path is returned so
// the caller can reuse its same-origin fetch machinery.
func declaredFaviconPath(base *url.URL, body string) string {
	if base == nil || strings.TrimSpace(body) == "" {
		return ""
	}
	tag := faviconLinkPattern.FindString(body)
	if tag == "" {
		return ""
	}
	href := hrefPattern.FindStringSubmatch(tag)
	if len(href) < 2 {
		return ""
	}
	raw := strings.TrimSpace(href[1])
	if raw == "" || strings.HasPrefix(raw, "data:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	if resolved.Hostname() != base.Hostname() {
		return ""
	}
	path := resolved.EscapedPath()
	if path == "" || path == "/" || path == "/favicon.ico" {
		return ""
	}
	return path
}

func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}
