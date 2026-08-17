package nucleiprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

const (
	featureID     = "passive.poc_scan"
	queueCapacity = 16
	// scheduledLimit bounds per-worker bookkeeping so a chatty origin cannot
	// grow the scheduled set without limit.
	scheduledLimit = 128
	// perRunTimeout caps how long a single nuclei invocation may run.
	perRunTimeout = 3 * time.Minute
	// maxTags bounds how many nuclei tags are passed for a single origin so a
	// host with many fingerprints cannot expand the template set unboundedly.
	maxTags = 12
)

// Policy is the live configuration surface used by the worker.
type Policy interface {
	Enabled(string) bool
}

// binaryResolver resolves the nuclei executable path. *Manager satisfies it.
type binaryResolver interface {
	Resolve() (string, error)
}

// templatesProvider is an optional capability a binaryResolver may implement to
// supply nuclei template directories. *Manager satisfies it. TemplatesDir is the
// directory passed to nuclei via -t (custom POCs); CalibrationTemplatesDir is
// the directory whose tags are indexed to drop tags that have no templates.
type templatesProvider interface {
	TemplatesDir() string
	CalibrationTemplatesDir() string
}

type queuedOrigin struct {
	origin     string
	host       string
	generation uint64
}

// Worker runs nuclei against newly observed in-scope origins. All network work
// happens in a background goroutine so the MITM response path is never blocked.
type Worker struct {
	cfg      config.Config
	engine   *engine.Engine
	policy   Policy
	resolver binaryResolver

	ctx    context.Context
	cancel context.CancelFunc
	queue  chan queuedOrigin

	// tagIndex lazily caches the set of tags that actually have templates so
	// derived tags with zero templates are not passed to nuclei.
	tagIndex tagIndexCache

	mu          sync.Mutex
	scheduled   map[string]struct{}
	stopped     bool
	generation  uint64
	batchCtx    context.Context
	batchCancel context.CancelFunc
	workers     sync.WaitGroup
}

// New builds a worker. resolver may be nil, in which case the worker stays
// idle (Observe becomes a no-op) so the runtime can be composed even when the
// nuclei manager is unavailable.
func New(cfg config.Config, e *engine.Engine, policy Policy, resolver binaryResolver) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	batchCtx, batchCancel := context.WithCancel(ctx)
	w := &Worker{
		cfg:         cfg,
		engine:      e,
		policy:      policy,
		resolver:    resolver,
		ctx:         ctx,
		cancel:      cancel,
		queue:       make(chan queuedOrigin, queueCapacity),
		scheduled:   make(map[string]struct{}),
		batchCtx:    batchCtx,
		batchCancel: batchCancel,
	}
	w.workers.Add(1)
	go w.run()
	w.warmTagIndex()
	return w
}

// warmTagIndex builds the template tag index in the background so the first
// scan is not blocked by walking a large template library. It is a no-op when
// the resolver cannot provide a calibration directory.
func (w *Worker) warmTagIndex() {
	tp, ok := w.resolver.(templatesProvider)
	if !ok {
		return
	}
	dir := strings.TrimSpace(tp.CalibrationTemplatesDir())
	if dir == "" {
		return
	}
	w.workers.Add(1)
	go func() {
		defer w.workers.Done()
		select {
		case <-w.ctx.Done():
			return
		default:
		}
		w.tagIndex.warm(dir)
	}()
}

// Observe only queues work. The nuclei invocation is performed by the
// background worker so the browser response path is never delayed.
func (w *Worker) Observe(tx model.Transaction) {
	if w == nil || w.engine == nil || w.policy == nil || w.resolver == nil {
		return
	}
	if !model.IsObservedProxySource(tx.Source) || !w.enabled() {
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
	if len(w.scheduled) >= scheduledLimit {
		return
	}
	item := queuedOrigin{origin: origin, host: parsed.Hostname(), generation: w.generation}
	select {
	case w.queue <- item:
		w.scheduled[origin] = struct{}{}
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
				w.scan(batch, item)
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

// scan resolves the nuclei binary, derives tags from the host's fingerprints,
// invokes nuclei once against the origin, and reports every matched result.
func (w *Worker) scan(ctx context.Context, item queuedOrigin) {
	if !w.enabled() || w.engine == nil || ctx.Err() != nil {
		return
	}
	binary, err := w.resolver.Resolve()
	if err != nil {
		return
	}
	tags := TagsFor(w.fingerprintsFor(item.host))
	if len(tags) == 0 {
		return
	}
	// If the resolver can point us at a template library, drop tags that have no
	// backing template so nuclei is never invoked with a tag that matches zero
	// POCs (a wasted process spawn). Also decide the -t custom template dir. The
	// index is read non-blockingly: while it is still warming up we skip
	// calibration rather than stalling the scan.
	var customTemplates string
	if tp, ok := w.resolver.(templatesProvider); ok {
		customTemplates = strings.TrimSpace(tp.TemplatesDir())
		if idx := w.tagIndex.ready(tp.CalibrationTemplatesDir()); idx.Size() > 0 {
			tags = idx.Filter(tags)
		}
	}
	if len(tags) == 0 {
		return
	}
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	runCtx, cancel := context.WithTimeout(ctx, perRunTimeout)
	defer cancel()
	args := []string{
		"-u", item.origin,
		"-tags", strings.Join(tags, ","),
		"-jsonl",
		"-silent",
		"-disable-update-check",
		"-no-color",
	}
	// Optionally extend the POC library with a user-provided template directory
	// (resolved above). Mocks without templatesProvider leave it empty and fall
	// back to nuclei's built-in templates.
	if customTemplates != "" {
		args = append(args, "-t", customTemplates)
	}
	cmd := exec.CommandContext(runCtx, binary, args...)
	hideWindow(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		w.logScanError(item.origin, "创建 nuclei 输出管道失败", err)
		return
	}
	// Capture stderr so a failed invocation (missing templates, bad flags, rate
	// limiting) is diagnosable instead of silently producing zero findings. A
	// bounded buffer prevents a chatty binary from growing memory without limit.
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{buf: &stderr, limit: 8 << 10}
	if err := cmd.Start(); err != nil {
		w.logScanError(item.origin, "启动 nuclei 进程失败", err)
		return
	}
	observedAt := time.Now().UTC()
	matches := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		if runCtx.Err() != nil {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result nucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		matches++
		w.report(item.origin, result, observedAt)
	}
	waitErr := cmd.Wait()
	// A non-zero exit while the run context is still live signals a real nuclei
	// failure. Context cancellation (batch reset / shutdown / timeout) is
	// expected teardown and must not be reported as an error.
	if waitErr != nil && runCtx.Err() == nil {
		w.logScanError(item.origin, "nuclei 执行失败", errWithStderr(waitErr, stderr.String()))
		return
	}
	if matches > 0 && w.engine != nil {
		w.engine.Log("info", "poc-scan", fmt.Sprintf("nuclei 命中 %d 个 POC：%s", matches, item.origin))
	}
}

// limitedWriter accumulates at most limit bytes into buf and discards the rest.
// It never returns an error so an overflowing stderr does not abort the pipe.
type limitedWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.buf.Len() < w.limit {
		remaining := w.limit - w.buf.Len()
		if remaining < len(p) {
			w.buf.Write(p[:remaining])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

// logScanError records a POC-scan failure to the runtime diagnostic log. It is
// a no-op when the engine is unavailable.
func (w *Worker) logScanError(origin, summary string, err error) {
	if w == nil || w.engine == nil {
		return
	}
	msg := summary + "：" + origin
	if err != nil {
		msg += "（" + err.Error() + "）"
	}
	w.engine.Log("warn", "poc-scan", msg)
}

// errWithStderr augments a process error with a trimmed stderr excerpt.
func errWithStderr(err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, firstLine(stderr))
}

// firstLine returns the first non-empty line of s, so multi-line nuclei banners
// do not flood the log.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// fingerprintsFor returns the recognized fingerprint labels for a host from the
// engine's asset inventory.
func (w *Worker) fingerprintsFor(host string) []string {
	return w.engine.FingerprintsForHost(host)
}

// report converts a nuclei result into a finding and records it with a
// synthetic MITM-probe transaction for evidence.
func (w *Worker) report(origin string, result nucleiResult, observedAt time.Time) {
	finding := result.toFinding(observedAt)
	if strings.TrimSpace(finding.URL) == "" {
		finding.URL = origin
	}
	tx := model.Transaction{
		Source: model.SourceMITMProbe,
		Request: model.Message{
			Method: "GET",
			URL:    finding.URL,
		},
		Response: model.Message{
			Body: truncateEvidence(result.Response),
		},
	}
	w.engine.ReportFindingWithEvidence(finding, []model.Transaction{tx})
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
	hostPort := host
	if strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	return scheme + "://" + hostPort + ":" + port
}
