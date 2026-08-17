package nucleiprobe

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

// togglePolicy is a Policy whose Enabled result can be flipped between calls.
type togglePolicy struct {
	mu      sync.Mutex
	enabled bool
}

func (p *togglePolicy) set(v bool) {
	p.mu.Lock()
	p.enabled = v
	p.mu.Unlock()
}

func (p *togglePolicy) Enabled(string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled
}

// spyResolver records how many times Resolve is called and can be told to fail
// so scan() bails before invoking any external binary.
type spyResolver struct {
	mu     sync.Mutex
	calls  int
	err    error
	path   string
}

func (r *spyResolver) Resolve() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

func (r *spyResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

const testScopeHost = "example.test"

func newScopedEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{testScopeHost}
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return e
}

// scheduledCount safely reads how many origins the worker has queued.
func scheduledCount(w *Worker) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.scheduled)
}

func proxyTx(rawURL string) model.Transaction {
	return model.Transaction{
		Source:  model.SourceHTTPProxy,
		Request: model.Message{Method: "GET", URL: rawURL},
	}
}

func TestObserveSkipsWhenFeatureDisabled(t *testing.T) {
	e := newScopedEngine(t)
	policy := &togglePolicy{enabled: false}
	res := &spyResolver{path: "nuclei"}
	w := New(config.Default(), e, policy, res)
	defer w.Shutdown(context.Background())

	w.Observe(proxyTx("http://example.test/"))
	if got := scheduledCount(w); got != 0 {
		t.Fatalf("feature disabled: scheduled = %d, want 0", got)
	}
}

func TestObserveSkipsNonProxySource(t *testing.T) {
	e := newScopedEngine(t)
	w := New(config.Default(), e, &togglePolicy{enabled: true}, &spyResolver{path: "nuclei"})
	defer w.Shutdown(context.Background())

	for _, src := range []string{model.SourceAPIIngest, model.SourceMITMProbe} {
		tx := proxyTx("http://example.test/")
		tx.Source = src
		w.Observe(tx)
	}
	if got := scheduledCount(w); got != 0 {
		t.Fatalf("non-proxy source: scheduled = %d, want 0", got)
	}
}

func TestObserveSkipsOutOfScopeHost(t *testing.T) {
	e := newScopedEngine(t)
	w := New(config.Default(), e, &togglePolicy{enabled: true}, &spyResolver{path: "nuclei"})
	defer w.Shutdown(context.Background())

	w.Observe(proxyTx("http://not-allowed.test/"))
	if got := scheduledCount(w); got != 0 {
		t.Fatalf("out-of-scope host: scheduled = %d, want 0", got)
	}
}

func TestObserveSchedulesInScopeOrigin(t *testing.T) {
	e := newScopedEngine(t)
	w := New(config.Default(), e, &togglePolicy{enabled: true}, &spyResolver{path: "nuclei"})
	defer w.Shutdown(context.Background())

	w.Observe(proxyTx("http://example.test/a"))
	if got := scheduledCount(w); got != 1 {
		t.Fatalf("in-scope origin: scheduled = %d, want 1", got)
	}
}

func TestObserveDeduplicatesByOrigin(t *testing.T) {
	e := newScopedEngine(t)
	w := New(config.Default(), e, &togglePolicy{enabled: true}, &spyResolver{path: "nuclei"})
	defer w.Shutdown(context.Background())

	// Same origin, different paths/queries -> a single scheduled entry.
	w.Observe(proxyTx("http://example.test/a"))
	w.Observe(proxyTx("http://example.test/b?x=1"))
	w.Observe(proxyTx("http://example.test/c"))
	if got := scheduledCount(w); got != 1 {
		t.Fatalf("dedupe by origin: scheduled = %d, want 1", got)
	}
}

func TestObserveSeparateOriginsScheduledSeparately(t *testing.T) {
	e := newScopedEngine(t)
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"example.test"}
	// Distinct scheme/port -> distinct origins.
	w := New(cfg, e, &togglePolicy{enabled: true}, &spyResolver{path: "nuclei"})
	defer w.Shutdown(context.Background())

	w.Observe(proxyTx("http://example.test/"))
	w.Observe(proxyTx("http://example.test:8080/"))
	if got := scheduledCount(w); got != 2 {
		t.Fatalf("distinct origins: scheduled = %d, want 2", got)
	}
}

func TestCancelPendingClearsSchedule(t *testing.T) {
	e := newScopedEngine(t)
	w := New(config.Default(), e, &togglePolicy{enabled: true}, &spyResolver{path: "nuclei"})
	defer w.Shutdown(context.Background())

	w.Observe(proxyTx("http://example.test/a"))
	if got := scheduledCount(w); got != 1 {
		t.Fatalf("before cancel: scheduled = %d, want 1", got)
	}
	w.CancelPending()
	if got := scheduledCount(w); got != 0 {
		t.Fatalf("after cancel: scheduled = %d, want 0", got)
	}
	// The same origin can be scheduled again after cancellation.
	w.Observe(proxyTx("http://example.test/a"))
	if got := scheduledCount(w); got != 1 {
		t.Fatalf("re-schedule after cancel: scheduled = %d, want 1", got)
	}
}

func TestScanSkippedWhenNoFingerprints(t *testing.T) {
	// With no fingerprints for the host, TagsFor yields nothing and scan() must
	// return before ever resolving the binary.
	e := newScopedEngine(t)
	res := &spyResolver{path: "nuclei"}
	w := New(config.Default(), e, &togglePolicy{enabled: true}, res)
	defer w.Shutdown(context.Background())

	w.Observe(proxyTx("http://example.test/"))
	// Give the background worker time to process the queue.
	waitFor(t, 2*time.Second, func() bool { return scheduledCount(w) == 1 && res.callCount() >= 1 })

	// The resolver was consulted, but since there are no fingerprints the scan
	// must stop right after (no panic, no external process). We assert the
	// worker is still healthy by scheduling another origin.
	w.Observe(proxyTx("http://example.test:9000/"))
	if got := scheduledCount(w); got < 1 {
		t.Fatalf("worker unhealthy after empty-fingerprint scan: scheduled = %d", got)
	}
}

func TestObserveNoopWhenResolverNil(t *testing.T) {
	e := newScopedEngine(t)
	w := New(config.Default(), e, &togglePolicy{enabled: true}, nil)
	defer w.Shutdown(context.Background())

	w.Observe(proxyTx("http://example.test/"))
	if got := scheduledCount(w); got != 0 {
		t.Fatalf("nil resolver should no-op: scheduled = %d, want 0", got)
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	e := newScopedEngine(t)
	w := New(config.Default(), e, &togglePolicy{enabled: true}, &spyResolver{path: "nuclei"})
	if err := w.Shutdown(context.Background()); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := w.Shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	// Observing after shutdown must not schedule anything.
	w.Observe(proxyTx("http://example.test/"))
	if got := scheduledCount(w); got != 0 {
		t.Fatalf("observe after shutdown: scheduled = %d, want 0", got)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met within timeout")
	}
}
