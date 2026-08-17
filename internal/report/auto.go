package report

import (
	"sync"
	"time"

	"github.com/example/easyscan/internal/model"
)

const autoHTMLDebounce = 300 * time.Millisecond

type htmlWriter func(string, []model.Finding, []model.Asset) error

type htmlSnapshot struct {
	findings []model.Finding
	assets   []model.Asset
	version  uint64
}

// AutoHTML serializes writes to one HTML report and coalesces bursty snapshot
// changes. It is safe for the proxy, active runner, and desktop lifecycle to
// call concurrently.
type AutoHTML struct {
	mu        sync.Mutex
	writeMu   sync.Mutex
	close     sync.Once
	filename  string
	debounce  time.Duration
	write     htmlWriter
	timer     *time.Timer
	snapshot  htmlSnapshot
	pending   bool
	closed    bool
	lastErr   error
	closeErr  error
	closeDone chan struct{}
}

// NewAutoHTML creates a debounced writer for filename. Schedule records a
// complete normalized snapshot; Close always commits the most recent one.
func NewAutoHTML(filename string) *AutoHTML {
	return newAutoHTML(filename, autoHTMLDebounce, WriteHTML)
}

func newAutoHTML(filename string, debounce time.Duration, write htmlWriter) *AutoHTML {
	if debounce < 0 {
		debounce = 0
	}
	return &AutoHTML{filename: filename, debounce: debounce, write: write, closeDone: make(chan struct{})}
}

// Schedule replaces the pending report with the newest snapshot and restarts
// the debounce window. Inputs are copied so callers can safely reuse them.
func (r *AutoHTML) Schedule(findings []model.Finding, assets []model.Asset) {
	if r == nil {
		return
	}
	snapshot := htmlSnapshot{findings: cloneFindings(findings), assets: cloneAssets(assets)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.snapshot.version++
	snapshot.version = r.snapshot.version
	r.snapshot = snapshot
	r.pending = true
	if r.timer == nil {
		r.timer = time.AfterFunc(r.debounce, r.flushFromTimer)
		return
	}
	r.timer.Reset(r.debounce)
}

// Flush synchronously writes the latest snapshot. It is useful for lifecycle
// boundaries and intentionally writes an empty report when nothing was seen.
func (r *AutoHTML) Flush() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		done := r.closeDone
		r.mu.Unlock()
		if done != nil {
			<-done
		}
		r.mu.Lock()
		err := r.closeErr
		r.mu.Unlock()
		return err
	}
	if r.timer != nil {
		r.timer.Stop()
	}
	r.mu.Unlock()
	return r.writeLatest(true, false)
}

// Close stops pending timers and synchronously commits the final snapshot.
// It is idempotent and excludes later Schedule calls before it waits for an
// already-running timer callback, preventing stale writes after the final one.
func (r *AutoHTML) Close() error {
	if r == nil {
		return nil
	}
	r.close.Do(func() {
		r.mu.Lock()
		r.closed = true
		if r.timer != nil {
			r.timer.Stop()
		}
		r.mu.Unlock()
		err := r.writeLatest(true, true)
		r.mu.Lock()
		r.closeErr = err
		if r.closeDone != nil {
			close(r.closeDone)
		}
		r.mu.Unlock()
	})
	<-r.closeDone
	r.mu.Lock()
	err := r.closeErr
	r.mu.Unlock()
	return err
}

func (r *AutoHTML) flushFromTimer() { _ = r.writeLatest(false, false) }

func (r *AutoHTML) writeLatest(force, includeClosed bool) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	r.mu.Lock()
	if (r.closed && !includeClosed) || (!force && !r.pending) {
		r.mu.Unlock()
		return nil
	}
	snapshot := r.snapshot
	r.pending = false
	r.mu.Unlock()

	err := r.write(r.filename, snapshot.findings, snapshot.assets)
	r.mu.Lock()
	if r.snapshot.version == snapshot.version {
		if err != nil {
			r.lastErr = err
			if !r.closed {
				r.pending = true
			}
		} else {
			r.lastErr = nil
		}
	}
	r.mu.Unlock()
	return err
}

func cloneFindings(values []model.Finding) []model.Finding {
	result := make([]model.Finding, len(values))
	copy(result, values)
	for index := range result {
		result[index].Tags = append([]string(nil), values[index].Tags...)
	}
	return result
}

func cloneAssets(values []model.Asset) []model.Asset {
	result := make([]model.Asset, len(values))
	copy(result, values)
	for index := range result {
		result[index].URLs = append([]string(nil), values[index].URLs...)
		result[index].Fingerprints = append([]string(nil), values[index].Fingerprints...)
		result[index].FingerprintEvidence = append([]model.FingerprintEvidence(nil), values[index].FingerprintEvidence...)
		for evidence := range result[index].FingerprintEvidence {
			result[index].FingerprintEvidence[evidence].Sources = append([]string(nil), values[index].FingerprintEvidence[evidence].Sources...)
		}
		result[index].Endpoints = append([]model.Endpoint(nil), values[index].Endpoints...)
		for endpoint := range result[index].Endpoints {
			result[index].Endpoints[endpoint].Parameters = append([]string(nil), values[index].Endpoints[endpoint].Parameters...)
			result[index].Endpoints[endpoint].Sources = append([]string(nil), values[index].Endpoints[endpoint].Sources...)
		}
	}
	return result
}
