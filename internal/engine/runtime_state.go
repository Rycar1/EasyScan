package engine

import (
	"fmt"
	"time"

	"github.com/example/easyscan/internal/model"
)

// Log appends a metadata-only event to the in-memory runtime log. Callers
// must pass summaries rather than HTTP messages; defensive redaction is still
// applied so a credential is never surfaced accidentally.
func (e *Engine) Log(level, component, message string) {
	entry := model.RuntimeLog{
		CreatedAt: time.Now().UTC(),
		Level:     runtimeLogLevel(level),
		Component: runtimeLogComponent(component),
		Message:   runtimeLogMessage(message),
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logSequence++
	entry.ID = fmt.Sprintf("log-%d", e.logSequence)
	e.logs[e.logNext] = entry
	e.logNext = (e.logNext + 1) % runtimeLogHistoryLimit
	if e.logCount < runtimeLogHistoryLimit {
		e.logCount++
	}
}

// Logs returns newest-first, session-only runtime events. The fixed-size ring
// prevents unbounded memory use and keeps the diagnostic feed out of durable
// storage.
func (e *Engine) Logs(limit int) []model.RuntimeLog {
	e.mu.RLock()
	defer e.mu.RUnlock()
	count := e.logCount
	if limit > 0 && limit < count {
		count = limit
	}
	result := make([]model.RuntimeLog, 0, count)
	for index := 0; index < count; index++ {
		position := (e.logNext - 1 - index + runtimeLogHistoryLimit) % runtimeLogHistoryLimit
		result = append(result, e.logs[position])
	}
	return result
}

// PassiveLogSummary returns the current session's compact passive-analysis
// counters. The desktop layer fills in the active-task queue counters before
// sending the snapshot to the frontend.
func (e *Engine) PassiveLogSummary() model.PassiveLogSummary {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.passiveSummary
}

// MarkPassiveRequestQueued reserves one request in the compact passive status
// before the proxy hands it to the asynchronous analysis worker. This keeps
// undo_http representative of the bounded proxy queue instead of showing zero
// while captured responses are waiting to be analyzed.
func (e *Engine) MarkPassiveRequestQueued() {
	e.beginPassiveRequest()
}

// MarkPassiveRequestDequeued releases the queue reservation immediately before
// Analyze starts. Analyze then records its normal in-flight request, so the
// cumulative request total is unchanged and there is no double counting.
func (e *Engine) MarkPassiveRequestDequeued() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.passiveSummary.RequestsTotal > e.passiveSummary.RequestsDone {
		e.passiveSummary.RequestsTotal--
	}
	e.passiveSummary.UndoHTTP = e.passiveSummary.RequestsTotal - e.passiveSummary.RequestsDone
}

func (e *Engine) beginPassiveRequest() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.passiveSummary.RequestsTotal++
	e.passiveSummary.UndoHTTP = e.passiveSummary.RequestsTotal - e.passiveSummary.RequestsDone
}

func (e *Engine) completePassiveRequest(newFingerprints []string, produced []model.Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.passiveSummary.DoneHTTP++
	e.passiveSummary.RequestsDone++
	e.passiveSummary.Fingerprints += len(newFingerprints)
	for _, finding := range produced {
		if !isInformationalFinding(finding) {
			e.passiveSummary.Vulnerabilities++
		}
	}
	e.passiveSummary.UndoHTTP = e.passiveSummary.RequestsTotal - e.passiveSummary.RequestsDone
}

// Traffic returns newest-first, session-only summaries of captured passive
// exchanges. The fixed-size ring deliberately avoids persisting traffic or
// retaining raw messages, which can include credentials and private content.
func (e *Engine) Traffic(limit int) []model.TrafficSummary {
	e.mu.RLock()
	defer e.mu.RUnlock()
	count := e.trafficCount
	if limit > 0 && limit < count {
		count = limit
	}
	result := make([]model.TrafficSummary, 0, count)
	for index := 0; index < count; index++ {
		position := (e.trafficNext - 1 - index + trafficHistoryLimit) % trafficHistoryLimit
		entry := e.traffic[position]
		entry.Findings = append([]string(nil), entry.Findings...)
		entry.Fingerprints = append([]string(nil), entry.Fingerprints...)
		result = append(result, entry)
	}
	return result
}
