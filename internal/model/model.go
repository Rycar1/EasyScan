package model

import "time"

// Transaction source labels shared by the proxy, analysis engine, and runtime
// workers. Keeping them centralized prevents imported traffic from entering
// MITM-only processing by mistake.
const (
	SourceHTTPProxy  = "http-proxy"
	SourceHTTPSMITM  = "https-mitm"
	SourceAPIIngest  = "api-ingest"
	SourceMITMProbe  = "mitm-probe"
)

// IsObservedProxySource reports whether a transaction came from ordinary
// browser traffic passing through EasyScan's HTTP proxy or HTTPS MITM path.
func IsObservedProxySource(source string) bool {
	return source == SourceHTTPProxy || source == SourceHTTPSMITM
}

// Message is one side of an observed HTTP exchange. Body is plain text after
// decoding by an importer or the traffic ingestion API.
type Message struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// Certificate and IconHash are optional already-observed metadata for
	// passive fingerprint rules. EasyScan never fetches either value itself.
	Certificate string `json:"certificate,omitempty"`
	IconHash    string `json:"icon_hash,omitempty"`
}

type Transaction struct {
	ID       string    `json:"id,omitempty"`
	Observed time.Time `json:"observed_at"`
	Source   string    `json:"source,omitempty"`
	ClientIP string    `json:"client_ip,omitempty"`
	Request  Message   `json:"request"`
	Response Message   `json:"response"`
}

// RuntimeLog is a short-lived, privacy-preserving runtime event for the
// desktop workbench. It deliberately has no request/response payload or
// header fields, and is never written to the persistent store.
type RuntimeLog struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
}

// PassiveLogSummary is the session-only counter line shown in the passive
// traffic console.  It mirrors the compact status format used by EZ while
// keeping detailed finding and fingerprint events in RuntimeLog.
type PassiveLogSummary struct {
	DoneHTTP        int `json:"done_http"`
	UndoHTTP        int `json:"undo_http"`
	UndoPort        int `json:"undo_port"`
	UndoTask        int `json:"undo_task"`
	RequestsDone    int `json:"requests_done"`
	RequestsTotal   int `json:"requests_total"`
	Fingerprints    int `json:"fingerprints"`
	Vulnerabilities int `json:"vulnerabilities"`
}

// TrafficSummary is a short-lived, privacy-preserving view of one passively
// observed HTTP exchange. It intentionally excludes request/response headers
// and bodies, and is never written to the persistent store.
type TrafficSummary struct {
	ID           string    `json:"id"`
	ObservedAt   time.Time `json:"observed_at"`
	Source       string    `json:"source,omitempty"`
	Method       string    `json:"method,omitempty"`
	URL          string    `json:"url"`
	Status       int       `json:"status,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
	Findings     []string  `json:"findings,omitempty"`
	Fingerprints []string  `json:"fingerprints,omitempty"`
}

// FindingEvidence is a full, in-memory HTTP exchange retained only for a
// finding produced during the current desktop session. Request and Response
// are deterministic HTTP/1.1 renderings of the captured messages, including
// all observed headers and bodies. It is deliberately separate from Finding:
// callers must never include it in SQLite snapshots or exported reports.
type FindingEvidence struct {
	ID         string    `json:"id"`
	FindingID  string    `json:"finding_id"`
	ObservedAt time.Time `json:"observed_at"`
	Source     string    `json:"source,omitempty"`
	Request    string    `json:"request"`
	Response   string    `json:"response"`
}

type Finding struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Confidence  string    `json:"confidence"`
	URL         string    `json:"url"`
	Method      string    `json:"method,omitempty"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	ObservedAt  time.Time `json:"observed_at"`
}

type Asset struct {
	Host                string                `json:"host"`
	URLs                []string              `json:"urls"`
	Fingerprints        []string              `json:"fingerprints"`
	FingerprintEvidence []FingerprintEvidence `json:"fingerprint_evidence,omitempty"`
	Endpoints           []Endpoint            `json:"endpoints,omitempty"`
	LastSeen            time.Time             `json:"last_seen"`
}

// FingerprintEvidence records compact matching metadata for one technology
// label. It deliberately stores only the evidence type, never response text,
// so it is safe to persist alongside the asset inventory.
type FingerprintEvidence struct {
	Fingerprint string   `json:"fingerprint"`
	Sources     []string `json:"sources,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	Score       int      `json:"score,omitempty"`
}

// FingerprintAssociation is a bounded co-occurrence summary used to surface
// rule quality. It counts products seen in the same observed exchange.
type FingerprintAssociation struct {
	Fingerprint string `json:"fingerprint"`
	Count       int    `json:"count"`
}

// FingerprintRuleQuality is a process-local quality summary. Hits counts
// matched exchanges, Assets counts distinct observed hosts, and
// Cooccurrences lists the strongest product associations.
type FingerprintRuleQuality struct {
	Fingerprint   string                   `json:"fingerprint"`
	Hits          int                      `json:"hits"`
	Assets        int                      `json:"assets"`
	Confidence    string                   `json:"confidence,omitempty"`
	LastSeen      time.Time                `json:"last_seen"`
	Cooccurrences []FingerprintAssociation `json:"cooccurrences,omitempty"`
}

// Endpoint is a normalized observed interface. It records names and metadata,
// never parameter values or form contents.
type Endpoint struct {
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Parameters []string `json:"parameters,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// ActiveTask is a bounded verification job. It never runs merely because
// traffic was observed; a caller must create it directly.
type ActiveTask struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Target     string         `json:"target"`
	Status     string         `json:"status"`
	CreatedAt  time.Time      `json:"created_at"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Error      string         `json:"error,omitempty"`
	Summary    map[string]int `json:"summary,omitempty"`
}

type TaskResult struct {
	ID         string            `json:"id"`
	TaskID     string            `json:"task_id"`
	Kind       string            `json:"kind"`
	Target     string            `json:"target"`
	Status     string            `json:"status"`
	Detail     string            `json:"detail,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"task_id,omitempty"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
