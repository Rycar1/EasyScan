package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/fingerprint"
	"github.com/example/easyscan/internal/model"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Severity    string   `yaml:"severity"`
	Confidence  string   `yaml:"confidence"`
	Targets     []string `yaml:"targets"`
	Pattern     string   `yaml:"pattern"`
	Description string   `yaml:"description"`
	Remediation string   `yaml:"remediation"`
	Tags        []string `yaml:"tags"`
	re          *regexp.Regexp
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

type compiledRule struct {
	Rule
}

type assetState struct {
	urls                map[string]struct{}
	fingerprints        map[string]struct{}
	fingerprintEvidence map[string]model.FingerprintEvidence
	endpoints           map[string]endpointState
	lastSeen            time.Time
}

type fingerprintQualityState struct {
	name          string
	hits          int
	assets        map[string]struct{}
	confidence    string
	lastSeen      time.Time
	cooccurrences map[string]int
}

const (
	trafficHistoryLimit    = 300
	runtimeLogHistoryLimit = 500
	runtimeLogMessageLimit = 320
	// Finding evidence is intentionally a small, session-only cache. A raw
	// exchange may contain a response body, so bound both the overall cache and
	// the number of alternate captures shown for one finding.
	findingEvidenceHistoryLimit    = 128
	findingEvidencePerFindingLimit = 8
	findingEvidenceByteLimit       = 64 << 20
)

var (
	runtimeLogSensitiveHeader = regexp.MustCompile(`(?i)(?:\b(?:authorization|proxy-authorization|cookie|set-cookie|(?:request|response)?[-_ ]?(?:headers?|body))\s*:|(?:请求|响应)(?:头|体)\s*[:：])`)
	runtimeLogSensitiveValue  = regexp.MustCompile(`(?i)\b(?:password|passwd|secret|token|api[_-]?key|session(?:id)?)\s*[:=]`)
)

// SnapshotSink persists only normalized findings and asset summaries. Raw
// request/response contents intentionally remain out of the persistence path.
type SnapshotSink interface {
	SaveSnapshot([]model.Finding, []model.Asset) error
}

// TransactionObserver receives an analyzed in-scope transaction after its
// normalized snapshot has been persisted. Observers must return promptly: the
// proxy analysis path invokes them synchronously, so callers that perform
// background work should enqueue a copy and return.
type TransactionObserver func(model.Transaction)

// FindingEnricher optionally enhances a finding after it has been recorded.
// The enrichment runs asynchronously and must not block the reporting path.
// Returning false signals that no enrichment was applied.
type FindingEnricher interface {
	Enrich(ctx context.Context, finding model.Finding) EnrichResult
}

// EnrichResult holds the enriched finding and whether AI enhancement was
// applied. It mirrors aiinsight.EnrichResult but lives in the engine package
// to avoid a circular import.
type EnrichResult struct {
	Finding  model.Finding
	Enriched bool
}

// FeatureGate controls optional analysis capabilities without coupling the
// passive engine to a specific configuration implementation.
type FeatureGate interface {
	Enabled(string) bool
}

type allFeaturesEnabled struct{}

func (allFeaturesEnabled) Enabled(string) bool { return true }

// DomainExclusionGate supplies the live user-managed host exclusions. It is
// deliberately independent of FeatureGate: excluded hosts are a scope rule,
// not an optional detector. Implementations must be safe for concurrent use.
type DomainExclusionGate interface {
	ExcludedHost(string) bool
}

// SuffixExclusionGate supplies the live user-managed URL path suffix
// exclusions. Implementations receive a parsed url.URL.Path, never a query
// string or fragment, and must be safe for concurrent use.
type SuffixExclusionGate interface {
	ExcludedURLPath(string) bool
}

// ContentTypeExclusionGate supplies the live response Content-Type filters.
// It is kept separate from path filtering because a URL extension is often
// absent or misleading for a downloaded asset. Implementations must be safe
// for concurrent use.
type ContentTypeExclusionGate interface {
	ExcludedContentType(string) bool
}

// RequestExclusionGate supplies live URL-path, Query-name, and POST/JSON-name
// exclusions. Implementations receive names only, never parameter values.
type RequestExclusionGate interface {
	ExcludedRequest(string, []string, []string) bool
}

// Engine evaluates captured transactions only. It never sends an HTTP request.
type Engine struct {
	cfg                      config.Config
	rules                    []compiledRule
	mu                       sync.RWMutex
	findings                 map[string]model.Finding
	assets                   map[string]*assetState
	traffic                  [trafficHistoryLimit]model.TrafficSummary
	trafficNext              int
	trafficCount             int
	trafficSequence          uint64
	logs                     [runtimeLogHistoryLimit]model.RuntimeLog
	logNext                  int
	logCount                 int
	logSequence              uint64
	passiveSummary           model.PassiveLogSummary
	findingEvidence          map[string][]model.FindingEvidence
	findingEvidenceOrder     []findingEvidenceReference
	findingEvidenceSequence  uint64
	findingEvidenceBytes     int
	hfinger                  *fingerprint.HFingerDatabase
	fingerprintQuality       map[string]*fingerprintQualityState
	sink                     SnapshotSink
	featureGate              FeatureGate
	domainExclusionGate      DomainExclusionGate
	suffixExclusionGate      SuffixExclusionGate
	contentTypeExclusionGate ContentTypeExclusionGate
	requestExclusionGate     RequestExclusionGate
	transactionObserver      TransactionObserver
	findingEnricher          FindingEnricher
	passiveDeduper           *passiveTransactionDeduper

	// snapshot persistence is debounced: high-frequency Analyze calls set a
	// pending flag and (re)arm a timer instead of each doing a full deep-copy
	// snapshot and synchronous disk write. snapshotMu guards these fields only.
	snapshotMu       sync.Mutex
	snapshotTimer    *time.Timer
	snapshotPending  bool
	snapshotInterval time.Duration
	snapshotClosed   bool
}

// findingEvidenceReference lets the bounded global FIFO remove an individual
// per-finding capture without retaining another copy of the HTTP payload.
type findingEvidenceReference struct {
	findingID  string
	evidenceID string
}

func New(cfg config.Config) (*Engine, error) {
	e := &Engine{
		cfg: cfg, findings: make(map[string]model.Finding), assets: make(map[string]*assetState), fingerprintQuality: make(map[string]*fingerprintQualityState),
		findingEvidence: make(map[string][]model.FindingEvidence), featureGate: allFeaturesEnabled{},
		passiveDeduper:   newPassiveTransactionDeduper(defaultPassiveDedupCapacity, defaultPassiveDedupTTL),
		snapshotInterval: defaultSnapshotInterval,
	}
	for _, file := range cfg.Rules.Files {
		if err := e.LoadRules(file); err != nil {
			return nil, err
		}
	}
	hfingerDB, err := fingerprint.LoadHFinger(cfg.Fingerprints.HFinger.CustomDir, cfg.Fingerprints.HFinger.MaxMatches)
	if err != nil {
		return nil, fmt.Errorf("load HFinger fingerprint database: %w", err)
	}
	e.hfinger = hfingerDB
	hfingerStats := hfingerDB.Stats()
	e.Log("info", "engine", fmt.Sprintf("被动分析引擎已初始化：规则 %d 条，HFinger 指纹 %d 条（自定义 %d 条）", len(e.rules), hfingerStats.Loaded, hfingerStats.CustomRules))
	for _, loadError := range hfingerStats.Errors {
		e.Log("error", "fingerprint", fmt.Sprintf("HFinger 自定义规则跳过：%s", loadError))
	}
	return e, nil
}

func (e *Engine) LoadRules(filename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read rule file %q: %w", filename, err)
	}
	var doc ruleFile
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parse rule file %q: %w", filename, err)
	}
	for i := range doc.Rules {
		r := doc.Rules[i]
		if r.ID == "" || r.Title == "" || r.Pattern == "" || len(r.Targets) == 0 {
			return fmt.Errorf("rule file %q: rule %d requires id, title, pattern and targets", filename, i+1)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
		r.re = re
		if r.Severity == "" {
			r.Severity = "info"
		}
		if r.Confidence == "" {
			r.Confidence = "firm"
		}
		e.rules = append(e.rules, compiledRule{r})
	}
	return nil
}

// Analyze records fingerprints and evaluates built-in and user supplied passive rules.
func (e *Engine) Analyze(tx model.Transaction) []model.Finding {
	if tx.Observed.IsZero() {
		tx.Observed = time.Now().UTC()
	}
	u, err := url.Parse(tx.Request.URL)
	if err != nil || u == nil || u.Hostname() == "" {
		return nil
	}
	if !e.allowsPassiveRequest(tx.Request, u) || !e.AllowsPassiveContentType(responseContentType(tx.Response.Headers)) {
		return nil
	}
	passive := isPassiveTraffic(tx)
	if passive {
		e.beginPassiveRequest()
		if e.passiveDeduper != nil && e.passiveDeduper.SeenOrAdd(tx, u) {
			e.completePassiveRequest(nil, nil)
			return nil
		}
		e.Log("info", "request", runtimeRequestMessage(tx, u))
	}
	fingerprints, newFingerprints := e.updateAsset(u, tx)
	var produced []model.Finding
	var matched []model.Finding
	add := func(f model.Finding) {
		if !e.checkEnabled(f.RuleID) {
			return
		}
		f.URL, f.Method, f.ObservedAt = tx.Request.URL, tx.Request.Method, tx.Observed
		if f.Confidence == "" {
			f.Confidence = "firm"
		}
		if f.Severity == "" {
			f.Severity = "info"
		}
		f.Evidence = e.evidence(f.Evidence)
		key := f.RuleID + "\x00" + f.URL
		digest := sha256.Sum256([]byte(key))
		f.ID = hex.EncodeToString(digest[:12])
		matched = append(matched, f)
		e.mu.Lock()
		_, exists := e.findings[key]
		if !exists {
			e.findings[key] = f
		}
		enricher := e.findingEnricher
		e.mu.Unlock()
		if !exists {
			produced = append(produced, f)
			if enricher != nil && !isInformationalFinding(f) {
				go e.enrichFinding(enricher, f)
			}
		}
	}

	if !e.cfg.Analysis.OnlyFingerprint {
		for _, f := range builtins(tx, u, e.featureEnabled) {
			add(f)
		}
		for _, r := range e.rules {
			for _, target := range r.Targets {
				text := targetText(target, tx)
				if match := r.re.FindString(text); match != "" {
					add(model.Finding{RuleID: r.ID, Title: r.Title, Severity: r.Severity, Confidence: r.Confidence,
						Description: r.Description, Remediation: r.Remediation, Tags: r.Tags, Evidence: match})
					break
				}
			}
		}
	}
	if passive {
		// Traffic keeps the fingerprints matched on every exchange, while the
		// runtime feed reports a fingerprint only when it is newly added to an
		// asset.
		for _, value := range newFingerprints {
			e.Log("info", "fingerprint", fmt.Sprintf("识别指纹：%s（%s）", runtimeLogText(value, 120), trafficURL(u)))
		}
		for _, finding := range produced {
			component := "finding"
			if isInformationalFinding(finding) {
				component = "information"
			}
			e.Log("info", component, runtimeFindingMessage(finding, u))
		}
	}
	// Raw evidence is kept exclusively in the process-local bounded cache. It
	// is intentionally recorded for duplicate matches too: one finding can
	// expose a few alternate observed exchanges in the desktop workbench.
	e.recordFindingEvidence(tx, matched)
	e.recordPassiveTraffic(tx, u, matched, fingerprints)
	if passive {
		e.completePassiveRequest(newFingerprints, produced)
	}
	e.mu.RLock()
	sink := e.sink
	observer := e.transactionObserver
	e.mu.RUnlock()
	if sink != nil {
		e.scheduleSnapshot()
	}
	if observer != nil {
		observer(tx)
	}
	return produced
}

func (e *Engine) checkEnabled(ruleID string) bool {
	for _, pattern := range e.cfg.Analysis.DisabledChecks {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "all" || pattern == ruleID {
			return false
		}
		if ok, _ := path.Match(pattern, ruleID); ok {
			return false
		}
	}
	return true
}

func (e *Engine) SetSnapshotSink(sink SnapshotSink) { e.mu.Lock(); e.sink = sink; e.mu.Unlock() }

// defaultSnapshotInterval is the debounce window used to coalesce snapshot
// persistence. Bursts of Analyze calls within this window trigger a single
// deep-copy + disk write instead of one per transaction.
const defaultSnapshotInterval = 500 * time.Millisecond

// scheduleSnapshot marks the snapshot dirty and ensures a debounced flush is
// pending. It never performs the (expensive) snapshot inline, so the hot
// Analyze path stays cheap. If the debounce interval is non-positive it falls
// back to writing synchronously (used to keep tests deterministic).
func (e *Engine) scheduleSnapshot() {
	e.mu.RLock()
	sink := e.sink
	e.mu.RUnlock()
	if sink == nil {
		return
	}
	if e.snapshotInterval <= 0 {
		e.flushSnapshot(sink)
		return
	}
	e.snapshotMu.Lock()
	defer e.snapshotMu.Unlock()
	if e.snapshotClosed {
		return
	}
	e.snapshotPending = true
	if e.snapshotTimer == nil {
		e.snapshotTimer = time.AfterFunc(e.snapshotInterval, e.onSnapshotTimer)
	}
}

// onSnapshotTimer fires when the debounce window elapses. It writes at most one
// snapshot and clears the pending flag; if more work arrived it re-arms itself.
func (e *Engine) onSnapshotTimer() {
	e.snapshotMu.Lock()
	if e.snapshotClosed {
		e.snapshotMu.Unlock()
		return
	}
	e.snapshotPending = false
	e.snapshotMu.Unlock()

	e.mu.RLock()
	sink := e.sink
	e.mu.RUnlock()
	if sink != nil {
		e.flushSnapshot(sink)
	}

	e.snapshotMu.Lock()
	if e.snapshotPending && !e.snapshotClosed {
		e.snapshotTimer.Reset(e.snapshotInterval)
	} else {
		e.snapshotTimer = nil
	}
	e.snapshotMu.Unlock()
}

// flushSnapshot performs the actual deep-copy snapshot and synchronous write.
func (e *Engine) flushSnapshot(sink SnapshotSink) {
	_ = sink.SaveSnapshot(e.Findings(), e.Assets())
}

// FlushSnapshot forces any pending debounced snapshot to disk immediately and
// stops the debounce timer. Call it during shutdown so the final batch of
// findings/assets is not lost.
func (e *Engine) FlushSnapshot() {
	e.snapshotMu.Lock()
	if e.snapshotTimer != nil {
		e.snapshotTimer.Stop()
		e.snapshotTimer = nil
	}
	pending := e.snapshotPending
	e.snapshotPending = false
	e.snapshotClosed = true
	e.snapshotMu.Unlock()

	e.mu.RLock()
	sink := e.sink
	e.mu.RUnlock()
	if sink != nil && pending {
		e.flushSnapshot(sink)
	}
}

// SetTransactionObserver installs one optional post-analysis observer. It is
// intentionally a single callback because Runtime is the composition root for
// background services. Passing nil detaches the observer before shutdown.
func (e *Engine) SetTransactionObserver(observer TransactionObserver) {
	e.mu.Lock()
	e.transactionObserver = observer
	e.mu.Unlock()
}

// SetFindingEnricher installs an optional AI enrichment hook. When set, every
// newly recorded non-informational finding is asynchronously enriched. Passing
// nil detaches the enricher.
func (e *Engine) SetFindingEnricher(enricher FindingEnricher) {
	e.mu.Lock()
	e.findingEnricher = enricher
	e.mu.Unlock()
}

// UpdateFinding replaces a stored finding in-place. It is used by the AI
// enricher to write back the enhanced description and remediation. The finding
// is identified by its ID; if no stored finding matches, the call is a no-op.
func (e *Engine) UpdateFinding(finding model.Finding) bool {
	e.mu.Lock()
	for key, existing := range e.findings {
		if existing.ID == finding.ID {
			updated := finding
			updated.ObservedAt = existing.ObservedAt
			e.findings[key] = updated
			sink := e.sink
			e.mu.Unlock()
			if sink != nil {
				e.scheduleSnapshot()
			}
			return true
		}
	}
	e.mu.Unlock()
	return false
}

// SetFeatureGate attaches runtime feature policy. A nil gate restores the
// default behavior, in which all passive detectors are available.
func (e *Engine) SetFeatureGate(gate FeatureGate) {
	if gate == nil {
		gate = allFeaturesEnabled{}
	}
	e.mu.Lock()
	e.featureGate = gate
	e.mu.Unlock()
}

// SetDomainExclusionGate attaches a live host-exclusion source. Passing nil
// removes only the dynamic exclusions; static scope.allow_hosts and
// scope.deny_hosts remain in force.
func (e *Engine) SetDomainExclusionGate(gate DomainExclusionGate) {
	e.mu.Lock()
	e.domainExclusionGate = gate
	e.mu.Unlock()
}

// SetSuffixExclusionGate attaches a live URL-path suffix exclusion source.
// Passing nil removes only dynamic suffix exclusions; host scope and dynamic
// domain exclusions remain in force.
func (e *Engine) SetSuffixExclusionGate(gate SuffixExclusionGate) {
	e.mu.Lock()
	e.suffixExclusionGate = gate
	e.mu.Unlock()
}

// SetContentTypeExclusionGate attaches a live response Content-Type filter.
// Passing nil removes only dynamic Content-Type exclusions; host and URL-path
// exclusions remain in force.
func (e *Engine) SetContentTypeExclusionGate(gate ContentTypeExclusionGate) {
	e.mu.Lock()
	e.contentTypeExclusionGate = gate
	e.mu.Unlock()
}

// SetRequestExclusionGate attaches the request-side path and parameter
// filters. Passing nil removes only these dynamic exclusions.
func (e *Engine) SetRequestExclusionGate(gate RequestExclusionGate) {
	e.mu.Lock()
	e.requestExclusionGate = gate
	e.mu.Unlock()
}

func (e *Engine) featureEnabled(id string) bool {
	e.mu.RLock()
	gate := e.featureGate
	e.mu.RUnlock()
	return gate == nil || gate.Enabled(id)
}

// Restore hydrates a running engine from a privacy-preserving saved snapshot.
func (e *Engine) Restore(findings []model.Finding, assets []model.Asset) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, finding := range findings {
		if retiredFindingRule(finding.RuleID) {
			continue
		}
		finding = canonicalFinding(finding)
		e.findings[finding.RuleID+"\x00"+finding.URL] = finding
	}
	for _, asset := range assets {
		state := &assetState{urls: map[string]struct{}{}, fingerprints: map[string]struct{}{}, fingerprintEvidence: map[string]model.FingerprintEvidence{}, endpoints: map[string]endpointState{}, lastSeen: asset.LastSeen}
		for _, value := range asset.URLs {
			state.urls[value] = struct{}{}
		}
		knownFingerprints := make(map[string]struct{}, len(asset.Fingerprints))
		for _, value := range asset.Fingerprints {
			value, keep := normalizeRestoredFingerprint(value)
			if !keep {
				continue
			}
			key := fingerprintKey(value)
			if key == "" {
				continue
			}
			if _, exists := knownFingerprints[key]; exists {
				continue
			}
			knownFingerprints[key] = struct{}{}
			state.fingerprints[value] = struct{}{}
		}
		for _, evidence := range asset.FingerprintEvidence {
			name := normalizeFingerprintName(evidence.Fingerprint)
			if name == "" {
				continue
			}
			evidence.Fingerprint = name
			evidence.Sources = normalizeFingerprintSources(evidence.Sources)
			if evidence.Confidence == "" {
				evidence.Confidence = fingerprintConfidence(evidence.Score)
			}
			state.fingerprintEvidence[fingerprintKey(name)] = evidence
		}
		for value := range state.fingerprints {
			key := fingerprintKey(value)
			if _, exists := state.fingerprintEvidence[key]; !exists {
				state.fingerprintEvidence[key] = model.FingerprintEvidence{Fingerprint: value, Sources: []string{"历史记录"}, Confidence: "medium", Score: 2}
			}
		}
		for _, endpoint := range asset.Endpoints {
			state.endpoints[endpoint.Method+"\x00"+endpoint.Path] = endpointState{method: endpoint.Method, path: endpoint.Path, parameters: toSet(endpoint.Parameters), sources: toSet(endpoint.Sources)}
		}
		e.assets[asset.Host] = state
		e.recordFingerprintQualityLocked(asset.Host, asset.LastSeen, evidenceMatches(state.fingerprintEvidence))
	}
}

// retiredFindingRule identifies detector output deliberately removed from the
// product.  Skipping it while restoring a snapshot also clears stale results
// for users who chose to retain data between restarts.
func retiredFindingRule(ruleID string) bool {
	ruleID = strings.TrimSpace(strings.ToLower(ruleID))
	if strings.HasPrefix(ruleID, "passive.sqli-probe") {
		return false
	}
	if strings.HasPrefix(ruleID, "passive.exposure.") || strings.HasPrefix(ruleID, "passive.information.") {
		return false
	}
	switch ruleID {
	case "passive.banner.x_powered_by", "passive.banner.x_aspnet_version":
		return true
	case "passive.directory-listing", "passive.api-documentation":
		return false
	default:
		return strings.HasPrefix(ruleID, "passive.") || ruleID == "custom.debug-token"
	}
}

// ReportFinding records a finding produced by a bounded active observer such
// as the MITM SQL probe.  It reuses the same deduplication, evidence cache,
// runtime log, and persistence path as normal passive rules without feeding
// the probe response back through the passive detector a second time.
func (e *Engine) ReportFinding(f model.Finding, tx *model.Transaction) (model.Finding, bool) {
	if strings.TrimSpace(f.RuleID) == "" || e.cfg.Analysis.OnlyFingerprint || !e.checkEnabled(f.RuleID) {
		return f, false
	}
	if tx != nil {
		if strings.TrimSpace(f.URL) == "" {
			f.URL = tx.Request.URL
		}
		if strings.TrimSpace(f.Method) == "" {
			f.Method = tx.Request.Method
		}
		if f.ObservedAt.IsZero() {
			f.ObservedAt = tx.Observed
		}
	}
	if f.ObservedAt.IsZero() {
		f.ObservedAt = time.Now().UTC()
	}
	if f.Confidence == "" {
		f.Confidence = "firm"
	}
	if f.Severity == "" {
		f.Severity = "medium"
	}
	f = canonicalFinding(f)
	f.Evidence = e.evidence(f.Evidence)
	key := f.RuleID + "\x00" + f.URL
	digest := sha256.Sum256([]byte(key))
	f.ID = hex.EncodeToString(digest[:12])

	e.mu.Lock()
	_, exists := e.findings[key]
	if !exists {
		e.findings[key] = f
		if !isInformationalFinding(f) {
			e.passiveSummary.Vulnerabilities++
		}
	}
	sink := e.sink
	enricher := e.findingEnricher
	e.mu.Unlock()
	if exists {
		return f, false
	}
	if tx != nil {
		e.recordFindingEvidence(*tx, []model.Finding{f})
	}
	if parsed, err := url.Parse(f.URL); err == nil {
		e.Log("info", "finding", runtimeFindingMessage(f, parsed))
	}
	if sink != nil {
		e.scheduleSnapshot()
	}
	if enricher != nil && !isInformationalFinding(f) {
		go e.enrichFinding(enricher, f)
	}
	return f, true
}

// enrichFinding runs the AI enrichment pipeline asynchronously and writes the
// result back via UpdateFinding. It never panics the reporting path: any error
// is logged and the original finding remains unchanged.
func (e *Engine) enrichFinding(enricher FindingEnricher, finding model.Finding) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result := enricher.Enrich(ctx, finding)
	if !result.Enriched {
		return
	}
	e.UpdateFinding(result.Finding)
	e.Log("info", "ai", fmt.Sprintf("AI 已增强漏洞解读：%s (%s)", finding.Title, finding.ID))
}

// ReportFindingWithEvidence records a finding together with the complete
// original, probe, and replay exchanges that established it. The exchanges
// remain in the same bounded, session-only evidence cache used by passive
// findings and are never written to the snapshot sink.
func (e *Engine) ReportFindingWithEvidence(f model.Finding, transactions []model.Transaction) (model.Finding, bool) {
	reported, created := e.ReportFinding(f, nil)
	if !created {
		return reported, false
	}
	for _, tx := range transactions {
		e.recordFindingEvidence(tx, []model.Finding{reported})
	}
	return reported, true
}

// ClearAnalysisSnapshot drops persisted-result state that was restored into
// this engine. Runtime logs and traffic are intentionally left alone: they
// belong to the current process and are already empty on a fresh launch.
func (e *Engine) ClearAnalysisSnapshot() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.findings = make(map[string]model.Finding)
	e.assets = make(map[string]*assetState)
	e.passiveSummary = model.PassiveLogSummary{}
	e.findingEvidence = make(map[string][]model.FindingEvidence)
	e.findingEvidenceOrder = nil
	e.findingEvidenceSequence = 0
	e.findingEvidenceBytes = 0
	e.fingerprintQuality = make(map[string]*fingerprintQualityState)
	if e.passiveDeduper != nil {
		e.passiveDeduper.Reset()
	}
}

// AllowsPassiveHost reports whether a host may be analyzed from observed
// traffic. Unlike AllowsActiveHost, an empty scope.allow_hosts means passive
// traffic remains eligible unless it is denied or dynamically excluded.
func (e *Engine) AllowsPassiveHost(host string) bool {
	return e.inScope(host)
}

// AllowsPassiveURL reports whether a complete observed URL is eligible for
// passive capture and analysis. It applies host scope plus suffix, path-Glob,
// and Query-name exclusions. Parsing is intentionally centralized here so
// proxy adapters can make the same decision before copying request bodies.
func (e *Engine) AllowsPassiveURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && e.allowsPassiveRequest(model.Message{URL: rawURL}, u)
}

// AllowsPassiveRequest is the unified request-side admission check used by
// proxy pre-capture filtering and by Analyze. It evaluates host scope, suffix,
// path globs, Query names, and POST form/JSON names without retaining values.
func (e *Engine) AllowsPassiveRequest(request model.Message) bool {
	u, err := url.Parse(request.URL)
	return err == nil && e.allowsPassiveRequest(request, u)
}

// AllowsPassiveContentType reports whether a response Content-Type is
// eligible for passive capture and analysis. It intentionally treats an
// omitted or malformed Content-Type as eligible, so API responses without a
// header do not disappear from the analysis pipeline.
func (e *Engine) AllowsPassiveContentType(contentType string) bool {
	return !e.contentTypeExcluded(contentType)
}

func (e *Engine) AllowsActiveHost(host string) bool {
	if len(e.cfg.Scope.AllowHosts) == 0 {
		return false
	}
	return e.inScope(host)
}

// HFinger 返回内部 HFinger 指纹数据库句柄，供主动 WAF 探测复用被动分析
// 的规则集进行厂商识别。
func (e *Engine) HFinger() *fingerprint.HFingerDatabase {
	return e.hfinger
}

func (e *Engine) allowsPassiveURL(u *url.URL) bool {
	return u != nil && u.Hostname() != "" && e.AllowsPassiveHost(u.Hostname()) && !e.urlPathExcluded(u.Path)
}

func (e *Engine) allowsPassiveRequest(request model.Message, u *url.URL) bool {
	if !e.allowsPassiveURL(u) {
		return false
	}
	queryParameters := passiveQueryParameterNames(u.RawQuery)
	bodyRequest := request
	// The existing shape extractor is intentionally named around POST for
	// deduplication, while request-side filtering should also cover JSON/form
	// bodies sent with PUT or PATCH.
	if strings.TrimSpace(bodyRequest.Body) != "" && normalizedPassiveMethod(bodyRequest.Method) != http.MethodPost {
		bodyRequest.Method = http.MethodPost
	}
	_, postParameters := passivePOSTParameterShape(bodyRequest)
	return !e.requestExcluded(u.Path, queryParameters, postParameters)
}

// WAFProviders returns the WAF products passively observed for an asset. It
// never sends a request, and active verification uses it only to reduce the
// number and impact of probes for that host.
func (e *Engine) WAFProviders(host string) []string {
	if !e.featureEnabled("passive.hfinger") {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	asset := e.assets[strings.ToLower(host)]
	if asset == nil {
		return nil
	}
	var providers []string
	prefix := "WAF · "
	for value := range asset.fingerprints {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
			providers = append(providers, strings.TrimSpace(value[len(prefix):]))
		}
	}
	sort.Strings(providers)
	return providers
}

func (e *Engine) inScope(host string) bool {
	host = strings.ToLower(strings.TrimRight(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	if e.domainExcluded(host) {
		return false
	}
	for _, item := range e.cfg.Scope.DenyHosts {
		if hostMatch(host, item) {
			return false
		}
	}
	if len(e.cfg.Scope.AllowHosts) == 0 {
		return true
	}
	for _, item := range e.cfg.Scope.AllowHosts {
		if hostMatch(host, item) {
			return true
		}
	}
	return false
}

func (e *Engine) domainExcluded(host string) bool {
	e.mu.RLock()
	gate := e.domainExclusionGate
	e.mu.RUnlock()
	return gate != nil && gate.ExcludedHost(host)
}

func (e *Engine) urlPathExcluded(urlPath string) bool {
	e.mu.RLock()
	gate := e.suffixExclusionGate
	e.mu.RUnlock()
	return gate != nil && gate.ExcludedURLPath(urlPath)
}

func (e *Engine) contentTypeExcluded(contentType string) bool {
	e.mu.RLock()
	gate := e.contentTypeExclusionGate
	e.mu.RUnlock()
	return gate != nil && gate.ExcludedContentType(contentType)
}

func (e *Engine) requestExcluded(urlPath string, queryParameters, postParameters []string) bool {
	e.mu.RLock()
	gate := e.requestExclusionGate
	e.mu.RUnlock()
	return gate != nil && gate.ExcludedRequest(urlPath, queryParameters, postParameters)
}

func responseContentType(headers map[string]string) string {
	for name, value := range headers {
		if strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			return value
		}
	}
	return ""
}

func hostMatch(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if ok, _ := path.Match(pattern, host); ok {
		return true
	}
	return host == pattern
}

func (e *Engine) updateAsset(u *url.URL, tx model.Transaction) ([]string, []string) {
	host := strings.ToLower(u.Hostname())
	matches := []fingerprint.Match{}
	if model.IsObservedProxySource(tx.Source) && e.featureEnabled("passive.hfinger") && e.hfinger != nil {
		matches = e.hfinger.MatchDetails(tx, e.featureEnabled("passive.cdn_detection"), true)
	}
	matches = normalizeFingerprintMatches(matches)
	fps := make([]string, 0, len(matches))
	for _, match := range matches {
		fps = append(fps, match.Name)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.assets[host]
	if a == nil {
		a = &assetState{urls: map[string]struct{}{}, fingerprints: map[string]struct{}{}, fingerprintEvidence: map[string]model.FingerprintEvidence{}, endpoints: map[string]endpointState{}}
		e.assets[host] = a
	}
	if a.fingerprintEvidence == nil {
		a.fingerprintEvidence = make(map[string]model.FingerprintEvidence)
	}
	a.urls[tx.Request.URL] = struct{}{}
	knownFingerprints := make(map[string]struct{}, len(a.fingerprints)+len(matches))
	for value := range a.fingerprints {
		if key := fingerprintKey(value); key != "" {
			knownFingerprints[key] = struct{}{}
		}
	}
	newFingerprints := make([]string, 0, len(matches))
	for _, match := range matches {
		key := fingerprintKey(match.Name)
		if key == "" {
			continue
		}
		evidence := toFingerprintEvidence(match)
		if existing, exists := a.fingerprintEvidence[key]; exists {
			a.fingerprintEvidence[key] = mergeFingerprintEvidence(existing, evidence)
		} else {
			a.fingerprintEvidence[key] = evidence
		}
		if _, exists := knownFingerprints[key]; exists {
			continue
		}
		knownFingerprints[key] = struct{}{}
		a.fingerprints[match.Name] = struct{}{}
		newFingerprints = append(newFingerprints, match.Name)
	}
	for _, endpoint := range observedEndpoints(u, tx) {
		key := endpoint.method + "\x00" + endpoint.path
		current, exists := a.endpoints[key]
		if !exists {
			current = endpointState{method: endpoint.method, path: endpoint.path, parameters: map[string]struct{}{}, sources: map[string]struct{}{}}
		}
		for name := range endpoint.parameters {
			current.parameters[name] = struct{}{}
		}
		for source := range endpoint.sources {
			current.sources[source] = struct{}{}
		}
		a.endpoints[key] = current
	}
	a.lastSeen = tx.Observed
	e.recordFingerprintQualityLocked(host, tx.Observed, matches)
	return fps, newFingerprints
}

// AddInferredFingerprint merges an externally inferred fingerprint (for
// example an AI technology-stack inference) into the asset's fingerprint set
// so it surfaces in the fingerprint inventory alongside HFinger matches. The
// sources let the UI distinguish AI-inferred labels from rule matches.
func (e *Engine) AddInferredFingerprint(host, name string, sources []string, confidence string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	name = normalizeFingerprintName(name)
	if host == "" || name == "" {
		return false
	}
	if confidence == "" {
		confidence = "medium"
	}
	sources = normalizeFingerprintSources(sources)

	e.mu.Lock()
	a := e.assets[host]
	if a == nil {
		a = &assetState{urls: map[string]struct{}{}, fingerprints: map[string]struct{}{}, fingerprintEvidence: map[string]model.FingerprintEvidence{}, endpoints: map[string]endpointState{}}
		e.assets[host] = a
	}
	if a.fingerprintEvidence == nil {
		a.fingerprintEvidence = make(map[string]model.FingerprintEvidence)
	}
	key := fingerprintKey(name)
	if key == "" {
		e.mu.Unlock()
		return false
	}
	_, existed := a.fingerprints[name]
	a.fingerprints[name] = struct{}{}
	evidence := model.FingerprintEvidence{Fingerprint: name, Sources: sources, Confidence: confidence}
	if existing, ok := a.fingerprintEvidence[key]; ok {
		a.fingerprintEvidence[key] = mergeFingerprintEvidence(existing, evidence)
	} else {
		a.fingerprintEvidence[key] = evidence
	}
	a.lastSeen = time.Now().UTC()
	sink := e.sink
	e.mu.Unlock()

	if existed {
		return false
	}
	if sink != nil {
		e.scheduleSnapshot()
	}
	return true
}

func fingerprintKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (e *Engine) recordPassiveTraffic(tx model.Transaction, u *url.URL, matched []model.Finding, fingerprints []string) {
	if !isPassiveTraffic(tx) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.trafficSequence++
	entry := model.TrafficSummary{
		ID:           fmt.Sprintf("traffic-%d", e.trafficSequence),
		ObservedAt:   tx.Observed,
		Source:       tx.Source,
		Method:       tx.Request.Method,
		URL:          trafficURL(u),
		Status:       tx.Response.Status,
		ContentType:  mediaType(header(tx.Response.Headers, "Content-Type")),
		Findings:     trafficFindingLabels(matched),
		Fingerprints: append([]string(nil), fingerprints...),
	}
	e.traffic[e.trafficNext] = entry
	e.trafficNext = (e.trafficNext + 1) % trafficHistoryLimit
	if e.trafficCount < trafficHistoryLimit {
		e.trafficCount++
	}
}

func isPassiveTraffic(tx model.Transaction) bool {
	return !strings.HasPrefix(strings.ToLower(strings.TrimSpace(tx.Source)), "active-")
}

func runtimeRequestMessage(tx model.Transaction, u *url.URL) string {
	method := strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	if method == "" {
		method = "HTTP"
	}
	source := runtimeLogSource(tx.Source)
	return fmt.Sprintf("接收请求：%s %s → %d（来源：%s）", method, trafficURL(u), tx.Response.Status, source)
}

func runtimeFindingMessage(finding model.Finding, u *url.URL) string {
	return fmt.Sprintf("发现风险：%s（%s，规则：%s，目标：%s）", runtimeLogText(finding.Title, 120), runtimeLogText(finding.Severity, 24), runtimeLogText(finding.RuleID, 96), trafficURL(u))
}

// isInformationalFinding distinguishes passive observations from a
// vulnerability in the live log.  TscanPlus information rules are explicit
// information observations even when an imported snapshot omits severity.
func isInformationalFinding(finding model.Finding) bool {
	if strings.EqualFold(strings.TrimSpace(finding.Severity), "info") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(finding.RuleID)), "tscan.info.")
}

func runtimeLogLevel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return "error"
	case "warn", "warning":
		return "warn"
	case "debug":
		return "debug"
	default:
		return "info"
	}
}

func runtimeLogComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "runtime"
	}
	return runtimeLogText(value, 48)
}

func runtimeLogSource(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var builder strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			builder.WriteRune(r)
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return runtimeLogText(builder.String(), 64)
}

func runtimeLogMessage(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if runtimeLogSensitiveHeader.MatchString(value) || runtimeLogSensitiveValue.MatchString(value) {
		return "运行事件包含敏感内容，已隐藏"
	}
	return runtimeLogText(value, runtimeLogMessageLimit)
}

func runtimeLogText(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "未提供详情"
	}
	if len(value) <= max {
		return value
	}
	return truncateRunes(value, max) + "…"
}

func trafficURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	copyURL := *u
	copyURL.User = nil
	copyURL.Fragment = ""
	if u.RawQuery != "" {
		keys := make([]string, 0, len(u.Query()))
		for key := range u.Query() {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		copyURL.RawQuery = strings.Join(keys, "&")
	}
	return copyURL.String()
}

func mediaType(value string) string {
	if separator := strings.Index(value, ";"); separator >= 0 {
		value = value[:separator]
	}
	return strings.TrimSpace(value)
}

func trafficFindingLabels(values []model.Finding) []string {
	seen := make(map[string]struct{}, len(values))
	for _, finding := range values {
		label := strings.TrimSpace(finding.Title)
		if label != "" {
			seen[label] = struct{}{}
		}
	}
	labels := make([]string, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func targetText(target string, tx model.Transaction) string {
	switch strings.ToLower(target) {
	case "url":
		return tx.Request.URL
	case "request_body":
		return tx.Request.Body
	case "response_body":
		return tx.Response.Body
	case "request_headers":
		return headersText(tx.Request.Headers)
	case "response_headers":
		return headersText(tx.Response.Headers)
	default:
		return ""
	}
}

func headersText(headers map[string]string) string {
	var lines []string
	for k, v := range headers {
		lines = append(lines, k+": "+v)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func header(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func (e *Engine) evidence(value string) string {
	value = excerpt(value, 240)
	if !e.cfg.Privacy.RedactEvidence {
		return value
	}
	redactions := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+`),
		regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;&]+`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	}
	for _, re := range redactions {
		value = re.ReplaceAllString(value, "$1[REDACTED]")
	}
	return value
}

func excerpt(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= max {
		return value
	}
	return truncateRunes(value, max) + "…"
}

// truncateRunes returns value trimmed to at most max bytes without splitting a
// multi-byte UTF-8 rune, so truncated Chinese text is not left garbled.
func truncateRunes(value string, max int) string {
	if len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
