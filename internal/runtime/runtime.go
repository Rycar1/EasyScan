// Package runtime owns the long-lived EasyScan services independently of any
// UI transport. The CLI, HTTP API, proxy, and desktop shell share this one
// composition root so their state remains consistent.
package runtime

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/example/easyscan/internal/active"
	"github.com/example/easyscan/internal/aiextra"
	"github.com/example/easyscan/internal/aiinsight"
	"github.com/example/easyscan/internal/aiprobe"
	"github.com/example/easyscan/internal/cmdprobe"
	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/fastjsonprobe"
	"github.com/example/easyscan/internal/features"
	"github.com/example/easyscan/internal/fileprobe"
	"github.com/example/easyscan/internal/fingerprintprobe"
	"github.com/example/easyscan/internal/ingest"
	"github.com/example/easyscan/internal/model"
	"github.com/example/easyscan/internal/nucleiprobe"
	"github.com/example/easyscan/internal/report"
	"github.com/example/easyscan/internal/shiroprobe"
	"github.com/example/easyscan/internal/sqlprobe"
	"github.com/example/easyscan/internal/ssrfprobe"
	"github.com/example/easyscan/internal/store"
	"github.com/example/easyscan/internal/uploadprobe"
	"github.com/example/easyscan/internal/wafprobe"
	"github.com/example/easyscan/internal/xssprobe"
	"github.com/example/easyscan/internal/xxeprobe"
)

type Runtime struct {
	cfg       config.Config
	engine    *engine.Engine
	policy    *features.Policy
	store     *store.Store
	runner    *active.Runner
	sqlProbe      *sqlprobe.Worker
	xssProbe      *xssprobe.Worker
	fileProbe     *fileprobe.Worker
	wafProbe      *wafprobe.Worker
	fastjsonProbe *fastjsonprobe.Worker
	fingerprintProbe *fingerprintprobe.Worker
	shiroProbe    *shiroprobe.Worker
	cmdProbe      *cmdprobe.Worker
	ssrfProbe     *ssrfprobe.Worker
	xxeProbe      *xxeprobe.Worker
	uploadProbe   *uploadprobe.Worker
	pocProbe      *nucleiprobe.Worker
	nucleiManager *nucleiprobe.Manager
	aiProbe       *aiprobe.Worker
	aiExtra       *aiextra.Worker
	reporter      *report.AutoHTML
	close     sync.Once
	closeErr  error
}

// snapshotSink makes durable state the source of truth before queueing an
// offline report update. Engine callers can continue to use one sink while
// the report writer independently coalesces bursts of captured traffic.
type snapshotSink struct {
	store    *store.Store
	reporter *report.AutoHTML
}

func (s snapshotSink) SaveSnapshot(findings []model.Finding, assets []model.Asset) error {
	if err := s.store.SaveSnapshot(findings, assets); err != nil {
		return err
	}
	if s.reporter != nil {
		s.reporter.Schedule(findings, assets)
	}
	return nil
}

func Open(cfg config.Config) (*Runtime, error) {
	policy, err := features.Load(cfg.Features.Path)
	if err != nil {
		return nil, err
	}
	e, err := engine.New(cfg)
	if err != nil {
		return nil, err
	}
	e.SetFeatureGate(policy)
	// The feature policy also owns the mutable domain exclusion list. Keep the
	// engine pointed at this live object so settings changes take effect for
	// the next passive exchange, CONNECT decision, or active scope check.
	e.SetDomainExclusionGate(policy)
	// The same live policy owns user-maintained URL path suffix exclusions.
	// Engine.Analyze and proxy pre-capture checks both consult this gate, so a
	// saved setting applies to the very next exchange without a restart.
	e.SetSuffixExclusionGate(policy)
	// Response Content-Type filters are evaluated once upstream headers arrive.
	// They share the same live policy, so editing the setting applies to the
	// next proxied response without restarting services.
	e.SetContentTypeExclusionGate(policy)
	// URL-path globs and Query/POST/JSON parameter-name filters are evaluated
	// before passive analysis. The policy is live, so saved desktop changes
	// apply to the next request without restarting the proxy.
	e.SetRequestExclusionGate(policy)
	database, err := store.Open(cfg.Storage.Path)
	if err != nil {
		return nil, err
	}
	if err := database.DeleteFindingsByRulePrefix("passive.cors.", "passive.cookie.", "passive.banner.server"); err != nil {
		_ = database.Close()
		return nil, err
	}
	findings, assets, err := database.LoadSnapshot()
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	e.Restore(findings, assets)
	var reporter *report.AutoHTML
	if cfg.Reports.AutoHTML && strings.TrimSpace(cfg.Reports.HTMLPath) != "" {
		reporter = report.NewAutoHTML(cfg.Reports.HTMLPath)
	}
	e.SetSnapshotSink(snapshotSink{store: database, reporter: reporter})
	sqlProbeWorker := sqlprobe.New(cfg, e, policy)
	xssProbeWorker := xssprobe.New(cfg, e, policy)
	fileProbeWorker := fileprobe.New(cfg, e, policy)
	wafProbeWorker := wafprobe.New(cfg, e, policy)
	fastjsonProbeWorker := fastjsonprobe.New(cfg, e, policy)
	fingerprintProbeWorker := fingerprintprobe.New(cfg, e, policy)
	shiroProbeWorker := shiroprobe.New(cfg, e, policy)
	cmdProbeWorker := cmdprobe.New(cfg, e, policy)
	ssrfProbeWorker := ssrfprobe.New(cfg, e, policy)
	xxeProbeWorker := xxeprobe.New(cfg, e, policy)
	uploadProbeWorker := uploadprobe.New(cfg, e, policy)
	nucleiManager := nucleiprobe.NewManager(filepath.Dir(cfg.Storage.Path), policy.NucleiBinaryPath)
	pocProbeWorker := nucleiprobe.New(cfg, e, policy, nucleiManager)
	aiProbeWorker := aiprobe.New(e, policy)
	aiExtraWorker := aiextra.New(e, policy)
	e.SetFindingEnricher(findingEnricherAdapter{aiinsight.New(policy, nil), aiExtraWorker})
	e.SetTransactionObserver(func(tx model.Transaction) {
		// Both plain HTTP proxy traffic and decrypted HTTPS MITM traffic are
		// browser observations. HFinger runs synchronously inside Engine.Analyze;
		// only the optional probe workers need scheduling here.
		if model.IsObservedProxySource(tx.Source) {
			sqlProbeWorker.Observe(tx)
			xssProbeWorker.Observe(tx)
			fileProbeWorker.Observe(tx)
			wafProbeWorker.Observe(tx)
			fastjsonProbeWorker.Observe(tx)
			fingerprintProbeWorker.Observe(tx)
			shiroProbeWorker.Observe(tx)
			cmdProbeWorker.Observe(tx)
			ssrfProbeWorker.Observe(tx)
			xxeProbeWorker.Observe(tx)
			uploadProbeWorker.Observe(tx)
			pocProbeWorker.Observe(tx)
			aiProbeWorker.Observe(tx)
			aiExtraWorker.Observe(tx)
		}
	})
	return &Runtime{cfg: cfg, engine: e, policy: policy, store: database, runner: active.New(cfg, e, database, policy), sqlProbe: sqlProbeWorker, xssProbe: xssProbeWorker, fileProbe: fileProbeWorker, wafProbe: wafProbeWorker, fastjsonProbe: fastjsonProbeWorker, fingerprintProbe: fingerprintProbeWorker, shiroProbe: shiroProbeWorker, cmdProbe: cmdProbeWorker, ssrfProbe: ssrfProbeWorker, xxeProbe: xxeProbeWorker, uploadProbe: uploadProbeWorker, pocProbe: pocProbeWorker, nucleiManager: nucleiManager, aiProbe: aiProbeWorker, aiExtra: aiExtraWorker, reporter: reporter}, nil
}

func (r *Runtime) Config() config.Config    { return r.cfg }
func (r *Runtime) Engine() *engine.Engine   { return r.engine }
func (r *Runtime) Policy() *features.Policy { return r.policy }
func (r *Runtime) Runner() *active.Runner   { return r.runner }

// CancelSQLiProbes stops queued and in-flight MITM SQL checks without
// stopping the worker.  A later MITM start can schedule new endpoints.
func (r *Runtime) CancelSQLiProbes() {
	if r.sqlProbe != nil {
		r.sqlProbe.CancelPending()
	}
}

// CancelXSSProbes stops queued and in-flight MITM reflected-XSS checks
// without stopping the worker. A later MITM start can schedule new requests.
func (r *Runtime) CancelXSSProbes() {
	if r.xssProbe != nil {
		r.xssProbe.CancelPending()
	}
}

// CancelFileProbes stops queued and in-flight MITM sensitive-file checks
// without stopping the worker. A later MITM start can schedule new origins.
func (r *Runtime) CancelFileProbes() {
	if r.fileProbe != nil {
		r.fileProbe.CancelPending()
	}
}

// CancelWAFProbes 停止排队中的 WAF 主动探测，允许在 MITM 重启后重新触发。
func (r *Runtime) CancelWAFProbes() {
	if r.wafProbe != nil {
		r.wafProbe.CancelPending()
	}
}

// CancelFastjsonProbes stops queued and in-flight MITM Fastjson checks without
// stopping the worker. A later MITM start can schedule new requests.
func (r *Runtime) CancelFastjsonProbes() {
	if r.fastjsonProbe != nil {
		r.fastjsonProbe.CancelPending()
	}
}

// CancelFingerprintProbes stops queued and in-flight active fingerprint probes
// without stopping the worker. A later MITM start can schedule new origins.
func (r *Runtime) CancelFingerprintProbes() {
	if r.fingerprintProbe != nil {
		r.fingerprintProbe.CancelPending()
	}
}

// CancelShiroProbes stops queued and in-flight MITM Shiro checks without
// stopping the worker. A later MITM start can schedule new hosts.
func (r *Runtime) CancelShiroProbes() {
	if r.shiroProbe != nil {
		r.shiroProbe.CancelPending()
	}
}

// CancelCmdProbes stops queued and in-flight MITM command-injection checks
// without stopping the worker. A later MITM start can schedule new endpoints.
func (r *Runtime) CancelCmdProbes() {
	if r.cmdProbe != nil {
		r.cmdProbe.CancelPending()
	}
}

// CancelSSRFProbes stops queued and in-flight MITM SSRF checks without stopping
// the worker. A later MITM start can schedule new endpoints.
func (r *Runtime) CancelSSRFProbes() {
	if r.ssrfProbe != nil {
		r.ssrfProbe.CancelPending()
	}
}

// CancelXXEProbes stops queued and in-flight MITM XXE checks without stopping
// the worker. A later MITM start can schedule new endpoints.
func (r *Runtime) CancelXXEProbes() {
	if r.xxeProbe != nil {
		r.xxeProbe.CancelPending()
	}
}

// CancelUploadProbes stops queued and in-flight MITM file-upload checks without
// stopping the worker. A later MITM start can schedule new endpoints.
func (r *Runtime) CancelUploadProbes() {
	if r.uploadProbe != nil {
		r.uploadProbe.CancelPending()
	}
}

// CancelPOCProbes stops queued and in-flight MITM nuclei runs without stopping
// the worker. A later MITM start can schedule new origins.
func (r *Runtime) CancelPOCProbes() {
	if r.pocProbe != nil {
		r.pocProbe.CancelPending()
	}
}

// NucleiManager returns the nuclei binary manager so the desktop layer can
// trigger downloads and report installation status.
func (r *Runtime) NucleiManager() *nucleiprobe.Manager {
	return r.nucleiManager
}

// CancelAIAnalysis drops collected, not-yet-analysed JS sites so a later MITM
// start restarts AI collection cleanly.
func (r *Runtime) CancelAIAnalysis() {
	if r.aiProbe != nil {
		r.aiProbe.CancelPending()
	}
	if r.aiExtra != nil {
		r.aiExtra.CancelPending()
	}
}

// ClearAnalysisSnapshot removes persisted and in-memory findings/assets while
// preserving task history. Desktop startup calls it before services begin.
func (r *Runtime) ClearAnalysisSnapshot() error {
	if err := r.store.ClearAnalysisSnapshot(); err != nil {
		return err
	}
	r.engine.ClearAnalysisSnapshot()
	return nil
}

// ScheduleReport queues the current normalized snapshot for automatic HTML
// output. It is intentionally a no-op when reports.auto_html is disabled.
func (r *Runtime) ScheduleReport() {
	if r.reporter == nil {
		return
	}
	r.reporter.Schedule(r.engine.Findings(), r.engine.Assets())
}

// HTTPHandler remains available for traffic adapters. It deliberately has no
// browser dashboard route; desktop presentation uses Wails bindings instead.
func (r *Runtime) HTTPHandler() http.Handler {
	server := ingest.New(r.engine, r.cfg.API.Token, r.cfg.Proxy.MaxBodyBytes, r.runner)
	server.SetFeaturePolicy(r.policy)
	return server.Handler()
}

func (r *Runtime) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.close.Do(func() {
		// Detach before cancellation so an in-flight Engine.Analyze cannot queue
		// fresh work while this close sequence is waiting for the worker.
		r.engine.SetTransactionObserver(nil)
		var sqlProbeErr error
		if r.sqlProbe != nil {
			sqlProbeErr = r.sqlProbe.Shutdown(ctx)
		}
		var xssProbeErr error
		if r.xssProbe != nil {
			xssProbeErr = r.xssProbe.Shutdown(ctx)
		}
		var fileProbeErr error
		if r.fileProbe != nil {
			fileProbeErr = r.fileProbe.Shutdown(ctx)
		}
		var wafProbeErr error
		if r.wafProbe != nil {
			wafProbeErr = r.wafProbe.Shutdown(ctx)
		}
		var fastjsonProbeErr error
		if r.fastjsonProbe != nil {
			fastjsonProbeErr = r.fastjsonProbe.Shutdown(ctx)
		}
		var fingerprintProbeErr error
		if r.fingerprintProbe != nil {
			fingerprintProbeErr = r.fingerprintProbe.Shutdown(ctx)
		}
		var shiroProbeErr error
		if r.shiroProbe != nil {
			shiroProbeErr = r.shiroProbe.Shutdown(ctx)
		}
		var cmdProbeErr error
		if r.cmdProbe != nil {
			cmdProbeErr = r.cmdProbe.Shutdown(ctx)
		}
		var ssrfProbeErr error
		if r.ssrfProbe != nil {
			ssrfProbeErr = r.ssrfProbe.Shutdown(ctx)
		}
		var xxeProbeErr error
		if r.xxeProbe != nil {
			xxeProbeErr = r.xxeProbe.Shutdown(ctx)
		}
		var uploadProbeErr error
		if r.uploadProbe != nil {
			uploadProbeErr = r.uploadProbe.Shutdown(ctx)
		}
		var pocProbeErr error
		if r.pocProbe != nil {
			pocProbeErr = r.pocProbe.Shutdown(ctx)
		}
		var aiProbeErr error
	if r.aiProbe != nil {
		aiProbeErr = r.aiProbe.Shutdown(ctx)
	}
	var aiExtraErr error
	if r.aiExtra != nil {
		aiExtraErr = r.aiExtra.Shutdown(ctx)
	}
	shutdownErr := r.runner.Shutdown(ctx)
	// All probes are stopped and the transaction observer is detached, so no
	// further Analyze calls can arrive. Force any debounced snapshot to disk
	// before returning so the final findings/assets batch is not lost.
	r.engine.FlushSnapshot()
	var closeErrors []error
		if sqlProbeErr != nil {
			closeErrors = append(closeErrors, sqlProbeErr)
		}
		if xssProbeErr != nil {
			closeErrors = append(closeErrors, xssProbeErr)
		}
		if fileProbeErr != nil {
			closeErrors = append(closeErrors, fileProbeErr)
		}
		if wafProbeErr != nil {
			closeErrors = append(closeErrors, wafProbeErr)
		}
		if fastjsonProbeErr != nil {
			closeErrors = append(closeErrors, fastjsonProbeErr)
		}
		if fingerprintProbeErr != nil {
			closeErrors = append(closeErrors, fingerprintProbeErr)
		}
		if shiroProbeErr != nil {
			closeErrors = append(closeErrors, shiroProbeErr)
		}
		if cmdProbeErr != nil {
			closeErrors = append(closeErrors, cmdProbeErr)
		}
		if ssrfProbeErr != nil {
			closeErrors = append(closeErrors, ssrfProbeErr)
		}
		if xxeProbeErr != nil {
			closeErrors = append(closeErrors, xxeProbeErr)
		}
		if uploadProbeErr != nil {
			closeErrors = append(closeErrors, uploadProbeErr)
		}
		if pocProbeErr != nil {
			closeErrors = append(closeErrors, pocProbeErr)
		}
		if aiProbeErr != nil {
		closeErrors = append(closeErrors, aiProbeErr)
	}
	if aiExtraErr != nil {
		closeErrors = append(closeErrors, aiExtraErr)
	}
	if shutdownErr != nil {
			closeErrors = append(closeErrors, shutdownErr)
		}
		if r.reporter != nil {
			if err := r.reporter.Close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		// Preserve the existing timeout behaviour: active workers may still be
		// using SQLite after a cancelled Shutdown, so do not close it early.
		if shutdownErr == nil && sqlProbeErr == nil && fileProbeErr == nil && wafProbeErr == nil {
			if err := r.store.Close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		r.closeErr = errors.Join(closeErrors...)
	})
	return r.closeErr
}

// findingEnricherAdapter bridges the aiinsight.Enricher and the aiextra
// secret-context enhancer to the engine.FindingEnricher interface.
type findingEnricherAdapter struct {
	insight *aiinsight.Enricher
	extra   *aiextra.Worker
}

func (a findingEnricherAdapter) Enrich(ctx context.Context, finding model.Finding) engine.EnrichResult {
	result := a.insight.Enrich(ctx, finding)
	if result.Enriched {
		return engine.EnrichResult{Finding: result.Finding, Enriched: true}
	}
	if a.extra != nil {
		if enhanced, ok := a.extra.EnrichSecretContext(ctx, result.Finding); ok {
			return engine.EnrichResult{Finding: enhanced, Enriched: true}
		}
	}
	return engine.EnrichResult{Finding: result.Finding, Enriched: false}
}
