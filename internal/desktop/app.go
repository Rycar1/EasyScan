// Package desktop exposes the local EasyScan runtime to the Wails WebView.
// It never bypasses the scanner's authorization, scope, or feature gates.
package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/active"
	"github.com/example/easyscan/internal/aiclient"
	"github.com/example/easyscan/internal/aiprobe"
	"github.com/example/easyscan/internal/features"
	"github.com/example/easyscan/internal/fingerprint"
	"github.com/example/easyscan/internal/model"
	"github.com/example/easyscan/internal/proxy"
	scanruntime "github.com/example/easyscan/internal/runtime"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type Status struct {
	Started         bool   `json:"running"`
	ProxyListen     string `json:"proxy_address"`
	APIListen       string `json:"api_address"`
	MITMEnabled     bool   `json:"mitm_enabled"`
	ActiveEnabled   bool   `json:"active_enabled"`
	LastError       string `json:"message,omitempty"`
	CertificatePath string `json:"certificate_path,omitempty"`
}

type Snapshot struct {
	Status                      Status                         `json:"status"`
	Logs                        []model.RuntimeLog             `json:"logs"`
	PassiveLogSummary           model.PassiveLogSummary        `json:"passive_log_summary"`
	Traffic                     []model.TrafficSummary         `json:"traffic"`
	Findings                    []model.Finding                `json:"findings"`
	Assets                      []model.Asset                  `json:"assets"`
	FingerprintQuality          []model.FingerprintRuleQuality `json:"fingerprint_quality"`
	Tasks                       []model.ActiveTask             `json:"tasks"`
	Features                    []features.Definition          `json:"features"`
	SQLiErrorEnabled            bool                           `json:"passive_sqli_error_enabled"`
	SQLiBooleanEnabled          bool                           `json:"passive_sqli_boolean_enabled"`
	SQLiTimeEnabled             bool                           `json:"passive_sqli_time_enabled"`
	PassiveSQLiProbeQPS         int                            `json:"passive_sqli_probe_qps"`
	PassiveSQLiMaxRequests      int                            `json:"passive_sqli_max_requests"`
	PassiveSQLiMaxParameters    int                            `json:"passive_sqli_max_parameters"`
	PassiveXSSProbeQPS          int                            `json:"passive_xss_probe_qps"`
	PassiveXSSMaxRequests       int                            `json:"passive_xss_max_requests"`
	PassiveXSSMaxParameters     int                            `json:"passive_xss_max_parameters"`
	PassivePOCQPS               int                            `json:"passive_poc_qps"`
	PassivePOCConcurrency       int                            `json:"passive_poc_concurrency"`
	PassiveFileProbeQPS         int                            `json:"passive_file_probe_qps"`
	PassiveFileProbeMaxPrefixes int                            `json:"passive_file_probe_max_prefixes"`
	PassiveFastjsonProbeQPS     int                            `json:"passive_fastjson_probe_qps"`
	PassiveShiroProbeQPS        int                            `json:"passive_shiro_probe_qps"`
	PassiveCmdProbeQPS          int                            `json:"passive_cmd_probe_qps"`
	PassiveSSRFProbeQPS         int                            `json:"passive_ssrf_probe_qps"`
	PassiveXXEProbeQPS          int                            `json:"passive_xxe_probe_qps"`
	PassiveUploadProbeQPS       int                            `json:"passive_upload_probe_qps"`
	OOBDomain                   string                         `json:"oob_domain"`
	ShiroKeys                   []string                       `json:"shiro_keys"`
	HFinger                     fingerprint.HFingerStats       `json:"hfinger"`
	ExcludedDomains             []string                       `json:"excluded_domains"`
	ExcludedSuffixes            []string                       `json:"excluded_suffixes"`
	ExcludedContentTypes        []string                       `json:"excluded_content_types"`
	ExcludedPaths               []string                       `json:"excluded_paths"`
	ExcludedQueryParameters     []string                       `json:"excluded_query_parameters"`
	ExcludedPostParameters      []string                       `json:"excluded_post_parameters"`
	SwaggerExcludedPaths        []string                       `json:"swagger_excluded_paths"`
	FileProbeCustomPaths        []string                       `json:"file_probe_custom_paths"`
}

type TaskRequest struct {
	Kind           string            `json:"kind"`
	Target         string            `json:"target"`
	SessionHeaders map[string]string `json:"session_headers,omitempty"`
}

type App struct {
	mu       sync.RWMutex
	ctx      context.Context
	scan     *scanruntime.Runtime
	status   Status
	starting bool
	cancel   context.CancelFunc
	api      *http.Server
}

type Lifecycle struct{ app *App }

func New(scan *scanruntime.Runtime) (*App, *Lifecycle) {
	cfg := scan.Config()
	app := &App{scan: scan, status: Status{
		ProxyListen: cfg.Proxy.Listen, APIListen: cfg.API.Listen, MITMEnabled: cfg.Proxy.MITM, ActiveEnabled: cfg.Active.Enabled,
	}}
	return app, &Lifecycle{app: app}
}

func (l *Lifecycle) Startup(ctx context.Context) {
	a := l.app
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	a.clearPreviousResultsOnStartup()
	a.scan.ScheduleReport()
	a.scan.Engine().Log("info", "runtime", "桌面运行时已启动")
	if _, err := a.StartServices(); err != nil {
		runtime.EventsEmit(ctx, "easyscan:service-error", err.Error())
	}
}

func (a *App) clearPreviousResultsOnStartup() {
	if !a.scan.Policy().Enabled("desktop.clear_previous_results_on_start") {
		a.scan.Engine().Log("info", "storage", "启动时保留上次的漏洞结果和指纹识别")
		return
	}
	if err := a.scan.ClearAnalysisSnapshot(); err != nil {
		a.scan.Engine().Log("error", "storage", fmt.Sprintf("启动时清理上次漏洞结果和指纹识别失败：%v", err))
		return
	}
	a.scan.Engine().Log("info", "storage", "启动时已清理上次的漏洞结果和指纹识别")
}

func (l *Lifecycle) Shutdown(ctx context.Context) {
	a := l.app
	a.scan.Engine().Log("info", "runtime", "桌面运行时正在关闭")
	a.scan.CancelSQLiProbes()
	a.scan.CancelXSSProbes()
	a.scan.CancelFileProbes()
	a.scan.CancelWAFProbes()
	a.mu.Lock()
	cancel, api, wasStarted, mitmEnabled := a.cancel, a.api, a.status.Started, a.status.MITMEnabled
	a.cancel, a.api, a.status.Started = nil, nil, false
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if api != nil {
		_ = api.Shutdown(ctx)
	}
	if wasStarted || cancel != nil || api != nil {
		a.logServicesStopped(mitmEnabled)
	}
	a.scan.Engine().Log("info", "runtime", "桌面运行时已关闭")
	_ = a.scan.Close(ctx)
}

func (a *App) Status() Status {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.status
}

func (a *App) Snapshot() (Snapshot, error) {
	tasks, err := a.scan.Runner().ListTasks(100)
	if err != nil {
		return Snapshot{}, err
	}
	passiveLogSummary := a.scan.Engine().PassiveLogSummary()
	for _, task := range tasks {
		switch strings.ToLower(strings.TrimSpace(task.Status)) {
		case "queued", "running":
			if task.Kind == active.KindPortScan {
				passiveLogSummary.UndoPort++
			} else {
				passiveLogSummary.UndoTask++
			}
		}
	}
	return Snapshot{
		Status:                      a.Status(),
		Logs:                        a.scan.Engine().Logs(0),
		PassiveLogSummary:           passiveLogSummary,
		Traffic:                     a.scan.Engine().Traffic(300),
		Findings:                    a.scan.Engine().Findings(),
		Assets:                      a.scan.Engine().Assets(),
		FingerprintQuality:          a.scan.Engine().FingerprintQuality(),
		Tasks:                       tasks,
		Features:                    a.scan.Policy().List(),
		SQLiErrorEnabled:            a.scan.Policy().SQLiErrorEnabled(),
		SQLiBooleanEnabled:          a.scan.Policy().SQLiBooleanEnabled(),
		SQLiTimeEnabled:             a.scan.Policy().SQLiTimeEnabled(),
		HFinger:                     a.scan.Engine().HFingerStats(),
		PassiveSQLiProbeQPS:         a.scan.Policy().PassiveSQLiProbeQPS(),
		PassiveSQLiMaxRequests:      a.scan.Policy().PassiveSQLiMaxRequests(),
		PassiveSQLiMaxParameters:    a.scan.Policy().PassiveSQLiMaxParameters(),
		PassiveXSSProbeQPS:          a.scan.Policy().PassiveXSSProbeQPS(),
		PassiveXSSMaxRequests:       a.scan.Policy().PassiveXSSMaxRequests(),
		PassiveXSSMaxParameters:     a.scan.Policy().PassiveXSSMaxParameters(),
		PassivePOCQPS:               a.scan.Policy().PassivePOCQPS(),
		PassivePOCConcurrency:       a.scan.Policy().PassivePOCConcurrency(),
		PassiveFileProbeQPS:         a.scan.Policy().PassiveFileProbeQPS(),
		PassiveFileProbeMaxPrefixes: a.scan.Policy().PassiveFileProbeMaxPrefixes(),
		PassiveFastjsonProbeQPS:     a.scan.Policy().PassiveFastjsonProbeQPS(),
		PassiveShiroProbeQPS:        a.scan.Policy().PassiveShiroProbeQPS(),
		PassiveCmdProbeQPS:          a.scan.Policy().PassiveCmdProbeQPS(),
		PassiveSSRFProbeQPS:         a.scan.Policy().PassiveSSRFProbeQPS(),
		PassiveXXEProbeQPS:          a.scan.Policy().PassiveXXEProbeQPS(),
		PassiveUploadProbeQPS:       a.scan.Policy().PassiveUploadProbeQPS(),
		OOBDomain:                   a.scan.Policy().OOBDomain(),
		ShiroKeys:                   a.scan.Policy().ShiroKeys(),
		ExcludedDomains:             a.scan.Policy().ExcludedDomains(),
		ExcludedSuffixes:            a.scan.Policy().ExcludedSuffixes(),
		ExcludedContentTypes:        a.scan.Policy().ExcludedContentTypes(),
		ExcludedPaths:               a.scan.Policy().ExcludedPaths(),
		ExcludedQueryParameters:     a.scan.Policy().ExcludedQueryParameters(),
		ExcludedPostParameters:      a.scan.Policy().ExcludedPostParameters(),
		SwaggerExcludedPaths:        a.scan.Policy().SwaggerExcludedPaths(),
		FileProbeCustomPaths:        a.scan.Policy().CustomProbePaths(),
	}, nil
}

// FindingEvidence lazily exposes full request/response captures for one
// finding. Unlike Snapshot, this method is only called after the user expands
// a finding, avoiding repeated serialization of raw HTTP bodies in the
// periodic dashboard refresh.
func (a *App) FindingEvidence(findingID string) ([]model.FindingEvidence, error) {
	if strings.TrimSpace(findingID) == "" {
		return []model.FindingEvidence{}, nil
	}
	return a.scan.Engine().EvidenceForFinding(findingID), nil
}

// RuntimeLogs returns the full in-memory runtime log ring (newest-first),
// including debug-level entries used for troubleshooting probe pipelines.
// Unlike Snapshot.Logs, this method does not filter and is intended for the
// dedicated runtime log view.
func (a *App) RuntimeLogs(limit int) ([]model.RuntimeLog, error) {
	if limit < 0 {
		limit = 0
	}
	return a.scan.Engine().Logs(limit), nil
}

func (a *App) StartServices() (Status, error) {
	a.mu.Lock()
	if a.status.Started || a.starting {
		status := a.status
		a.mu.Unlock()
		return status, nil
	}
	a.starting, a.status.LastError = true, ""
	a.mu.Unlock()
	a.scan.Engine().Log("info", "runtime", "正在启动本地服务")

	status, err := a.startServices()
	a.mu.Lock()
	a.starting = false
	if err != nil {
		a.status.LastError = err.Error()
		status = a.status
	} else {
		a.status = status
	}
	a.mu.Unlock()
	if err != nil {
		a.scan.Engine().Log("error", "runtime", fmt.Sprintf("本地服务启动失败：%v", err))
		a.emit("easyscan:service-error", err.Error())
	} else {
		a.scan.Engine().Log("info", "runtime", "本地服务已启动")
	}
	return status, err
}

func (a *App) startServices() (Status, error) {
	cfg := a.scan.Config()
	a.scan.Engine().Log("info", "api", fmt.Sprintf("正在监听流量 API：%s", cfg.API.Listen))
	apiListener, err := net.Listen("tcp", cfg.API.Listen)
	if err != nil {
		a.scan.Engine().Log("error", "api", fmt.Sprintf("流量 API 启动失败：%v", err))
		return a.Status(), fmt.Errorf("listen traffic API %s: %w", cfg.API.Listen, err)
	}
	a.scan.Engine().Log("info", "api", fmt.Sprintf("流量 API 已监听：%s", cfg.API.Listen))
	proxyServer := proxy.New(a.scan.Engine(), cfg.Proxy.MaxBodyBytes)
	status := Status{Started: true, ProxyListen: cfg.Proxy.Listen, APIListen: cfg.API.Listen, MITMEnabled: cfg.Proxy.MITM, ActiveEnabled: cfg.Active.Enabled}
	if cfg.Proxy.MITM {
		a.scan.Engine().Log("info", "mitm", "正在启用 HTTPS 拦截")
		certificatePath, err := proxyServer.EnableMITM(cfg.Proxy.CADir)
		if err != nil {
			_ = apiListener.Close()
			a.scan.Engine().Log("error", "mitm", fmt.Sprintf("HTTPS 拦截初始化失败：%v", err))
			return a.Status(), fmt.Errorf("enable HTTPS interception: %w", err)
		}
		status.CertificatePath = certificatePath
		a.scan.Engine().Log("info", "mitm", "HTTPS 拦截已启用")
	}
	a.scan.Engine().Log("info", "proxy", fmt.Sprintf("正在监听被动代理：%s", cfg.Proxy.Listen))
	proxyListener, err := net.Listen("tcp", cfg.Proxy.Listen)
	if err != nil {
		_ = apiListener.Close()
		a.scan.Engine().Log("error", "proxy", fmt.Sprintf("被动代理启动失败：%v", err))
		return a.Status(), fmt.Errorf("listen passive proxy %s: %w", cfg.Proxy.Listen, err)
	}
	a.scan.Engine().Log("info", "proxy", fmt.Sprintf("被动代理已监听：%s", cfg.Proxy.Listen))
	serviceCtx, cancel := context.WithCancel(context.Background())
	api := &http.Server{Addr: cfg.API.Listen, Handler: a.scan.HTTPHandler()}
	a.mu.Lock()
	a.cancel, a.api = cancel, api
	a.mu.Unlock()
	go a.serveAPI(serviceCtx, api, apiListener)
	go a.serveProxy(serviceCtx, proxyServer, proxyListener)
	return status, nil
}

func (a *App) StopServices() Status {
	a.mu.Lock()
	cancel, api, wasStarted, mitmEnabled := a.cancel, a.api, a.status.Started, a.status.MITMEnabled
	a.cancel, a.api, a.status.Started = nil, nil, false
	a.mu.Unlock()
	a.scan.CancelSQLiProbes()
	a.scan.CancelXSSProbes()
	a.scan.CancelFileProbes()
	a.scan.CancelWAFProbes()
	if wasStarted || cancel != nil || api != nil {
		a.scan.Engine().Log("info", "runtime", "正在停止本地服务")
	}
	if cancel != nil {
		cancel()
	}
	if api != nil {
		_ = api.Shutdown(context.Background())
	}
	if wasStarted || cancel != nil || api != nil {
		a.logServicesStopped(mitmEnabled)
	}
	a.emit("easyscan:services-stopped", a.Status())
	return a.Status()
}

func (a *App) serveAPI(ctx context.Context, server *http.Server, listener net.Listener) {
	go func() { <-ctx.Done(); _ = server.Shutdown(context.Background()) }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.serviceFailed("api", fmt.Errorf("traffic API stopped: %w", err))
	}
}

func (a *App) serveProxy(ctx context.Context, server *proxy.Server, listener net.Listener) {
	if err := server.Serve(ctx, listener); err != nil {
		a.serviceFailed("proxy", fmt.Errorf("passive proxy stopped: %w", err))
	}
}

func (a *App) serviceFailed(component string, err error) {
	a.mu.Lock()
	if !a.status.Started {
		a.mu.Unlock()
		return
	}
	cancel, api, mitmEnabled := a.cancel, a.api, a.status.MITMEnabled
	a.cancel, a.api, a.status.Started = nil, nil, false
	a.status.LastError = err.Error()
	a.mu.Unlock()
	a.scan.CancelSQLiProbes()
	a.scan.CancelXSSProbes()
	a.scan.CancelFileProbes()
	a.scan.CancelWAFProbes()
	if cancel != nil {
		cancel()
	}
	if api != nil {
		_ = api.Close()
	}
	a.scan.Engine().Log("error", component, fmt.Sprintf("服务异常停止：%v", err))
	a.logServicesStopped(mitmEnabled)
	a.emit("easyscan:service-error", err.Error())
}

func (a *App) logServicesStopped(mitmEnabled bool) {
	a.scan.Engine().Log("info", "proxy", "被动代理已停止")
	a.scan.Engine().Log("info", "api", "流量 API 已停止")
	if mitmEnabled {
		a.scan.Engine().Log("info", "mitm", "HTTPS 拦截已停用")
	}
	a.scan.Engine().Log("info", "runtime", "本地服务已停止")
}

func (a *App) emit(name string, value any) {
	a.mu.RLock()
	ctx := a.ctx
	a.mu.RUnlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, name, value)
	}
}

func (a *App) SubmitTask(request TaskRequest) (model.ActiveTask, error) {
	task, err := a.scan.Runner().Submit(active.Request{Kind: request.Kind, Target: request.Target, SessionHeaders: request.SessionHeaders})
	if err == nil {
		a.emit("easyscan:task-created", task)
	}
	return task, err
}

func (a *App) CancelTask(id string) error {
	err := a.scan.Runner().Cancel(id)
	if err == nil {
		a.emit("easyscan:task-cancelled", id)
	}
	return err
}

func (a *App) TaskResults(id string) ([]model.TaskResult, error) {
	return a.scan.Runner().ListTaskResults(id, 500)
}

func (a *App) SetFeature(id string, enabled bool) ([]features.Definition, error) {
	if err := a.scan.Policy().Set(id, enabled); err != nil {
		return nil, err
	}
	if id == "passive.sqli_probe" && !enabled {
		a.scan.CancelSQLiProbes()
	}
	if id == "passive.xss_probe" && !enabled {
		a.scan.CancelXSSProbes()
	}
	if id == "passive.file_probe" && !enabled {
		a.scan.CancelFileProbes()
	}
	if id == "passive.waf_probe" && !enabled {
		a.scan.CancelWAFProbes()
	}
	if id == "passive.fastjson_probe" && !enabled {
		a.scan.CancelFastjsonProbes()
	}
	if id == "passive.fingerprint_probe" && !enabled {
		a.scan.CancelFingerprintProbes()
	}
	if id == "passive.shiro_probe" && !enabled {
		a.scan.CancelShiroProbes()
	}
	if id == "passive.cmd_probe" && !enabled {
		a.scan.CancelCmdProbes()
	}
	if id == "passive.ssrf_probe" && !enabled {
		a.scan.CancelSSRFProbes()
	}
	if id == "passive.xxe_probe" && !enabled {
		a.scan.CancelXXEProbes()
	}
	if id == "passive.upload_probe" && !enabled {
		a.scan.CancelUploadProbes()
	}
	if id == "passive.poc_scan" && !enabled {
		a.scan.CancelPOCProbes()
	}
	if id == aiprobe.FeatureAnalysis && !enabled {
		a.scan.CancelAIAnalysis()
	}
	items := a.scan.Policy().List()
	a.emit("easyscan:features-changed", items)
	return items, nil
}

func (a *App) SetSQLiTechniques(errorEnabled, booleanEnabled, timeEnabled bool) ([]features.Definition, error) {
	if err := a.scan.Policy().SetSQLiTechniques(errorEnabled, booleanEnabled, timeEnabled); err != nil {
		return nil, err
	}
	a.scan.CancelSQLiProbes()
	items := a.scan.Policy().List()
	a.emit("easyscan:features-changed", items)
	return items, nil
}

func (a *App) SetPassiveSQLiProbeQPS(qps int) error {
	if err := a.scan.Policy().SetPassiveSQLiProbeQPS(qps); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

func (a *App) SetPassiveSQLiMaxRequests(requests int) error {
	if err := a.scan.Policy().SetPassiveSQLiMaxRequests(requests); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

func (a *App) SetPassiveSQLiMaxParameters(parameters int) error {
	if err := a.scan.Policy().SetPassiveSQLiMaxParameters(parameters); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassiveXSSProbeQPS updates the global request rate for the optional MITM
// reflected-XSS worker. The worker reads the live policy before scheduling
// the next probe request.
func (a *App) SetPassiveXSSProbeQPS(qps int) error {
	if err := a.scan.Policy().SetPassiveXSSProbeQPS(qps); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassiveXSSMaxRequests updates the per-request probe budget for the MITM
// reflected-XSS worker.
func (a *App) SetPassiveXSSMaxRequests(requests int) error {
	if err := a.scan.Policy().SetPassiveXSSMaxRequests(requests); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassiveXSSMaxParameters updates the per-request parameter limit for the
// MITM reflected-XSS worker.
func (a *App) SetPassiveXSSMaxParameters(parameters int) error {
	if err := a.scan.Policy().SetPassiveXSSMaxParameters(parameters); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassivePOCQPS updates the global rate used by the optional MITM POC
// worker. The worker reads the live policy before scheduling the next request.
func (a *App) SetPassivePOCQPS(qps int) error {
	if err := a.scan.Policy().SetPassivePOCQPS(qps); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassivePOCConcurrency updates the maximum number of concurrent MITM POC
// requests. Queued work observes the new limit without restarting the app.
func (a *App) SetPassivePOCConcurrency(concurrency int) error {
	if err := a.scan.Policy().SetPassivePOCConcurrency(concurrency); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassiveFileProbeQPS updates the request rate for MITM sensitive-file
// probing. In-flight probes observe the new value on their next scheduled
// request without restarting the app.
func (a *App) SetPassiveFileProbeQPS(qps int) error {
	if err := a.scan.Policy().SetPassiveFileProbeQPS(qps); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassiveFileProbeMaxPrefixes bounds how many captured path prefixes are
// probed per origin. A value of 0 disables the per-origin cap.
func (a *App) SetPassiveFileProbeMaxPrefixes(max int) error {
	if err := a.scan.Policy().SetPassiveFileProbeMaxPrefixes(max); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassiveFastjsonProbeQPS updates the request rate for MITM Fastjson probing.
func (a *App) SetPassiveFastjsonProbeQPS(qps int) error {
	if err := a.scan.Policy().SetPassiveFastjsonProbeQPS(qps); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetPassiveShiroProbeQPS updates the request rate for MITM Shiro probing.
func (a *App) SetPassiveShiroProbeQPS(qps int) error {
	if err := a.scan.Policy().SetPassiveShiroProbeQPS(qps); err != nil {
		return err
	}
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// SetShiroKeys replaces the user-supplied Shiro key dictionary used alongside
// the built-in list for rememberMe decryption checks.
func (a *App) SetShiroKeys(keys []string) error {
	if err := a.scan.Policy().SetShiroKeys(keys); err != nil {
		return err
	}
	a.scan.CancelShiroProbes()
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// GetOOBDomain returns the reserved out-of-band callback domain used by the
// SSRF and XXE probes for blind confirmation.
func (a *App) GetOOBDomain() string {
	return a.scan.Policy().OOBDomain()
}

// SetOOBDomain stores the reserved out-of-band callback domain used by the SSRF
// and XXE probes, and restarts those probe batches so it applies immediately.
func (a *App) SetOOBDomain(domain string) error {
	if err := a.scan.Policy().SetOOBDomain(domain); err != nil {
		return err
	}
	a.scan.CancelSSRFProbes()
	a.scan.CancelXXEProbes()
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// GetAISettings returns the AI endpoint configuration and analysis switches
// for the AI settings page.
func (a *App) GetAISettings() map[string]any {
	policy := a.scan.Policy()
	baseURL := policy.AIBaseURL()
	modelName := policy.AIModel()
	apiKey := policy.AIAPIKey()
	return map[string]any{
		"baseUrl":         baseURL,
		"model":           modelName,
		"apiKey":          apiKey,
		"configured":      aiclient.Configured(baseURL, modelName, apiKey),
		"analysisEnabled": policy.Enabled(aiprobe.FeatureAnalysis),
		"routesEnabled":   policy.Enabled(aiprobe.FeatureRoutes),
		"secretsEnabled":  policy.Enabled(aiprobe.FeatureSecrets),
	}
}

// SaveAISettings stores the AI endpoint configuration (base URL, model and
// API key) and restarts JS collection so the new settings apply immediately.
func (a *App) SaveAISettings(baseURL, modelName, apiKey string) error {
	if err := a.scan.Policy().SetAIConfig(baseURL, modelName, apiKey); err != nil {
		return err
	}
	a.scan.CancelAIAnalysis()
	a.emit("easyscan:features-changed", a.scan.Policy().List())
	return nil
}

// ReloadHFingerRules refreshes the embedded+custom rule set without restarting
// MITM services. Invalid custom files are isolated and listed in the returned
// status while valid files remain active.
func (a *App) ReloadHFingerRules() (fingerprint.HFingerStats, error) {
	if err := a.scan.Engine().ReloadHFingerRules(); err != nil {
		return a.scan.Engine().HFingerStats(), err
	}
	stats := a.scan.Engine().HFingerStats()
	a.emit("easyscan:hfinger-rules-changed", stats)
	return stats, nil
}

// ImportHFingerRule opens a native YAML picker, validates the selected HFinger
// file, copies it into the configured custom directory, and hot-reloads it.
func (a *App) ImportHFingerRule() (fingerprint.HFingerStats, error) {
	a.mu.RLock()
	ctx := a.ctx
	a.mu.RUnlock()
	if ctx == nil {
		return a.scan.Engine().HFingerStats(), errors.New("桌面运行时尚未启动")
	}
	stats := a.scan.Engine().HFingerStats()
	selected, err := runtime.OpenFileDialog(ctx, runtime.OpenDialogOptions{
		Title:            "添加 YAML 指纹",
		DefaultDirectory: stats.CustomDir,
		Filters: []runtime.FileFilter{{
			DisplayName: "指纹 YAML (*.yaml;*.yml)",
			Pattern:     "*.yaml;*.yml",
		}},
	})
	if err != nil {
		return stats, err
	}
	if strings.TrimSpace(selected) == "" {
		return stats, nil
	}
	info, err := os.Stat(selected)
	if err != nil {
		return stats, err
	}
	if info.IsDir() || info.Size() > 8<<20 {
		return stats, errors.New("指纹 YAML 必须是大小不超过 8 MiB 的文件")
	}
	ruleCount, err := a.scan.Engine().ValidateHFingerRuleFile(selected)
	if err != nil {
		return stats, fmt.Errorf("指纹 YAML 校验失败: %w", err)
	}
	if strings.TrimSpace(stats.CustomDir) == "" {
		return stats, errors.New("自定义指纹目录尚未配置")
	}
	if err := os.MkdirAll(stats.CustomDir, 0o700); err != nil {
		return stats, err
	}
	destination := filepath.Join(stats.CustomDir, filepath.Base(selected))
	selectedAbs, _ := filepath.Abs(selected)
	destinationAbs, _ := filepath.Abs(destination)
	if !strings.EqualFold(selectedAbs, destinationAbs) {
		data, readErr := os.ReadFile(selected)
		if readErr != nil {
			return stats, readErr
		}
		if writeErr := os.WriteFile(destination, data, 0o600); writeErr != nil {
			return stats, writeErr
		}
	}
	if err := a.scan.Engine().ReloadHFingerRules(); err != nil {
		return a.scan.Engine().HFingerStats(), err
	}
	stats = a.scan.Engine().HFingerStats()
	a.scan.Engine().Log("info", "fingerprint", fmt.Sprintf("已导入指纹 YAML：%s（%d 条规则）", filepath.Base(destination), ruleCount))
	a.emit("easyscan:hfinger-rules-changed", stats)
	return stats, nil
}

// SetExcludedDomains updates the locally persisted list of domains that are
// forwarded by the proxy but excluded from new analysis and active probes.
// The returned list is normalized by the feature policy for immediate UI use.
func (a *App) SetExcludedDomains(domains []string) ([]string, error) {
	if err := a.scan.Policy().SetExcludedDomains(domains); err != nil {
		return nil, fmt.Errorf("保存排除域名失败：%w", err)
	}
	updated := a.scan.Policy().ExcludedDomains()
	a.emit("easyscan:excluded-domains-changed", updated)
	return updated, nil
}

// SetExcludedSuffixes updates the locally persisted list of URL path suffixes
// that are forwarded by the proxy but excluded from capture and all analysis.
// The returned list is normalized by the feature policy for immediate UI use.
func (a *App) SetExcludedSuffixes(suffixes []string) ([]string, error) {
	if err := a.scan.Policy().SetExcludedSuffixes(suffixes); err != nil {
		return nil, fmt.Errorf("保存排除后缀失败：%w", err)
	}
	updated := a.scan.Policy().ExcludedSuffixes()
	a.emit("easyscan:excluded-suffixes-changed", updated)
	return updated, nil
}

// SetExcludedContentTypes updates locally persisted response Content-Type
// filters. Matching traffic remains transparently proxied but is not logged,
// fingerprinted, or analyzed.
func (a *App) SetExcludedContentTypes(contentTypes []string) ([]string, error) {
	if err := a.scan.Policy().SetExcludedContentTypes(contentTypes); err != nil {
		return nil, fmt.Errorf("保存过滤 Content-Type 失败: %w", err)
	}
	updated := a.scan.Policy().ExcludedContentTypes()
	a.emit("easyscan:excluded-content-types-changed", updated)
	return updated, nil
}

// SetExcludedPaths persists URL path globs that suppress the complete passive
// transaction while leaving proxy forwarding unchanged.
func (a *App) SetExcludedPaths(paths []string) ([]string, error) {
	if err := a.scan.Policy().SetExcludedPaths(paths); err != nil {
		return nil, fmt.Errorf("保存排除路径失败: %w", err)
	}
	updated := a.scan.Policy().ExcludedPaths()
	a.emit("easyscan:excluded-paths-changed", updated)
	return updated, nil
}

// SetSwaggerExcludedPaths persists path prefixes that the swagger
// documentation probe must skip. Captured prefixes whose directory starts
// with one of these patterns (segment boundary) are not probed. Pending
// probes are cancelled so the new exclusion applies immediately.
func (a *App) SetSwaggerExcludedPaths(paths []string) ([]string, error) {
	if err := a.scan.Policy().SetSwaggerExcludedPaths(paths); err != nil {
		return nil, fmt.Errorf("保存 Swagger 探测排除路径失败: %w", err)
	}
	a.scan.CancelFileProbes()
	updated := a.scan.Policy().SwaggerExcludedPaths()
	a.emit("easyscan:swagger-excluded-paths-changed", updated)
	return updated, nil
}

// SetCustomProbePaths persists the user-supplied sensitive-file probe paths.
// Pending file probes are cancelled so the new list applies immediately.
func (a *App) SetCustomProbePaths(paths []string) ([]string, error) {
	if err := a.scan.Policy().SetCustomProbePaths(paths); err != nil {
		return nil, fmt.Errorf("保存自定义探测路径失败: %w", err)
	}
	a.scan.CancelFileProbes()
	updated := a.scan.Policy().CustomProbePaths()
	a.emit("easyscan:custom-probe-paths-changed", updated)
	return updated, nil
}

// NucleiStatus reports whether a usable nuclei binary is available, the active
// path, and its version. It is used by the settings screen to show install
// state without blocking.
type NucleiStatus struct {
	Installed     bool   `json:"installed"`
	ConfiguredPath string `json:"configured_path"`
	Version       string `json:"version,omitempty"`
	Message       string `json:"message,omitempty"`
}

// GetNucleiStatus returns the current nuclei availability for the settings UI.
func (a *App) GetNucleiStatus() NucleiStatus {
	status := NucleiStatus{ConfiguredPath: a.scan.Policy().NucleiBinaryPath()}
	manager := a.scan.NucleiManager()
	if manager == nil {
		status.Message = "nuclei 管理器不可用"
		return status
	}
	status.Installed = manager.Installed()
	if !status.Installed {
		status.Message = "未安装 nuclei，请下载或指定路径"
		return status
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if version, err := manager.Version(ctx); err == nil {
		status.Version = version
	}
	return status
}

// SetNucleiBinaryPath persists a user-specified nuclei executable path. An
// empty value clears the override. Pending POC probes are cancelled so the new
// binary applies immediately.
func (a *App) SetNucleiBinaryPath(path string) (NucleiStatus, error) {
	if err := a.scan.Policy().SetNucleiBinaryPath(path); err != nil {
		return NucleiStatus{}, fmt.Errorf("保存 nuclei 路径失败: %w", err)
	}
	a.scan.CancelPOCProbes()
	status := a.GetNucleiStatus()
	a.emit("easyscan:nuclei-status-changed", status)
	return status, nil
}

// DownloadNuclei fetches and installs the latest nuclei release from GitHub.
// It returns the refreshed status so the UI can confirm success.
func (a *App) DownloadNuclei() (NucleiStatus, error) {
	manager := a.scan.NucleiManager()
	if manager == nil {
		return NucleiStatus{}, errors.New("nuclei 管理器不可用")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := manager.DownloadLatest(ctx); err != nil {
		return NucleiStatus{}, err
	}
	a.scan.CancelPOCProbes()
	status := a.GetNucleiStatus()
	a.emit("easyscan:nuclei-status-changed", status)
	return status, nil
}

// SetExcludedQueryParameters persists query-string parameter names. Matching
// requests remain transparent but skip all passive and scheduled analysis.
func (a *App) SetExcludedQueryParameters(parameters []string) ([]string, error) {
	if err := a.scan.Policy().SetExcludedQueryParameters(parameters); err != nil {
		return nil, fmt.Errorf("保存排除 Query 参数失败: %w", err)
	}
	updated := a.scan.Policy().ExcludedQueryParameters()
	a.emit("easyscan:excluded-query-parameters-changed", updated)
	return updated, nil
}

// SetExcludedPostParameters persists form and JSON parameter names that
// suppress the whole passively observed transaction.
func (a *App) SetExcludedPostParameters(parameters []string) ([]string, error) {
	if err := a.scan.Policy().SetExcludedPostParameters(parameters); err != nil {
		return nil, fmt.Errorf("保存排除 POST/JSON 参数失败: %w", err)
	}
	updated := a.scan.Policy().ExcludedPostParameters()
	a.emit("easyscan:excluded-post-parameters-changed", updated)
	return updated, nil
}

// WaitUntilStopped is useful to callers that need to give a just-cancelled
// service a brief chance to release its listener before retrying a start.
func (a *App) WaitUntilStopped() { time.Sleep(100 * time.Millisecond) }
