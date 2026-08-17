package runtime

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/model"
	"github.com/example/easyscan/internal/store"
)

func TestClearAnalysisSnapshotClearsMemoryAndSQLite(t *testing.T) {
	cfg := runtimeTestConfig(t, false)
	run, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	analyzeRuntimeFixture(run)
	if len(run.Engine().Findings()) == 0 || len(run.Engine().Assets()) == 0 {
		t.Fatalf("expected fixture analysis to create a snapshot: %#v %#v", run.Engine().Findings(), run.Engine().Assets())
	}
	if err := run.ClearAnalysisSnapshot(); err != nil {
		t.Fatal(err)
	}
	if findings, assets := run.Engine().Findings(), run.Engine().Assets(); len(findings) != 0 || len(assets) != 0 {
		t.Fatalf("expected in-memory snapshot to be clear, got %#v %#v", findings, assets)
	}
	if err := run.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close(context.Background())
	if findings, assets := reopened.Engine().Findings(), reopened.Engine().Assets(); len(findings) != 0 || len(assets) != 0 {
		t.Fatalf("expected persisted snapshot to be clear, got %#v %#v", findings, assets)
	}
}

func TestCloseFlushesAutomaticHTMLReportForEmptyAndChangedSnapshots(t *testing.T) {
	cfg := runtimeTestConfig(t, true)
	run, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Open deliberately does not schedule a restored snapshot: the desktop
	// lifecycle first decides whether it should be cleared or retained.
	run.ScheduleReport()
	if err := run.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(cfg.Reports.HTMLPath)
	if err != nil {
		t.Fatal(err)
	}
	if text := string(contents); !strings.Contains(text, "暂无漏洞结果") || !strings.Contains(text, "暂无指纹识别结果") {
		t.Fatalf("empty final report is incomplete: %s", text)
	}

	// A later session's in-flight debounce must be committed by Close rather
	// than lost when the desktop exits immediately after new traffic arrives.
	run, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	analyzeRuntimeFixture(run)
	if err := run.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	contents, err = os.ReadFile(cfg.Reports.HTMLPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, want := range []string{"漏洞结果", "指纹识别", "app.example.test", "passive.api-documentation"} {
		if !strings.Contains(text, want) {
			t.Fatalf("final automatic report does not contain %q:\n%s", want, text)
		}
	}
}

func TestRuntimeAppliesLiveExcludedDomainsToEngineScope(t *testing.T) {
	cfg := runtimeTestConfig(t, false)
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	if err := os.WriteFile(cfg.Features.Path, []byte("excluded_domains:\n  - BLOCKED.EXAMPLE.TEST.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close(context.Background())

	if run.Engine().AllowsPassiveHost("blocked.example.test") || run.Engine().AllowsActiveHost("blocked.example.test") {
		t.Fatal("runtime must attach feature-policy exclusions to engine scope")
	}
	if err := run.Policy().SetExcludedDomains(nil); err != nil {
		t.Fatal(err)
	}
	if !run.Engine().AllowsPassiveHost("blocked.example.test") || !run.Engine().AllowsActiveHost("blocked.example.test") {
		t.Fatal("editing exclusions must update the live engine scope without restart")
	}
}

func TestRuntimeAppliesLiveExcludedSuffixesToEngine(t *testing.T) {
	cfg := runtimeTestConfig(t, false)
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	if err := os.WriteFile(cfg.Features.Path, []byte("excluded_suffixes:\n  - PNG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close(context.Background())

	filteredURL := "https://app.example.test/assets/LOGO.PNG?cache=1"
	if run.Engine().AllowsPassiveURL(filteredURL) {
		t.Fatal("persisted suffix exclusions must be attached to the live engine")
	}
	logCount := len(run.Engine().Logs(0))
	run.Engine().Analyze(model.Transaction{
		Source:   model.SourceHTTPSMITM,
		Request:  model.Message{Method: http.MethodGet, URL: filteredURL},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Server": "nginx"}},
	})
	if assets, traffic := run.Engine().Assets(), run.Engine().Traffic(10); len(assets) != 0 || len(traffic) != 0 {
		t.Fatalf("persisted suffix exclusion must suppress analysis: assets=%#v traffic=%#v", assets, traffic)
	}
	if len(run.Engine().Logs(0)) != logCount {
		t.Fatalf("persisted suffix exclusion must suppress analysis logs: %#v", run.Engine().Logs(0))
	}

	if err := run.Policy().SetExcludedSuffixes([]string{" css, .Js "}); err != nil {
		t.Fatal(err)
	}
	if !run.Engine().AllowsPassiveURL(filteredURL) {
		t.Fatal("saved suffix updates must apply to the next exchange without restart")
	}
	run.Engine().Analyze(model.Transaction{
		Source:   model.SourceHTTPSMITM,
		Request:  model.Message{Method: http.MethodGet, URL: filteredURL},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Server": "nginx"}},
	})
	if len(run.Engine().Assets()) != 1 || len(run.Engine().Traffic(10)) != 1 {
		t.Fatalf("removed suffix must be analyzed immediately: assets=%#v traffic=%#v", run.Engine().Assets(), run.Engine().Traffic(10))
	}
	if run.Engine().AllowsPassiveURL("https://app.example.test/assets/site.CSS?cache=1") {
		t.Fatal("newly saved suffix must apply immediately")
	}
	data, err := os.ReadFile(cfg.Features.Path)
	if err != nil {
		t.Fatal(err)
	}
	if text := string(data); !strings.Contains(text, "excluded_suffixes:") || !strings.Contains(text, ".css") || !strings.Contains(text, ".js") {
		t.Fatalf("updated suffix exclusions were not persisted: %s", text)
	}
}

func TestRuntimeAppliesLiveExcludedContentTypesToEngine(t *testing.T) {
	cfg := runtimeTestConfig(t, false)
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	if err := os.WriteFile(cfg.Features.Path, []byte("excluded_content_types:\n  - image/*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close(context.Background())

	if run.Engine().AllowsPassiveContentType("image/png; charset=binary") {
		t.Fatal("persisted Content-Type exclusions must be attached to the live engine")
	}
	logCount := len(run.Engine().Logs(0))
	run.Engine().Analyze(model.Transaction{
		Source:   model.SourceHTTPSMITM,
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/assets/logo"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "image/png", "Server": "nginx"}},
	})
	if assets, traffic := run.Engine().Assets(), run.Engine().Traffic(10); len(assets) != 0 || len(traffic) != 0 {
		t.Fatalf("Content-Type exclusion must suppress analysis: assets=%#v traffic=%#v", assets, traffic)
	}
	if len(run.Engine().Logs(0)) != logCount {
		t.Fatalf("Content-Type exclusion must suppress analysis logs: %#v", run.Engine().Logs(0))
	}

	if err := run.Policy().SetExcludedContentTypes(nil); err != nil {
		t.Fatal(err)
	}
	if !run.Engine().AllowsPassiveContentType("image/png") {
		t.Fatal("clearing Content-Type filters must update the live engine without restart")
	}
	run.Engine().Analyze(model.Transaction{
		Source:   model.SourceHTTPSMITM,
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/assets/logo"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "image/png", "Server": "nginx"}},
	})
	if len(run.Engine().Assets()) != 1 || len(run.Engine().Traffic(10)) != 1 {
		t.Fatalf("cleared Content-Type exclusion must allow immediate analysis: assets=%#v traffic=%#v", run.Engine().Assets(), run.Engine().Traffic(10))
	}
}

func TestOpenRemovesRetiredServerBannerAndKeepsSensitiveExposure(t *testing.T) {
	cfg := runtimeTestConfig(t, false)
	database, err := store.Open(cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	err = database.SaveSnapshot([]model.Finding{
		{ID: "retired-server-banner", RuleID: "passive.banner.server", Title: "Detailed server version exposed", URL: "https://app.example.test/"},
		{ID: "keep-finding", RuleID: "passive.exposure.private-key", Title: "Private key material exposed", URL: "https://app.example.test/key"},
	}, nil)
	if closeErr := database.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	run, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close(context.Background())
	findings := run.Engine().Findings()
	if len(findings) != 1 || findings[0].RuleID != "passive.exposure.private-key" {
		t.Fatalf("retired banner must be removed while active sensitive-exposure findings remain: %#v", findings)
	}
}

func containsRuntimeString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func runtimeTestConfig(t *testing.T, autoHTML bool) config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(dir, "state", "easyscan.db")
	cfg.Features.Path = filepath.Join(dir, "features.yaml")
	cfg.Reports.AutoHTML = autoHTML
	cfg.Reports.HTMLPath = filepath.Join(dir, "easyscan-scan-report.html")
	cfg.Scope.DenyHosts = nil
	return cfg
}

func analyzeRuntimeFixture(run *Runtime) {
	run.Engine().Analyze(model.Transaction{
		Request:  model.Message{Method: "GET", URL: "https://app.example.test/swagger"},
		Response: model.Message{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<title>Index of /</title>"},
	})
	run.Engine().Analyze(model.Transaction{
		Request:  model.Message{Method: "GET", URL: "https://app.example.test/v1/swagger.json"},
		Response: model.Message{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"swagger":"2.0","info":{"title":"Example API"}}`},
	})
}
