package desktop

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/model"
	scanruntime "github.com/example/easyscan/internal/runtime"
)

func TestStartupCleanupFollowsFeaturePolicy(t *testing.T) {
	t.Run("enabled clears persisted findings and assets", func(t *testing.T) {
		cfg := desktopTestConfig(t, "")
		scan := openDesktopRuntime(t, cfg)
		app, _ := New(scan)
		analyzeDesktopFixture(scan)
		app.clearPreviousResultsOnStartup()
		if findings, assets := scan.Engine().Findings(), scan.Engine().Assets(); len(findings) != 0 || len(assets) != 0 {
			t.Fatalf("expected startup cleanup to clear results, got %#v %#v", findings, assets)
		}
		if !hasRuntimeLog(scan, "启动时已清理") {
			t.Fatalf("expected cleanup success log, got %#v", scan.Engine().Logs(0))
		}
	})

	t.Run("disabled keeps restored results", func(t *testing.T) {
		cfg := desktopTestConfig(t, "features:\n  desktop.clear_previous_results_on_start: false\n")
		scan := openDesktopRuntime(t, cfg)
		app, _ := New(scan)
		analyzeDesktopFixture(scan)
		app.clearPreviousResultsOnStartup()
		if len(scan.Engine().Findings()) == 0 || len(scan.Engine().Assets()) == 0 {
			t.Fatalf("expected disabled startup cleanup to retain results")
		}
		if !hasRuntimeLog(scan, "启动时保留") {
			t.Fatalf("expected retention log, got %#v", scan.Engine().Logs(0))
		}
	})
}

func TestHFingerRuleStatusIsExposedAndReloaded(t *testing.T) {
	cfg := desktopTestConfig(t, "")
	cfg.Fingerprints.HFinger.CustomDir = filepath.Join(t.TempDir(), "hfinger-custom")
	scan := openDesktopRuntime(t, cfg)
	app, _ := New(scan)

	snapshot, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.HFinger.Loaded < 900 || snapshot.HFinger.CustomRules != 0 {
		t.Fatalf("unexpected initial HFinger status: %#v", snapshot.HFinger)
	}
	custom := `id: desktop-custom-rule
name: Desktop Custom Product
category: cms
match:
  strategy: any
  matchers:
    - type: header.contains
      key: X-Desktop-Product
      value: enabled
metadata:
  references: ["https://example.test/desktop-product"]
`
	if err := os.MkdirAll(cfg.Fingerprints.HFinger.CustomDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Fingerprints.HFinger.CustomDir, "desktop.yaml"), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	stats, err := app.ReloadHFingerRules()
	if err != nil {
		t.Fatal(err)
	}
	if stats.CustomFiles != 1 || stats.CustomRules != 1 || stats.FailedFiles != 0 {
		t.Fatalf("custom HFinger YAML was not reloaded: %#v", stats)
	}
}

func TestExcludedDomainsAreExposedAndPersisted(t *testing.T) {
	cfg := desktopTestConfig(t, "")
	scan := openDesktopRuntime(t, cfg)
	app, _ := New(scan)

	initial, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.ExcludedDomains) != 0 {
		t.Fatalf("expected no excluded domains by default, got %#v", initial.ExcludedDomains)
	}
	if _, err := app.SetExcludedDomains([]string{"https://invalid.example.com"}); err == nil || !strings.Contains(err.Error(), "保存排除域名失败") {
		t.Fatalf("expected a clear domain exclusion validation error, got %v", err)
	}

	updated, err := app.SetExcludedDomains([]string{" *.Example.COM. ", "stats.example.com", "*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(updated, ","), "*.example.com,stats.example.com"; got != want {
		t.Fatalf("expected normalized excluded domains %q, got %q", want, got)
	}

	snapshot, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(snapshot.ExcludedDomains, ","), "*.example.com,stats.example.com"; got != want {
		t.Fatalf("expected snapshot excluded domains %q, got %q", want, got)
	}

	data, err := os.ReadFile(cfg.Features.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"excluded_domains:", "*.example.com", "stats.example.com"} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("expected persisted domain %q, got %s", expected, data)
		}
	}
}

func TestExcludedSuffixesAreExposedAndPersisted(t *testing.T) {
	cfg := desktopTestConfig(t, "")
	scan := openDesktopRuntime(t, cfg)
	app, _ := New(scan)

	initial, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	defaultSuffixes := []string{".css", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".ico", ".bmp", ".flv", ".aac", ".ogg", ".avi", ".svg", ".gif", ".woff", ".woff2", ".doc", ".docx", ".pptx", ".ppt", ".pdf"}
	if got, want := strings.Join(initial.ExcludedSuffixes, ","), strings.Join(defaultSuffixes, ","); got != want {
		t.Fatalf("expected default excluded suffixes %q, got %q", want, got)
	}
	if _, err := app.SetExcludedSuffixes([]string{"https://invalid.example.com/file.png"}); err == nil || !strings.Contains(err.Error(), "保存排除后缀失败") {
		t.Fatalf("expected a clear suffix exclusion validation error, got %v", err)
	}

	updated, err := app.SetExcludedSuffixes([]string{" PNG, .css ", " .Tar.GZ "})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(updated, ","), ".css,.png,.tar.gz"; got != want {
		t.Fatalf("expected normalized excluded suffixes %q, got %q", want, got)
	}

	snapshot, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(snapshot.ExcludedSuffixes, ","), ".css,.png,.tar.gz"; got != want {
		t.Fatalf("expected snapshot excluded suffixes %q, got %q", want, got)
	}

	data, err := os.ReadFile(cfg.Features.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"excluded_suffixes:", ".css", ".png", ".tar.gz"} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("expected persisted suffix %q, got %s", expected, data)
		}
	}
}

func TestExcludedContentTypesAreExposedAndPersisted(t *testing.T) {
	cfg := desktopTestConfig(t, "")
	scan := openDesktopRuntime(t, cfg)
	app, _ := New(scan)

	initial, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"image/*", "audio/*", "video/*", "application/pdf", "*zip"} {
		if !containsDesktopString(initial.ExcludedContentTypes, expected) {
			t.Fatalf("expected default Content-Type filter %q, got %#v", expected, initial.ExcludedContentTypes)
		}
	}
	if _, err := app.SetExcludedContentTypes([]string{"image / *"}); err == nil || !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("expected a clear Content-Type validation error, got %v", err)
	}

	updated, err := app.SetExcludedContentTypes([]string{" IMAGE/*, application/pdf ", "*ZIP"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(updated, ","), "*zip,application/pdf,image/*"; got != want {
		t.Fatalf("expected normalized Content-Type filters %q, got %q", want, got)
	}

	snapshot, err := app.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(snapshot.ExcludedContentTypes, ","), "*zip,application/pdf,image/*"; got != want {
		t.Fatalf("expected snapshot Content-Type filters %q, got %q", want, got)
	}

	data, err := os.ReadFile(cfg.Features.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"excluded_content_types:", "*zip", "application/pdf", "image/*"} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("expected persisted Content-Type %q, got %s", expected, data)
		}
	}
}

func containsDesktopString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func desktopTestConfig(t *testing.T, features string) config.Config {
	t.Helper()
	dir := t.TempDir()
	featuresPath := filepath.Join(dir, "features.yaml")
	if features != "" {
		if err := os.WriteFile(featuresPath, []byte(features), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(dir, "state.db")
	cfg.Features.Path = featuresPath
	cfg.Reports.AutoHTML = false
	cfg.Scope.DenyHosts = nil
	return cfg
}

func openDesktopRuntime(t *testing.T, cfg config.Config) *scanruntime.Runtime {
	t.Helper()
	scan, err := scanruntime.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scan.Close(context.Background()); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})
	return scan
}

func analyzeDesktopFixture(scan *scanruntime.Runtime) {
	scan.Engine().Analyze(model.Transaction{
		Request:  model.Message{Method: "GET", URL: "https://app.example.test/swagger"},
		Response: model.Message{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<title>Index of /</title>"},
	})
}

func hasRuntimeLog(scan *scanruntime.Runtime, want string) bool {
	for _, entry := range scan.Engine().Logs(0) {
		if strings.Contains(entry.Message, want) {
			return true
		}
	}
	return false
}
