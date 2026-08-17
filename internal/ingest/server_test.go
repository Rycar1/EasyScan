package ingest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/features"
	"github.com/example/easyscan/internal/model"
)

func TestTrafficEndpointAnalyzesTransaction(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/traffic", bytes.NewBufferString(`{
        "request":{"method":"GET","url":"https://app.example.test/","headers":{}},
		"response":{"status":200,"headers":{},"body":"<title>Index of /</title>"}
    }`))
	recorder := httptest.NewRecorder()
	New(e, "", 1024).Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected accepted, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(e.Findings()) != 1 {
		t.Fatalf("expected one finding, got %d", len(e.Findings()))
	}
}

func TestTrafficEndpointReservesInternalMITMSource(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/traffic", bytes.NewBufferString(`{
        "source":"https-mitm",
        "request":{"method":"GET","url":"https://app.example.test/","headers":{}},
        "response":{"status":200,"headers":{}}
    }`))
	recorder := httptest.NewRecorder()
	New(e, "", 1024).Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected accepted, got %d: %s", recorder.Code, recorder.Body.String())
	}
	traffic := e.Traffic(1)
	if len(traffic) != 1 || traffic[0].Source != model.SourceAPIIngest {
		t.Fatalf("API payload must not retain reserved source: %#v", traffic)
	}
}

func TestTrustedIngestSourceReservesBothProxyLabels(t *testing.T) {
	for _, source := range []string{model.SourceHTTPProxy, model.SourceHTTPSMITM, "HTTP-PROXY", "HTTPS-MITM"} {
		if got := trustedIngestSource(source); got != model.SourceAPIIngest {
			t.Fatalf("reserved source %q became %q", source, got)
		}
	}
	if got := trustedIngestSource("burp-import"); got != "burp-import" {
		t.Fatalf("descriptive adapter source was changed to %q", got)
	}
}

func TestFeaturePolicyEndpointUpdatesOnlyEditableFeatures(t *testing.T) {
	cfg := config.Default()
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := features.Load(filepath.Join(t.TempDir(), "features.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	server := New(e, "", 1024)
	server.SetFeaturePolicy(policy)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/features", bytes.NewBufferString(`{"id":"passive.sqli_probe","enabled":false}`))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || policy.Enabled("passive.sqli_probe") {
		t.Fatalf("expected editable policy update, got %d %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPut, "/api/v1/features", bytes.NewBufferString(`{"id":"locked.ssrf_oob","enabled":true}`))
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || policy.Enabled("locked.ssrf_oob") {
		t.Fatalf("locked feature must remain unavailable, got %d %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPut, "/api/v1/features", bytes.NewBufferString(`{"id":"passive.sqli_techniques","error_enabled":true,"boolean_enabled":false,"time_enabled":true}`))
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !policy.SQLiErrorEnabled() || policy.SQLiBooleanEnabled() || !policy.SQLiTimeEnabled() {
		t.Fatalf("expected SQLi technique update, got %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestRootDoesNotServeBrowserDashboard(t *testing.T) {
	cfg := config.Default()
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	New(e, "", 1024).Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("root route must remain unavailable after desktop migration, got %d", recorder.Code)
	}
}
