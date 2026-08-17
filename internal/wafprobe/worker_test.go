package wafprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

type testPolicy struct{ on bool }

func (p testPolicy) Enabled(string) bool { return p.on }

func newTestEngine(t *testing.T) (*engine.Engine, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.AllowPrivateIPs = true
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, cfg
}

func waitForFindings(t *testing.T, e *engine.Engine, wait time.Duration) []model.Finding {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		findings := e.Findings()
		if len(findings) > 0 {
			return findings
		}
		time.Sleep(50 * time.Millisecond)
	}
	return e.Findings()
}

// canaryValueSeen 用于让服务器识别 canary 请求（不管 encode 形式如何）。
func canaryValueSeen(raw string) bool {
	if raw == "" {
		return false
	}
	// url.Values 会将空格保留、单引号保留、<>转义。
	return strings.Contains(raw, "'") || strings.Contains(raw, "<script>")
}

func TestClassifyDetectsWAFBodyKeywords(t *testing.T) {
	baseline := probeResult{status: 200, body: "<html><body>Home page</body></html>"}
	attempt := probeResult{status: 200, body: "<html>Web Application Firewall blocked your request</html>"}
	verdict, vendor, evidence := classify(baseline, attempt)
	if verdict == "" || evidence == "" {
		t.Fatalf("expected WAF detection, got verdict=%q evidence=%q vendor=%q", verdict, evidence, vendor)
	}
}

func TestClassifyIgnoresKeywordsWhenBaselineAlsoContainsThem(t *testing.T) {
	baseline := probeResult{status: 200, body: "This blog post explains web application firewall rules"}
	attempt := probeResult{status: 200, body: "This blog post explains web application firewall rules"}
	if v, _, _ := classify(baseline, attempt); v != "" {
		t.Fatalf("baseline noise must not trigger detection: %v", v)
	}
}

func TestClassifyDetectsBlockingStatusCode(t *testing.T) {
	baseline := probeResult{status: 200}
	attempt := probeResult{status: 403, body: "Forbidden"}
	verdict, _, _ := classify(baseline, attempt)
	if verdict == "" {
		t.Fatalf("403 with 200 baseline must trigger detection")
	}
}

func TestClassifyIgnoresSameBlockingStatusOnBaseline(t *testing.T) {
	baseline := probeResult{status: 403}
	attempt := probeResult{status: 403, body: "Forbidden"}
	if v, _, _ := classify(baseline, attempt); v != "" {
		t.Fatalf("identical blocking status on both must not trigger detection")
	}
}

func TestClassifyDetectsDroppedConnection(t *testing.T) {
	baseline := probeResult{status: 200}
	attempt := probeResult{err: &net.OpError{Op: "read", Err: &timeoutError{}}, dropped: true}
	verdict, _, evidence := classify(baseline, attempt)
	if verdict == "" || evidence == "" {
		t.Fatalf("dropped canary with healthy baseline must trigger detection")
	}
}

func TestClassifyDetectsHeaderIndicator(t *testing.T) {
	attempt := probeResult{status: 200, headers: http.Header{"Cf-Ray": []string{"abc123"}}}
	baseline := probeResult{status: 200, headers: http.Header{}}
	if v, _, _ := classify(baseline, attempt); v == "" {
		t.Fatalf("cf-ray header should be a WAF indicator")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestObserveTriggersActiveProbeAndReportsFinding(t *testing.T) {
	blocked := "<html><body>访问被防火墙已拦截，请求非法请求已被阻断</body></html>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if canaryValueSeen(id) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blocked))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Welcome</body></html>`))
	}))
	defer server.Close()

	e, cfg := newTestEngine(t)
	worker := New(cfg, e, testPolicy{on: true})
	defer func() { _ = worker.Shutdown(context.Background()) }()

	worker.Observe(model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: server.URL + "/"},
		Response: model.Message{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "ok"},
	})

	findings := waitForFindings(t, e, 5*time.Second)
	if len(findings) == 0 {
		t.Fatalf("expected an INFO finding for WAF probe, got %#v", findings)
	}
	f := findings[0]
	if f.Severity != "info" || !strings.Contains(f.Title, "存在 WAF") || !strings.HasPrefix(f.RuleID, "passive.waf-probe.") {
		t.Fatalf("unexpected finding shape: %#v", f)
	}
}

func TestObserveDeduplicatesSameOrigin(t *testing.T) {
	var mu struct {
		hits int
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if canaryValueSeen(r.URL.Query().Get("id")) {
			mu.hits++
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked by firewall"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	e, cfg := newTestEngine(t)
	worker := New(cfg, e, testPolicy{on: true})
	defer func() { _ = worker.Shutdown(context.Background()) }()

	tx := model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: server.URL + "/a"},
		Response: model.Message{Status: 200, Body: "ok"},
	}
	worker.Observe(tx)
	tx.Request.URL = server.URL + "/b?other=1"
	worker.Observe(tx)

	_ = waitForFindings(t, e, 3*time.Second)
	// hits 计数至少一次；第二次同 origin 观察不应再触发。命中一次即可（sqli canary 命中就 return，不发 xss）。
	if mu.hits != 1 {
		t.Fatalf("expected exactly one canary hit per origin, got %d", mu.hits)
	}
	if got := len(e.Findings()); got != 1 {
		t.Fatalf("expected exactly one finding per origin, got %d", got)
	}
}

func TestObserveSkippedWhenFeatureDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked by firewall"))
	}))
	defer server.Close()

	e, cfg := newTestEngine(t)
	worker := New(cfg, e, testPolicy{on: false})
	defer func() { _ = worker.Shutdown(context.Background()) }()

	worker.Observe(model.Transaction{
		Observed: time.Now().UTC(),
		Source:   model.SourceHTTPProxy,
		Request:  model.Message{Method: http.MethodGet, URL: server.URL + "/"},
		Response: model.Message{Status: 200},
	})

	time.Sleep(400 * time.Millisecond)
	if got := e.Findings(); len(got) != 0 {
		t.Fatalf("disabled feature must not emit findings: %#v", got)
	}
}

func TestOriginKeyNormalizesSchemeAndPort(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://example.com/", "http://example.com:80"},
		{"https://example.com/", "https://example.com:443"},
		{"https://example.com:8443/x", "https://example.com:8443"},
	}
	for _, c := range cases {
		u, err := url.Parse(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if got := originKey(u); got != c.want {
			t.Fatalf("originKey(%q) = %q want %q", c.in, got, c.want)
		}
	}
}
