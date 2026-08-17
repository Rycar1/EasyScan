package aiextra

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

func TestIsLowValueFingerprint(t *testing.T) {
	for _, tc := range []struct {
		name         string
		result       fingerprintInference
		serverHeader string
		wantLowValue bool
	}{
		{
			name:         "nginx-echo-of-server-header",
			result:       fingerprintInference{Server: "nginx", Confidence: "low"},
			serverHeader: "nginx",
			wantLowValue: true,
		},
		{
			name:         "nginx-echo-with-version-suffix",
			result:       fingerprintInference{Server: "nginx"},
			serverHeader: "nginx/1.25.3",
			wantLowValue: true,
		},
		{
			name:         "server-only-no-header-still-low",
			result:       fingerprintInference{Server: "Apache"},
			serverHeader: "",
			wantLowValue: false,
		},
		{
			name:         "empty-server-is-low",
			result:       fingerprintInference{},
			serverHeader: "nginx",
			wantLowValue: true,
		},
		{
			name:         "framework-inference-is-valuable",
			result:       fingerprintInference{Framework: "Halo", Server: "nginx"},
			serverHeader: "nginx",
			wantLowValue: false,
		},
		{
			name:         "language-inference-is-valuable",
			result:       fingerprintInference{Language: "Java", Server: "nginx"},
			serverHeader: "nginx",
			wantLowValue: false,
		},
		{
			name:         "version-inference-is-valuable",
			result:       fingerprintInference{Server: "nginx", Version: "1.25.3"},
			serverHeader: "nginx",
			wantLowValue: false,
		},
		{
			name:         "server-differs-from-header-is-valuable",
			result:       fingerprintInference{Server: "OpenResty"},
			serverHeader: "nginx",
			wantLowValue: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLowValueFingerprint(tc.result, tc.serverHeader); got != tc.wantLowValue {
				t.Fatalf("isLowValueFingerprint(%#v, %q) = %v, want %v", tc.result, tc.serverHeader, got, tc.wantLowValue)
			}
		})
	}
}

func TestServerToken(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{in: "nginx", want: "nginx"},
		{in: "Nginx", want: "nginx"},
		{in: "nginx/1.25.3", want: "nginx"},
		{in: "Apache/2.4.57 (Unix)", want: "apache"},
		{in: "  nginx  ", want: "nginx"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := serverToken(tc.in); got != tc.want {
				t.Fatalf("serverToken(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCookieNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "single-set-cookie-with-attributes",
			in:   "laravel_session=abc123def; path=/; HttpOnly; SameSite=Lax",
			want: []string{"laravel_session"},
		},
		{
			name: "multiple-set-cookie-lines",
			in:   "JSESSIONID=xyz; Path=/\ncsrftoken=tok; Secure",
			want: []string{"JSESSIONID", "csrftoken"},
		},
		{
			name: "dedupes-repeated-names",
			in:   "PHPSESSID=a; path=/\nPHPSESSID=b; path=/",
			want: []string{"PHPSESSID"},
		},
		{
			name: "value-with-no-name-yields-nothing",
			in:   "=only-value; path=/",
			want: nil,
		},
		{
			name: "empty-input",
			in:   "",
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cookieNames(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("cookieNames(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestBuildHeaderSummaryRedactsCookieValues(t *testing.T) {
	summary := buildHeaderSummary(map[string]string{
		"Set-Cookie":    "laravel_session=SECRETVALUE; path=/; HttpOnly",
		"Authorization": "Bearer SECRETTOKEN",
		"Server":        "nginx",
	})
	if !strings.Contains(summary, "laravel_session") {
		t.Fatalf("expected cookie name to be preserved, got:\n%s", summary)
	}
	if strings.Contains(summary, "SECRETVALUE") {
		t.Fatalf("cookie value must be redacted, got:\n%s", summary)
	}
	if strings.Contains(summary, "SECRETTOKEN") {
		t.Fatalf("authorization header must be dropped, got:\n%s", summary)
	}
	if !strings.Contains(summary, "nginx") {
		t.Fatalf("normal headers must be preserved, got:\n%s", summary)
	}
}

func TestTruncateCharsIsRuneSafe(t *testing.T) {
	in := strings.Repeat("登", 10)
	got := truncateChars(in, 3)
	if !strings.HasPrefix(got, "登登登") {
		t.Fatalf("expected rune-safe prefix, got %q", got)
	}
	if !utf8ValidString(got) {
		t.Fatalf("truncated output must remain valid UTF-8, got %q", got)
	}
	if truncateChars("abc", 10) != "abc" {
		t.Fatalf("short input must be returned unchanged")
	}
}

func utf8ValidString(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

// stubPolicy satisfies the Policy interface with fixed configuration.
type stubPolicy struct {
	baseURL string
	model   string
	apiKey  string
}

func (p *stubPolicy) Enabled(string) bool { return true }
func (p *stubPolicy) AIBaseURL() string   { return p.baseURL }
func (p *stubPolicy) AIModel() string     { return p.model }
func (p *stubPolicy) AIAPIKey() string    { return p.apiKey }

// stubChat records the prompt it receives and returns a canned reply.
type stubChat struct {
	mu     sync.Mutex
	prompt string
	reply  string
}

func (s *stubChat) Chat(_ context.Context, _, user string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompt = user
	return s.reply, nil
}

func (s *stubChat) lastPrompt() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prompt
}

func newTestWorker(t *testing.T, reply string) (*Worker, *engine.Engine, *stubChat) {
	t.Helper()
	eng, err := engine.New(config.Default())
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	policy := &stubPolicy{baseURL: "https://api.test", model: "m", apiKey: "k"}
	stub := &stubChat{reply: reply}
	w := New(eng, policy)
	w.newClient = func(_, _, _ string) chatClient { return stub }
	return w, eng, stub
}

// TestObserveFingerprintReportsValuableInference drives the full
// Observe -> observeFingerprint -> inferFingerprint chain with a stubbed AI
// client, proving the improved behaviour end to end: cookie NAMES reach the
// prompt (value redacted), and a real framework inference surfaces as a finding.
func TestObserveFingerprintReportsValuableInference(t *testing.T) {
	reply := `{"framework":"Laravel","version":"","language":"PHP","server":"nginx","evidence":["Set-Cookie 中含 laravel_session"],"confidence":"high"}`
	w, eng, stub := newTestWorker(t, reply)

	tx := model.Transaction{
		Source: model.SourceHTTPProxy,
		Request: model.Message{
			Method: "GET",
			URL:    "https://shop.example.test/",
		},
		Response: model.Message{
			Status: 200,
			Headers: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
				"Server":       "nginx",
				"Set-Cookie":   "laravel_session=TOPSECRETVALUE; path=/; HttpOnly",
			},
			Body: "<html><head><title>Shop</title></head><body>登录</body></html>",
		},
	}

	w.Observe(tx)
	if err := w.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	prompt := stub.lastPrompt()
	if !strings.Contains(prompt, "laravel_session") {
		t.Fatalf("cookie name must reach the AI prompt, got:\n%s", prompt)
	}
	if strings.Contains(prompt, "TOPSECRETVALUE") {
		t.Fatalf("cookie value must never reach the AI prompt, got:\n%s", prompt)
	}

	findings := eng.Findings()
	var found bool
	for _, f := range findings {
		if f.RuleID == "passive.ai.fingerprint" {
			found = true
			if !strings.Contains(f.Description, "Laravel") {
				t.Fatalf("finding must report the inferred framework, got: %q", f.Description)
			}
		}
	}
	if !found {
		t.Fatalf("expected a passive.ai.fingerprint finding, got %d findings", len(findings))
	}
}

// TestObserveFingerprintDropsServerEcho proves the low-value filter: when the AI
// only echoes the Server header, no finding is reported.
func TestObserveFingerprintDropsServerEcho(t *testing.T) {
	reply := `{"framework":"","version":"","language":"","server":"nginx","evidence":["Server: nginx"],"confidence":"low"}`
	w, eng, _ := newTestWorker(t, reply)

	tx := model.Transaction{
		Source: model.SourceHTTPProxy,
		Request: model.Message{Method: "GET", URL: "https://blog.example.test/"},
		Response: model.Message{
			Status:  200,
			Headers: map[string]string{"Content-Type": "text/html", "Server": "nginx"},
			Body:    "<html><head><title>Blog</title></head><body>hi</body></html>",
		},
	}

	w.Observe(tx)
	if err := w.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	for _, f := range eng.Findings() {
		if f.RuleID == "passive.ai.fingerprint" {
			t.Fatalf("server-header echo must not be reported, got: %q", f.Description)
		}
	}
}
