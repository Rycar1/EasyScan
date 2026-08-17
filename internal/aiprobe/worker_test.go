package aiprobe

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/example/easyscan/internal/model"
)

func TestParseStringArrayDirect(t *testing.T) {
	got, err := parseStringArray("好的，结果如下：\n```json\n[\"https://a/app.js\", \"https://a/vendor.js\"]\n```")
	if err != nil {
		t.Fatalf("parseStringArray: %v", err)
	}
	if len(got) != 2 || got[0] != "https://a/app.js" {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestParseStringArrayWrappedObject(t *testing.T) {
	got, err := parseStringArray(`{"files": ["https://a/app.js"]}`)
	if err != nil {
		t.Fatalf("parseStringArray: %v", err)
	}
	if len(got) != 1 || got[0] != "https://a/app.js" {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestParseJSONArray(t *testing.T) {
	var routes []routeEntry
	raw := "分析结果：\n[{\"method\": \"get\", \"path\": \"/api/user\", \"description\": \"用户\"}]"
	if err := parseJSONArray(raw, &routes); err != nil {
		t.Fatalf("parseJSONArray: %v", err)
	}
	if len(routes) != 1 || routes[0].Path != "/api/user" {
		t.Fatalf("unexpected routes: %#v", routes)
	}
}

func TestParseJSONArrayMissing(t *testing.T) {
	var routes []routeEntry
	if err := parseJSONArray("没有任何 JSON", &routes); err == nil {
		t.Fatal("expected error for missing JSON array")
	}
}

func TestIsJavaScript(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		contentType string
		want        bool
	}{
		{"js suffix", "https://a/app.js", "text/plain", true},
		{"mjs suffix", "https://a/app.mjs", "", true},
		{"content type", "https://a/blob", "application/javascript; charset=utf-8", true},
		{"css", "https://a/app.css", "text/css", false},
		{"html", "https://a/", "text/html", false},
	}
	for _, testCase := range cases {
		tx := model.Transaction{
			Request:  model.Message{URL: testCase.url},
			Response: model.Message{Headers: map[string]string{"Content-Type": testCase.contentType}},
		}
		parsed, err := url.Parse(testCase.url)
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		if got := isJavaScript(tx, parsed); got != testCase.want {
			t.Fatalf("%s: isJavaScript = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

func TestDedupeRoutes(t *testing.T) {
	routes := dedupeRoutes([]routeEntry{
		{Method: "GET", Path: "/api/a"},
		{Method: "GET", Path: "/api/a"},
		{Method: "POST", Path: "/api/a"},
	})
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %#v", routes)
	}
}

func TestObserveCollectsJSUntilAnalyzed(t *testing.T) {
	policy := &stubPolicy{baseURL: "https://api.test", model: "test-model", apiKey: "test-key"}
	worker := New(nil, policy)
	defer func() {
		if err := worker.Shutdown(nil); err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	}()

	tx := model.Transaction{
		Source: "http-proxy",
		Request: model.Message{
			Method: http.MethodGet,
			URL:    "https://site.test/static/app.js",
		},
		Response: model.Message{
			Status:  http.StatusOK,
			Headers: map[string]string{"Content-Type": "application/javascript"},
			Body:    "console.log(1)",
		},
	}
	worker.Observe(tx)
	worker.mu.Lock()
	site, ok := worker.sites["https://site.test"]
	count := 0
	if ok {
		count = len(site.files)
	}
	worker.mu.Unlock()
	if !ok || count != 1 {
		t.Fatalf("expected one collected JS file, ok=%v count=%d", ok, count)
	}

	worker.Observe(tx)
	worker.mu.Lock()
	count = len(worker.sites["https://site.test"].files)
	worker.mu.Unlock()
	if count != 1 {
		t.Fatalf("duplicate URL should not be collected twice, count=%d", count)
	}
}

func TestObserveRequiresConfiguration(t *testing.T) {
	policy := &stubPolicy{baseURL: "", model: "", apiKey: ""}
	worker := New(nil, policy)
	defer func() {
		if err := worker.Shutdown(nil); err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	}()
	tx := model.Transaction{
		Source: "http-proxy",
		Request: model.Message{
			Method: http.MethodGet,
			URL:    "https://site.test/static/app.js",
		},
		Response: model.Message{
			Status:  http.StatusOK,
			Headers: map[string]string{"Content-Type": "application/javascript"},
			Body:    "console.log(1)",
		},
	}
	worker.Observe(tx)
	worker.mu.Lock()
	count := len(worker.sites)
	worker.mu.Unlock()
	if count != 0 {
		t.Fatalf("unconfigured worker should not collect sites, count=%d", count)
	}
}

type stubPolicy struct {
	baseURL string
	model   string
	apiKey  string
}

func (p *stubPolicy) Enabled(string) bool { return true }
func (p *stubPolicy) AIBaseURL() string   { return p.baseURL }
func (p *stubPolicy) AIModel() string     { return p.model }
func (p *stubPolicy) AIAPIKey() string    { return p.apiKey }
