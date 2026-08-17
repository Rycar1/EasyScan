package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/features"
	"github.com/example/easyscan/internal/model"
)

type memoryStore struct {
	mu      sync.Mutex
	tasks   map[string]model.ActiveTask
	results []model.TaskResult
	audit   []model.AuditEvent
}

func newMemoryStore() *memoryStore { return &memoryStore{tasks: map[string]model.ActiveTask{}} }
func (s *memoryStore) CreateTask(t model.ActiveTask) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks[t.ID] = t
	return nil
}
func (s *memoryStore) UpdateTask(t model.ActiveTask) error { return s.CreateTask(t) }
func (s *memoryStore) ListTasks(_ int) ([]model.ActiveTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := make([]model.ActiveTask, 0, len(s.tasks))
	for _, t := range s.tasks {
		r = append(r, t)
	}
	return r, nil
}
func (s *memoryStore) AddTaskResult(r model.TaskResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, r)
	return nil
}
func (s *memoryStore) ListTaskResults(id string, _ int) ([]model.TaskResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r []model.TaskResult
	for _, item := range s.results {
		if item.TaskID == id {
			r = append(r, item)
		}
	}
	return r, nil
}
func (s *memoryStore) AddAudit(e model.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, e)
	return nil
}
func (s *memoryStore) ListAudit(_ int) ([]model.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.AuditEvent(nil), s.audit...), nil
}

func testRunner(t *testing.T) (*Runner, *memoryStore) {
	t.Helper()
	cfg := config.Default()
	cfg.Active.Enabled = true
	cfg.Active.MinIntervalMS = 1
	cfg.Active.MaxConcurrentRequests = 1
	cfg.Active.MaxConcurrentTasks = 1
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryStore()
	return New(cfg, e, store), store
}
func TestSubmitEnforcesScope(t *testing.T) {
	r, _ := testRunner(t)
	if _, err := r.Submit(Request{Kind: KindPortScan, Target: "outside.test"}); err == nil {
		t.Fatal("expected scope error")
	}
}
func TestSubmitRespectsFeaturePolicy(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "features.yaml")
	if err := os.WriteFile(configPath, []byte("features:\n  active.web_crawl: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := features.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Active.Enabled = true
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runner := New(cfg, e, newMemoryStore(), policy)
	if _, err := runner.Submit(Request{Kind: KindCrawl, Target: "https://app.example.test/?q=one"}); err == nil || !strings.Contains(err.Error(), "feature") {
		t.Fatalf("expected disabled feature rejection, got %v", err)
	}
}
func TestSessionHeadersAreRestrictedAndMemoryOnly(t *testing.T) {
	headers, err := sanitizeSessionHeaders(map[string]string{"Cookie": "sid=temporary", "Authorization": "Bearer temporary"})
	if err != nil || headers.Get("Cookie") != "sid=temporary" || headers.Get("Authorization") != "Bearer temporary" {
		t.Fatalf("expected accepted temporary session headers, got %#v %v", headers, err)
	}
	if _, err := sanitizeSessionHeaders(map[string]string{"Host": "outside.test"}); err == nil {
		t.Fatal("Host must not be accepted as a session header")
	}
	if _, err := sanitizeSessionHeaders(map[string]string{"Cookie": "a=b\r\nX-Forwarded-Host: outside.test"}); err == nil {
		t.Fatal("header injection must be rejected")
	}
}
func TestHeadlessURLPolicy(t *testing.T) {
	root, err := url.Parse("https://app.example.test:8443/")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"/assets/app.js", "https://app.example.test:8443/api/list?x=1"} {
		if !headlessAllowedURL(root, raw, true) {
			t.Fatalf("expected allowed same-origin GET URL %q", raw)
		}
	}
	for _, raw := range []string{"https://outside.test/x", "https://app.example.test/api/list", "/logout", "/api/delete"} {
		if headlessAllowedURL(root, raw, true) {
			t.Fatalf("unexpected allowed headless URL %q", raw)
		}
	}
}
func TestHeadlessCrawlDiscoversDynamicGETEndpoint(t *testing.T) {
	if _, err := os.Stat(`C:\Program Files\Google\Chrome\Application\chrome.exe`); err != nil {
		t.Skip("Chrome is unavailable")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<main>app</main><script>fetch('/api/widgets')</script>`))
			return
		}
		if request.URL.Path == "/api/widgets" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[]}`))
			return
		}
		http.NotFound(w, request)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Active.Enabled = true
	cfg.Active.EnableHeadlessCrawl = true
	cfg.Active.MaxRequestsPerTask = 10
	cfg.Active.TimeoutSeconds = 8
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.DenyHosts = nil
	cfg.Scope.AllowPrivateIPs = true
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runner := New(cfg, e, newMemoryStore())
	task := model.ActiveTask{ID: "headless", Kind: KindHeadless, Target: server.URL, Summary: map[string]int{}}
	if err := runner.headlessCrawl(context.Background(), &task); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range e.Assets()[0].Endpoints {
		if endpoint.Path == "/api/widgets" && endpoint.Method == http.MethodGet {
			return
		}
	}
	t.Fatalf("expected dynamic endpoint inventory, got %#v", e.Assets())
}
func TestBasicAuthDoesNotPersistPassword(t *testing.T) {
	r, store := testRunner(t)
	task := model.ActiveTask{ID: "basic", Kind: KindBasicAuth, Target: "https://app.example.test/", Summary: map[string]int{}}
	r.record(&task, KindBasicAuth, task.Target, "valid", "accepted", map[string]string{"username": "admin", "password": "[REDACTED]"})
	results, _ := store.ListTaskResults(task.ID, 10)
	if len(results) != 1 || results[0].Metadata["password"] != "[REDACTED]" {
		t.Fatalf("unexpected credential record: %#v", results)
	}
}
func TestCancelUnknownTask(t *testing.T) {
	r, _ := testRunner(t)
	if err := r.Cancel("missing"); err == nil {
		t.Fatal("expected missing task error")
	}
}
func TestCommonPortsBound(t *testing.T) {
	if len(CommonPorts) != 50 {
		t.Fatalf("expected exactly 50 ports, got %d", len(CommonPorts))
	}
	seen := map[int]bool{}
	for _, port := range CommonPorts {
		if seen[port] {
			t.Fatalf("duplicate port %d", port)
		}
		seen[port] = true
	}
}

func TestBasicAuthSmallDictionary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		user, password, ok := request.BasicAuth()
		if !ok || user != "admin" || password != "admin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Active.Enabled = true
	cfg.Active.MinIntervalMS = 1
	cfg.Active.MaxConcurrentRequests = 1
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryStore()
	runner := New(cfg, e, store)
	task := model.ActiveTask{ID: "basic-http", Kind: KindBasicAuth, Target: server.URL, Summary: map[string]int{}}
	if err := runner.basicAuth(context.Background(), &task); err != nil {
		t.Fatal(err)
	}
	results, _ := store.ListTaskResults(task.ID, 10)
	if len(results) != 1 || results[0].Metadata["username"] != "admin" || results[0].Metadata["password"] != "[REDACTED]" {
		t.Fatalf("unexpected basic result: %#v", results)
	}
}

func TestRunnerShutdownRejectsNewTasks(t *testing.T) {
	cfg := config.Default()
	cfg.Active.Enabled = true
	cfg.Scope.AllowHosts = []string{"app.example.test"}
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runner := New(cfg, e, newMemoryStore())
	if err := runner.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Submit(Request{Kind: KindPortScan, Target: "app.example.test"}); err == nil {
		t.Fatal("shut down runner must not accept a new task")
	}
}

func TestCrawlStaysSameOriginAndAvoidsLogout(t *testing.T) {
	var requests []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests = append(requests, request.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch request.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<a href="/catalog">catalog</a><a href="/logout">logout</a><a href="https://outside.test/x">outside</a>`))
		case "/catalog":
			_, _ = w.Write([]byte(`<a href="/detail?id=1">detail</a>`))
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Active.Enabled = true
	cfg.Active.MinIntervalMS = 1
	cfg.Active.MaxConcurrentRequests = 1
	cfg.Active.MaxRequestsPerTask = 10
	cfg.Scope.AllowHosts = []string{"127.0.0.1"}
	cfg.Scope.DenyHosts = nil
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryStore()
	runner := New(cfg, e, store)
	task := model.ActiveTask{ID: "crawl", Kind: KindCrawl, Target: server.URL, Summary: map[string]int{}}
	if err := runner.crawl(context.Background(), &task); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(requests, ",") != "/,/catalog,/detail" {
		t.Fatalf("unexpected crawl requests: %#v", requests)
	}
}
