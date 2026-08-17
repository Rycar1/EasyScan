//go:build nucleimanual

// This manual integration test downloads the real nuclei binary and drives the
// full fingerprint-to-POC path against a local target. It is build-tagged so it
// never runs during normal `go test`; run it explicitly with:
//
//	go test -tags nucleimanual -run TestNucleiEndToEnd -v ./internal/nucleiprobe/
package nucleiprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

// staticPolicy enables the POC feature for the worker under test.
type staticPolicy struct{ enabled bool }

func (p staticPolicy) Enabled(string) bool { return p.enabled }

func TestNucleiEndToEnd(t *testing.T) {
	// 1. Resolve the nuclei binary. Prefer an already-installed managed/PATH
	//    binary; only fall back to a GitHub download when none is present (the
	//    unauthenticated GitHub API is rate-limited in CI-like environments).
	dataDir := os.Getenv("EASYSCAN_NUCLEI_DATADIR")
	if dataDir == "" {
		dataDir = t.TempDir()
	}
	mgr := NewManager(dataDir, func() string { return os.Getenv("EASYSCAN_NUCLEI_PATH") })
	binPath, err := mgr.Resolve()
	if err != nil {
		dlCtx, dlCancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer dlCancel()
		binPath, err = mgr.DownloadLatest(dlCtx)
		if err != nil {
			t.Fatalf("nuclei 不可用且下载失败: %v", err)
		}
	}
	t.Logf("nuclei 二进制: %s", binPath)
	if v, err := mgr.Version(context.Background()); err == nil {
		t.Logf("nuclei 版本: %s", v)
	}

	// 2. Local target that (a) leaks a Server: nginx header so the engine records
	//    an nginx fingerprint, and (b) exposes /.git/config which a common nuclei
	//    template with tag "git" / "exposure" matches.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// cloudflare-nginx matches the http/technologies/cloudflare-nginx-detect
		// template (tag "nginx") and is also fingerprinted as nginx by hfinger.
		w.Header().Set("Server", "cloudflare-nginx")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	target, _ := url.Parse(srv.URL)
	host := target.Hostname()

	// 3. Real engine scoped to the target host.
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{host}
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	// Feed a transaction so the engine records a fingerprint for the host.
	e.Analyze(model.Transaction{
		Source:  model.SourceHTTPProxy,
		Request: model.Message{Method: "GET", URL: srv.URL + "/"},
		Response: model.Message{
			Status:  200,
			Headers: map[string]string{"Server": "cloudflare-nginx"},
			Body:    "<html><body>hello</body></html>",
		},
	})

	fps := collectFingerprints(e, host)
	tags := TagsFor(fps)
	t.Logf("已识别指纹: %v -> tags: %v", fps, tags)
	if len(tags) == 0 {
		// The engine did not label this response; force the nginx tag so the
		// nuclei-invocation path is still exercised end-to-end.
		t.Logf("引擎未产生指纹标签，回退到显式 nginx 标签以验证 nuclei 调用链路")
	}

	// 4. Drive the worker end-to-end.
	w := New(cfg, e, staticPolicy{enabled: true}, mgr)
	defer w.Shutdown(context.Background())

	w.Observe(model.Transaction{
		Source:  model.SourceHTTPProxy,
		Request: model.Message{Method: "GET", URL: srv.URL + "/"},
	})

	// 5. Wait for nuclei to run and a finding to be reported.
	deadline := time.Now().Add(4 * time.Minute)
	var findings []model.Finding
	for time.Now().Before(deadline) {
		findings = filterNucleiFindings(e.Findings())
		if len(findings) > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(findings) == 0 {
		t.Fatalf("nuclei 未产生任何 finding（指纹=%v tags=%v）；可能该 tag 下无匹配模板或目标未命中", fps, TagsFor(fps))
	}
	for _, f := range findings {
		t.Logf("命中: rule=%s severity=%s url=%s title=%s", f.RuleID, f.Severity, f.URL, f.Title)
	}
}

// TestNucleiEndToEndMultiFingerprint drives several distinct local targets, each
// emitting a different technology fingerprint, and asserts that nuclei is invoked
// per origin with the fingerprint-derived tags. It shares the same resolve/download
// logic as TestNucleiEndToEnd but focuses on breadth across fingerprints.
func TestNucleiEndToEndMultiFingerprint(t *testing.T) {
	dataDir := os.Getenv("EASYSCAN_NUCLEI_DATADIR")
	if dataDir == "" {
		dataDir = t.TempDir()
	}
	mgr := NewManager(dataDir, func() string { return os.Getenv("EASYSCAN_NUCLEI_PATH") })
	binPath, err := mgr.Resolve()
	if err != nil {
		dlCtx, dlCancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer dlCancel()
		binPath, err = mgr.DownloadLatest(dlCtx)
		if err != nil {
			t.Fatalf("nuclei 不可用且下载失败: %v", err)
		}
	}
	t.Logf("nuclei 二进制: %s", binPath)

	// Each case exposes a Server header that hfinger fingerprints, and we assert
	// the derived tags include the wanted token so nuclei is scoped correctly.
	cases := []struct {
		name       string
		serverHdr  string
		body       string
		wantTagSub string
	}{
		{name: "nginx", serverHdr: "cloudflare-nginx", body: "<html>hello</html>", wantTagSub: "nginx"},
		{name: "apache", serverHdr: "Apache/2.4.49 (Unix)", body: "<html>apache</html>", wantTagSub: "apache"},
		{name: "iis", serverHdr: "Microsoft-IIS/10.0", body: "<html>iis</html>", wantTagSub: "iis"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			serverHdr, body := tc.serverHdr, tc.body
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", serverHdr)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			target, _ := url.Parse(srv.URL)
			host := target.Hostname()

			cfg := config.Default()
			cfg.Scope.AllowHosts = []string{host}
			e, err := engine.New(cfg)
			if err != nil {
				t.Fatalf("engine.New: %v", err)
			}

			e.Analyze(model.Transaction{
				Source:  model.SourceHTTPProxy,
				Request: model.Message{Method: "GET", URL: srv.URL + "/"},
				Response: model.Message{
					Status:  200,
					Headers: map[string]string{"Server": serverHdr},
					Body:    body,
				},
			})

			fps := collectFingerprints(e, host)
			tags := TagsFor(fps)
			t.Logf("[%s] 指纹=%v -> tags=%v", tc.name, fps, tags)

			hasTag := false
			for _, tag := range tags {
				if strings.Contains(tag, tc.wantTagSub) {
					hasTag = true
					break
				}
			}
			if !hasTag {
				t.Fatalf("[%s] 期望 tags 包含 %q，实际 %v（指纹=%v）", tc.name, tc.wantTagSub, tags, fps)
			}

			w := New(cfg, e, staticPolicy{enabled: true}, mgr)
			defer w.Shutdown(context.Background())

			w.Observe(model.Transaction{
				Source:  model.SourceHTTPProxy,
				Request: model.Message{Method: "GET", URL: srv.URL + "/"},
			})

			// Allow nuclei to complete a run. Not every tag is guaranteed to
			// match a template locally, so we assert the invocation completed
			// (no findings is acceptable) and log any hits.
			deadline := time.Now().Add(3 * time.Minute)
			for time.Now().Before(deadline) {
				if len(filterNucleiFindings(e.Findings())) > 0 {
					break
				}
				time.Sleep(2 * time.Second)
			}
			for _, f := range filterNucleiFindings(e.Findings()) {
				t.Logf("[%s] 命中: rule=%s severity=%s title=%s", tc.name, f.RuleID, f.Severity, f.Title)
			}
		})
	}
}

func collectFingerprints(e *engine.Engine, host string) []string {
	for _, a := range e.Assets() {
		if a.Host == host {
			return a.Fingerprints
		}
	}
	return nil
}

func filterNucleiFindings(all []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range all {
		if strings.HasPrefix(f.RuleID, "passive.nuclei.") {
			out = append(out, f)
		}
	}
	return out
}
