package engine

import (
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/model"
)

func TestHFingerMITMAccuracyCorpus(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		status    int
		headers   map[string]string
		body      string
		expected  []string
		forbidden []string
		empty     bool
	}{
		{name: "blank", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html"}, body: `<html><body>Hello world</body></html>`, empty: true},
		{name: "generic-static-libraries", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html"}, body: `<link href="/bootstrap.min.css"><script src="/jquery.min.js"></script>`, forbidden: []string{"jQuery", "Bootstrap", "Bootstrap-CDN", "GZIP encode", "GSE"}},
		{name: "nginx", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html", "Server": "nginx/1.26.0"}, body: `<title>Welcome</title>`, expected: []string{"nginx"}},
		{name: "apache", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html", "Server": "Apache/2.4.58"}, body: `<title>Home</title>`, expected: []string{"Apache HTTP Server"}},
		{name: "iis", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html", "Server": "Microsoft-IIS/10.0"}, body: `<title>Home</title>`, expected: []string{"Microsoft IIS"}},
		{name: "tomcat", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html", "Server": "Apache-Coyote/1.1"}, body: `<title>Apache Tomcat</title>`, expected: []string{"Apache Tomcat"}},
		{name: "wordpress", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html"}, body: `<a href="/wp-admin/">Admin</a><script src="/wp-content/themes/site/app.js"></script>`, expected: []string{"WordPress"}, forbidden: []string{"jQuery"}},
		{name: "grafana", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html"}, body: `<title>Grafana</title><script>window.grafanaBootData={}</script>`, expected: []string{"Grafana"}},
		{name: "phpmyadmin", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html", "Set-Cookie": "phpMyAdmin=abc; Path=/; HttpOnly"}, body: `<title>phpMyAdmin</title>`, expected: []string{"phpMyAdmin"}},
		{name: "cloudflare", path: "/", status: 200, headers: map[string]string{"Content-Type": "text/html", "Server": "cloudflare", "CF-Ray": "fixture-SJC"}, body: `<title>Home</title>`, expected: []string{"CDN · Cloudflare"}},
		{name: "discuz-404-reflection", path: "/admin/discuzfiles.md5", status: 404, headers: map[string]string{"Content-Type": "text/html"}, body: `<title>Not Found</title>missing /admin/discuzfiles.md5`, forbidden: []string{"Discuz", "Discuz!"}, empty: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host := test.name + ".fixture.test"
			e.Analyze(model.Transaction{
				Source:   model.SourceHTTPSMITM,
				Request:  model.Message{Method: "GET", URL: "https://" + host + test.path},
				Response: model.Message{Status: test.status, Headers: test.headers, Body: test.body},
			})
			fingerprints := assetFingerprints(e.Assets(), host)
			for _, expected := range test.expected {
				if !containsString(fingerprints, expected) {
					t.Fatalf("missing %q in %#v", expected, fingerprints)
				}
			}
			for _, forbidden := range test.forbidden {
				if containsString(fingerprints, forbidden) {
					t.Fatalf("unexpected false positive %q in %#v", forbidden, fingerprints)
				}
			}
			if test.empty && len(fingerprints) != 0 {
				t.Fatalf("expected no fingerprints, got %#v", fingerprints)
			}
		})
	}
}

func TestHFingerRunsOnlyForObservedMITMTraffic(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Analyze(model.Transaction{
		Source:   model.SourceAPIIngest,
		Request:  model.Message{URL: "https://api-import.fixture.test/"},
		Response: model.Message{Status: 200, Headers: map[string]string{"Server": "nginx/1.26.0"}},
	})
	if got := assetFingerprints(e.Assets(), "api-import.fixture.test"); len(got) != 0 {
		t.Fatalf("API import should not run MITM HFinger matching: %#v", got)
	}
}

func assetFingerprints(assets []model.Asset, host string) []string {
	for _, asset := range assets {
		if asset.Host == host {
			return asset.Fingerprints
		}
	}
	return nil
}
