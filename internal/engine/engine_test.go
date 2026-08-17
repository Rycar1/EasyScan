package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/model"
)

type featureGateFunc func(string) bool

func (f featureGateFunc) Enabled(id string) bool { return f(id) }

type domainExclusionGateFunc func(string) bool

func (f domainExclusionGateFunc) ExcludedHost(host string) bool { return f(host) }

type suffixExclusionGateFunc func(string) bool

func (f suffixExclusionGateFunc) ExcludedURLPath(urlPath string) bool { return f(urlPath) }

func TestBuiltinsAndDeduplication(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tx := model.Transaction{Request: model.Message{Method: "GET", URL: "https://app.example.test/swagger", Headers: map[string]string{}}, Response: model.Message{Status: 200, Headers: map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true", "Set-Cookie": "sid=abc", "Content-Type": "text/html"}, Body: "<title>Index of /</title>"}}
	got := e.Analyze(tx)
	if len(got) != 1 {
		t.Fatalf("expected only directory listing finding (HTML body is not API docs), got %d: %#v", len(got), got)
	}
	if again := e.Analyze(tx); len(again) != 0 {
		t.Fatalf("expected duplicate transaction to produce no findings, got %d", len(again))
	}
	if len(e.Assets()) != 1 {
		t.Fatalf("expected asset inventory to contain host")
	}
	for _, finding := range got {
		if finding.RuleID == "passive.api-documentation" && finding.Severity != "low" {
			t.Fatalf("API documentation exposure must be low severity: %#v", finding)
		}
	}
}

func TestRestoreNormalizesAPIDocumentationSeverity(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Restore([]model.Finding{{ID: "api-docs", RuleID: "passive.api-documentation", Severity: "info", URL: "https://app.example.test/swagger"}}, nil)
	findings := e.Findings()
	if len(findings) != 1 || findings[0].Severity != "low" {
		t.Fatalf("restored API documentation finding must be normalized to low: %#v", findings)
	}
}

func TestAPIDocumentationRequiresHTTP200(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		findings := e.Analyze(model.Transaction{
			Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/swagger/index.html"},
			Response: model.Message{Status: status, Headers: map[string]string{"Content-Type": "text/html"}},
		})
		for _, finding := range findings {
			if finding.RuleID == "passive.api-documentation" {
				t.Fatalf("status %d must not report API documentation exposure: %#v", status, finding)
			}
		}
	}
	// 200 + text/html 不应触发（SPA 回退场景）
	findings := e.Analyze(model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/swagger/index.html"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<!DOCTYPE html><html></html>"},
	})
	for _, finding := range findings {
		if finding.RuleID == "passive.api-documentation" {
			t.Fatalf("200 + text/html must not report API documentation exposure (SPA fallback): %#v", finding)
		}
	}
	// 200 + application/json + swagger 结构标记才触发
	swaggerBody := `{"swagger":"2.0","info":{"title":"API","version":"1.0"},"paths":{}}`
	findings = e.Analyze(model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/v1/swagger.json"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Content-Type": "application/json"}, Body: swaggerBody},
	})
	found := false
	for _, finding := range findings {
		if finding.RuleID == "passive.api-documentation" {
			found = true
		}
	}
	if !found {
		t.Fatalf("200 + application/json with swagger body must report API documentation exposure: %#v", findings)
	}
}

func TestRestoreDropsLegacyKScanFingerprintPrefixes(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Restore(nil, []model.Asset{{
		Host: "app.example.test",
		Fingerprints: []string{
			"nginx",
			"KScan · nginx",
			"KScan · Example appliance",
		},
	}})
	assets := e.Assets()
	if len(assets) != 1 {
		t.Fatalf("expected one restored asset, got %#v", assets)
	}
	got := assets[0].Fingerprints
	if len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("legacy KScan fingerprints should be removed: %#v", got)
	}
	for _, value := range got {
		if strings.HasPrefix(strings.ToLower(value), "kscan ·") {
			t.Fatalf("legacy KScan prefix leaked from restored snapshot: %#v", got)
		}
	}
}

func TestCORSAndCookieFindingsAreNotProduced(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := e.Analyze(model.Transaction{Request: model.Message{Method: "GET", URL: "https://app.example.test/"}, Response: model.Message{Status: 200, Headers: map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true", "Set-Cookie": "sid=abc"}}})
	for _, finding := range got {
		if strings.HasPrefix(finding.RuleID, "passive.cors.") || strings.HasPrefix(finding.RuleID, "passive.cookie.") {
			t.Fatalf("unexpected removed check: %#v", finding)
		}
	}
}

func TestObservedEndpointsAndPassiveCandidates(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tx := model.Transaction{Request: model.Message{Method: "GET", URL: "https://app.example.test/search?q=%3Ctag%3E", Headers: map[string]string{}}, Response: model.Message{Status: 500, Headers: map[string]string{"Content-Type": "text/html", "X-Runtime": "log4j 2.14.1"}, Body: `<form method="post" action="/api/login"><input name="username"><input name="password"></form><script>var q="<tag>";</script> SQL syntax error near mysql java.io.ObjectInputStream /bin/sh`}}
	got := e.Analyze(tx)
	found := map[string]bool{}
	for _, finding := range got {
		found[finding.RuleID] = true
	}
	for id := range found {
		if strings.HasPrefix(id, "passive.candidate.") {
			t.Fatalf("candidate vulnerability must no longer be reported: %#v", got)
		}
	}
	assets := e.Assets()
	if len(assets) != 1 || len(assets[0].Endpoints) != 2 {
		t.Fatalf("expected request and form endpoints, got %#v", assets)
	}
}

func TestPassiveCandidatesRequireRelevantEvidence(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := e.Analyze(model.Transaction{
		Request:  model.Message{Method: "GET", URL: "https://app.example.test/docs?q=%3Ctag%3E"},
		Response: model.Message{Status: 200, Headers: map[string]string{"Content-Type": "text/plain"}, Body: "Documentation: SQL syntax error near mysql; /bin/sh; log4j 2.14.1; rO0ABAAAAAAAAAAAAAAAA"},
	})
	for _, finding := range got {
		if strings.HasPrefix(finding.RuleID, "passive.candidate.") {
			t.Fatalf("documentation text must not be reported as a vulnerability candidate: %#v", finding)
		}
	}
}

func TestExactComponentVersionAdvisoryIsTentative(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := e.Analyze(model.Transaction{Request: model.Message{Method: "GET", URL: "https://app.example.test/"}, Response: model.Message{Status: 200, Headers: map[string]string{"Server": "Apache/2.4.49"}}})
	for _, finding := range got {
		if strings.HasPrefix(finding.RuleID, "passive.candidate.") {
			t.Fatalf("component advisory must no longer be reported: %#v", got)
		}
	}
}

func TestOnlyFingerprintAndDisabledChecks(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	cfg.Analysis.OnlyFingerprint = true
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Analyze(model.Transaction{Request: model.Message{Method: "GET", URL: "https://app.example.test/"}, Response: model.Message{Status: 200, Headers: map[string]string{"Server": "nginx/1.24.0"}, Body: "-----BEGIN PRIVATE KEY-----"}})
	if len(e.Findings()) != 0 || len(e.Assets()) != 1 {
		t.Fatalf("only fingerprint mode should retain inventory only: %#v %#v", e.Findings(), e.Assets())
	}
	cfg.Analysis.OnlyFingerprint = false
	cfg.Analysis.DisabledChecks = []string{"passive.exposure.*"}
	e, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := e.Analyze(model.Transaction{Request: model.Message{URL: "https://app.example.test/"}, Response: model.Message{Status: 200, Body: "-----BEGIN PRIVATE KEY-----"}})
	for _, finding := range got {
		if strings.HasPrefix(finding.RuleID, "passive.exposure.") {
			t.Fatalf("disabled check appeared: %#v", finding)
		}
	}
}

func TestTransactionObserverReceivesOnlySuccessfullyAnalyzedTransactions(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"app.example.test"}
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var observed []model.Transaction
	e.SetTransactionObserver(func(tx model.Transaction) { observed = append(observed, tx) })
	e.Analyze(model.Transaction{
		Source:   model.SourceHTTPSMITM,
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/"},
		Response: model.Message{Status: http.StatusOK},
	})
	e.Analyze(model.Transaction{
		Source:   model.SourceHTTPSMITM,
		Request:  model.Message{Method: http.MethodGet, URL: "https://out-of-scope.example.test/"},
		Response: model.Message{Status: http.StatusOK},
	})
	if len(observed) != 1 || observed[0].Request.URL != "https://app.example.test/" {
		t.Fatalf("expected only the analyzed in-scope transaction, got %#v", observed)
	}
	e.SetTransactionObserver(nil)
	e.Analyze(model.Transaction{Request: model.Message{URL: "https://app.example.test/after-detach"}, Response: model.Message{Status: http.StatusOK}})
	if len(observed) != 1 {
		t.Fatalf("detached observer was invoked: %#v", observed)
	}
}

func TestCDNAndWAFFingerprintsAreAddedToAsset(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Analyze(model.Transaction{Source: model.SourceHTTPSMITM, Request: model.Message{URL: "https://app.example.test/"}, Response: model.Message{Status: 403, Headers: map[string]string{"CF-Ray": "abc", "CF-Mitigated": "challenge", "Server": "cloudflare"}}})
	assets := e.Assets()
	if len(assets) != 1 || !containsString(assets[0].Fingerprints, "CDN · Cloudflare") || !containsString(assets[0].Fingerprints, "WAF · Cloudflare WAF Managed Challenge") {
		t.Fatalf("expected Cloudflare CDN/WAF inventory, got %#v", assets)
	}
	if providers := e.WAFProviders("app.example.test"); len(providers) != 1 || providers[0] != "Cloudflare WAF Managed Challenge" {
		t.Fatalf("unexpected WAF providers: %#v", providers)
	}
}

func TestCloudFrontIsNotAssumedToBeWAF(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Analyze(model.Transaction{Source: model.SourceHTTPSMITM, Request: model.Message{URL: "https://app.example.test/"}, Response: model.Message{Headers: map[string]string{"X-Amz-Cf-Id": "abc"}}})
	if providers := e.WAFProviders("app.example.test"); len(providers) != 0 {
		t.Fatalf("CDN alone must not enable WAF mode: %#v", providers)
	}
}

func TestCDNAndWAFDetectionCanBeDisabledIndependently(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	tx := model.Transaction{Source: model.SourceHTTPSMITM, Request: model.Message{URL: "https://app.example.test/"}, Response: model.Message{Status: 403, Headers: map[string]string{"CF-Ray": "abc", "CF-Mitigated": "challenge", "Server": "cloudflare"}}}

	hfingerDisabled, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// WAF vendor identification is now bundled into hfinger; when hfinger is
	// off nothing is fingerprinted at all.
	hfingerDisabled.SetFeatureGate(featureGateFunc(func(id string) bool { return id != "passive.hfinger" }))
	hfingerDisabled.Analyze(tx)
	assets := hfingerDisabled.Assets()
	if len(assets) != 1 || len(assets[0].Fingerprints) != 0 {
		t.Fatalf("expected no fingerprints with hfinger disabled, got %#v", assets)
	}
	if providers := hfingerDisabled.WAFProviders("app.example.test"); len(providers) != 0 {
		t.Fatalf("WAF mode must be disabled with hfinger disabled, got %#v", providers)
	}

	cdnDisabled, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cdnDisabled.SetFeatureGate(featureGateFunc(func(id string) bool { return id != "passive.cdn_detection" }))
	cdnDisabled.Analyze(tx)
	assets = cdnDisabled.Assets()
	if len(assets) != 1 || containsString(assets[0].Fingerprints, "CDN · Cloudflare") || !containsString(assets[0].Fingerprints, "WAF · Cloudflare WAF Managed Challenge") {
		t.Fatalf("expected only WAF fingerprint with CDN detection disabled, got %#v", assets)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestScope(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := e.Analyze(model.Transaction{Request: model.Message{URL: "https://outside.test/"}})
	if got != nil || len(e.Assets()) != 0 {
		t.Fatal("out of scope traffic should be ignored")
	}
}

func TestServerVersionHeaderDoesNotCreateFinding(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Analyze(model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/static/app.js"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Server": "nginx/1.24.0"}},
	})
	if findings := e.Findings(); len(findings) != 0 {
		t.Fatalf("server version headers must not create a vulnerability finding, got %#v", findings)
	}
	if assets := e.Assets(); len(assets) != 1 {
		t.Fatalf("server header traffic should still contribute to passive asset inventory, got %#v", assets)
	}
}

func TestAllowsPassiveHostDoesNotRequireAnActiveAllowList(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.AllowHosts = nil
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !e.AllowsPassiveHost("observed.example.test") {
		t.Fatal("passive host checks should retain the default open observation scope")
	}
	if e.AllowsActiveHost("observed.example.test") {
		t.Fatal("active host checks must still require scope.allow_hosts")
	}
}

func TestDynamicDomainExclusionGateStopsPassiveAndActiveScope(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	blocked := false
	e.SetDomainExclusionGate(domainExclusionGateFunc(func(host string) bool {
		return blocked && strings.EqualFold(host, "blocked.example.test")
	}))

	if !e.AllowsPassiveHost("blocked.example.test") || !e.AllowsActiveHost("blocked.example.test") {
		t.Fatal("host should be in scope before the live exclusion is enabled")
	}
	blocked = true
	if e.AllowsPassiveHost("blocked.example.test") {
		t.Fatal("dynamic exclusion must stop passive analysis scope")
	}
	if e.AllowsActiveHost("blocked.example.test") {
		t.Fatal("dynamic exclusion must stop active scope and MITM CONNECT eligibility")
	}
	if got := e.Analyze(model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: "https://blocked.example.test/new-traffic"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Server": "nginx"}},
	}); got != nil {
		t.Fatalf("excluded traffic must not produce findings, got %#v", got)
	}
	if assets := e.Assets(); len(assets) != 0 {
		t.Fatalf("excluded traffic must not create assets, got %#v", assets)
	}

	// Detaching the gate immediately restores the static scope behavior.
	e.SetDomainExclusionGate(nil)
	if !e.AllowsPassiveHost("blocked.example.test") || !e.AllowsActiveHost("blocked.example.test") {
		t.Fatal("removing the live exclusion gate should restore static scope")
	}
	e.Analyze(model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: "https://blocked.example.test/after-removal"},
		Response: model.Message{Status: http.StatusOK},
	})
	if assets := e.Assets(); len(assets) != 1 || assets[0].Host != "blocked.example.test" {
		t.Fatalf("traffic should be analyzed after exclusion removal, got %#v", assets)
	}
}

func TestDynamicSuffixExclusionGateSkipsAnalysisAndObservers(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.AllowHosts = []string{"*.example.test"}
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.SetDomainExclusionGate(domainExclusionGateFunc(func(host string) bool {
		return strings.EqualFold(host, "blocked.example.test")
	}))
	filtered := true
	e.SetSuffixExclusionGate(suffixExclusionGateFunc(func(urlPath string) bool {
		return filtered && strings.HasSuffix(strings.ToLower(urlPath), ".png")
	}))
	var observed []model.Transaction
	e.SetTransactionObserver(func(tx model.Transaction) { observed = append(observed, tx) })

	if e.AllowsPassiveURL("https://blocked.example.test/page.html") {
		t.Fatal("domain and suffix exclusion gates must remain compatible")
	}
	if e.AllowsPassiveURL("https://app.example.test/assets/LOGO.PNG?cache=1#fragment") {
		t.Fatal("an excluded suffix must stop passive eligibility")
	}
	logCount := len(e.Logs(0))
	filteredTx := model.Transaction{
		Source:   model.SourceHTTPSMITM,
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/assets/LOGO.PNG?cache=1#fragment"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"X-Powered-By": "ExampleFramework/1.2.3"}},
	}
	if got := e.Analyze(filteredTx); got != nil {
		t.Fatalf("filtered traffic must not produce findings, got %#v", got)
	}
	if findings, assets, traffic := e.Findings(), e.Assets(), e.Traffic(10); len(findings) != 0 || len(assets) != 0 || len(traffic) != 0 {
		t.Fatalf("filtered traffic must not enter analysis state: findings=%#v assets=%#v traffic=%#v", findings, assets, traffic)
	}
	if len(e.Logs(0)) != logCount {
		t.Fatalf("filtered traffic must not create runtime logs: %#v", e.Logs(0))
	}
	if len(observed) != 0 {
		t.Fatalf("filtered traffic must not invoke observers: %#v", observed)
	}

	// The query contains a suffix-like value, but only url.URL.Path participates
	// in the exclusion check, so this exchange remains eligible.
	queryOnly := filteredTx
	queryOnly.Request.URL = "https://app.example.test/download?file=LOGO.PNG#fragment"
	if !e.AllowsPassiveURL(queryOnly.Request.URL) {
		t.Fatal("query and fragment values must not trigger a suffix exclusion")
	}
	e.Analyze(queryOnly)
	if len(e.Assets()) != 1 || len(e.Traffic(10)) != 1 || len(observed) != 1 {
		t.Fatalf("query-only suffix text should be analyzed normally: assets=%#v traffic=%#v observed=%#v", e.Assets(), e.Traffic(10), observed)
	}

	filtered = false
	if !e.AllowsPassiveURL(filteredTx.Request.URL) {
		t.Fatal("changing the live suffix gate must apply without restarting")
	}
	e.Analyze(filteredTx)
	if len(e.Traffic(10)) != 2 || len(observed) != 2 {
		t.Fatalf("traffic should be analyzed immediately after suffix removal: traffic=%#v observed=%#v", e.Traffic(10), observed)
	}
}

func TestPassiveTrafficHistoryIsBoundedAndRedactsURL(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < trafficHistoryLimit+2; index++ {
		e.Analyze(model.Transaction{
			Source:   "http-proxy",
			Request:  model.Message{Method: "GET", URL: fmt.Sprintf("https://user:secret@app.example.test/item/%d?token=private-value&page=%d", index, index)},
			Response: model.Message{Status: 200, Headers: map[string]string{"Content-Type": "application/json; charset=utf-8"}, Body: `{"secret":"never retained"}`},
		})
	}
	e.Analyze(model.Transaction{
		Source:   "active-crawl",
		Request:  model.Message{Method: "GET", URL: "https://app.example.test/active-only"},
		Response: model.Message{Status: 200},
	})
	traffic := e.Traffic(trafficHistoryLimit + 10)
	if len(traffic) != trafficHistoryLimit {
		t.Fatalf("expected a bounded passive traffic history, got %d entries", len(traffic))
	}
	newest := traffic[0]
	if newest.URL == "" || strings.Contains(newest.URL, "secret") || strings.Contains(newest.URL, "private-value") {
		t.Fatalf("expected URL credentials and query values to be redacted, got %q", newest.URL)
	}
	if !strings.Contains(newest.URL, "page") || !strings.Contains(newest.URL, "token") {
		t.Fatalf("expected query parameter names to remain useful for routing, got %q", newest.URL)
	}
	if newest.ContentType != "application/json" {
		t.Fatalf("expected normalized content type, got %q", newest.ContentType)
	}
	for _, entry := range traffic {
		if strings.Contains(entry.URL, "active-only") {
			t.Fatalf("active verification traffic must not enter passive history: %#v", entry)
		}
	}
}

func TestRuntimeLogsDescribePassiveAnalysisWithoutRetainingSensitiveContent(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "test", "Authorization: Bearer must-not-appear; Cookie: session=must-not-appear; Request Body: request-body-must-not-appear")
	e.Analyze(model.Transaction{
		Source: "http-proxy",
		Request: model.Message{
			Method:  "GET",
			URL:     "https://user:secret@app.example.test/health?token=private-value",
			Headers: map[string]string{"Authorization": "Bearer must-not-appear", "Cookie": "session=must-not-appear"},
			Body:    "request-body-must-not-appear",
		},
		Response: model.Message{
			Status:  200,
			Headers: map[string]string{"Server": "nginx", "Set-Cookie": "session=must-not-appear"},
			Body:    "<title>Index of /</title>",
		},
	})

	logs := e.Logs(0)
	if len(logs) < 4 {
		t.Fatalf("expected initialization, request, fingerprint and finding logs, got %#v", logs)
	}
	components := map[string]bool{}
	for _, entry := range logs {
		components[entry.Component] = true
		if entry.ID == "" || entry.CreatedAt.IsZero() || entry.Level == "" || entry.Message == "" {
			t.Fatalf("runtime log is incomplete: %#v", entry)
		}
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		for _, sensitive := range []string{"secret", "private-value", "must-not-appear", "request-body-must-not-appear", "response-body-must-not-appear", "Authorization", "Cookie"} {
			if strings.Contains(string(encoded), sensitive) {
				t.Fatalf("runtime log leaked %q: %s", sensitive, encoded)
			}
		}
	}
	for _, component := range []string{"engine", "request", "fingerprint", "finding"} {
		if !components[component] {
			t.Fatalf("missing %q runtime log: %#v", component, logs)
		}
	}
	if !strings.Contains(logs[0].Message, "发现风险") {
		t.Fatalf("expected newest event to be a finding, got %#v", logs[0])
	}
}

func TestRuntimeLogsIgnoreActiveTrafficAndUseABoundedRing(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Analyze(model.Transaction{
		Source:   "active-crawl",
		Request:  model.Message{Method: "GET", URL: "https://app.example.test/active-only"},
		Response: model.Message{Status: 200, Headers: map[string]string{"Server": "nginx"}},
	})
	if logs := e.Logs(0); len(logs) != 1 || logs[0].Component != "engine" {
		t.Fatalf("active traffic must not create analysis logs: %#v", logs)
	}

	for index := 0; index < runtimeLogHistoryLimit+2; index++ {
		e.Log("info", "test", fmt.Sprintf("entry %d", index))
	}
	logs := e.Logs(runtimeLogHistoryLimit + 1)
	if len(logs) != runtimeLogHistoryLimit {
		t.Fatalf("expected bounded log ring, got %d entries", len(logs))
	}
	if logs[0].Message != fmt.Sprintf("entry %d", runtimeLogHistoryLimit+1) {
		t.Fatalf("expected newest log first, got %#v", logs[0])
	}
}

func TestFingerprintRuntimeLogsOnlyNewAssetFingerprints(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	transaction := func(host, route string) model.Transaction {
		return model.Transaction{
			Source:   "http-proxy",
			Request:  model.Message{Method: http.MethodGet, URL: "https://" + host + route},
			Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Server": "nginx/1.26.0"}},
		}
	}
	fingerprintLogCount := func() int {
		count := 0
		for _, entry := range e.Logs(0) {
			if entry.Component == "fingerprint" {
				count++
			}
		}
		return count
	}

	// The matched fingerprint remains attached to every traffic row, but only
	// the first sighting on a host should be written to the runtime log.
	e.Analyze(transaction("app.example.test", "/assets/one.js"))
	e.Analyze(transaction("app.example.test", "/assets/two.css"))
	if got := fingerprintLogCount(); got != 1 {
		t.Fatalf("expected one fingerprint log for repeated host fingerprint, got %d: %#v", got, e.Logs(0))
	}
	traffic := e.Traffic(2)
	if len(traffic) != 2 || !containsString(traffic[0].Fingerprints, "nginx") || !containsString(traffic[1].Fingerprints, "nginx") {
		t.Fatalf("each passive exchange must retain its matched fingerprint, got %#v", traffic)
	}

	// A different host owns a separate asset inventory and gets its first log.
	e.Analyze(transaction("cdn.example.test", "/static/app.js"))
	if got := fingerprintLogCount(); got != 2 {
		t.Fatalf("expected a separate fingerprint log for a different host, got %d: %#v", got, e.Logs(0))
	}

	// Clearing restored analysis data removes the asset fingerprint inventory,
	// so the same host can be announced again in the new analysis session.
	e.ClearAnalysisSnapshot()
	e.Analyze(transaction("app.example.test", "/assets/after-clear.js"))
	if got := fingerprintLogCount(); got != 3 {
		t.Fatalf("expected fingerprint logging to restart after clearing the snapshot, got %d: %#v", got, e.Logs(0))
	}
}

func TestFingerprintRuntimeLogDeduplicationIsConcurrentSafe(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 24
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			e.Analyze(model.Transaction{
				Source:   "http-proxy",
				Request:  model.Message{Method: http.MethodGet, URL: fmt.Sprintf("https://app.example.test/static/%d.js", index)},
				Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Server": "nginx/1.26.0"}},
			})
		}()
	}
	close(start)
	group.Wait()

	count := 0
	for _, entry := range e.Logs(0) {
		if entry.Component == "fingerprint" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one concurrent fingerprint log, got %d: %#v", count, e.Logs(0))
	}
}

func TestRestoredFingerprintAliasesDoNotProduceAnotherRuntimeLog(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Old snapshots can contain the same product with differently cased display
	// labels. Retain the first display label, but treat both as one asset
	// fingerprint when deciding whether a later observation is new.
	e.Restore(nil, []model.Asset{{
		Host:         "app.example.test",
		Fingerprints: []string{"Nginx", "nginx"},
	}})
	assets := e.Assets()
	if len(assets) != 1 || len(assets[0].Fingerprints) != 1 || assets[0].Fingerprints[0] != "Nginx" {
		t.Fatalf("expected restored aliases to keep one display fingerprint, got %#v", assets)
	}

	e.Analyze(model.Transaction{
		Source:   "http-proxy",
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/assets/app.js"},
		Response: model.Message{Status: http.StatusOK, Headers: map[string]string{"Server": "nginx/1.26.0"}},
	})
	for _, entry := range e.Logs(0) {
		if entry.Component == "fingerprint" {
			t.Fatalf("restored case-insensitive fingerprint must not be announced again: %#v", e.Logs(0))
		}
	}
	traffic := e.Traffic(1)
	if len(traffic) != 1 || !containsString(traffic[0].Fingerprints, "nginx") {
		t.Fatalf("restored assets must not suppress traffic match data, got %#v", traffic)
	}
}

func TestFindingEvidenceRetainsFullPacketsAndAlternates(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, time.August, 3, 10, 11, 12, 0, time.FixedZone("CST", 8*60*60))
	tx := model.Transaction{
		Source:   "http-proxy",
		Observed: observed,
		Request: model.Message{
			Method: "POST",
			URL:    "https://user:secret@app.example.test:8443/api/items?token=visible&sort=asc",
			Headers: map[string]string{
				"X-Zeta":        "last",
				"authorization": "Bearer raw-token",
				"X-Alpha":       "first\nsecond",
				"Content-Type":  "application/json",
				"Cookie":        "session=visible-cookie",
			},
			Body: `{"password":"visible-request-body"}`,
		},
		Response: model.Message{
			Status: 500,
			Headers: map[string]string{
				"X-Zebra":      "response-last",
				"Set-Cookie":   "session=visible-response-cookie",
				"Content-Type": "text/plain",
				"Server":       "nginx/1.24.0",
				"X-Powered-By": "ExampleFramework/1.2.3",
			},
			Body: "<title>Index of /</title> visible-response-body",
		},
	}
	findings := e.Analyze(tx)
	var evidenceFinding model.Finding
	for _, finding := range findings {
		if finding.RuleID == "passive.directory-listing" {
			evidenceFinding = finding
			break
		}
	}
	if evidenceFinding.ID == "" {
		t.Fatalf("expected directory listing finding, got %#v", findings)
	}
	evidence := e.EvidenceForFinding(evidenceFinding.ID)
	if len(evidence) != 1 {
		t.Fatalf("expected one evidence capture, got %#v", evidence)
	}
	capture := evidence[0]
	if capture.FindingID != evidenceFinding.ID || capture.Source != "http-proxy" || !capture.ObservedAt.Equal(observed.UTC()) {
		t.Fatalf("unexpected capture metadata: %#v", capture)
	}
	wantRequest := "POST /api/items?token=visible&sort=asc HTTP/1.1\r\n" +
		"Host: app.example.test:8443\r\n" +
		"authorization: Bearer raw-token\r\n" +
		"Content-Type: application/json\r\n" +
		"Cookie: session=visible-cookie\r\n" +
		"X-Alpha: first\r\n" +
		"X-Alpha: second\r\n" +
		"X-Zeta: last\r\n\r\n" +
		`{"password":"visible-request-body"}`
	if capture.Request != wantRequest {
		t.Fatalf("unexpected complete request rendering:\nwant %q\n got %q", wantRequest, capture.Request)
	}
	wantResponse := "HTTP/1.1 500 Internal Server Error\r\n" +
		"Content-Type: text/plain\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"Set-Cookie: session=visible-response-cookie\r\n" +
		"X-Powered-By: ExampleFramework/1.2.3\r\n" +
		"X-Zebra: response-last\r\n\r\n" +
		"<title>Index of /</title> visible-response-body"
	if capture.Response != wantResponse {
		t.Fatalf("unexpected complete response rendering:\nwant %q\n got %q", wantResponse, capture.Response)
	}
	for _, raw := range []string{"raw-token", "visible-cookie", "visible-request-body", "visible-response-body"} {
		if !strings.Contains(capture.Request+capture.Response, raw) {
			t.Fatalf("full in-memory evidence must retain %q", raw)
		}
	}
	storedFindings, err := json.Marshal(e.Findings())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storedFindings), "raw-token") || strings.Contains(string(storedFindings), "visible-request-body") {
		t.Fatalf("raw evidence must not be embedded in persistent finding payload: %s", storedFindings)
	}

	for index := 1; index <= findingEvidencePerFindingLimit+1; index++ {
		next := tx
		next.Observed = observed.Add(time.Duration(index) * time.Minute)
		next.Response.Body = fmt.Sprintf("<title>Index of /</title> capture-%d", index)
		e.Analyze(next)
	}
	evidence = e.EvidenceForFinding(evidenceFinding.ID)
	if len(evidence) != findingEvidencePerFindingLimit {
		t.Fatalf("expected %d alternate captures, got %#v", findingEvidencePerFindingLimit, evidence)
	}
	for index, expected := range []string{"capture-2", "capture-3", "capture-4"} {
		if !strings.Contains(evidence[index].Response, expected) {
			t.Fatalf("expected oldest-first alternate capture %q at %d, got %#v", expected, index, evidence)
		}
	}

	byFinding := e.FindingEvidence()
	byFinding[evidenceFinding.ID][0].Request = "mutated by caller"
	if got := e.EvidenceForFinding(evidenceFinding.ID)[0].Request; got == "mutated by caller" {
		t.Fatal("finding evidence caller must receive a copy")
	}
}

func TestFindingEvidenceIsGloballyBounded(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var firstID, lastID string
	for index := 0; index < findingEvidenceHistoryLimit+2; index++ {
		findings := e.Analyze(model.Transaction{
			Observed: time.Date(2026, time.August, 3, 12, 0, index, 0, time.UTC),
			Request:  model.Message{Method: "GET", URL: fmt.Sprintf("https://app.example.test/evidence/%d", index)},
			Response: model.Message{Status: http.StatusInternalServerError, Headers: map[string]string{"Content-Type": "text/html"}, Body: fmt.Sprintf("<title>Index of /</title>; body-%d", index)},
		})
		for _, finding := range findings {
			if finding.RuleID != "passive.directory-listing" {
				continue
			}
			if index == 0 {
				firstID = finding.ID
			}
			if index == findingEvidenceHistoryLimit+1 {
				lastID = finding.ID
			}
		}
	}
	byFinding := e.FindingEvidence()
	if len(byFinding) != findingEvidenceHistoryLimit {
		t.Fatalf("expected globally bounded cache of %d finding IDs, got %d", findingEvidenceHistoryLimit, len(byFinding))
	}
	if _, exists := byFinding[firstID]; exists || firstID == "" {
		t.Fatalf("expected oldest evidence to be evicted, got %#v", byFinding[firstID])
	}
	if captures := byFinding[lastID]; len(captures) != 1 || !strings.Contains(captures[0].Response, fmt.Sprintf("body-%d", findingEvidenceHistoryLimit+1)) {
		t.Fatalf("expected newest evidence to remain, got %#v", captures)
	}
	if e.findingEvidenceBytes > findingEvidenceByteLimit || len(e.findingEvidenceOrder) > findingEvidenceHistoryLimit {
		t.Fatalf("evidence cache exceeded its configured bounds: bytes=%d order=%d", e.findingEvidenceBytes, len(e.findingEvidenceOrder))
	}
}

func TestFindingEvidenceConcurrentAnalyzeAndRead(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for index := 0; index < 20; index++ {
				e.Analyze(model.Transaction{
					Observed: time.Date(2026, time.August, 3, 14, worker, index, 0, time.UTC),
					Request:  model.Message{Method: "GET", URL: fmt.Sprintf("https://app.example.test/concurrent/%d/%d", worker, index)},
					Response: model.Message{Status: http.StatusInternalServerError, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<title>Index of /</title> captured"},
				})
				_ = e.FindingEvidence()
			}
		}()
	}
	for reader := 0; reader < 4; reader++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for index := 0; index < 50; index++ {
				for findingID := range e.FindingEvidence() {
					_ = e.EvidenceForFinding(findingID)
				}
			}
		}()
	}
	close(start)
	group.Wait()
	if captures := e.FindingEvidence(); len(captures) == 0 {
		t.Fatal("expected concurrent matching traffic to retain evidence")
	}
}
