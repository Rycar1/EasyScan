package fingerprint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/easyscan/internal/model"
)

const customHFingerRule = `rules:
  - id: custom-easyscan-console
    name: EasyScan Test Console
    category: cms
    match:
      strategy: score
      threshold: 80
      matchers:
        - type: header.contains
          key: X-EasyScan-Product
          value: console
          case_sensitive: false
          weight: 50
        - type: body.contains
          value: easyscan-console-root
          case_sensitive: false
          weight: 40
    negative:
      - type: body.contains
        value: documentation example
    metadata:
      references: ["https://example.test/easyscan-console"]
`

func TestHFingerLoadsCustomYAMLAndMatchesObservedResponse(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "custom.yaml")
	if err := os.WriteFile(filename, []byte(customHFingerRule), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := LoadHFinger(directory, 40)
	if err != nil {
		t.Fatal(err)
	}
	stats := database.Stats()
	if stats.BuiltinRules < 900 || stats.CustomFiles != 1 || stats.CustomRules != 1 || stats.FailedFiles != 0 {
		t.Fatalf("unexpected HFinger stats: %#v", stats)
	}
	matches := database.MatchDetails(model.Transaction{
		Request: model.Message{URL: "https://console.example.test/"},
		Response: model.Message{
			Status:  200,
			Headers: map[string]string{"X-EasyScan-Product": "CONSOLE", "Content-Type": "text/html"},
			Body:    "<html><title>Console</title>easyscan-console-root</html>",
		},
	}, true, true)
	if !containsFingerprintMatch(matches, "EasyScan Test Console") {
		t.Fatalf("custom HFinger rule did not match: %#v", matches)
	}
}

func TestHFingerIsolatesInvalidCustomFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "valid.yaml"), []byte(customHFingerRule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "broken.yaml"), []byte("rules: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := LoadHFinger(directory, 40)
	if err != nil {
		t.Fatal(err)
	}
	stats := database.Stats()
	if stats.CustomFiles != 1 || stats.CustomRules != 1 || stats.FailedFiles != 1 || len(stats.Errors) != 1 {
		t.Fatalf("invalid file was not isolated: %#v", stats)
	}
}

func TestHFingerRejectsBodyOnlyFingerprintOn404(t *testing.T) {
	directory := t.TempDir()
	rule := `
id: custom-discuz-reflection
name: Discuz
category: cms
match:
  strategy: any
  matchers:
    - type: body.contains
      value: discuzfiles.md5
metadata:
  references: ["https://example.test/discuz"]
`
	if err := os.WriteFile(filepath.Join(directory, "discuz.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := LoadHFinger(directory, 40)
	if err != nil {
		t.Fatal(err)
	}
	matches := database.MatchDetails(model.Transaction{
		Request:  model.Message{URL: "https://gateway.example.test/admin/discuzfiles.md5"},
		Response: model.Message{Status: 404, Body: "not found: /admin/discuzfiles.md5"},
	}, true, true)
	if containsFingerprintMatch(matches, "Discuz") {
		t.Fatalf("404 reflection became a Discuz fingerprint: %#v", matches)
	}
}

func TestHFingerFiltersLowValueLibraryLabels(t *testing.T) {
	for _, name := range []string{"jQuery", "Bootstrap", "Bootstrap-CDN", "GZIP encode", "GSE"} {
		if !lowValueHFingerProduct(name) {
			t.Fatalf("expected %q to be filtered", name)
		}
	}
}

func TestObservedTLSInfoMapsCapturedCertificateSummary(t *testing.T) {
	info := observedTLSInfo("subject=CN=console.example.test, O=Example; issuer=CN=Example Root; serial=42; dns=console.example.test; dns=*.example.test")
	if info.Subject != "CN=console.example.test, O=Example" || info.Issuer != "CN=Example Root" {
		t.Fatalf("unexpected TLS subject/issuer: %#v", info)
	}
	if len(info.DNSNames) != 2 || info.DNSNames[0] != "console.example.test" || info.DNSNames[1] != "*.example.test" {
		t.Fatalf("unexpected TLS DNS names: %#v", info.DNSNames)
	}
}

func TestObservedTLSInfoKeepsDelimitersInsideDistinguishedName(t *testing.T) {
	// A distinguished name legitimately contains "; " which must not be treated
	// as a field boundary; the tail after it belongs to the same subject value.
	info := observedTLSInfo("subject=CN=vpn.example.test; OU=Security; O=Example Corp; issuer=CN=Internal CA; dns=vpn.example.test")
	if info.Subject != "CN=vpn.example.test; OU=Security; O=Example Corp" {
		t.Fatalf("unexpected TLS subject: %q", info.Subject)
	}
	if info.Issuer != "CN=Internal CA" {
		t.Fatalf("unexpected TLS issuer: %q", info.Issuer)
	}
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "vpn.example.test" {
		t.Fatalf("unexpected TLS DNS names: %#v", info.DNSNames)
	}
}

func TestHFingerAcceptsCapturedTLSEvidenceOnErrorPage(t *testing.T) {
	directory := t.TempDir()
	rule := `
id: custom-tls-appliance
name: Example TLS Appliance
category: security-device
match:
  strategy: any
  matchers:
    - type: tls.cert.subject.contains
      value: Example TLS Appliance
metadata:
  references: ["https://example.test/tls-appliance"]
`
	if err := os.WriteFile(filepath.Join(directory, "tls.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := LoadHFinger(directory, 40)
	if err != nil {
		t.Fatal(err)
	}
	matches := database.MatchDetails(model.Transaction{
		Request: model.Message{URL: "https://appliance.example.test/missing"},
		Response: model.Message{
			Status:      404,
			Body:        "generic not found",
			Certificate: "subject=CN=Example TLS Appliance; issuer=CN=Example Root; dns=appliance.example.test",
		},
	}, true, true)
	if !containsFingerprintMatch(matches, "Example TLS Appliance") {
		t.Fatalf("captured TLS evidence should survive the error-page gate: %#v", matches)
	}
}

func TestHFingerRespectsCDNAndWAFFeatureGates(t *testing.T) {
	directory := t.TempDir()
	rules := `
rules:
  - id: custom-cdn-gate
    name: Example CDN
    category: cdn
    match:
      strategy: any
      matchers:
        - type: header.contains
          key: X-Example-CDN
          value: enabled
  - id: custom-waf-gate
    name: Example WAF
    category: waf
    match:
      strategy: any
      matchers:
        - type: header.contains
          key: X-Example-WAF
          value: enabled
`
	if err := os.WriteFile(filepath.Join(directory, "gates.yaml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := LoadHFinger(directory, 40)
	if err != nil {
		t.Fatal(err)
	}
	tx := model.Transaction{
		Request: model.Message{URL: "https://edge.example.test/"},
		Response: model.Message{Status: 200, Headers: map[string]string{
			"X-Example-CDN": "enabled",
			"X-Example-WAF": "enabled",
		}},
	}
	if matches := database.MatchDetails(tx, false, false); containsFingerprintMatch(matches, "CDN · Example CDN") || containsFingerprintMatch(matches, "WAF · Example WAF") {
		t.Fatalf("disabled CDN/WAF categories leaked into matches: %#v", matches)
	}
	matches := database.MatchDetails(tx, true, true)
	if !containsFingerprintMatch(matches, "CDN · Example CDN") || !containsFingerprintMatch(matches, "WAF · Example WAF") {
		t.Fatalf("enabled CDN/WAF categories did not match: %#v", matches)
	}
}

func TestHFingerBuiltinLanguageRulesMatchSessionCookies(t *testing.T) {
	database, err := LoadHFinger(t.TempDir(), 40)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		cookie string
		name   string
	}{
		{"PHPSESSID=abc123; path=/", "PHP"},
		{"JSESSIONID=9A1B2C3D; Path=/; HttpOnly", "Java"},
		{"ASP.NET_SessionId=lk3n2; path=/; HttpOnly", "ASP.NET"},
	}
	for _, tc := range cases {
		matches := database.MatchDetails(model.Transaction{
			Request: model.Message{URL: "https://app.example.test/"},
			Response: model.Message{
				Status:  200,
				Headers: map[string]string{"Set-Cookie": tc.cookie, "Content-Type": "text/html"},
			},
		}, true, true)
		if !containsFingerprintMatch(matches, tc.name) {
			t.Fatalf("language rule %q did not match cookie %q: %#v", tc.name, tc.cookie, matches)
		}
	}
}

func TestMatchDetailsMultiAggregatesResponses(t *testing.T) {
	directory := t.TempDir()
	rule := `rules:
  - id: custom-multi-response
    name: MultiResponse Product
    category: framework
    match:
      strategy: score
      threshold: 80
      probes:
        - id: home
          matchers:
            - type: header.contains
              key: X-Multi-Marker
              value: home
              weight: 50
        - id: notfound
          matchers:
            - type: body.contains
              value: multi-response-error-token
              weight: 50
    metadata:
      references: ["https://example.test/multi"]
`
	if err := os.WriteFile(filepath.Join(directory, "multi.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := LoadHFinger(directory, 40)
	if err != nil {
		t.Fatal(err)
	}
	home := model.Transaction{
		Request:  model.Message{URL: "https://multi.example.test/"},
		Response: model.Message{Status: 200, Headers: map[string]string{"X-Multi-Marker": "home"}},
	}
	notFound := model.Transaction{
		Request:  model.Message{URL: "https://multi.example.test/missing"},
		Response: model.Message{Status: 404, Body: "multi-response-error-token"},
	}
	if matches := database.MatchDetails(home, true, true); containsFingerprintMatch(matches, "MultiResponse Product") {
		t.Fatalf("single home response should not reach the threshold: %#v", matches)
	}
	matches := database.MatchDetailsMulti([]model.Transaction{home, notFound}, true, true)
	if !containsFingerprintMatch(matches, "MultiResponse Product") {
		t.Fatalf("aggregated responses did not reach the threshold: %#v", matches)
	}
}

func containsFingerprintMatch(matches []Match, name string) bool {
	for _, match := range matches {
		if match.Name == name {
			return true
		}
	}
	return false
}

// TestHFingerMatchesPHPFromRequestCookie verifies that cookie-based
// fingerprints stay stable when the server no longer re-issues Set-Cookie and
// the session cookie only travels on the request Cookie header. Without the
// request-cookie mirroring this recognition was non-deterministic across visits.
func TestHFingerMatchesPHPFromRequestCookie(t *testing.T) {
	database, err := LoadHFinger(t.TempDir(), 40)
	if err != nil {
		t.Fatal(err)
	}
	matches := database.MatchDetails(model.Transaction{
		Request: model.Message{
			URL:     "https://shop.example.test/index/index/getcookie.html",
			Headers: map[string]string{"Cookie": "PHPSESSID=deadbeef; think_lang=zh-cn"},
		},
		Response: model.Message{
			Status:  200,
			Headers: map[string]string{"Server": "nginx", "Content-Type": "text/html"},
			Body:    "<html><head><title>Shop</title></head><body>hi</body></html>",
		},
	}, true, true)
	if !containsFingerprintMatch(matches, "PHP") {
		t.Fatalf("PHP should be recognized from request Cookie PHPSESSID: %#v", matches)
	}
}

func TestRequestCookieNames(t *testing.T) {
	got := requestCookieNames(map[string]string{
		"Cookie":       "PHPSESSID=abc; think_lang=zh-cn; PHPSESSID=dup",
		"Content-Type": "text/html",
	})
	want := []string{"PHPSESSID", "think_lang"}
	if len(got) != len(want) {
		t.Fatalf("requestCookieNames = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("requestCookieNames = %#v, want %#v", got, want)
		}
	}
}
