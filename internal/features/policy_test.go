package features

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPolicyPersistsEditableFeaturesAndRejectsLockedOnes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	if err := os.WriteFile(path, []byte("features:\n  passive.sqli_probe: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Enabled("passive.sqli_probe") {
		t.Fatal("expected configured safe feature to be disabled")
	}
	if err := policy.Set("passive.sqli_probe", true); err != nil {
		t.Fatal(err)
	}
	if !policy.Enabled("passive.sqli_probe") {
		t.Fatal("expected editable feature to update")
	}
	if !policy.Enabled("passive.cdn_detection") || !policy.Enabled("passive.sensitive_info") {
		t.Fatal("expected passive edge detectors to default to enabled")
	}
	if !policy.Enabled("passive.hfinger") {
		t.Fatal("expected HFinger MITM detection to default to enabled")
	}
	if !policy.Enabled("desktop.clear_previous_results_on_start") {
		t.Fatal("expected prior-result clearing to default to enabled")
	}
	if err := policy.Set("desktop.clear_previous_results_on_start", false); err != nil || policy.Enabled("desktop.clear_previous_results_on_start") {
		t.Fatalf("expected prior-result clearing setting to persist as disabled, got %v", err)
	}
	if err := policy.Set("passive.sensitive_info", false); err != nil || policy.Enabled("passive.sensitive_info") {
		t.Fatalf("expected sensitive information master switch to persist as disabled, got %v", err)
	}
	if err := policy.SetSQLiTechniques(true, false, true); err != nil || !policy.SQLiErrorEnabled() || policy.SQLiBooleanEnabled() || !policy.SQLiTimeEnabled() {
		t.Fatalf("expected independent SQLi technique settings to update, got error=%v boolean=%v time=%v err=%v", policy.SQLiErrorEnabled(), policy.SQLiBooleanEnabled(), policy.SQLiTimeEnabled(), err)
	}
	if err := policy.Set("locked.ssrf_oob", true); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("expected locked SSRF feature rejection, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "passive.sqli_probe: true") || !strings.Contains(string(data), "passive.hfinger: true") || !strings.Contains(string(data), "passive.sensitive_info: false") || !strings.Contains(string(data), "desktop.clear_previous_results_on_start: false") || !strings.Contains(string(data), "passive_sqli_error_enabled: true") || !strings.Contains(string(data), "passive_sqli_boolean_enabled: false") || !strings.Contains(string(data), "passive_sqli_time_enabled: true") || strings.Contains(string(data), "sqli_level:") || strings.Contains(string(data), "locked.ssrf_oob") {
		t.Fatalf("unexpected persisted policy: %s", data)
	}
}

func TestPolicyMigratesLegacySQLiLevelToTechniqueSwitches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	if err := os.WriteFile(path, []byte("sqli_level: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.SQLiErrorEnabled() || !policy.SQLiBooleanEnabled() || policy.SQLiTimeEnabled() {
		t.Fatalf("legacy level 2 was not migrated: error=%v boolean=%v time=%v", policy.SQLiErrorEnabled(), policy.SQLiBooleanEnabled(), policy.SQLiTimeEnabled())
	}
}

func TestPolicyExcludedDomainsNormalizeMatchAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	contents := `excluded_domains:
  - " Example.COM. "
  - "*.Google.COM."
  - "example.com"
  - "LOCALHOST"
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.google.com", "example.com", "localhost"}
	if got := policy.ExcludedDomains(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected normalized exclusions: got %#v, want %#v", got, want)
	}
	for _, host := range []string{"example.com", "EXAMPLE.COM.", "maps.google.com", "LOCALHOST"} {
		if !policy.ExcludedHost(host) {
			t.Fatalf("expected %q to be excluded", host)
		}
	}
	for _, host := range []string{"google.com", "example.net", "https://example.com"} {
		if policy.ExcludedHost(host) {
			t.Fatalf("did not expect %q to be excluded", host)
		}
	}

	if err := policy.SetExcludedDomains([]string{"api.example.test", "*.assets.example.test", "API.EXAMPLE.TEST.", ""}); err != nil {
		t.Fatal(err)
	}
	want = []string{"*.assets.example.test", "api.example.test"}
	if got := policy.ExcludedDomains(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected updated exclusions: got %#v, want %#v", got, want)
	}
	// The caller must receive a copy rather than the live policy slice.
	copy := policy.ExcludedDomains()
	copy[0] = "modified.example.test"
	if got := policy.ExcludedDomains(); !reflect.DeepEqual(got, want) {
		t.Fatalf("excluded domain result must be copied, got %#v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if text := string(data); !strings.Contains(text, "excluded_domains:") || !strings.Contains(text, "*.assets.example.test") || !strings.Contains(text, "api.example.test") {
		t.Fatalf("exclusions were not persisted: %s", text)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.ExcludedDomains(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reloaded exclusions: got %#v, want %#v", got, want)
	}
}

func TestPolicyExcludedDomainsRejectInvalidValuesWithoutChangingPolicy(t *testing.T) {
	policy, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SetExcludedDomains([]string{"keep.example.test"}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"https://example.test",
		"example.test/path",
		"example.test:443",
		"example test",
		"example..test",
		"*.example.[test",
		"-bad.example.test",
	} {
		if err := policy.SetExcludedDomains([]string{value}); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
		if got := policy.ExcludedDomains(); !reflect.DeepEqual(got, []string{"keep.example.test"}) {
			t.Fatalf("invalid update %q changed policy: %#v", value, got)
		}
	}
	if got, err := NormalizeExcludedDomains([]string{"2001:DB8::1", "127.0.0.1", "*.example.test"}); err != nil || !reflect.DeepEqual(got, []string{"*.example.test", "127.0.0.1", "2001:db8::1"}) {
		t.Fatalf("expected IP literals and glob to normalize, got %#v, %v", got, err)
	}
}

func TestPolicyRejectsInvalidPersistedExcludedDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	if err := os.WriteFile(path, []byte("excluded_domains:\n  - https://example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "排除域名") {
		t.Fatalf("expected persisted invalid exclusion error, got %v", err)
	}
}

func TestPolicyExcludedSuffixesNormalizeMatchAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	contents := "excluded_suffixes:\n  - \" PNG \"\n  - \".png\"\n  - \" css， .Tar.Gz；SVG\\n \"\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".css", ".png", ".svg", ".tar.gz"}
	if got := policy.ExcludedSuffixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected normalized suffix exclusions: got %#v, want %#v", got, want)
	}
	for _, urlPath := range []string{"/assets/LOGO.PNG", "/archives/backup.TAR.GZ", "/styles/site.css", "/icons/mark.SvG"} {
		if !policy.ExcludedURLPath(urlPath) {
			t.Fatalf("expected %q to be excluded", urlPath)
		}
	}
	if policy.ExcludedURLPath("/api/download") {
		t.Fatal("a path without an excluded suffix must remain eligible")
	}

	if err := policy.SetExcludedSuffixes([]string{" JS, .css ", "tar.gz", ""}); err != nil {
		t.Fatal(err)
	}
	want = []string{".css", ".js", ".tar.gz"}
	if got := policy.ExcludedSuffixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected updated suffix exclusions: got %#v, want %#v", got, want)
	}
	copy := policy.ExcludedSuffixes()
	copy[0] = ".changed"
	if got := policy.ExcludedSuffixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("suffix exclusion result must be copied, got %#v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if text := string(data); !strings.Contains(text, "excluded_suffixes:") || !strings.Contains(text, ".tar.gz") || !strings.Contains(text, ".js") {
		t.Fatalf("suffix exclusions were not persisted: %s", text)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.ExcludedSuffixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reloaded suffix exclusions: got %#v, want %#v", got, want)
	}
}

func TestPolicyExcludedSuffixesRejectInvalidValuesWithoutChangingPolicy(t *testing.T) {
	policy, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SetExcludedSuffixes([]string{"keep"}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"https://example.test/file.png",
		"images/logo.png",
		"png css",
		".png?download=1",
		strings.Repeat("a", 256),
	} {
		if err := policy.SetExcludedSuffixes([]string{value}); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
		if got := policy.ExcludedSuffixes(); !reflect.DeepEqual(got, []string{".keep"}) {
			t.Fatalf("invalid update %q changed policy: %#v", value, got)
		}
	}
	if got, err := NormalizeExcludedSuffixes([]string{"png,css\n.tar.gz", " .PNG "}); err != nil || !reflect.DeepEqual(got, []string{".css", ".png", ".tar.gz"}) {
		t.Fatalf("expected comma/newline separated suffixes to normalize, got %#v, %v", got, err)
	}
}

func TestPolicyRejectsInvalidPersistedExcludedSuffixes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	if err := os.WriteFile(path, []byte("excluded_suffixes:\n  - https://example.test/file.png\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid persisted suffix exclusion to fail")
	}
}

func TestPolicyExcludedContentTypesUseDefaultsMatchAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	if err := os.WriteFile(path, []byte("features:\n  active.web_crawl: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, contentType := range []string{"image/jpeg; charset=utf-8", "audio/mpeg", "application/pdf", "application/zip"} {
		if !policy.ExcludedContentType(contentType) {
			t.Fatalf("expected default filter to match %q", contentType)
		}
	}
	if policy.ExcludedContentType("application/json") {
		t.Fatal("application/json must remain eligible by default")
	}

	if err := policy.SetExcludedContentTypes([]string{" TEXT/PLAIN ", "application/pdf; charset=utf-8", "*ZIP", "text/plain"}); err == nil {
		t.Fatal("configured patterns must not accept response parameters")
	}
	if err := policy.SetExcludedContentTypes([]string{" TEXT/PLAIN ", "*ZIP", "text/plain"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"*zip", "text/plain"}
	if got := policy.ExcludedContentTypes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected normalized Content-Type filters: got %#v, want %#v", got, want)
	}
	for _, contentType := range []string{"text/plain; charset=utf-8", "application/zip"} {
		if !policy.ExcludedContentType(contentType) {
			t.Fatalf("expected configured filter to match %q", contentType)
		}
	}
	if policy.ExcludedContentType("image/png") {
		t.Fatal("replaced Content-Type filters must take effect immediately")
	}

	copy := policy.ExcludedContentTypes()
	copy[0] = "changed"
	if got := policy.ExcludedContentTypes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Content-Type result must be copied, got %#v", got)
	}
	if err := policy.SetExcludedContentTypes(nil); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.ExcludedContentTypes(); len(got) != 0 {
		t.Fatalf("explicitly cleared Content-Type filters must persist, got %#v", got)
	}
}

func TestPolicyExcludedContentTypesRejectInvalidValuesWithoutChangingPolicy(t *testing.T) {
	policy, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SetExcludedContentTypes([]string{"application/json"}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"image / *", "https://example.test/image/png", "*", "image/png/*", "application/pdf; charset=utf-8", "*zip/png"} {
		if err := policy.SetExcludedContentTypes([]string{value}); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
		if got := policy.ExcludedContentTypes(); !reflect.DeepEqual(got, []string{"application/json"}) {
			t.Fatalf("invalid update %q changed policy: %#v", value, got)
		}
	}
}

func TestPolicySwaggerExcludedPathsUsePrefixSemantics(t *testing.T) {
	policy, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SetSwaggerExcludedPaths([]string{"/js"}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		prefix string
		want   bool
	}{
		// Root is never excluded so site-root documentation paths remain probed.
		{"", false},
		{"/", false},
		// Exact and nested descendants of /js are excluded.
		{"/js", true},
		{"/js/123", true},
		{"/js/v1/swagger.json", true},
		// Segment boundary: /json and unrelated paths are NOT excluded.
		{"/json", false},
		{"/json/v1/swagger.json", false},
		{"/admin", false},
		{"/foo/js", false},
	}
	for _, tc := range cases {
		if got := policy.SwaggerExcludedPath(tc.prefix); got != tc.want {
			t.Fatalf("SwaggerExcludedPath(%q) = %v, want %v", tc.prefix, got, tc.want)
		}
	}
}

func TestPolicySwaggerExcludedPathsSupportGlobsAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	policy, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SetSwaggerExcludedPaths([]string{"/assets/**", "/static/*"}); err != nil {
		t.Fatal(err)
	}
	if got := policy.SwaggerExcludedPaths(); !reflect.DeepEqual(got, []string{"/assets/**", "/static/*"}) {
		t.Fatalf("expected swagger excluded paths to persist, got %#v", got)
	}
	// /assets/** matches the base directory and everything beneath it.
	if !policy.SwaggerExcludedPath("/assets") || !policy.SwaggerExcludedPath("/assets/index-C_HOOOpe.js") {
		t.Fatal("expected /assets/** to exclude /assets and nested paths")
	}
	// /static/* matches one segment beneath /static but not deeper nesting.
	if !policy.SwaggerExcludedPath("/static/app") {
		t.Fatal("expected /static/* to exclude /static/app")
	}
	if policy.SwaggerExcludedPath("/static/app/v1") {
		t.Fatal("expected /static/* to NOT cross segment boundary into /static/app/v1")
	}
	// Reload to confirm on-disk persistence.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.SwaggerExcludedPaths(); !reflect.DeepEqual(got, []string{"/assets/**", "/static/*"}) {
		t.Fatalf("expected swagger excluded paths to reload from disk, got %#v", got)
	}
}

func TestPolicyMigratesLegacySwaggerExcludedPathsToFileProbeField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "features.yaml")
	legacy := "swagger_excluded_paths:\n  - /js\n  - /assets/**\nfeatures: {}\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := Load(path)
	if err != nil {
		t.Fatalf("legacy swagger_excluded_paths must still load: %v", err)
	}
	if got := policy.SwaggerExcludedPaths(); !reflect.DeepEqual(got, []string{"/assets/**", "/js"}) {
		t.Fatalf("expected legacy paths to migrate into the new field, got %#v", got)
	}
	if err := policy.SetSwaggerExcludedPaths([]string{"/js"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "swagger_excluded_paths:") {
		t.Fatalf("legacy swagger_excluded_paths key must be dropped after save, got %s", text)
	}
	if !strings.Contains(text, "file_probe_excluded_paths:") {
		t.Fatalf("expected file_probe_excluded_paths key in saved file, got %s", text)
	}
}
