package nucleiprobe

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTagsForMapsFingerprintsToNucleiTags(t *testing.T) {
	cases := []struct {
		name         string
		fingerprints []string
		want         []string
	}{
		{
			name:         "direct product names normalize",
			fingerprints: []string{"WordPress", "nginx"},
			want:         []string{"nginx", "wordpress"},
		},
		{
			name:         "aliases expand and dedupe",
			fingerprints: []string{"Spring Boot", "Apache Tomcat"},
			want:         []string{"spring", "springboot", "tomcat"},
		},
		{
			name:         "punctuation and case stripped",
			fingerprints: []string{"ThinkPHP", "phpMyAdmin"},
			want:         []string{"phpmyadmin", "thinkphp"},
		},
		{
			name:         "empty and non-alnum ignored",
			fingerprints: []string{"", "   ", "###"},
			want:         []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TagsFor(tc.fingerprints)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("TagsFor(%v) = %v, want %v", tc.fingerprints, got, tc.want)
			}
		})
	}
}

func TestToFindingParsesNucleiJSONL(t *testing.T) {
	line := `{"template-id":"CVE-2021-44228","type":"http","host":"example.com","matched-at":"https://example.com:8080/api","response":"HTTP/1.1 200 OK\r\n\r\nhit","info":{"name":"Log4j RCE","severity":"critical","description":"Remote code execution","tags":["cve","log4j"]}}`
	var result nucleiResult
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		t.Fatalf("unmarshal nuclei jsonl: %v", err)
	}
	observedAt := time.Unix(1700000000, 0).UTC()
	finding := result.toFinding(observedAt)

	if finding.RuleID != "passive.nuclei.CVE-2021-44228" {
		t.Errorf("RuleID = %q", finding.RuleID)
	}
	if finding.Title != "Nuclei: Log4j RCE" {
		t.Errorf("Title = %q", finding.Title)
	}
	if finding.Severity != "critical" {
		t.Errorf("Severity = %q", finding.Severity)
	}
	if finding.URL != "https://example.com:8080/api" {
		t.Errorf("URL = %q", finding.URL)
	}
	if finding.ObservedAt != observedAt {
		t.Errorf("ObservedAt = %v", finding.ObservedAt)
	}
	if !reflect.DeepEqual(finding.Tags, []string{"cve", "log4j"}) {
		t.Errorf("Tags = %v", finding.Tags)
	}
}

func TestToFindingFallsBackWhenFieldsMissing(t *testing.T) {
	result := nucleiResult{TemplateID: "generic-detect", Host: "http://a.test"}
	finding := result.toFinding(time.Now())
	if finding.Title != "Nuclei: generic-detect" {
		t.Errorf("fallback Title = %q", finding.Title)
	}
	if finding.URL != "http://a.test" {
		t.Errorf("fallback URL = %q", finding.URL)
	}
	if finding.Severity != "info" {
		t.Errorf("fallback Severity = %q", finding.Severity)
	}
	if finding.Description == "" {
		t.Error("fallback Description should not be empty")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"Critical":      "critical",
		"HIGH":          "high",
		"medium":        "medium",
		"low":           "low",
		"informational": "info",
		"":              "info",
		"weird":         "info",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOriginKeyDefaultsPortsByScheme(t *testing.T) {
	cases := map[string]string{
		"https://a.test/path?q=1": "https://a.test:443",
		"http://b.test/x":         "http://b.test:80",
		"https://c.test:8443/y":   "https://c.test:8443",
		"http://d.test:8080":      "http://d.test:8080",
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := originKey(u); got != want {
			t.Errorf("originKey(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestSelectAssetMatchesPlatform(t *testing.T) {
	assets := []ghAsset{
		{Name: "nuclei_3.1.0_linux_amd64.zip", BrowserDownloadURL: "u1"},
		{Name: "nuclei_3.1.0_windows_amd64.zip", BrowserDownloadURL: "u2"},
		{Name: "nuclei_3.1.0_windows_arm64.zip", BrowserDownloadURL: "u3"},
		{Name: "checksums.txt", BrowserDownloadURL: "u4"},
	}
	asset, err := selectAsset(assets)
	if err != nil {
		t.Fatalf("selectAsset returned error: %v", err)
	}
	// The current test binary runs on windows/amd64 in this environment.
	if asset.Name == "" || asset.BrowserDownloadURL == "" {
		t.Fatalf("selectAsset returned empty asset: %+v", asset)
	}
}

func TestTruncateEvidenceBounds(t *testing.T) {
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	if got := truncateEvidence(string(long)); len(got) != 2048 {
		t.Errorf("truncateEvidence length = %d, want 2048", len(got))
	}
}

func TestTagsForMergesAndDedupesAcrossFingerprints(t *testing.T) {
	// Two fingerprints that both alias to "spring" plus a distinct one must
	// collapse to a sorted, de-duplicated tag set.
	got := TagsFor([]string{"Spring Boot", "Spring Cloud", "Nginx", "nginx"})
	want := []string{"nginx", "spring", "springboot"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TagsFor merge = %v, want %v", got, want)
	}
}

func TestTagsForUnknownFingerprintFallsBackToNormalizedToken(t *testing.T) {
	got := TagsFor([]string{"Acme Custom Portal 2024"})
	want := []string{"acmecustomportal2024"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TagsFor unknown = %v, want %v", got, want)
	}
}

func TestTagsForApacheHTTPServerMapsToApache(t *testing.T) {
	// The engine emits "Apache HTTP Server"; nuclei apache templates are tagged
	// "apache", not "apachehttpserver", so the alias must collapse it.
	cases := [][]string{
		{"Apache HTTP Server"},
		{"Apache httpd"},
		{"Apache"},
	}
	for _, fps := range cases {
		got := TagsFor(fps)
		if !reflect.DeepEqual(got, []string{"apache"}) {
			t.Fatalf("TagsFor(%v) = %v, want [apache]", fps, got)
		}
	}
}

func TestNormalizeTagStripsNonAlnum(t *testing.T) {
	cases := map[string]string{
		"Spring Boot":  "springboot",
		"ASP.NET":      "aspnet",
		"Node.js v18":  "nodejsv18",
		"  Redis  ":    "redis",
		"版本 nginx 1.0": "nginx10",
		"":             "",
	}
	for in, want := range cases {
		if got := normalizeTag(in); got != want {
			t.Errorf("normalizeTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSelectAssetExactOSArchBoundary(t *testing.T) {
	// Regression: strings.Contains(name, "arm") would also match an arm64
	// asset. selectAsset must match the exact "_<os>_<arch>." boundary.
	got, err := selectAssetFor("linux", "arm", []ghAsset{
		{Name: "nuclei_3.1.0_linux_arm64.zip", BrowserDownloadURL: "u-arm64"},
		{Name: "nuclei_3.1.0_linux_arm.zip", BrowserDownloadURL: "u-arm"},
	})
	if err != nil {
		t.Fatalf("selectAssetFor returned error: %v", err)
	}
	if got.BrowserDownloadURL != "u-arm" {
		t.Fatalf("selectAssetFor(linux/arm) = %q, want the arm (not arm64) asset", got.BrowserDownloadURL)
	}
}

func TestSelectAssetArm64NotMatchedByArm(t *testing.T) {
	// When only an arm64 asset exists, a 32-bit arm build must NOT select it.
	_, err := selectAssetFor("linux", "arm", []ghAsset{
		{Name: "nuclei_3.1.0_linux_arm64.zip", BrowserDownloadURL: "u-arm64"},
	})
	if err == nil {
		t.Fatal("selectAssetFor(linux/arm) must not match an arm64-only release")
	}
}

func TestSelectAssetRejectsNonMatchingPlatform(t *testing.T) {
	// Only linux/macOS assets present -> selectAsset must fail on any platform
	// that is neither, and specifically it must never return a checksums file.
	assets := []ghAsset{
		{Name: "nuclei_3.1.0_freebsd_amd64.zip", BrowserDownloadURL: "u1"},
		{Name: "nuclei_3.1.0_checksums.txt", BrowserDownloadURL: "u2"},
	}
	if _, err := selectAsset(assets); err == nil {
		t.Fatal("selectAsset should fail when no OS/arch match exists")
	}
}

func TestToFindingTruncatesLargeResponseEvidence(t *testing.T) {
	big := strings.Repeat("x", 4000)
	result := nucleiResult{TemplateID: "t", Response: big, Info: nucleiInfo{Name: "n", Severity: "high"}}
	finding := result.toFinding(time.Now())
	if len(finding.Evidence) != 2048 {
		t.Errorf("evidence length = %d, want 2048", len(finding.Evidence))
	}
	if finding.Severity != "high" {
		t.Errorf("severity = %q", finding.Severity)
	}
}

func TestTagsForDropsBroadFallbackTags(t *testing.T) {
	// Specific-product fingerprints that only normalize onto a broad technology
	// tag must be dropped from the fallback path to avoid running a flood of
	// unrelated nuclei templates against the host.
	cases := [][]string{
		{"天融信VPN设备"},
		{"网宿-CDN"},
		{"阿里云-CDN"},
		{"悟空CRM"},
		{"明源云ERP"},
		{"Java"},
		{"PHP"},
		{"Python"},
		{"Amazon"},
		{"Google"},
	}
	for _, fps := range cases {
		if got := TagsFor(fps); len(got) != 0 {
			t.Errorf("TagsFor(%v) = %v, want empty (broad tag dropped)", fps, got)
		}
	}
}

func TestTagsForKeepsSpecificProductFallback(t *testing.T) {
	// Specific product names that are not in the alias table must still fall
	// back to their normalized token (which matches a real nuclei product tag).
	cases := map[string]string{
		"Grafana":       "grafana",
		"GitLab":        "gitlab",
		"Zabbix":        "zabbix",
		"Nacos":         "nacos",
		"Elasticsearch": "elasticsearch",
	}
	for name, want := range cases {
		got := TagsFor([]string{name})
		if !reflect.DeepEqual(got, []string{want}) {
			t.Errorf("TagsFor(%q) = %v, want [%s]", name, got, want)
		}
	}
}

func TestTagsForVerifiedAliasesResolveToNucleiTags(t *testing.T) {
	// Newly added explicit aliases whose fingerprint token differs from the
	// nuclei tag must resolve to the verified (non-empty) nuclei tag. Each key
	// below is a real hfinger rule name.
	cases := map[string][]string{
		"泛微-EMobile":      {"ecology", "weaver"},
		"Weaver e-mobile": {"ecology", "weaver"},
		"Landray OA":      {"landray"},
		"JeecgBoot":       {"jeecg"},
		"RuoYi 若依":        {"ruoyi"},
		"XXL-JOB":         {"xxljob"},
		"Spring Boot":     {"spring", "springboot"},
	}
	for name, want := range cases {
		got := TagsFor([]string{name})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("TagsFor(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTagsForAliasWinsOverBroadDrop(t *testing.T) {
	// Middleware/web-server fingerprints are explicitly aliased even though the
	// tag also appears in broadTags: the human-verified alias must win so the
	// tag is emitted rather than dropped.
	for _, name := range []string{"Apache HTTP Server", "Nginx", "Microsoft IIS"} {
		if got := TagsFor([]string{name}); len(got) == 0 {
			t.Errorf("TagsFor(%q) = empty, want the aliased tag (alias must win over broad drop)", name)
		}
	}
}

func TestTagsForMixedDropsBroadKeepsSpecific(t *testing.T) {
	// A host fingerprinted as both a specific product and a broad category must
	// keep only the specific product tag.
	got := TagsFor([]string{"悟空CRM", "Grafana", "天融信VPN"})
	if !reflect.DeepEqual(got, []string{"grafana"}) {
		t.Fatalf("TagsFor mixed = %v, want [grafana]", got)
	}
}

func TestCleanVersionOutputStripsAnsiAndExtractsVersion(t *testing.T) {
	// nuclei prints its banner through the logger, so "-version" output is
	// colorized with ANSI codes, prefixed with "[INF]", and mixed with unrelated
	// directory lines. The cleaned result must be just the engine version.
	raw := "\x1b[34mINF\x1b[0m Nuclei Engine Version: v3.11.1\n" +
		"\x1b[34mINF\x1b[0m Nuclei Config Directory: C:\\Users\\AgiUser\\AppData\\Roaming\\nuclei\n" +
		"\x1b[34mINF\x1b[0m Nuclei Cache Directory: C:\\Users\\AgiUser\\AppData\\Local\\nuclei\n" +
		"\x1b[34mINF\x1b[0m PDCP Directory: C:\\Users\\AgiUser\\.pdcp\n"
	if got := cleanVersionOutput(raw); got != "v3.11.1" {
		t.Fatalf("cleanVersionOutput = %q, want %q", got, "v3.11.1")
	}
}

func TestCleanVersionOutputFallsBackWithoutBanner(t *testing.T) {
	// If nuclei ever changes its banner wording, fall back to the first
	// meaningful de-prefixed line rather than returning the raw colorized blob.
	// nuclei wraps the level tag as "[" + color + "INF" + reset + "]".
	raw := "[\x1b[34mINF\x1b[0m] v9.9.9\n"
	if got := cleanVersionOutput(raw); got != "v9.9.9" {
		t.Fatalf("cleanVersionOutput fallback = %q, want %q", got, "v9.9.9")
	}
}

func TestBuildTagIndexParsesInlineAndBlockTags(t *testing.T) {
	dir := t.TempDir()
	inline := "id: t1\ninfo:\n  name: A\n  tags: apache,cve,rce\nhttp: []\n"
	block := "id: t2\ninfo:\n  name: B\n  tags:\n    - nginx\n    - \"lfi\"\nhttp: []\n"
	notemplate := "id: t3\ninfo:\n  name: C\n  tags: nacos\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(inline), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte(block), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-yaml file must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "c.txt"), []byte(notemplate), 0o644); err != nil {
		t.Fatal(err)
	}

	idx := BuildTagIndex(dir)
	for _, want := range []string{"apache", "cve", "rce", "nginx", "lfi"} {
		if !idx.Has(want) {
			t.Errorf("index missing expected tag %q", want)
		}
	}
	if idx.Has("nacos") {
		t.Errorf("index must not include tags from non-yaml files")
	}
}

func TestTagIndexFilterDropsUnknownTags(t *testing.T) {
	idx := &TagIndex{tags: map[string]struct{}{"apache": {}, "nginx": {}}}
	got := idx.Filter([]string{"apache", "35", "nginx", "53"})
	if !reflect.DeepEqual(got, []string{"apache", "nginx"}) {
		t.Fatalf("Filter = %v, want [apache nginx]", got)
	}
}

func TestTagIndexFilterEmptyIndexPassesThrough(t *testing.T) {
	var idx *TagIndex
	in := []string{"apache", "35"}
	if got := idx.Filter(in); !reflect.DeepEqual(got, in) {
		t.Fatalf("nil index Filter = %v, want passthrough %v", got, in)
	}
	empty := &TagIndex{tags: map[string]struct{}{}}
	if got := empty.Filter(in); !reflect.DeepEqual(got, in) {
		t.Fatalf("empty index Filter = %v, want passthrough %v", got, in)
	}
}

func TestBuildTagIndexMissingDirIsEmpty(t *testing.T) {
	idx := BuildTagIndex(filepath.Join(t.TempDir(), "does-not-exist"))
	if idx == nil || idx.Size() != 0 {
		t.Fatalf("missing dir should yield empty index, got size %d", idx.Size())
	}
}

func TestTagsForVerifiedAliasGapsResolve(t *testing.T) {
	// Full fingerprint names whose normalized token carries a suffix
	// (Device/Console/OA/NC) must still resolve to the correct nuclei product
	// tag rather than falling through to a template-less token. Each target tag
	// was confirmed present in the real nuclei template library.
	cases := map[string][]string{
		"Seeyon 致远 OA":         {"seeyon"},
		"Tongda 通达 OA":         {"tongda"},
		"Yonyou NC":            {"yonyou"},
		"Yonyou U8/GRP-U8":     {"yonyou"},
		"WebLogic Console":     {"weblogic"},
		"Oracle WebLogic":      {"weblogic"},
		"Sangfor Device":       {"sangfor"},
		"Ruijie Device":        {"ruijie"},
		"Topsec Device":        {"topsec"},
		"SAP Netweaver":        {"netweaver"},
		"金蝶K/3 Cloud":          {"kingdee"},
		"iOffice(红帆oa)":        {"hongfan"},
		"Weaver e-office":      {"eoffice", "weaver"},
		"Spring Boot Actuator": {"spring", "springboot"},
		"Spring Cloud Gateway": {"spring"},
	}
	for name, want := range cases {
		got := TagsFor([]string{name})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("TagsFor(%q) = %v, want %v", name, got, want)
		}
	}
}
