package fingerprint

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/easyscan/internal/model"
)

// fpTarget is a real, publicly reachable site that is NOT any of the systems
// our ruleset fingerprints. Any fingerprint match against these is, by
// definition, a false positive (with narrow documented exceptions listed in
// allow, e.g. a site legitimately fronted by a known CDN/language runtime).
type fpTarget struct {
	url   string
	label string
	allow []string // fingerprint names that are acceptable (true tech on the page)
}

// falsePositiveTargets is a spread of unrelated real sites: news, docs,
// static blogs, SaaS marketing pages and dev portals. None of them are RuoYi,
// Shiro, Discuz, WebLogic, etc., so our high-value app rules must stay silent.
func falsePositiveTargets() []fpTarget {
	return []fpTarget{
		{url: "https://example.com/", label: "IANA example"},
		{url: "https://www.iana.org/", label: "IANA"},
		{url: "https://httpbin.org/html", label: "httpbin html"},
		{url: "https://www.rust-lang.org/", label: "rust-lang"},
		{url: "https://go.dev/", label: "go.dev"},
		{url: "https://news.ycombinator.com/", label: "Hacker News"},
		{url: "https://www.wikipedia.org/", label: "Wikipedia portal"},
		{url: "https://developer.mozilla.org/en-US/", label: "MDN"},
		{url: "https://www.python.org/", label: "python.org"},
		{url: "https://www.debian.org/", label: "debian.org"},
		{url: "https://www.kernel.org/", label: "kernel.org"},
		{url: "https://www.cloudflare.com/", label: "cloudflare"},
		{url: "https://github.com/", label: "github.com"},
		{url: "https://stackoverflow.com/", label: "stackoverflow"},
		{url: "https://www.djangoproject.com/", label: "django site", allow: []string{"Django"}},
		{url: "https://laravel.com/", label: "laravel site", allow: []string{"Laravel"}},
		{url: "https://spring.io/", label: "spring.io"},
		{url: "https://www.apache.org/", label: "apache.org"},
		{url: "https://www.nginx.com/", label: "nginx.com"},
		{url: "https://www.php.net/", label: "php.net"},
		{url: "https://www.oracle.com/", label: "oracle.com"},
		{url: "https://www.elastic.co/", label: "elastic.co"},
		{url: "https://min.io/", label: "min.io"},
		{url: "https://www.jenkins.io/", label: "jenkins.io"},
		{url: "https://grafana.com/", label: "grafana.com"},
		{url: "https://about.gitlab.com/", label: "gitlab marketing"},

		// --- Search / portals ---
		{url: "https://www.google.com/", label: "Google"},
		{url: "https://www.bing.com/", label: "Bing"},
		{url: "https://duckduckgo.com/", label: "DuckDuckGo"},
		{url: "https://www.baidu.com/", label: "Baidu"},
		{url: "https://www.yahoo.com/", label: "Yahoo"},
		{url: "https://www.ecosia.org/", label: "Ecosia"},

		// --- News / media ---
		{url: "https://www.bbc.com/", label: "BBC"},
		{url: "https://www.nytimes.com/", label: "NYTimes"},
		{url: "https://www.theguardian.com/international", label: "Guardian"},
		{url: "https://www.reuters.com/", label: "Reuters"},
		{url: "https://techcrunch.com/", label: "TechCrunch"},
		{url: "https://arstechnica.com/", label: "Ars Technica"},
		{url: "https://www.wired.com/", label: "Wired"},
		{url: "https://www.economist.com/", label: "Economist"},

		// --- Dev / docs / tooling ---
		{url: "https://developer.apple.com/", label: "Apple Developer"},
		{url: "https://docs.microsoft.com/en-us/", label: "MS Learn"},
		{url: "https://learn.microsoft.com/en-us/", label: "MS Learn 2"},
		{url: "https://nodejs.org/en", label: "nodejs.org"},
		{url: "https://deno.com/", label: "deno.com"},
		{url: "https://www.typescriptlang.org/", label: "typescriptlang"},
		{url: "https://reactjs.org/", label: "reactjs"},
		{url: "https://vuejs.org/", label: "vuejs"},
		{url: "https://angular.io/", label: "angular"},
		{url: "https://svelte.dev/", label: "svelte"},
		{url: "https://tailwindcss.com/", label: "tailwind"},
		{url: "https://getbootstrap.com/", label: "bootstrap"},
		{url: "https://kubernetes.io/", label: "kubernetes.io"},
		{url: "https://www.docker.com/", label: "docker.com"},
		{url: "https://www.terraform.io/", label: "terraform"},
		{url: "https://prometheus.io/", label: "prometheus"},
		{url: "https://redis.io/", label: "redis.io"},
		{url: "https://www.postgresql.org/", label: "postgresql"},
		{url: "https://www.mysql.com/", label: "mysql.com"},
		{url: "https://www.mongodb.com/", label: "mongodb"},
		{url: "https://www.rabbitmq.com/", label: "rabbitmq"},
		{url: "https://kafka.apache.org/", label: "kafka"},
		{url: "https://www.ruby-lang.org/en/", label: "ruby-lang"},
		{url: "https://kotlinlang.org/", label: "kotlin"},
		{url: "https://www.scala-lang.org/", label: "scala"},
		{url: "https://elixir-lang.org/", label: "elixir"},
		{url: "https://www.lua.org/", label: "lua"},
		{url: "https://en.cppreference.com/w/", label: "cppreference"},
		{url: "https://pkg.go.dev/", label: "pkg.go.dev"},
		{url: "https://crates.io/", label: "crates.io"},
		{url: "https://pypi.org/", label: "pypi"},
		{url: "https://www.npmjs.com/", label: "npmjs"},
		{url: "https://readthedocs.org/", label: "readthedocs"},
		{url: "https://www.gnu.org/", label: "gnu.org"},
		{url: "https://www.freebsd.org/", label: "freebsd"},
		{url: "https://ubuntu.com/", label: "ubuntu.com"},
		{url: "https://www.centos.org/", label: "centos"},
		{url: "https://archlinux.org/", label: "archlinux"},

		// --- SaaS / product marketing ---
		{url: "https://slack.com/", label: "slack.com"},
		{url: "https://www.notion.so/", label: "notion"},
		{url: "https://www.figma.com/", label: "figma"},
		{url: "https://www.atlassian.com/", label: "atlassian"},
		{url: "https://www.dropbox.com/", label: "dropbox"},
		{url: "https://zoom.us/", label: "zoom"},
		{url: "https://stripe.com/", label: "stripe"},
		{url: "https://www.twilio.com/en-us", label: "twilio"},
		{url: "https://vercel.com/", label: "vercel"},
		{url: "https://www.netlify.com/", label: "netlify"},
		{url: "https://www.heroku.com/", label: "heroku"},
		{url: "https://www.digitalocean.com/", label: "digitalocean"},
		{url: "https://aws.amazon.com/", label: "aws"},
		{url: "https://azure.microsoft.com/en-us/", label: "azure"},
		{url: "https://cloud.google.com/", label: "gcp"},

		// --- Reference / community ---
		{url: "https://en.wikipedia.org/wiki/Main_Page", label: "Wikipedia EN"},
		{url: "https://archive.org/", label: "archive.org"},
		{url: "https://www.mozilla.org/en-US/", label: "mozilla.org"},
		{url: "https://www.w3.org/", label: "w3.org"},
		{url: "https://www.rfc-editor.org/", label: "rfc-editor"},
		{url: "https://letsencrypt.org/", label: "letsencrypt"},
		{url: "https://www.eff.org/", label: "eff.org"},
		{url: "https://creativecommons.org/", label: "creativecommons"},
		{url: "https://www.reddit.com/", label: "reddit"},
		{url: "https://medium.com/", label: "medium"},
		{url: "https://dev.to/", label: "dev.to"},
		{url: "https://hn.algolia.com/", label: "hn algolia"},

		// --- CN mainstream ---
		{url: "https://www.zhihu.com/", label: "zhihu"},
		{url: "https://juejin.cn/", label: "juejin"},
		{url: "https://segmentfault.com/", label: "segmentfault"},
		{url: "https://www.cnblogs.com/", label: "cnblogs"},
		{url: "https://gitee.com/", label: "gitee"},
		{url: "https://www.aliyun.com/", label: "aliyun"},
		{url: "https://cloud.tencent.com/", label: "tencent cloud"},
		{url: "https://www.qq.com/", label: "qq.com"},
		{url: "https://www.163.com/", label: "163"},
		{url: "https://www.sina.com.cn/", label: "sina"},
		{url: "https://www.douban.com/", label: "douban"},
		{url: "https://bilibili.com/", label: "bilibili"},
	}
}

// TestFingerprintFalsePositiveOnRealSites fetches a spread of real, unrelated
// sites and asserts our ruleset does not mislabel them. It only runs when
// EASYSCAN_NET_TESTS=1 (needs outbound network); otherwise it is skipped so it
// never breaks offline/CI runs.
func TestFingerprintFalsePositiveOnRealSites(t *testing.T) {
	if os.Getenv("EASYSCAN_NET_TESTS") != "1" {
		t.Skip("set EASYSCAN_NET_TESTS=1 to run live false-positive checks")
	}

	database, err := LoadHFinger(t.TempDir(), 40)
	if err != nil {
		t.Fatalf("load hfinger: %v", err)
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // FP survey against public sites
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	targets := falsePositiveTargets()
	tested := 0
	falsePositives := 0
	withAnyMatch := 0
	unreachable := 0
	fpNameCount := make(map[string]int)

	for _, target := range targets {
		tx, ok := fetchTransaction(t, client, target.url)
		if !ok {
			unreachable++
			t.Logf("[SKIP] %s (%s) unreachable", target.label, target.url)
			continue
		}
		tested++

		matches := database.MatchDetailsMulti([]model.Transaction{tx}, true, true)
		allNames := make([]string, 0, len(matches))
		var unexpected []string
		for _, m := range matches {
			allNames = append(allNames, m.Name)
			fpNameCount[m.Name]++
			if isInfraCategory(m.Category) || isInfraFingerprint(m.Name) || allowedFingerprint(target.allow, m.Name) {
				continue
			}
			unexpected = append(unexpected, m.Name)
		}
		if len(allNames) > 0 {
			withAnyMatch++
		}

		if len(unexpected) > 0 {
			falsePositives++
			t.Errorf("[FP] %s (%s) => %s", target.label, target.url, strings.Join(unexpected, ", "))
		} else if len(allNames) > 0 {
			t.Logf("[OK] %-22s clean; matched: %s", target.label, strings.Join(allNames, ", "))
		} else {
			t.Logf("[OK] %-22s clean; no fingerprint", target.label)
		}
	}

	if tested == 0 {
		t.Skip("no targets reachable; skipping FP assessment")
	}

	rate := float64(falsePositives) / float64(tested) * 100
	t.Logf("=== 样本总数: %d，有效: %d，不可达: %d ===", len(targets), tested, unreachable)
	t.Logf("=== 误报率: %.1f%% (误报 %d / 有效样本 %d) ===", rate, falsePositives, tested)
	t.Logf("=== 有指纹匹配的站点: %d/%d (其余为纯静态/未覆盖infra) ===", withAnyMatch, tested)
	t.Logf("=== 匹配到的指纹分布: %s ===", formatNameCounts(fpNameCount))
}

// formatNameCounts renders a deterministic "name(count)" summary of every
// fingerprint observed across the live survey, so the report shows real-world
// recognition coverage in addition to the false-positive verdict.
func formatNameCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"("+strconv.Itoa(counts[name])+")")
	}
	return strings.Join(parts, ", ")
}

func fetchTransaction(t *testing.T, client *http.Client, url string) (model.Transaction, bool) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return model.Transaction{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan fingerprint FP survey)")
	resp, err := client.Do(req)
	if err != nil {
		return model.Transaction{}, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	tx := model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: url},
		Response: model.Message{Status: resp.StatusCode, Headers: headers, Body: string(body)},
	}
	return tx, true
}

// isInfraCategory returns true for transport/infrastructure categories (CDN,
// WAF, DNS behavior, server, language runtime). Matches in these categories are
// generic capabilities that legitimately appear on arbitrary real sites, so
// they are excluded from the *application* false-positive assessment.
func isInfraCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "cdn", "waf", "dns", "dns-behavior", "server", "web-server",
		"language", "os", "network", "tls", "proxy":
		return true
	}
	return false
}

// isInfraFingerprint filters out infrastructure/CDN/language fingerprints that
// legitimately match arbitrary real sites (nginx, cloudflare, PHP, etc.).
// Those are not application false positives; the FP survey targets the
// high-value application rules.
func isInfraFingerprint(name string) bool {
	lower := strings.ToLower(name)
	infra := []string{
		"nginx", "apache httpd", "apache http server", "openresty", "cloudflare",
		"cloudfront", "akamai", "fastly", "iis", "microsoft-iis", "litespeed",
		"tengine", "caddy", "haproxy", "varnish", "envoy", "google frontend",
		"php", "asp.net", "java", "python", "node.js", "ruby", "express",
		"jsdelivr", "gunicorn", "werkzeug", "kestrel",
		// Hosting platforms / managed infrastructure that legitimately appear on
		// large public sites; not application-level findings for this survey.
		"amazon-ecs", "amazon s3", "aws", "kubesphere", "kubernetes", "vercel",
		"netlify", "heroku", "github pages", "gitlab", "wordpress", "drupal",
		"joomla", "cdn", "sucuri", "incapsula",
	}
	for _, k := range infra {
		if lower == k || strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

func allowedFingerprint(allow []string, name string) bool {
	for _, a := range allow {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}
