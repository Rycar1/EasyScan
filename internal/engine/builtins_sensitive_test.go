package engine

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/model"
)

func TestSensitiveFileContentSignaturesAreValidated(t *testing.T) {
	for _, test := range []struct {
		name   string
		path   string
		status int
		body   string
	}{
		{name: "git-path-only", path: "/site/.git/HEAD", status: 200, body: "generic application page"},
		{name: "svn-500-echo", path: "/site/.svn/entries", status: 500, body: "requested /site/.svn/entries"},
		{name: "idea-500-echo", path: "/site/.idea/workspace.xml", status: 500, body: "requested /site/.idea/workspace.xml"},
		{name: "env-placeholder", path: "/site/.env", status: 200, body: "not an environment file"},
	} {
		t.Run("negative-"+test.name, func(t *testing.T) {
			parsed, _ := url.Parse("https://app.example.test" + test.path)
			findings := sensitiveFileFindings(model.Transaction{Response: model.Message{Status: test.status, Body: test.body}}, parsed)
			if len(findings) != 0 {
				t.Fatalf("path/status-only response must not be reported: %#v", findings)
			}
		})
	}
}

func TestSensitiveFileDetectionIsNotPassive(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings := e.Analyze(model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/site/.git/HEAD"},
		Response: model.Message{Status: 200, Body: "ref: refs/heads/main\n"},
	})
	if containsRule(findings, "passive.exposure.git-repository") {
		t.Fatalf("sensitive file exposure must not be reported by passive analysis, got %#v", findings)
	}
}

func TestSensitiveInformationDetectionUsesLowNoiseSignatures(t *testing.T) {
	cfg := config.Default()
	cfg.Scope.DenyHosts = nil
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		"-----BEGIN PRIVATE KEY-----",
		"AKIAABCDEFGHIJKLMNOP",
		"LTAI5tExampleAccessKey123",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2",
		"jdbc:mysql://db.internal:3306/app?user=app&password=secret",
		"client_secret=correct-horse-battery-staple",
		"admin@example.com",
		"13800138000",
		"at com.example.Service.run(Service.java:42)",
	}, "\n")
	findings := e.Analyze(model.Transaction{
		Request:  model.Message{Method: http.MethodGet, URL: "https://app.example.test/debug"},
		Response: model.Message{Status: http.StatusOK, Body: body},
	})
	for _, rule := range []string{
		"passive.exposure.private-key",
		"passive.exposure.aws-access-key",
		"passive.exposure.aliyun-access-key",
		"passive.exposure.github-token",
		"passive.exposure.jwt",
		"passive.exposure.database-connection",
		"passive.exposure.application-secret",
		"passive.exposure.stack-trace",
		"passive.information.email-address",
		"passive.information.phone-number",
	} {
		if !containsRule(findings, rule) {
			t.Errorf("expected %s, got %#v", rule, findings)
		}
	}

	parsed, _ := url.Parse("https://app.example.test/docs")
	placeholderFindings := sensitiveInformationFindings(model.Transaction{Response: model.Message{Status: 200, Body: `{"password":"password","token":"your_token","type":"string"}`}}, parsed, func(string) bool { return true })
	if containsRule(placeholderFindings, "passive.exposure.application-secret") {
		t.Fatalf("documentation placeholders must not become secret findings: %#v", placeholderFindings)
	}

	conservativePlaceholders := strings.Join([]string{
		`password=xxxxxxxx`,
		`api_key=test123`,
		`secret=<your-key>`,
		`token=xxxx-xxxx-xxxx`,
	}, "\n")
	conservativeFindings := sensitiveInformationFindings(model.Transaction{Response: model.Message{Status: 200, Body: conservativePlaceholders}}, parsed, func(string) bool { return true })
	if containsRule(conservativeFindings, "passive.exposure.application-secret") {
		t.Fatalf("common placeholder patterns must not be reported as secrets: %#v", conservativeFindings)
	}
}

func TestHighValueCloudTokenDetection(t *testing.T) {
	parsed, _ := url.Parse("https://app.example.test/debug")
	// Build provider-shaped fixtures at runtime so GitHub push protection does not
	// mistake these intentionally synthetic test values for real credentials.
	slackFixture := strings.Join([]string{
		"xoxb",
		"1234567890123",
		"1234567890123",
		"abcdefghij1234567890abcd",
	}, "-")
	stripeFixture := strings.Join([]string{
		"sk",
		"live",
		"abcDEF1234567890abcdefghij",
	}, "_")
	for _, test := range []struct {
		name string
		body string
		rule string
	}{
		{name: "google-api-key", body: "key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567", rule: "passive.exposure.google-api-key"},
		{name: "slack-token", body: slackFixture, rule: "passive.exposure.slack-token"},
		{name: "stripe-key", body: stripeFixture, rule: "passive.exposure.stripe-key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			findings := sensitiveInformationFindings(model.Transaction{Response: model.Message{Status: 200, Body: test.body}}, parsed, func(string) bool { return true })
			if !containsRule(findings, test.rule) {
				t.Fatalf("expected %s for body %q, got %#v", test.rule, test.body, findings)
			}
		})
	}
}

func TestLiveVulinboxSensitiveCoverage(t *testing.T) {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("EASYSCAN_VULINBOX_BASE")), "/")
	if baseURL == "" {
		t.Skip("set EASYSCAN_VULINBOX_BASE to run the local Vulinbox sensitive-data regression")
	}
	tests := []struct {
		name      string
		path      string
		wantRules []string
		forbidden []string
	}{
		{name: "git-head", path: "/git/website/.git/HEAD", forbidden: []string{"passive.exposure.git-repository"}},
		{name: "git-config", path: "/git/website/.git/config", forbidden: []string{"passive.exposure.git-repository"}},
		{name: "git-index", path: "/git/website/.git/index", forbidden: []string{"passive.exposure.git-repository"}},
		{name: "missing-svn", path: "/git/website/.svn/entries", forbidden: []string{"passive.exposure.svn-metadata"}},
		{name: "missing-idea", path: "/git/website/.idea/workspace.xml", forbidden: []string{"passive.exposure.idea-project"}},
		{name: "swagger-sensitive-info", path: "/sensitive/v2/swagger.json", wantRules: []string{"passive.api-documentation", "passive.information.email-address"}},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := client.Get(baseURL + test.path) // #nosec G107 -- explicit local integration target
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			cfg := config.Default()
			cfg.Scope.DenyHosts = nil
			e, engineErr := New(cfg)
			if engineErr != nil {
				t.Fatal(engineErr)
			}
			findings := e.Analyze(model.Transaction{
				Source:   model.SourceHTTPProxy,
				Request:  model.Message{Method: http.MethodGet, URL: baseURL + test.path},
				Response: model.Message{Status: response.StatusCode, Headers: map[string]string{"Content-Type": response.Header.Get("Content-Type")}, Body: string(body)},
			})
			for _, rule := range test.wantRules {
				if !containsRule(findings, rule) {
					t.Errorf("status=%d expected %s, got %#v", response.StatusCode, rule, findings)
				}
			}
			for _, rule := range test.forbidden {
				if containsRule(findings, rule) {
					t.Errorf("status=%d unexpected %s: %#v", response.StatusCode, rule, findings)
				}
			}
		})
	}
}

func TestEnvironmentFileRejectsHTMLFallback(t *testing.T) {
	htmlFallback := strings.Join([]string{
		`<!DOCTYPE html>`,
		`<html lang="zh-CN"><head><title>登录 - Rycarl's blog</title>`,
		`<script>window.__CONFIG__={apiKey="abcd1234",csrfToken="ffee"};</script>`,
		`<a href="/login?token=abcd&secret=zz">go</a></head><body></body></html>`,
	}, "\n")
	for _, path := range []string{
		"/apis/.env",
		"/apis/api.summary.summaraidgpt.lik.cc/v1alpha1/.env.production",
	} {
		parsed, _ := url.Parse("http://blog.example.test" + path)
		tx := model.Transaction{Response: model.Message{
			Status:  200,
			Headers: map[string]string{"Content-Type": "text/html; charset=utf-8"},
			Body:    htmlFallback,
		}}
		if findings := sensitiveFileFindings(tx, parsed); containsRule(findings, "passive.exposure.environment-file") {
			t.Fatalf("HTML SPA fallback at %s must not be reported as .env leak: %#v", path, findings)
		}
	}
}

func TestEnvironmentFileStillDetectsRealDotenv(t *testing.T) {
	dotenv := strings.Join([]string{
		"APP_ENV=production",
		"DB_PASSWORD=s3cr3t-value",
		"REDIS_URL=redis://127.0.0.1:6379",
		"AWS_SECRET_ACCESS_KEY=AKIAEXAMPLEKEY1234567890",
	}, "\n")
	parsed, _ := url.Parse("http://app.example.test/.env")
	tx := model.Transaction{Response: model.Message{
		Status:  200,
		Headers: map[string]string{"Content-Type": "text/plain; charset=utf-8"},
		Body:    dotenv,
	}}
	if findings := sensitiveFileFindings(tx, parsed); !containsRule(findings, "passive.exposure.environment-file") {
		t.Fatalf("genuine plaintext .env must still be reported: %#v", findings)
	}
}

func TestIDEAProjectRejectsHTMLFallback(t *testing.T) {
	htmlFallback := strings.Join([]string{
		`<!DOCTYPE html>`,
		`<html lang="zh-CN"><head><title>404 - /apis/.idea/workspace.xml</title></head>`,
		`<body><div id="app" data-config="&lt;project&gt;&lt;component&gt;"></div>`,
		`<script>var tpl="<project><component name='x'/></project>";</script></body></html>`,
	}, "\n")
	parsed, _ := url.Parse("http://blog.example.test/apis/.idea/workspace.xml")
	tx := model.Transaction{Response: model.Message{
		Status:  200,
		Headers: map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:    htmlFallback,
	}}
	if findings := sensitiveFileFindings(tx, parsed); containsRule(findings, "passive.exposure.idea-project") {
		t.Fatalf("HTML fallback echoing .idea tokens must not be reported: %#v", findings)
	}
}

func TestIDEAProjectStillDetectsRealXML(t *testing.T) {
	ideaXML := strings.Join([]string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<project version="4">`,
		`  <component name="ProjectModuleManager">`,
		`    <modules><module filepath="$PROJECT_DIR$/app.iml" /></modules>`,
		`  </component>`,
		`</project>`,
	}, "\n")
	parsed, _ := url.Parse("http://app.example.test/.idea/modules.xml")
	tx := model.Transaction{Response: model.Message{
		Status:  200,
		Headers: map[string]string{"Content-Type": "application/xml"},
		Body:    ideaXML,
	}}
	if findings := sensitiveFileFindings(tx, parsed); !containsRule(findings, "passive.exposure.idea-project") {
		t.Fatalf("genuine IDEA project XML must still be reported: %#v", findings)
	}
}

func TestEnvironmentFileRejectsHaloLoginFallback(t *testing.T) {
	haloLogin := strings.Join([]string{
		`<!DOCTYPE html>`,
		`<html lang="zh-CN">`,
		`  <head>`,
		`    <meta charset="UTF-8" />`,
		`    <title>登录 - Rycarl's little blog</title>`,
		`    <script type="text/javascript">`,
		`      const publicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAi0jaQ172cZdLfha7k5ZXm7a";`,
		`      function encryptPassword(password) { return password; }`,
		`    </script>`,
		`  </head>`,
		`  <body class="gateway-page">`,
		`    <form name="login-form" id="login-form" action="/login" method="post">`,
		`      <input type="hidden" name="_csrf" value="mxKfg_1Q-Lq8gtwIoAD4t0qfDSvGPgxsq1NDAJENjd5" />`,
		`    </form>`,
		`  </body>`,
		`</html>`,
	}, "\n")
	parsed, _ := url.Parse("http://blog.rycarl.cn:80/apis/api.summary.summaraidgpt.lik.cc/v1alpha1/.env")
	tx := model.Transaction{Response: model.Message{
		Status: 200,
		Headers: map[string]string{
			"Content-Type":     "text/html",
			"Server":           "nginx",
			"Content-Language": "zh-CN",
		},
		Body: haloLogin,
	}}
	if findings := sensitiveFileFindings(tx, parsed); containsRule(findings, "passive.exposure.environment-file") {
		t.Fatalf("Halo SPA login fallback served at .env path must not be reported as env leak: %#v", findings)
	}
}

func containsRule(findings []model.Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}
