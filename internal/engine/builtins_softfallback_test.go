package engine

import (
	"net/url"
	"strings"
	"testing"

	"github.com/example/easyscan/internal/model"
)

// htmlSoft404 renders a realistic SPA / soft-404 HTML page that echoes the
// requested path and embeds tokens which naive substring checks might mistake
// for the real artifact (DIRC, refs/, <project>, SQL keywords, etc.).
func htmlSoft404(path string) string {
	return strings.Join([]string{
		`<!DOCTYPE html>`,
		`<html lang="zh-CN"><head><meta charset="utf-8">`,
		`<title>404 Not Found - ` + path + `</title>`,
		`<script>window.__ROUTE__="` + path + `";var hint="DIRC refs/heads/main ref: create table insert into <project><component>";</script>`,
		`</head><body><div id="app">page not found: ` + path + `</div>`,
		`<a href="/login?token=abcd1234&secret=zzzz">home</a></body></html>`,
	}, "\n")
}

func htmlHeaders() map[string]string {
	return map[string]string{"Content-Type": "text/html; charset=utf-8", "Server": "nginx"}
}

// TestSensitiveFileRejectsSoft200Fallbacks feeds each sensitive-file rule a
// path that matches its trigger but whose 200 body is an HTML soft-404 / SPA
// catch-all. None may be reported: every rule is gated on a content signature,
// not merely the path + status. This is the primary false-positive contract.
func TestSensitiveFileRejectsSoft200Fallbacks(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		forbidden   string
		contentType string
		body        string
	}{
		{
			name:      "git-index-html-200",
			path:      "/app/.git/index",
			forbidden: "passive.exposure.git-repository",
			body:      htmlSoft404("/app/.git/index"),
		},
		{
			name:      "git-head-html-200",
			path:      "/app/.git/HEAD",
			forbidden: "passive.exposure.git-repository",
			body:      htmlSoft404("/app/.git/HEAD"),
		},
		{
			name:      "git-config-html-200",
			path:      "/app/.git/config",
			forbidden: "passive.exposure.git-repository",
			body:      htmlSoft404("/app/.git/config"),
		},
		{
			name:      "git-packed-refs-html-200",
			path:      "/app/.git/packed-refs",
			forbidden: "passive.exposure.git-repository",
			body:      htmlSoft404("/app/.git/packed-refs"),
		},
		{
			name:      "git-logs-head-html-200",
			path:      "/app/.git/logs/HEAD",
			forbidden: "passive.exposure.git-repository",
			body:      htmlSoft404("/app/.git/logs/HEAD"),
		},
		{
			name:      "svn-entries-html-200",
			path:      "/app/.svn/entries",
			forbidden: "passive.exposure.svn-metadata",
			body:      htmlSoft404("/app/.svn/entries"),
		},
		{
			name:      "svn-wcdb-html-200",
			path:      "/app/.svn/wc.db",
			forbidden: "passive.exposure.svn-metadata",
			body:      htmlSoft404("/app/.svn/wc.db"),
		},
		{
			name:      "idea-workspace-html-200",
			path:      "/app/.idea/workspace.xml",
			forbidden: "passive.exposure.idea-project",
			body:      htmlSoft404("/app/.idea/workspace.xml"),
		},
		{
			name:      "ds-store-html-200",
			path:      "/app/.DS_Store",
			forbidden: "passive.exposure.ds-store",
			body:      htmlSoft404("/app/.DS_Store"),
		},
		{
			name:      "backup-zip-html-200",
			path:      "/backup/site.zip",
			forbidden: "passive.exposure.backup-file",
			body:      htmlSoft404("/backup/site.zip"),
		},
		{
			name:      "database-dump-html-200",
			path:      "/db/dump.sql",
			forbidden: "passive.exposure.database-dump",
			body:      htmlSoft404("/db/dump.sql"),
		},
		{
			name:        "env-html-200",
			path:        "/config/.env",
			forbidden:   "passive.exposure.environment-file",
			contentType: "text/html; charset=utf-8",
			body:        htmlSoft404("/config/.env"),
		},
		{
			name:        "actuator-env-html-200",
			path:        "/actuator/env",
			forbidden:   "passive.exposure.springboot-actuator",
			contentType: "text/html; charset=utf-8",
			body:        htmlSoft404("/actuator/env"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse("https://app.example.test" + tc.path)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			headers := htmlHeaders()
			if tc.contentType != "" {
				headers["Content-Type"] = tc.contentType
			}
			tx := model.Transaction{Response: model.Message{Status: 200, Headers: headers, Body: tc.body}}
			findings := sensitiveFileFindings(tx, parsed)
			if containsRule(findings, tc.forbidden) {
				t.Fatalf("soft-200 HTML fallback at %s must not raise %s: %#v", tc.path, tc.forbidden, findings)
			}
		})
	}
}

// TestSensitiveFileRejectsJSONSoft200 covers APIs that answer every unknown
// path with a 200 JSON envelope (e.g. {"code":404,"msg":"not found"}), which
// must not satisfy actuator or other JSON-gated signatures.
func TestSensitiveFileRejectsJSONSoft200(t *testing.T) {
	jsonSoft404 := `{"code":404,"message":"resource not found","_links":null,"path":"/actuator/env"}`
	for _, path := range []string{"/actuator/env", "/actuator", "/actuator/beans", "/actuator/mappings"} {
		parsed, _ := url.Parse("https://api.example.test" + path)
		tx := model.Transaction{Response: model.Message{
			Status:  200,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    jsonSoft404,
		}}
		if findings := sensitiveFileFindings(tx, parsed); containsRule(findings, "passive.exposure.springboot-actuator") {
			t.Fatalf("JSON soft-404 at %s must not raise actuator finding: %#v", path, findings)
		}
	}
}

// TestActuatorHealthUpIsNotSensitive ensures a benign /actuator/health "UP"
// response (commonly public by design) is not treated as a sensitive endpoint
// leak, since health is not in the sensitive endpoint set.
func TestActuatorHealthUpIsNotSensitive(t *testing.T) {
	parsed, _ := url.Parse("https://api.example.test/actuator/health")
	tx := model.Transaction{Response: model.Message{
		Status:  200,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"status":"UP"}`,
	}}
	if findings := sensitiveFileFindings(tx, parsed); containsRule(findings, "passive.exposure.springboot-actuator") {
		t.Fatalf("/actuator/health UP must not be reported as sensitive: %#v", findings)
	}
}

// TestSensitiveFileStillDetectsGenuineArtifacts is the paired positive contract:
// with real content signatures each rule must still fire, proving the anti-FP
// guards above do not over-block.
func TestSensitiveFileStillDetectsGenuineArtifacts(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		want        string
		contentType string
		body        string
	}{
		{
			name: "git-head-ref",
			path: "/app/.git/HEAD",
			want: "passive.exposure.git-repository",
			body: "ref: refs/heads/main\n",
		},
		{
			name: "git-index-dirc",
			path: "/app/.git/index",
			want: "passive.exposure.git-repository",
			body: "DIRC\x00\x00\x00\x02\x00\x00\x00\x10rest-of-binary-index",
		},
		{
			name: "git-config",
			path: "/app/.git/config",
			want: "passive.exposure.git-repository",
			body: "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
		},
		{
			name: "svn-entries",
			path: "/app/.svn/entries",
			want: "passive.exposure.svn-metadata",
			body: "12\n\ndir\n1234\nhttps://svn.example.test/repo\n",
		},
		{
			name:        "database-dump",
			path:        "/db/dump.sql",
			want:        "passive.exposure.database-dump",
			contentType: "application/sql",
			body:        "-- MySQL dump 10.13\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, _ := url.Parse("https://app.example.test" + tc.path)
			headers := map[string]string{}
			if tc.contentType != "" {
				headers["Content-Type"] = tc.contentType
			}
			tx := model.Transaction{Response: model.Message{Status: 200, Headers: headers, Body: tc.body}}
			if findings := sensitiveFileFindings(tx, parsed); !containsRule(findings, tc.want) {
				t.Fatalf("genuine artifact at %s must raise %s: %#v", tc.path, tc.want, findings)
			}
		})
	}
}

// TestActuatorGenuineEnvStillDetected confirms a real actuator /env JSON body
// is still reported, pairing the JSON soft-404 negative above.
func TestActuatorGenuineEnvStillDetected(t *testing.T) {
	parsed, _ := url.Parse("https://api.example.test/actuator/env")
	tx := model.Transaction{Response: model.Message{
		Status:  200,
		Headers: map[string]string{"Content-Type": "application/vnd.spring-boot.actuator.v3+json"},
		Body:    `{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"PATH":{"value":"/usr/bin"}}}]}`,
	}}
	if findings := sensitiveFileFindings(tx, parsed); !containsRule(findings, "passive.exposure.springboot-actuator") {
		t.Fatalf("genuine actuator /env must still be reported: %#v", findings)
	}
}

// TestActuatorGenuineIndexStillDetected pairs the JSON soft-404 negative for the
// bare /actuator index: a real HAL index with a populated "_links" object must
// still fire even after tightening the check to reject "_links":null envelopes.
func TestActuatorGenuineIndexStillDetected(t *testing.T) {
	parsed, _ := url.Parse("https://api.example.test/actuator")
	tx := model.Transaction{Response: model.Message{
		Status:  200,
		Headers: map[string]string{"Content-Type": "application/vnd.spring-boot.actuator.v3+json"},
		Body:    `{"_links":{"self":{"href":"http://api/actuator","templated":false},"env":{"href":"http://api/actuator/env"}}}`,
	}}
	if findings := sensitiveFileFindings(tx, parsed); !containsRule(findings, "passive.exposure.springboot-actuator") {
		t.Fatalf("genuine actuator index must still be reported: %#v", findings)
	}
}

// TestDirectoryListingRejectsTitleMention guards the directory-listing rule
// against pages that merely mention "index of /" in prose rather than being an
// actual autoindex page.
func TestDirectoryListingRejectsTitleMention(t *testing.T) {
	body := `<!DOCTYPE html><html><head><title>Docs</title></head><body>` +
		`<p>To browse an Index of / directory you must enable autoindex.</p></body></html>`
	parsed, _ := url.Parse("https://docs.example.test/guide")
	tx := model.Transaction{Response: model.Message{Status: 200, Headers: htmlHeaders(), Body: body}}
	findings := builtins(tx, parsed, func(string) bool { return true })
	if containsRule(findings, "passive.directory-listing") {
		t.Fatalf("prose mentioning 'index of /' must not be a directory-listing finding: %#v", findings)
	}
}
