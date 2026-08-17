package engine

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/example/easyscan/internal/model"
)

var (
	gitCommitPattern       = regexp.MustCompile(`(?i)^[0-9a-f]{40}$`)
	gitPackedRefsPattern   = regexp.MustCompile(`(?m)^[0-9a-fA-F]{40} refs/`)
	gitLogsHeadPattern     = regexp.MustCompile(`(?m)^[0-9a-fA-F]{40} [0-9a-fA-F]{40} .+ <[^>]+> \d+ [+-]\d{4}\t`)
	svnEntriesPattern      = regexp.MustCompile(`(?is)^\s*(?:<\?xml[^>]*>.*<(?:wc-entries|entry)\b|\d+\r?\n.+)`)
	envAssignmentPattern   = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]{1,80})[ \t]*=[ \t]*([^\r\n#]{1,512})`)
	privateKeyPattern      = regexp.MustCompile(`(?m)-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)
	awsAccessKeyPattern    = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	aliyunAccessKeyPattern = regexp.MustCompile(`\bLTAI[A-Za-z0-9]{12,24}\b`)
	githubTokenPattern     = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,255}\b`)
	googleAPIKeyPattern    = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)
	slackTokenPattern      = regexp.MustCompile(`\bxox[abprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{10,48}\b`)
	stripeKeyPattern       = regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}\b`)
	jwtPattern             = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	databaseDSNPattern     = regexp.MustCompile(`(?i)\b(?:jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb)|(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://)[^\s"'<>]{6,}`)
	assignedSecretPattern  = regexp.MustCompile(`(?im)["']?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9_./+@=-]{8,256})`)
	emailPattern           = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b`)
	phonePattern           = regexp.MustCompile(`\b1[3-9][0-9]{9}\b`)
	stackTracePattern      = regexp.MustCompile(`(?m)(?:^Traceback \(most recent call last\):|^panic: .+|^goroutine \d+ \[|\bat [A-Za-z_$][A-Za-z0-9_.$]+\([^\r\n()]+:\d+\))`)
)

func builtins(tx model.Transaction, u *url.URL, enabled func(string) bool) []model.Finding {
	var result []model.Finding
	add := func(rule, title, severity, confidence, description, remediation, evidence string, tags ...string) {
		result = append(result, model.Finding{RuleID: rule, Title: title, Severity: severity, Confidence: confidence,
			Description: description, Remediation: remediation, Evidence: evidence, Tags: tags})
	}

	body := tx.Response.Body
	normalizedBody := strings.Join(strings.Fields(strings.ToLower(body)), " ")
	if strings.Contains(normalizedBody, "<title>index of /") {
		add("passive.directory-listing", "Directory listing exposed", "medium", "firm",
			"The response resembles a web-server directory index.", "Disable autoindex/directory browsing and review exposed files.", "<title>Index of /", "information-disclosure", "directory-listing")
	}

	if isAPIDocumentationResponse(tx, u) {
		add("passive.api-documentation", "API documentation exposed", "low", "firm",
			"An API documentation endpoint was observed in captured traffic.", "Confirm that exposed API documentation is intended and does not reveal internal-only operations.", u.Path, "api", "inventory")
	}
	result = append(result, sensitiveInformationFindings(tx, u, enabled)...)
	return result
}

// SensitiveFileFindings validates whether a captured response is a genuine
// sensitive file exposure. It is exported so the MITM file-probe worker can
// reuse the same path + content-signature checks against probed responses.
func SensitiveFileFindings(tx model.Transaction, u *url.URL) []model.Finding {
	return sensitiveFileFindings(tx, u)
}

// APIDocumentationFinding returns an API documentation exposure finding when
// the response is a genuine swagger/openapi document (HTTP 200, JSON body
// carrying the "swagger" or "openapi" structure marker), or nil otherwise.
// It is exported so the MITM file-probe worker can validate active probe
// responses with the same content-signature check used by the passive engine,
// avoiding SPA fallback pages and arbitrary JSON endpoints being reported.
func APIDocumentationFinding(tx model.Transaction, u *url.URL) *model.Finding {
	if !isAPIDocumentationResponse(tx, u) {
		return nil
	}
	return &model.Finding{
		RuleID:      "passive.api-documentation",
		Title:       "API documentation exposed",
		Severity:    "low",
		Confidence:  "firm",
		Description: "An API documentation endpoint was exposed at a well-known path.",
		Remediation: "Confirm that exposed API documentation is intended and does not reveal internal-only operations.",
		Evidence:    u.Path,
		Tags:        []string{"api", "inventory"},
	}
}

func sensitiveFileFindings(tx model.Transaction, u *url.URL) []model.Finding {
	if u == nil || (tx.Response.Status != http.StatusOK && tx.Response.Status != http.StatusPartialContent) {
		return nil
	}
	pathLower := strings.ToLower(u.Path)
	body := tx.Response.Body
	bodyBytes := []byte(body)
	var result []model.Finding
	add := func(rule, title, severity, evidence string, tags ...string) {
		result = append(result, model.Finding{
			RuleID:      rule,
			Title:       title,
			Severity:    severity,
			Confidence:  "firm",
			Description: "响应路径与文件内容签名同时匹配，目标公开返回了不应由 Web 服务直接访问的项目或配置文件。",
			Remediation: "从 Web 根目录移除该文件，限制静态文件映射，并在网关或服务器层拒绝访问隐藏目录、备份和配置文件。",
			Evidence:    u.Path + "；" + evidence,
			Tags:        append([]string{"information-disclosure", "sensitive-file"}, tags...),
		})
	}

	if strings.Contains(pathLower, "/.git/") && isGitMetadata(pathLower, bodyBytes) {
		add("passive.exposure.git-repository", "Git 仓库元数据泄漏", "high", "Git 路径和仓库文件签名均匹配", "git")
	}
	if finding, ok := springBootActuatorFinding(tx, u, pathLower, bodyBytes); ok {
		result = append(result, finding)
	}
	if strings.Contains(pathLower, "/.svn/") && isSVNMetadata(pathLower, bodyBytes) {
		add("passive.exposure.svn-metadata", "SVN 工作副本元数据泄漏", "high", "SVN 路径和工作副本文件签名均匹配", "svn")
	}
	if strings.Contains(pathLower, "/.idea/") && strings.HasSuffix(pathLower, ".xml") {
		if looksLikeIDEAProject(body) {
			add("passive.exposure.idea-project", "IDEA 项目配置泄漏", "medium", "IDEA XML 项目结构签名匹配", "idea")
		}
	}
	if strings.HasSuffix(pathLower, "/.ds_store") && bytes.HasPrefix(bodyBytes, []byte("Bud1")) {
		add("passive.exposure.ds-store", ".DS_Store 文件泄漏", "low", "DS_Store Bud1 文件头匹配", "ds-store")
	}
	if isEnvironmentPath(pathLower) && envContentTypeAllowed(tx.Response.Headers) && looksLikeEnvironmentFile(body) {
		add("passive.exposure.environment-file", "环境变量文件泄漏", "high", "多行环境变量赋值及敏感配置键匹配", "environment")
	}
	if isBackupPath(pathLower) && hasArchiveSignature(bodyBytes) {
		add("passive.exposure.backup-file", "站点备份文件泄漏", "high", "备份扩展名与归档文件头同时匹配", "backup")
	}
	if isDatabaseDumpPath(pathLower) && looksLikeDatabaseDump(body) {
		add("passive.exposure.database-dump", "数据库转储文件泄漏", "high", "数据库转储路径与 SQL 内容签名同时匹配", "database")
	}
	return result
}

func isGitMetadata(pathLower string, body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	switch {
	case strings.HasSuffix(pathLower, "/.git/head"):
		return strings.HasPrefix(trimmed, "ref: refs/heads/") || gitCommitPattern.MatchString(trimmed)
	case strings.HasSuffix(pathLower, "/.git/config"):
		normalized := strings.ToLower(trimmed)
		return strings.Contains(normalized, "[core]") && strings.Contains(normalized, "repositoryformatversion")
	case strings.HasSuffix(pathLower, "/.git/index"):
		return bytes.HasPrefix(body, []byte("DIRC"))
	case strings.HasSuffix(pathLower, "/.git/packed-refs"):
		return strings.Contains(trimmed, "refs/") && (strings.Contains(trimmed, "pack-refs with") || gitPackedRefsPattern.MatchString(trimmed))
	case strings.HasSuffix(pathLower, "/.git/logs/head"):
		return gitLogsHeadPattern.MatchString(trimmed)
	default:
		return false
	}
}

// springBootActuatorEndpoints lists the actuator route leaves EasyScan probes.
// It covers both the modern /actuator/<name> layout and the legacy Spring Boot
// 1.x root-level routes.
var springBootActuatorEndpoints = map[string]struct{}{
	"actuator": {}, "env": {}, "heapdump": {}, "configprops": {},
	"mappings": {}, "beans": {}, "threaddump": {}, "httptrace": {},
	"trace": {}, "dump": {},
}

// springBootActuatorFinding validates whether a probed path is a genuine
// Spring Boot Actuator management endpoint exposing sensitive runtime data. It
// mirrors the .git path + content-signature dual check: the path must end with
// a known actuator route and the response body must carry that endpoint's
// structural marker, so SPA fallback pages and unrelated JSON endpoints are
// ignored.
func springBootActuatorFinding(tx model.Transaction, u *url.URL, pathLower string, body []byte) (model.Finding, bool) {
	endpoint := actuatorEndpointName(pathLower)
	if endpoint == "" {
		return model.Finding{}, false
	}
	if !isValidActuatorResponse(endpoint, body, tx.Response.Headers) {
		return model.Finding{}, false
	}
	title, severity, evidence := actuatorFindingMetadata(endpoint)
	return model.Finding{
		RuleID:      "passive.exposure.springboot-actuator",
		Title:       title,
		Severity:    severity,
		Confidence:  "firm",
		Description: "响应路径与 Spring Boot Actuator 端点内容签名同时匹配，目标公开暴露了运行时管理端点，" + evidence + "。",
		Remediation: "通过 management.endpoints.web.exposure.include 限制 Actuator 暴露范围，为管理端点启用认证授权，或在网关层拒绝外部访问 /actuator 路径。",
		Evidence:    u.Path + "；" + evidence,
		Tags:        []string{"information-disclosure", "springboot", "actuator"},
	}, true
}

func actuatorEndpointName(pathLower string) string {
	trimmed := strings.TrimSuffix(pathLower, "/")
	index := strings.LastIndex(trimmed, "/")
	leaf := trimmed[index+1:]
	if _, ok := springBootActuatorEndpoints[leaf]; ok {
		return leaf
	}
	return ""
}

func isValidActuatorResponse(endpoint string, body []byte, headers map[string]string) bool {
	if len(bytes.TrimSpace(body)) == 0 {
		return false
	}
	if endpoint == "heapdump" {
		// Java HPROF binary heap dump header.
		return bytes.HasPrefix(body, []byte("JAVA PROFILE"))
	}
	if !hasJSONContentType(headers) {
		return false
	}
	normalized := strings.ToLower(string(body))
	switch endpoint {
	case "actuator":
		// The actuator index links object must be a populated map, not the
		// null/empty value a soft-404 JSON envelope (e.g. {"_links":null})
		// commonly carries.
		return containsJSONObjectKey(normalized, "_links")
	case "env":
		return strings.Contains(normalized, `"propertysources"`) || strings.Contains(normalized, `"activeprofiles"`)
	case "configprops":
		return strings.Contains(normalized, `"contexts"`) && (strings.Contains(normalized, `"beans"`) || strings.Contains(normalized, `"prefix"`))
	case "mappings":
		return strings.Contains(normalized, `"contexts"`) && (strings.Contains(normalized, `"dispatcherservlets"`) || strings.Contains(normalized, `"dispatcherhandlers"`) || strings.Contains(normalized, `"mappings"`))
	case "beans":
		return strings.Contains(normalized, `"contexts"`) && strings.Contains(normalized, `"beans"`)
	case "threaddump", "dump":
		return strings.Contains(normalized, `"threads"`) && (strings.Contains(normalized, `"threadname"`) || strings.Contains(normalized, `"threadstate"`) || strings.Contains(normalized, `"stacktrace"`))
	case "httptrace", "trace":
		return strings.Contains(normalized, `"traces"`) && (strings.Contains(normalized, `"timestamp"`) || strings.Contains(normalized, `"request"`))
	}
	return false
}

func hasJSONContentType(headers map[string]string) bool {
	contentType := strings.ToLower(header(headers, "Content-Type"))
	return strings.Contains(contentType, "json")
}

// containsJSONObjectKey reports whether normalized JSON text contains the given
// key mapped to a non-empty object value ("key":{...}). It tolerates arbitrary
// whitespace between the colon and the opening brace. This distinguishes a
// genuine structured payload from a soft-404 envelope that carries the key with
// a null or scalar value (e.g. {"_links":null}). The key argument must already
// be lowercased to match the normalized body.
func containsJSONObjectKey(normalized, key string) bool {
	needle := `"` + key + `"`
	for start := 0; ; {
		idx := strings.Index(normalized[start:], needle)
		if idx < 0 {
			return false
		}
		cursor := start + idx + len(needle)
		rest := strings.TrimLeft(normalized[cursor:], " \t\r\n")
		if strings.HasPrefix(rest, ":") {
			rest = strings.TrimLeft(rest[1:], " \t\r\n")
			if strings.HasPrefix(rest, "{") {
				return true
			}
		}
		start = cursor
	}
}

func actuatorFindingMetadata(endpoint string) (title, severity, evidence string) {
	switch endpoint {
	case "heapdump":
		return "Spring Boot Heapdump 端点暴露", "critical", "Java 堆内存转储可能包含明文密钥、会话凭据等敏感数据"
	case "env":
		return "Spring Boot Env 端点暴露", "high", "环境变量与配置属性可能泄漏数据库连接串、密钥等敏感信息"
	case "configprops":
		return "Spring Boot Configprops 端点暴露", "high", "配置属性绑定信息可能泄漏敏感配置"
	case "mappings":
		return "Spring Boot Mappings 端点暴露", "medium", "全部 URL 映射泄漏了应用的路由结构"
	case "beans":
		return "Spring Boot Beans 端点暴露", "low", "Spring Bean 列表泄漏了应用内部组件结构"
	case "threaddump", "dump":
		return "Spring Boot Threaddump 端点暴露", "medium", "线程转储可能泄漏内部调用与类路径信息"
	case "httptrace", "trace":
		return "Spring Boot Httptrace 端点暴露", "medium", "近期 HTTP 请求记录可能泄漏认证头等敏感信息"
	case "actuator":
		return "Spring Boot Actuator 索引端点暴露", "low", "Actuator 索引列出了全部启用的管理端点"
	}
	return "Spring Boot Actuator 端点暴露", "medium", "管理端点可被公开访问"
}

func isSVNMetadata(pathLower string, body []byte) bool {
	switch {
	case strings.HasSuffix(pathLower, "/.svn/wc.db"):
		return bytes.HasPrefix(body, []byte("SQLite format 3\x00"))
	case strings.HasSuffix(pathLower, "/.svn/entries"):
		return svnEntriesPattern.Match(body)
	default:
		return false
	}
}

func isEnvironmentPath(pathLower string) bool {
	leaf := pathLower
	if index := strings.LastIndex(leaf, "/"); index >= 0 {
		leaf = leaf[index+1:]
	}
	return leaf == ".env" || strings.HasPrefix(leaf, ".env.")
}

func looksLikeEnvironmentFile(body string) bool {
	if bodyLooksLikeMarkup(body) {
		return false
	}
	matches := envAssignmentPattern.FindAllStringSubmatch(body, -1)
	if len(matches) < 2 {
		return false
	}
	for _, match := range matches {
		key := strings.ToLower(match[1])
		for _, marker := range []string{"password", "passwd", "secret", "token", "key", "database", "db_", "redis", "smtp", "aws", "aliyun"} {
			if strings.Contains(key, marker) {
				return true
			}
		}
	}
	return false
}

// envContentTypeAllowed rejects responses whose Content-Type indicates a
// rendered document (HTML/XML) rather than a raw dotenv file. Real .env files
// are served as text/plain, application/octet-stream, or without a type; SPA
// catch-all routes answer every path with text/html and must not be reported
// as environment-file leaks.
func envContentTypeAllowed(headers map[string]string) bool {
	contentType := strings.ToLower(header(headers, "Content-Type"))
	if contentType == "" {
		return true
	}
	for _, blocked := range []string{"text/html", "application/xhtml", "text/xml", "application/xml"} {
		if strings.Contains(contentType, blocked) {
			return false
		}
	}
	return true
}

// bodyLooksLikeMarkup guards against SPA fallback pages that echo the requested
// path (defeating response dedupe) and happen to contain KEY=value-like
// fragments in inline scripts or URLs. A genuine dotenv file never begins with
// an HTML document preamble.
func bodyLooksLikeMarkup(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}
	if len(trimmed) > 512 {
		trimmed = trimmed[:512]
	}
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, "<!doctype") ||
		strings.HasPrefix(lower, "<html") ||
		strings.HasPrefix(lower, "<?xml") ||
		strings.HasPrefix(lower, "<head") ||
		strings.Contains(lower, "<html") && strings.Contains(lower, "<body")
}

// looksLikeIDEAProject validates a genuine IntelliJ IDEA project XML instead of
// a naive "<project"+"<component" substring test. A SPA fallback page that
// echoes the requested .idea path could otherwise embed those tokens in inline
// scripts or markup and be misreported. The document must carry the IDEA XML
// structure (<project> root with a <component>) and must not be an HTML page.
func looksLikeIDEAProject(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "<html") || strings.Contains(lower, "<body") {
		return false
	}
	return strings.Contains(lower, "<project") && strings.Contains(lower, "<component")
}

func isBackupPath(pathLower string) bool {
	for _, suffix := range []string{".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".7z", ".rar", ".bak", ".backup", ".old"} {
		if strings.HasSuffix(pathLower, suffix) {
			return true
		}
	}
	return false
}

func hasArchiveSignature(body []byte) bool {
	if bytes.HasPrefix(body, []byte("PK\x03\x04")) || bytes.HasPrefix(body, []byte("7z\xbc\xaf'\x1c")) || bytes.HasPrefix(body, []byte("Rar!\x1a\x07")) || bytes.HasPrefix(body, []byte{0x1f, 0x8b}) {
		return true
	}
	return len(body) > 262 && string(body[257:262]) == "ustar"
}

func isDatabaseDumpPath(pathLower string) bool {
	return strings.HasSuffix(pathLower, ".sql") || strings.HasSuffix(pathLower, ".dump")
}

func looksLikeDatabaseDump(body string) bool {
	if bodyLooksLikeMarkup(body) {
		return false
	}
	normalized := strings.ToLower(body)
	markers := 0
	for _, marker := range []string{"-- mysql dump", "-- postgresql database dump", "create table", "insert into", "pragma foreign_keys", "lock tables"} {
		if strings.Contains(normalized, marker) {
			markers++
		}
	}
	return markers >= 2
}

func sensitiveInformationFindings(tx model.Transaction, u *url.URL, enabled func(string) bool) []model.Finding {
	if u == nil || tx.Response.Status < 200 || tx.Response.Status >= 300 || tx.Response.Body == "" {
		return nil
	}
	if !enabled("passive.sensitive_info") {
		return nil
	}
	body := tx.Response.Body
	if len(body) > 4<<20 {
		body = body[:4<<20]
	}
	var result []model.Finding
	add := func(rule, title, severity, confidence, evidence string, tags ...string) {
		result = append(result, model.Finding{
			RuleID:      rule,
			Title:       title,
			Severity:    severity,
			Confidence:  confidence,
			Description: "响应正文中检测到可能导致凭据、个人信息或内部实现细节暴露的内容特征。",
			Remediation: "确认响应字段的业务必要性；移除密钥与凭据，使用密钥管理服务，并对个人信息和错误详情做最小化输出。",
			Evidence:    u.Path + "；" + evidence,
			Tags:        append([]string{"information-disclosure", "sensitive-information"}, tags...),
		})
	}
	if enabled("passive.sensitive_info.private_key") && privateKeyPattern.MatchString(body) {
		add("passive.exposure.private-key", "私钥材料泄漏", "critical", "firm", "PEM 私钥头匹配", "credential", "private-key")
	}
	if enabled("passive.sensitive_info.aws_access_key") && awsAccessKeyPattern.MatchString(body) {
		add("passive.exposure.aws-access-key", "AWS 访问密钥疑似泄漏", "high", "firm", "AWS Access Key ID 格式匹配", "credential", "cloud")
	}
	if enabled("passive.sensitive_info.aliyun_access_key") && aliyunAccessKeyPattern.MatchString(body) {
		add("passive.exposure.aliyun-access-key", "阿里云访问密钥疑似泄漏", "high", "firm", "阿里云 AccessKey ID 格式匹配", "credential", "cloud")
	}
	if enabled("passive.sensitive_info.github_token") && githubTokenPattern.MatchString(body) {
		add("passive.exposure.github-token", "GitHub Token 疑似泄漏", "high", "firm", "GitHub Token 格式匹配", "credential", "github")
	}
	if enabled("passive.sensitive_info.google_api_key") && googleAPIKeyPattern.MatchString(body) {
		add("passive.exposure.google-api-key", "Google API Key 疑似泄漏", "high", "firm", "Google API Key 格式匹配", "credential", "cloud", "google")
	}
	if enabled("passive.sensitive_info.slack_token") && slackTokenPattern.MatchString(body) {
		add("passive.exposure.slack-token", "Slack Token 疑似泄漏", "high", "firm", "Slack Token 格式匹配", "credential", "slack")
	}
	if enabled("passive.sensitive_info.stripe_key") && stripeKeyPattern.MatchString(body) {
		add("passive.exposure.stripe-key", "Stripe 密钥疑似泄漏", "high", "firm", "Stripe Secret Key 格式匹配", "credential", "stripe")
	}
	if enabled("passive.sensitive_info.jwt") && jwtPattern.MatchString(body) {
		add("passive.exposure.jwt", "JWT 凭据疑似泄漏", "medium", "firm", "三段式 JWT 格式匹配", "credential", "jwt")
	}
	if enabled("passive.sensitive_info.database_dsn") && databaseDSNPattern.MatchString(body) {
		add("passive.exposure.database-connection", "数据库连接串泄漏", "high", "firm", "数据库连接协议与地址格式匹配", "credential", "database")
	}
	if enabled("passive.sensitive_info.application_secret") && assignedSecret(body) {
		add("passive.exposure.application-secret", "应用密钥或口令疑似泄漏", "high", "tentative", "敏感字段名与非占位值同时匹配", "credential", "secret")
	}
	if enabled("passive.sensitive_info.stack_trace") && stackTracePattern.MatchString(body) {
		add("passive.exposure.stack-trace", "应用堆栈信息泄漏", "low", "firm", "运行时堆栈帧格式匹配", "stack-trace")
	}
	if enabled("passive.sensitive_info.email") && emailPattern.MatchString(body) {
		add("passive.information.email-address", "响应中发现邮箱地址", "info", "firm", "邮箱地址格式匹配", "personal-data", "email")
	}
	if enabled("passive.sensitive_info.phone") && phonePattern.MatchString(body) {
		add("passive.information.phone-number", "响应中发现手机号码", "info", "tentative", "中国大陆手机号码格式匹配", "personal-data", "phone")
	}
	return result
}

func assignedSecret(body string) bool {
	for _, match := range assignedSecretPattern.FindAllStringSubmatch(body, -1) {
		if len(match) < 2 {
			continue
		}
		value := strings.ToLower(strings.Trim(match[1], `"'`))
		if value == "" || looksLikePlaceholder(value) {
			continue
		}
		return true
	}
	return false
}

// looksLikePlaceholder reports whether a captured secret value is a
// documentation placeholder or example value rather than a real credential.
// The check is intentionally conservative: it favours suppressing false
// positives over catching every possible secret.
func looksLikePlaceholder(value string) bool {
	switch value {
	case "password", "passwd", "changeme", "your_secret", "your_token",
		"redacted", "undefined", "example123", "secret", "token", "apikey",
		"your-key", "your_key", "your-secret", "your-password", "your_password",
		"placeholder", "dummy", "fake", "sample", "demo", "test", "test123",
		"xxx", "xxxx", "xxxxxxxx", "xxxx-xxxx-xxxx", "00000000", "12345678":
		return true
	}
	if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "<") {
		return true
	}
	if strings.HasPrefix(value, "your-") || strings.HasPrefix(value, "your_") {
		return true
	}
	if strings.HasPrefix(value, "replace") || strings.HasPrefix(value, "insert") {
		return true
	}
	if strings.HasPrefix(value, "xxxx") {
		return true
	}
	if strings.HasPrefix(value, "test") && len(value) <= 8 {
		return true
	}
	return false
}

// isAPIDocumentationResponse intentionally uses the stable route and status
// signal. API documentation endpoints are often returned with an empty body,
// a redirect-free HTML shell, or a vendor-specific media type; requiring a
// particular body marker caused valid 200 responses to be missed. The route
// dictionary is deliberately narrow; the HTTP 200 requirement and content-type
// / body-signature checks prevent SPA fallback pages from becoming findings.
func isAPIDocumentationResponse(tx model.Transaction, u *url.URL) bool {
	if tx.Response.Status != http.StatusOK || u == nil {
		return false
	}
	pathLower := strings.ToLower(u.Path)
	if !strings.Contains(pathLower, "swagger") && !strings.Contains(pathLower, "openapi") && !strings.Contains(pathLower, "api-docs") {
		return false
	}
	// SPA 框架常对不存在的路径返回 200 + text/html（前端路由回退），
	// 必须验证响应确实是 JSON 才能判定为 API 文档。
	contentType := strings.ToLower(tx.Response.Headers["Content-Type"])
	if !strings.Contains(contentType, "json") {
		return false
	}
	body := strings.TrimSpace(tx.Response.Body)
	if body == "" || (body[0] != '{' && body[0] != '[') {
		return false
	}
	// 确认 JSON 体包含 swagger/openapi 结构标记，而非碰巧返回 JSON 的其他接口。
	normalized := strings.ToLower(body)
	if !strings.Contains(normalized, `"swagger"`) && !strings.Contains(normalized, `"openapi"`) {
		return false
	}
	return true
}

// canonicalFinding keeps detector-result metadata stable when a saved
// snapshot created by an earlier EasyScan version is restored.
func canonicalFinding(finding model.Finding) model.Finding {
	if finding.RuleID == "passive.api-documentation" {
		finding.Severity = "low"
	}
	return finding
}
