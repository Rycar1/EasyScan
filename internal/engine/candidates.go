package engine

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/example/easyscan/internal/model"
)

var (
	sqlErrorPattern        = regexp.MustCompile(`(?i)(?:sql syntax.*?(?:mysql|mariadb)|warning.*?\b(?:mysql|mysqli|pg_)|unclosed quotation mark after the character string|quoted string not properly terminated|microsoft ole db provider for sql server|odbc sql server driver|org\.postgresql\.util\.psqlexception|sqlite(?:_exception| error)|syntax error at or near)`)
	javaContentTypePattern = regexp.MustCompile(`(?i)application/(?:x-)?java-(?:serialized-object|object)`)
	javaExceptionPattern   = regexp.MustCompile(`(?i)java\.io\.(?:objectinputstream|invalidclassexception|streamcorruptedexception)`)
	javaStreamPattern      = regexp.MustCompile(`rO0AB[A-Za-z0-9+/]{16,}`)
	commandErrorPattern    = regexp.MustCompile(`(?i)(?:/bin/(?:sh|bash)|cmd\.exe|powershell(?:\.exe)?|java\.lang\.processbuilder|cannot run program|(?:sh|bash): .*?(?:not found|syntax error))`)
	log4jPattern           = regexp.MustCompile(`(?i)log4j(?:-core)?[\s:/_-]*v?(2\.[0-9]+(?:\.[0-9]+)?)`)
)

// vulnerabilityCandidates uses evidence already observed in traffic. Findings
// with confidence "tentative" are leads, not proof of exploitability.
func vulnerabilityCandidates(tx model.Transaction, u *url.URL) []model.Finding {
	var result []model.Finding
	add := func(rule, title, severity, confidence, description, remediation, evidence string, tags ...string) {
		result = append(result, model.Finding{RuleID: rule, Title: title, Severity: severity, Confidence: confidence, Description: description, Remediation: remediation, Evidence: evidence, Tags: tags})
	}
	responseHeaders := headersText(tx.Response.Headers)
	response := responseHeaders + "\n" + tx.Response.Body
	requestHeaders := headersText(tx.Request.Headers)
	if match := sqlErrorPattern.FindString(response); match != "" && likelyErrorResponse(tx) {
		add("passive.candidate.sql-error", "Database error disclosure observed", "low", "tentative", "The captured error response contains a database error signature. This is evidence of error disclosure, not proof that a request parameter is injectable.", "Disable detailed database errors in client responses and use parameterized queries.", match, "candidate", "sqli", "passive", "error-disclosure")
	}
	if match := javaDeserializationEvidence(requestHeaders, responseHeaders, tx.Request.Body, tx.Response.Body); match != "" {
		add("passive.candidate.java-deserialization", "Java serialized-object handling observed", "medium", "tentative", "Captured traffic indicates serialized-object content handling or a deserialization exception. This does not establish a gadget chain or exploitation.", "Avoid native Java deserialization for untrusted data; enforce allow-lists and integrity protection.", match, "candidate", "java-deserialization", "passive")
	}
	if match := commandErrorPattern.FindString(response); match != "" && likelyErrorResponse(tx) {
		add("passive.candidate.command-execution", "Process execution detail disclosed", "low", "tentative", "An error response exposes process or shell execution details. This is information disclosure, not evidence that input controls command execution.", "Remove command execution from request paths; use fixed argument allow-lists and avoid shell invocation.", match, "candidate", "command-injection", "passive", "error-disclosure")
	}
	if match := vulnerableLog4j(responseHeaders); match != "" {
		add("passive.candidate.log4j2-version", "Potentially vulnerable Log4j2 version exposed", "medium", "tentative", "A response header exposes a Log4j2 version in a range associated with historical lookup vulnerabilities. Deployment context and the actual runtime component must be verified.", "Upgrade Log4j2 to a currently supported release and remove vulnerable lookup behavior.", match, "candidate", "log4j2", "passive", "version")
	}
	result = append(result, componentVersionCandidates(responseHeaders)...)
	for name, values := range u.Query() {
		for _, value := range values {
			if !containsSpecial(value) || !isHTML(tx.Response.Headers) || !strings.Contains(tx.Response.Body, value) {
				continue
			}
			context := reflectionContext(tx.Response.Body, value)
			if isExecutableContext(context) {
				add("passive.candidate.reflected-input", "Unencoded input in executable HTML context", "low", "tentative", "A captured query value containing HTML-significant characters was reflected without encoding in a script, tag, or attribute context. It needs authorized browser-based confirmation before it can be classified as XSS.", "Apply context-aware output encoding and verify with a browser-based test in an authorized environment.", name+" reflected in "+context, "candidate", "xss", "passive")
			}
		}
	}
	return result
}

func containsSpecial(value string) bool             { return strings.ContainsAny(value, "<>'\"") }
func likelyErrorResponse(tx model.Transaction) bool { return tx.Response.Status >= 500 }
func isHTML(headers map[string]string) bool {
	return strings.Contains(strings.ToLower(headersText(headers)), "content-type: text/html") || strings.Contains(strings.ToLower(headersText(headers)), "content-type: application/xhtml+xml")
}
func isExecutableContext(context string) bool {
	return context == "script context" || context == "HTML attribute context" || context == "HTML tag context"
}
func javaDeserializationEvidence(requestHeaders, responseHeaders, requestBody, responseBody string) string {
	if match := javaContentTypePattern.FindString(requestHeaders); match != "" {
		return match
	}
	if match := javaContentTypePattern.FindString(responseHeaders); match != "" {
		return match
	}
	if match := javaExceptionPattern.FindString(responseBody); match != "" {
		return match
	}
	if (javaContentTypePattern.MatchString(requestHeaders) || javaContentTypePattern.MatchString(responseHeaders)) && javaStreamPattern.MatchString(requestBody+"\n"+responseBody) {
		return "Java serialized stream with serialized-object content type"
	}
	return ""
}
func reflectionContext(body, value string) string {
	at := strings.Index(body, value)
	if at < 0 {
		return ""
	}
	start := at - 180
	if start < 0 {
		start = 0
	}
	prefix := strings.ToLower(body[start:at])
	if strings.LastIndex(prefix, "<!--") > strings.LastIndex(prefix, "-->") {
		return "HTML comment context"
	}
	if strings.LastIndex(prefix, "<script") > strings.LastIndex(prefix, "</script") {
		return "script context"
	}
	if strings.LastIndex(prefix, "=") > strings.LastIndex(prefix, "<") {
		return "HTML attribute context"
	}
	if strings.LastIndex(prefix, "<") > strings.LastIndex(prefix, ">") {
		return "HTML tag context"
	}
	return "HTML text context"
}
func vulnerableLog4j(text string) string {
	match := log4jPattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return ""
	}
	parts := strings.Split(match[1], ".")
	if len(parts) < 2 {
		return ""
	}
	minor, _ := strconv.Atoi(parts[1])
	patch := 0
	if len(parts) > 2 {
		patch, _ = strconv.Atoi(parts[2])
	}
	// Log4Shell-era lookup exposure was present in the 2.0–2.14 line;
	// 2.15.0 was an incomplete remediation, while 2.16+ removed lookups.
	if minor <= 14 || minor == 15 && patch == 0 {
		return match[0]
	}
	return ""
}
