package aiinsight

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/example/easyscan/internal/model"
)

type stubPolicy struct {
	enabled      bool
	baseURL      string
	modelName    string
	apiKey       string
}

func (s stubPolicy) Enabled(string) bool { return s.enabled }
func (s stubPolicy) AIBaseURL() string   { return s.baseURL }
func (s stubPolicy) AIModel() string    { return s.modelName }
func (s stubPolicy) AIAPIKey() string    { return s.apiKey }

type stubChatClient struct {
	response string
	err      error
	called   bool
	system   string
	user     string
}

func (s *stubChatClient) Chat(ctx context.Context, system, user string) (string, error) {
	s.called = true
	s.system = system
	s.user = user
	return s.response, s.err
}

func TestEnrichSkipsInformationalFindings(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "https://api.test/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	client := &stubChatClient{}
	enricher := New(policy, client)
	finding := model.Finding{ID: "abc", RuleID: "passive.information.email-address", Severity: "info", Title: "Email", Description: "found email", Remediation: "n/a"}
	result := enricher.Enrich(context.Background(), finding)
	if result.Enriched {
		t.Fatalf("info-severity finding must not be enriched")
	}
	if client.called {
		t.Fatalf("AI client must not be called for info findings")
	}
}

func TestEnrichSkipsWhenDisabled(t *testing.T) {
	policy := stubPolicy{enabled: false, baseURL: "https://api.test/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	client := &stubChatClient{}
	enricher := New(policy, client)
	finding := model.Finding{ID: "abc", RuleID: "passive.sqli-probe.query", Severity: "high", Title: "SQLi", Description: "found", Remediation: "fix"}
	result := enricher.Enrich(context.Background(), finding)
	if result.Enriched {
		t.Fatalf("disabled enricher must not enrich")
	}
	if client.called {
		t.Fatalf("AI client must not be called when disabled")
	}
}

func TestEnrichSkipsAlreadyEnriched(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "https://api.test/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	client := &stubChatClient{}
	enricher := New(policy, client)
	finding := model.Finding{
		ID:          "abc",
		RuleID:      "passive.sqli-probe.query",
		Severity:    "high",
		Title:       "SQLi",
		Description: "found\n\n--- AI 漏洞解读 ---\nalready enriched",
		Remediation: "fix",
	}
	result := enricher.Enrich(context.Background(), finding)
	if result.Enriched {
		t.Fatalf("already-enriched finding must not be re-enriched")
	}
	if client.called {
		t.Fatalf("AI client must not be called for already-enriched findings")
	}
}

func TestEnrichParsesAIResponseAndAppendsInsight(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "https://api.test/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	client := &stubChatClient{
		response: `{"impact":"该 SQL 注入可通过 UNION 查询读取用户表","exploitation":"构造 id=1 UNION SELECT 1,2,3--","fix":"使用参数化查询，Java 用 PreparedStatement"}`,
	}
	enricher := New(policy, client)
	finding := model.Finding{
		ID:          "abc123",
		RuleID:      "passive.sqli-probe.query",
		Severity:    "high",
		Confidence:  "firm",
		Title:       "SQL 注入",
		URL:         "https://app.test/user?id=1",
		Method:      "GET",
		Description: "Single-quoted error detected",
		Evidence:    "syntax error near '1''",
		Remediation: "Use parameterized queries",
		Tags:        []string{"sqli", "error-based"},
	}
	result := enricher.Enrich(context.Background(), finding)
	if !result.Enriched {
		t.Fatalf("expected enrichment, got none")
	}
	if !strings.Contains(result.Finding.Description, "--- AI 漏洞解读 ---") {
		t.Errorf("description must contain AI insight marker, got: %s", result.Finding.Description)
	}
	if !strings.Contains(result.Finding.Description, "UNION 查询读取用户表") {
		t.Errorf("description must contain AI impact text, got: %s", result.Finding.Description)
	}
	if !strings.Contains(result.Finding.Remediation, "PreparedStatement") {
		t.Errorf("remediation must contain AI fix text, got: %s", result.Finding.Remediation)
	}
	if !strings.Contains(client.user, "https://app.test/user?id=1") {
		t.Errorf("prompt must include finding URL, got: %s", client.user)
	}
	if !strings.Contains(client.user, "SQL 注入") {
		t.Errorf("prompt must include finding title, got: %s", client.user)
	}
}

func TestEnrichHandlesAIClientError(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "https://api.test/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	client := &stubChatClient{err: errors.New("network timeout")}
	enricher := New(policy, client)
	finding := model.Finding{ID: "abc", RuleID: "passive.sqli-probe.query", Severity: "high", Title: "SQLi", Description: "found", Remediation: "fix"}
	result := enricher.Enrich(context.Background(), finding)
	if result.Enriched {
		t.Fatalf("AI error must not mark as enriched")
	}
	if result.Finding.Description != finding.Description {
		t.Errorf("original description must be unchanged on error")
	}
}

func TestEnrichHandlesMalformedJSON(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "https://api.test/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	client := &stubChatClient{response: "这不是 JSON"}
	enricher := New(policy, client)
	finding := model.Finding{ID: "abc", RuleID: "passive.sqli-probe.query", Severity: "high", Title: "SQLi", Description: "found", Remediation: "fix"}
	result := enricher.Enrich(context.Background(), finding)
	if result.Enriched {
		t.Fatalf("malformed JSON must not mark as enriched")
	}
	if result.Finding.Description != finding.Description {
		t.Errorf("original description must be unchanged on parse failure")
	}
}

func TestEnrichSkipsWhenNotConfigured(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "", modelName: "", apiKey: ""}
	client := &stubChatClient{}
	enricher := New(policy, client)
	finding := model.Finding{ID: "abc", RuleID: "passive.sqli-probe.query", Severity: "high", Title: "SQLi", Description: "found", Remediation: "fix"}
	result := enricher.Enrich(context.Background(), finding)
	if result.Enriched {
		t.Fatalf("unconfigured AI must not enrich")
	}
	if client.called {
		t.Fatalf("AI client must not be called when unconfigured")
	}
}

func TestBuildPromptIncludesRelevantContext(t *testing.T) {
	finding := model.Finding{
		RuleID:      "passive.sqli-probe.query",
		Severity:    "high",
		Confidence:  "firm",
		Title:       "SQL 注入",
		URL:         "https://app.test/user?id=1",
		Method:      "GET",
		Description: "Single-quoted error detected",
		Evidence:    "syntax error near '1''",
		Tags:        []string{"sqli", "error-based"},
	}
	prompt := buildPrompt(finding)
	mustContain := []string{
		"passive.sqli-probe.query",
		"high",
		"SQL 注入",
		"https://app.test/user?id=1",
		"GET",
		"Single-quoted error detected",
		"firm",
	}
	for _, expected := range mustContain {
		if !strings.Contains(prompt, expected) {
			t.Errorf("prompt must contain %q, got: %s", expected, prompt)
		}
	}
}

func TestParseInsightExtractsFieldsFromValidJSON(t *testing.T) {
	raw := `{"impact":"数据泄漏风险","exploitation":"构造 UNION 查询","fix":"参数化查询"}`
	insight, err := parseInsight(raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if insight.Impact != "数据泄漏风险" {
		t.Errorf("impact mismatch: %s", insight.Impact)
	}
	if insight.Exploitation != "构造 UNION 查询" {
		t.Errorf("exploitation mismatch: %s", insight.Exploitation)
	}
	if insight.Fix != "参数化查询" {
		t.Errorf("fix mismatch: %s", insight.Fix)
	}
}

func TestParseInsightHandlesMarkdownFencedJSON(t *testing.T) {
	raw := "```json\n{\"impact\":\"x\",\"exploitation\":\"y\",\"fix\":\"z\"}\n```"
	insight, err := parseInsight(raw)
	if err != nil {
		t.Fatalf("expected no error for fenced JSON, got %v", err)
	}
	if insight.Impact != "x" {
		t.Errorf("impact mismatch: %s", insight.Impact)
	}
}

func TestParseInsightRejectsNonJSON(t *testing.T) {
	_, err := parseInsight("not json at all")
	if err == nil {
		t.Fatalf("expected error for non-JSON input")
	}
}

func TestNewWithRealClient(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "https://api.openai.com/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	enricher := New(policy, nil)
	if enricher == nil {
		t.Fatalf("New must return non-nil enricher with nil client fallback")
	}
	result := enricher.Enrich(context.Background(), model.Finding{ID: "x", RuleID: "passive.sqli-probe.query", Severity: "high", Title: "SQLi", Description: "d", Remediation: "r"})
	if result.Enriched {
		t.Fatalf("enricher with nil client must not enrich")
	}
}

func TestInsightMarker(t *testing.T) {
	if marker() != "--- AI 漏洞解读 ---" {
		t.Errorf("unexpected marker: %s", marker())
	}
}

func TestEnrichPreservesOriginalFields(t *testing.T) {
	policy := stubPolicy{enabled: true, baseURL: "https://api.test/v1", modelName: "gpt-4o-mini", apiKey: "sk-test"}
	client := &stubChatClient{
		response: `{"impact":"i","exploitation":"e","fix":"f"}`,
	}
	enricher := New(policy, client)
	finding := model.Finding{
		ID:          "abc123",
		RuleID:      "passive.sqli-probe.query",
		Severity:    "high",
		Confidence:  "firm",
		Title:       "SQL 注入",
		URL:         "https://app.test/user?id=1",
		Method:      "GET",
		Description: "original desc",
		Evidence:    "original evidence",
		Remediation: "original remediation",
		Tags:        []string{"sqli"},
	}
	result := enricher.Enrich(context.Background(), finding)
	if result.Finding.ID != finding.ID {
		t.Errorf("ID must be preserved")
	}
	if result.Finding.RuleID != finding.RuleID {
		t.Errorf("RuleID must be preserved")
	}
	if result.Finding.Severity != finding.Severity {
		t.Errorf("Severity must be preserved")
	}
	if result.Finding.Confidence != finding.Confidence {
		t.Errorf("Confidence must be preserved")
	}
	if result.Finding.Title != finding.Title {
		t.Errorf("Title must be preserved")
	}
	if result.Finding.URL != finding.URL {
		t.Errorf("URL must be preserved")
	}
	if result.Finding.Evidence != finding.Evidence {
		t.Errorf("Evidence must be preserved")
	}
	if !strings.HasPrefix(result.Finding.Description, finding.Description) {
		t.Errorf("original description must be prefix of enriched description")
	}
}

var _ chatClient = (*stubChatClient)(nil)
