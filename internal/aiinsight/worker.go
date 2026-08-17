// Package aiinsight provides AI-powered vulnerability finding enrichment.
// It reads a finding's context (rule, severity, URL, evidence) and asks an
// OpenAI-compatible model to produce an impact analysis, exploitation sketch
// and concrete remediation. The result is appended to the finding's
// description and remediation fields without overwriting the original text.
package aiinsight

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/example/easyscan/internal/aiclient"
	"github.com/example/easyscan/internal/model"
)

const (
	// FeatureInsight gates the AI vulnerability-enrichment pipeline.
	FeatureInsight = "passive.ai_insight"

	// insightMarker is prepended to the AI-generated section so callers can
	// detect findings that have already been enriched (idempotency guard).
	insightMarker = "--- AI 漏洞解读 ---"

	systemPrompt = "你是一名资深安全顾问。你只输出 JSON，不输出任何解释、注释或 Markdown 标记。"

	aiTimeout = 120 * time.Second

	maxEvidenceChars = 4000
)

// Policy exposes the feature switch and AI endpoint configuration.
type Policy interface {
	Enabled(id string) bool
	AIBaseURL() string
	AIModel() string
	AIAPIKey() string
}

// chatClient abstracts aiclient.Chat so the enricher can be unit-tested with a
// stub implementation.
type chatClient interface {
	Chat(ctx context.Context, system, user string) (string, error)
}

// Enricher runs the AI vulnerability-enrichment pipeline for a single finding.
type Enricher struct {
	policy Policy
	client chatClient
}

// New builds an enricher. If client is nil, a real aiclient.Client is built
// from the policy configuration on each Enrich call so that setting changes
// take effect immediately.
func New(policy Policy, client chatClient) *Enricher {
	return &Enricher{policy: policy, client: client}
}

// EnrichResult holds the enriched finding and whether AI enhancement was
// applied.
type EnrichResult struct {
	Finding  model.Finding
	Enriched bool
}

// Enrich asks the AI to analyse a finding and appends the insight to the
// finding's description and remediation. The original fields are preserved;
// the AI text is appended after a marker. The call is a no-op for
// informational findings, disabled switches, unconfigured endpoints or
// findings that have already been enriched.
func (e *Enricher) Enrich(ctx context.Context, finding model.Finding) EnrichResult {
	if e == nil || e.policy == nil {
		return EnrichResult{Finding: finding}
	}
	if !e.policy.Enabled(FeatureInsight) {
		return EnrichResult{Finding: finding}
	}
	if !aiclient.Configured(e.policy.AIBaseURL(), e.policy.AIModel(), e.policy.AIAPIKey()) {
		return EnrichResult{Finding: finding}
	}
	if isInformational(finding) {
		return EnrichResult{Finding: finding}
	}
	if alreadyEnriched(finding) {
		return EnrichResult{Finding: finding}
	}

	client := e.client
	if client == nil {
		client = aiclient.New(e.policy.AIBaseURL(), e.policy.AIModel(), e.policy.AIAPIKey())
	}

	callCtx, cancel := context.WithTimeout(ctx, aiTimeout)
	defer cancel()
	raw, err := client.Chat(callCtx, systemPrompt, buildPrompt(finding))
	if err != nil {
		return EnrichResult{Finding: finding}
	}
	insight, err := parseInsight(raw)
	if err != nil {
		return EnrichResult{Finding: finding}
	}

	enriched := finding
	enriched.Description = appendInsight(finding.Description, formatInsight(insight))
	if insight.Fix != "" {
		enriched.Remediation = appendInsight(finding.Remediation, "AI 修复建议："+insight.Fix)
	}
	return EnrichResult{Finding: enriched, Enriched: true}
}

// insight holds the structured AI analysis of a vulnerability finding.
type insight struct {
	Impact       string `json:"impact"`
	Exploitation string `json:"exploitation"`
	Fix          string `json:"fix"`
}

// buildPrompt constructs the user prompt sent to the AI. It includes only the
// context needed for analysis: the rule, severity, confidence, title, URL,
// method, description and a truncated evidence excerpt.
func buildPrompt(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "请对以下安全漏洞 finding 进行深度分析。\n")
	fmt.Fprintf(&b, "漏洞类型：%s\n", f.RuleID)
	fmt.Fprintf(&b, "严重程度：%s\n", f.Severity)
	if f.Confidence != "" {
		fmt.Fprintf(&b, "置信度：%s\n", f.Confidence)
	}
	if f.Title != "" {
		fmt.Fprintf(&b, "标题：%s\n", f.Title)
	}
	if f.URL != "" {
		fmt.Fprintf(&b, "URL：%s\n", f.URL)
	}
	if f.Method != "" {
		fmt.Fprintf(&b, "请求方法：%s\n", f.Method)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "描述：%s\n", f.Description)
	}
	if f.Evidence != "" {
		evidence := f.Evidence
		if len(evidence) > maxEvidenceChars {
			evidence = evidence[:maxEvidenceChars] + "...（已截断）"
		}
		fmt.Fprintf(&b, "证据：%s\n", evidence)
	}
	if len(f.Tags) > 0 {
		fmt.Fprintf(&b, "标签：%s\n", strings.Join(f.Tags, ", "))
	}
	b.WriteString("\n请输出一个 JSON 对象，包含以下字段：\n")
	b.WriteString("- impact: 该漏洞的影响范围与危害分析\n")
	b.WriteString("- exploitation: 具体利用方式与攻击步骤\n")
	b.WriteString("- fix: 针对当前漏洞的具体修复建议（包含技术方案）\n")
	b.WriteString("只输出 JSON，不要输出任何解释或 Markdown 标记。")
	return b.String()
}

// parseInsight extracts the structured analysis from the AI response. It
// tolerates markdown code fences wrapping the JSON object.
func parseInsight(raw string) (insight, error) {
	body := extractJSONObject(raw)
	if body == "" {
		return insight{}, fmt.Errorf("未找到 JSON 对象")
	}
	var result insight
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return insight{}, fmt.Errorf("解析 AI 响应失败: %w", err)
	}
	return result, nil
}

// extractJSONObject finds the outermost JSON object in the raw string,
// tolerating markdown fences.
func extractJSONObject(raw string) string {
	start := strings.IndexByte(raw, '{')
	if start < 0 {
		return ""
	}
	end := strings.LastIndexByte(raw, '}')
	if end <= start {
		return ""
	}
	return raw[start : end+1]
}

// formatInsight renders the structured analysis as human-readable text.
func formatInsight(i insight) string {
	var b strings.Builder
	if i.Impact != "" {
		fmt.Fprintf(&b, "影响分析：%s\n", i.Impact)
	}
	if i.Exploitation != "" {
		fmt.Fprintf(&b, "利用方式：%s\n", i.Exploitation)
	}
	return strings.TrimRight(b.String(), "\n")
}

// appendInsight appends the AI section to the original text with a marker.
func appendInsight(original, aiText string) string {
	if strings.TrimSpace(aiText) == "" {
		return original
	}
	if original == "" {
		return insightMarker + "\n" + aiText
	}
	return original + "\n\n" + insightMarker + "\n" + aiText
}

// alreadyEnriched reports whether the finding has already been processed by
// the AI enricher.
func alreadyEnriched(f model.Finding) bool {
	return strings.Contains(f.Description, insightMarker)
}

// isInformational reports whether the finding is low-severity informational
// output that does not warrant AI analysis.
func isInformational(f model.Finding) bool {
	if strings.EqualFold(strings.TrimSpace(f.Severity), "info") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.RuleID)), "passive.information.")
}

// marker exposes the insight marker for testing.
func marker() string {
	return insightMarker
}
