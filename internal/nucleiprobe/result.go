package nucleiprobe

import (
	"strings"
	"time"

	"github.com/example/easyscan/internal/model"
)

// nucleiResult is the subset of a nuclei JSONL output line we consume. nuclei
// emits one JSON object per matched template with -jsonl.
type nucleiResult struct {
	TemplateID string       `json:"template-id"`
	Type       string       `json:"type"`
	Host       string       `json:"host"`
	MatchedAt  string       `json:"matched-at"`
	Request    string       `json:"request,omitempty"`
	Response   string       `json:"response,omitempty"`
	Info       nucleiInfo   `json:"info"`
}

// nucleiInfo carries the template metadata block.
type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Reference   []string `json:"reference,omitempty"`
}

// toFinding converts a nuclei result into an EasyScan finding. The rule ID is
// namespaced under "passive.nuclei." so results are grouped with the other
// MITM POC detectors and are easy to filter or purge.
func (r nucleiResult) toFinding(observedAt time.Time) model.Finding {
	targetURL := strings.TrimSpace(r.MatchedAt)
	if targetURL == "" {
		targetURL = strings.TrimSpace(r.Host)
	}
	title := strings.TrimSpace(r.Info.Name)
	if title == "" {
		title = r.TemplateID
	}
	description := strings.TrimSpace(r.Info.Description)
	if description == "" {
		description = "nuclei 模板 " + r.TemplateID + " 命中。"
	}
	return model.Finding{
		RuleID:      "passive.nuclei." + r.TemplateID,
		Title:       "Nuclei: " + title,
		Severity:    normalizeSeverity(r.Info.Severity),
		Confidence:  "medium",
		URL:         targetURL,
		Description: description,
		Evidence:    truncateEvidence(r.Response),
		Remediation: strings.TrimSpace(r.Info.Remediation),
		Tags:        append([]string(nil), r.Info.Tags...),
		ObservedAt:  observedAt,
	}
}

// normalizeSeverity maps nuclei severity labels to EasyScan's vocabulary,
// defaulting to "info" for unknown or empty values.
func normalizeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "info"
	}
}

// truncateEvidence bounds the response snippet stored on a finding so a large
// nuclei response body cannot bloat the snapshot.
func truncateEvidence(body string) string {
	const maxEvidence = 2048
	body = strings.TrimSpace(body)
	if len(body) > maxEvidence {
		return body[:maxEvidence]
	}
	return body
}
