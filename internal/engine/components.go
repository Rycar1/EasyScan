package engine

import (
	"regexp"

	"github.com/example/easyscan/internal/model"
)

// headerAdvisories is deliberately small and exact-match only. Distribution
// backports and deployment configuration can change exploitability, so every
// match remains a tentative version advisory rather than a confirmed finding.
type headerAdvisory struct {
	ruleID, title, description, remediation, evidence string
	pattern                                           *regexp.Regexp
}

var headerAdvisories = []headerAdvisory{
	{
		ruleID:      "passive.candidate.apache-httpd-cve-2021-41773",
		title:       "Apache HTTP Server 2.4.49 version advisory",
		description: "A response header reports Apache HTTP Server 2.4.49, a version associated with CVE-2021-41773. Vendor backports and configuration affect exposure; verify the installed package and patch state before treating this as vulnerable.",
		remediation: "Upgrade to a supported vendor package and verify that CVE-2021-41773 is remediated.",
		evidence:    "Apache/2.4.49",
		pattern:     regexp.MustCompile(`(?i)\bapache/2\.4\.49\b`),
	},
	{
		ruleID:      "passive.candidate.apache-httpd-cve-2021-42013",
		title:       "Apache HTTP Server 2.4.50 version advisory",
		description: "A response header reports Apache HTTP Server 2.4.50, a version associated with CVE-2021-42013. Vendor backports and configuration affect exposure; verify the installed package and patch state before treating this as vulnerable.",
		remediation: "Upgrade to a supported vendor package and verify that CVE-2021-42013 is remediated.",
		evidence:    "Apache/2.4.50",
		pattern:     regexp.MustCompile(`(?i)\bapache/2\.4\.50\b`),
	},
}

func componentVersionCandidates(headers string) []model.Finding {
	var findings []model.Finding
	for _, advisory := range headerAdvisories {
		if advisory.pattern.MatchString(headers) {
			findings = append(findings, model.Finding{
				RuleID:      advisory.ruleID,
				Title:       advisory.title,
				Severity:    "low",
				Confidence:  "tentative",
				Description: advisory.description,
				Remediation: advisory.remediation,
				Evidence:    advisory.evidence,
				Tags:        []string{"candidate", "component-version", "passive", "cve-advisory"},
			})
		}
	}
	return findings
}
