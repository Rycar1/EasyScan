package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/easyscan/internal/model"
)

func WriteJSON(filename string, findings []model.Finding) error {
	if filename == "" {
		return nil
	}
	return writeJSON(filename, findings)
}

// WriteHTML writes a self-contained offline report. Its two primary sections
// deliberately separate vulnerabilities from passively observed fingerprints,
// so it remains useful even when either collection is empty.
func WriteHTML(filename string, findings []model.Finding, assets []model.Asset) error {
	if filename == "" {
		return nil
	}
	contents, err := renderHTML(findings, assets)
	if err != nil {
		return err
	}
	return writeFile(filename, contents)
}

func WriteSARIF(filename string, findings []model.Finding) error {
	if filename == "" {
		return nil
	}
	type location struct {
		URI string `json:"uri"`
	}
	type result struct {
		RuleID    string                `json:"ruleId"`
		Level     string                `json:"level"`
		Message   map[string]string     `json:"message"`
		Locations []map[string]location `json:"locations"`
	}
	results := make([]result, 0, len(findings))
	for _, f := range findings {
		results = append(results, result{f.RuleID, sarifLevel(f.Severity), map[string]string{"text": f.Title + ": " + f.Description}, []map[string]location{{"physicalLocation": {URI: f.URL}}}})
	}
	payload := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "EasyScan", "informationUri": "https://github.com/example/easyscan"}}, "results": results}}}
	return writeJSON(filename, payload)
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
func writeJSON(filename string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filename, append(b, '\n'))
}
func writeFile(filename string, contents []byte) error {
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o755); err != nil && directory != "." {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Render into a sibling temporary file and rename only after it has been
	// closed. AutoHTML serializes writers, and this keeps readers from seeing
	// a partially written report while a debounced update is being committed.
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(filename)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary output permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	return nil
}
