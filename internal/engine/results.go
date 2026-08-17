package engine

import (
	"fmt"
	"sort"

	"github.com/example/easyscan/internal/fingerprint"
	"github.com/example/easyscan/internal/model"
)

// Findings returns a stable oldest-first copy of the current finding set.
func (e *Engine) Findings() []model.Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]model.Finding, 0, len(e.findings))
	for _, f := range e.findings {
		result = append(result, f)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ObservedAt.Before(result[j].ObservedAt) })
	return result
}

// RuleCount reports the number of compiled passive rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// HFingerStats reports the embedded and user-supplied YAML rule counts.
func (e *Engine) HFingerStats() fingerprint.HFingerStats {
	e.mu.RLock()
	database := e.hfinger
	e.mu.RUnlock()
	if database != nil {
		return database.Stats()
	}
	return fingerprint.HFingerStats{Source: "HackAllSec/hfinger"}
}

// ReloadHFingerRules hot-reloads the configured custom YAML directory.
func (e *Engine) ReloadHFingerRules() error {
	e.mu.RLock()
	database := e.hfinger
	e.mu.RUnlock()
	if database == nil {
		return fmt.Errorf("HFinger is not initialized")
	}
	if err := database.Reload(); err != nil {
		return err
	}
	stats := database.Stats()
	e.Log("info", "fingerprint", fmt.Sprintf("HFinger 规则已重载：%d 条，自定义 %d 条", stats.Loaded, stats.CustomRules))
	for _, loadError := range stats.Errors {
		e.Log("error", "fingerprint", fmt.Sprintf("HFinger 自定义规则跳过：%s", loadError))
	}
	return nil
}

// ValidateHFingerRuleFile validates a candidate YAML before desktop import.
func (e *Engine) ValidateHFingerRuleFile(filename string) (int, error) {
	e.mu.RLock()
	database := e.hfinger
	e.mu.RUnlock()
	if database == nil {
		return 0, fmt.Errorf("HFinger is not initialized")
	}
	return database.ValidateFile(filename)
}
