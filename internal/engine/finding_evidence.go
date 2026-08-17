package engine

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/example/easyscan/internal/model"
)

// FindingEvidence returns complete request/response captures grouped by
// finding ID. The data exists only for this running Engine and is copied out
// of the bounded in-memory cache; it is never part of SnapshotSink, SQLite,
// or report payloads.
func (e *Engine) FindingEvidence() map[string][]model.FindingEvidence {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string][]model.FindingEvidence, len(e.findingEvidence))
	for findingID, entries := range e.findingEvidence {
		result[findingID] = cloneFindingEvidence(entries)
	}
	return result
}

// EvidenceForFinding returns the current session's complete HTTP captures for
// one finding. Entries are oldest-first, so a desktop client can label them
// Request 1, Request 2, and so on deterministically.
func (e *Engine) EvidenceForFinding(findingID string) []model.FindingEvidence {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return cloneFindingEvidence(e.findingEvidence[findingID])
}

func cloneFindingEvidence(entries []model.FindingEvidence) []model.FindingEvidence {
	result := make([]model.FindingEvidence, len(entries))
	copy(result, entries)
	sort.Slice(result, func(i, j int) bool {
		if result[i].ObservedAt.Equal(result[j].ObservedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].ObservedAt.Before(result[j].ObservedAt)
	})
	return result
}

func (e *Engine) recordFindingEvidence(tx model.Transaction, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	request, response := formatFindingEvidenceExchange(tx)
	captureBytes := len(request) + len(response)
	// Do not truncate a packet marked as raw. If one imported exchange alone
	// exceeds the complete cache quota, omit it instead of returning a
	// misleading partial request or response.
	if captureBytes > findingEvidenceByteLimit {
		return
	}
	observed := tx.Observed.UTC()
	source := strings.TrimSpace(tx.Source)
	if source == "" {
		source = "unknown"
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		findingID := strings.TrimSpace(finding.ID)
		if findingID == "" {
			continue
		}
		if _, exists := seen[findingID]; exists {
			continue
		}
		seen[findingID] = struct{}{}

		e.findingEvidenceSequence++
		capture := model.FindingEvidence{
			ID:         fmt.Sprintf("evidence-%d", e.findingEvidenceSequence),
			FindingID:  findingID,
			ObservedAt: observed,
			Source:     source,
			Request:    request,
			Response:   response,
		}
		entries := e.findingEvidence[findingID]
		for len(entries) >= findingEvidencePerFindingLimit {
			dropped := entries[0]
			e.removeFindingEvidenceReferenceLocked(findingID, dropped.ID)
			e.removeFindingEvidenceLocked(findingID, dropped.ID)
			entries = e.findingEvidence[findingID]
		}
		entries = append(entries, capture)
		e.findingEvidence[findingID] = entries
		e.findingEvidenceOrder = append(e.findingEvidenceOrder, findingEvidenceReference{findingID: findingID, evidenceID: capture.ID})
		e.findingEvidenceBytes += captureBytes

		for len(e.findingEvidenceOrder) > findingEvidenceHistoryLimit || e.findingEvidenceBytes > findingEvidenceByteLimit {
			oldest := e.findingEvidenceOrder[0]
			e.findingEvidenceOrder[0] = findingEvidenceReference{}
			e.findingEvidenceOrder = e.findingEvidenceOrder[1:]
			e.removeFindingEvidenceLocked(oldest.findingID, oldest.evidenceID)
		}
	}
}

func (e *Engine) removeFindingEvidenceLocked(findingID, evidenceID string) {
	entries := e.findingEvidence[findingID]
	for index, entry := range entries {
		if entry.ID != evidenceID {
			continue
		}
		e.findingEvidenceBytes -= findingEvidenceSize(entry)
		copy(entries[index:], entries[index+1:])
		entries[len(entries)-1] = model.FindingEvidence{}
		entries = entries[:len(entries)-1]
		if len(entries) == 0 {
			delete(e.findingEvidence, findingID)
		} else {
			e.findingEvidence[findingID] = entries
		}
		return
	}
}

func findingEvidenceSize(entry model.FindingEvidence) int {
	return len(entry.Request) + len(entry.Response)
}

func (e *Engine) removeFindingEvidenceReferenceLocked(findingID, evidenceID string) {
	for index, reference := range e.findingEvidenceOrder {
		if reference.findingID != findingID || reference.evidenceID != evidenceID {
			continue
		}
		copy(e.findingEvidenceOrder[index:], e.findingEvidenceOrder[index+1:])
		e.findingEvidenceOrder[len(e.findingEvidenceOrder)-1] = findingEvidenceReference{}
		e.findingEvidenceOrder = e.findingEvidenceOrder[:len(e.findingEvidenceOrder)-1]
		return
	}
}

func formatFindingEvidenceExchange(tx model.Transaction) (string, string) {
	method := strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	if method == "" {
		method = http.MethodGet
	}
	target, host := findingEvidenceRequestTarget(tx.Request.URL, method)
	request := formatFindingEvidenceMessage(
		fmt.Sprintf("%s %s HTTP/1.1", method, target),
		tx.Request.Headers,
		tx.Request.Body,
		host,
	)

	statusLine := fmt.Sprintf("HTTP/1.1 %d", tx.Response.Status)
	if text := http.StatusText(tx.Response.Status); text != "" {
		statusLine += " " + text
	}
	response := formatFindingEvidenceMessage(statusLine, tx.Response.Headers, tx.Response.Body, "")
	return request, response
}

func findingEvidenceRequestTarget(rawURL, method string) (string, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		if strings.TrimSpace(rawURL) != "" {
			return rawURL, ""
		}
		return "/", ""
	}
	if method == http.MethodConnect && parsed.Host != "" {
		return parsed.Host, parsed.Host
	}
	target := parsed.RequestURI()
	if target == "" {
		target = "/"
	}
	return target, parsed.Host
}

func formatFindingEvidenceMessage(startLine string, headers map[string]string, body, defaultHost string) string {
	lines := []string{startLine}
	if defaultHost != "" && !hasFindingEvidenceHeader(headers, "Host") {
		lines = append(lines, "Host: "+defaultHost)
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := strings.ToLower(keys[i]), strings.ToLower(keys[j])
		if left == right {
			return keys[i] < keys[j]
		}
		return left < right
	})
	for _, key := range keys {
		// Header values originating from net/http can contain multiple values
		// joined by a newline. Render each one as its own HTTP header line.
		values := strings.Split(strings.ReplaceAll(headers[key], "\r\n", "\n"), "\n")
		for _, value := range values {
			lines = append(lines, key+": "+value)
		}
	}
	return strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}

func hasFindingEvidenceHeader(headers map[string]string, expected string) bool {
	for key := range headers {
		if strings.EqualFold(key, expected) {
			return true
		}
	}
	return false
}
