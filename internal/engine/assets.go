package engine

import (
	"sort"
	"strings"

	"github.com/example/easyscan/internal/model"
)

// Assets returns a stable, detached view of the observed hosts. Internal maps
// and evidence slices are copied so callers can safely render or persist the
// snapshot without holding the engine lock.
func (e *Engine) Assets() []model.Asset {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]model.Asset, 0, len(e.assets))
	for host, state := range e.assets {
		a := model.Asset{Host: host, LastSeen: state.lastSeen}
		for value := range state.urls {
			a.URLs = append(a.URLs, value)
		}
		for value := range state.fingerprints {
			a.Fingerprints = append(a.Fingerprints, value)
		}
		for _, evidence := range state.fingerprintEvidence {
			evidence.Sources = append([]string(nil), evidence.Sources...)
			a.FingerprintEvidence = append(a.FingerprintEvidence, evidence)
		}
		for _, endpoint := range state.endpoints {
			a.Endpoints = append(a.Endpoints, endpointModel(endpoint))
		}
		sort.Strings(a.URLs)
		sort.Strings(a.Fingerprints)
		sort.Slice(a.FingerprintEvidence, func(i, j int) bool {
			return strings.ToLower(a.FingerprintEvidence[i].Fingerprint) < strings.ToLower(a.FingerprintEvidence[j].Fingerprint)
		})
		sort.Slice(a.Endpoints, func(i, j int) bool {
			if a.Endpoints[i].Path == a.Endpoints[j].Path {
				return a.Endpoints[i].Method < a.Endpoints[j].Method
			}
			return a.Endpoints[i].Path < a.Endpoints[j].Path
		})
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Host < result[j].Host })
	return result
}

// FingerprintsForHost returns a sorted, detached copy of the fingerprints
// recorded for a single host. It avoids the full-snapshot cost of Assets when a
// caller only needs one host's fingerprints (e.g. the nuclei POC worker picking
// tags for an origin). The lookup mirrors the lowercase host key used elsewhere.
func (e *Engine) FingerprintsForHost(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	state := e.assets[host]
	if state == nil {
		return nil
	}
	fps := make([]string, 0, len(state.fingerprints))
	for value := range state.fingerprints {
		fps = append(fps, value)
	}
	sort.Strings(fps)
	return fps
}
