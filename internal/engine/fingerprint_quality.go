package engine

import (
	"sort"
	"strings"
	"time"

	"github.com/example/easyscan/internal/fingerprint"
	"github.com/example/easyscan/internal/model"
)

const maxFingerprintCooccurrences = 4

func normalizeFingerprintMatches(matches []fingerprint.Match) []fingerprint.Match {
	combined := make(map[string]fingerprint.Match, len(matches))
	for _, match := range matches {
		name := normalizeFingerprintName(match.Name)
		if name == "" {
			continue
		}
		match.Name = name
		match.Sources = normalizeFingerprintSources(match.Sources)
		if match.Score <= 0 {
			match.Score = 1
		}
		key := fingerprintKey(name)
		if current, exists := combined[key]; exists {
			match.Sources = mergeStrings(current.Sources, match.Sources)
			if current.Score > match.Score {
				match.Score = current.Score
			}
			if current.Reliability > match.Reliability {
				match.Reliability = current.Reliability
			}
		}
		combined[key] = match
	}
	result := make([]fingerprint.Match, 0, len(combined))
	for _, match := range combined {
		result = append(result, match)
	}
	sort.Slice(result, func(i, j int) bool {
		leftRole, rightRole := fingerprintRole(result[i].Name), fingerprintRole(result[j].Name)
		if leftRole != rightRole {
			return leftRole < rightRole
		}
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result
}

func normalizeFingerprintName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	normalized, keep := normalizeRestoredFingerprint(value)
	if !keep {
		return ""
	}
	value = normalized
	key := normalizedFingerprintProductKey(value)
	if canonical, ok := fingerprintAliases[key]; ok {
		return canonical
	}
	return value
}

func normalizedFingerprintProductKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "", "-", "", "_", "", ".", "", "/", "")
	return replacer.Replace(value)
}

// normalizeRestoredFingerprint prevents legacy KScan-prefixed labels from
// surviving the HFinger migration while keeping ordinary current snapshots.
func normalizeRestoredFingerprint(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "kscan ·") {
		return "", false
	}
	return value, value != ""
}

var fingerprintAliases = map[string]string{
	"nginx":               "nginx",
	"nginxhttpserver":     "nginx",
	"nginxwebserver":      "nginx",
	"apache":              "Apache HTTP Server",
	"apachehttpd":         "Apache HTTP Server",
	"apachehttpserver":    "Apache HTTP Server",
	"microsoftiis":        "Microsoft IIS",
	"iis":                 "Microsoft IIS",
	"springboot":          "Spring Boot",
	"springbootactuator":  "Spring Boot Actuator",
	"springframework":     "Spring Framework",
	"shiro":               "Apache Shiro",
	"apacheshiro":         "Apache Shiro",
	"aspnet":              "ASP.NET",
	"aspnetcore":          "ASP.NET",
	"wordpress":           "WordPress",
	"vuejs":               "Vue.js",
	"phpmyadmin":          "phpMyAdmin",
	"jira":                "Jira",
	"atlassianjira":       "Jira",
	"atlassianconfluence": "Confluence",
	"openresty":           "OpenResty",
	"traefik":             "Traefik",
	"haproxy":             "HAProxy",
}

func normalizeFingerprintSources(values []string) []string {
	labels := map[string]string{
		"header":       "响应头",
		"server":       "Server 响应头",
		"banner":       "响应头",
		"body":         "响应正文",
		"title":        "页面标题",
		"response":     "完整响应",
		"path":         "访问路径",
		"status":       "响应状态",
		"content_type": "Content-Type",
		"hash":         "静态资源哈希",
		"icon":         "网站图标哈希",
		"cert":         "TLS 证书",
		"port":         "服务端口",
		"protocol":     "协议",
		"keyword":      "响应正文关键字",
		"md5":          "响应正文 MD5",
		"regx":         "响应正文正则",
		"cdn_header":   "CDN 响应头",
		"waf_header":   "WAF 响应头",
		"hostname":     "域名特征",
		"builtin":      "响应特征",
		"cookie":       "请求 Cookie",
		"set-cookie":   "Set-Cookie 响应头",
		"历史记录":         "历史记录",
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if label, ok := labels[strings.ToLower(value)]; ok {
			value = label
		}
		if value != "" {
			result = append(result, value)
		}
	}
	return mergeStrings(nil, result)
}

func mergeStrings(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	result := make([]string, 0, len(left)+len(right))
	for _, values := range [][]string{left, right} {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func fingerprintRole(value string) int {
	name := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(name, "cdn"):
		return 0
	case strings.HasPrefix(name, "waf"):
		return 1
	case containsAny(name, "openresty", "traefik", "haproxy", "envoy", "caddy", "reverse proxy"):
		return 2
	case containsAny(name, "nginx", "apache http", "microsoft iis", "tomcat", "web server"):
		return 3
	case containsAny(name, "spring", "shiro", "django", "laravel", "express", "asp.net", "flask", "rails"):
		return 4
	case containsAny(name, "wordpress", "drupal", "discuz", "confluence", "jira", "grafana", "gitlab", "cms"):
		return 5
	default:
		return 6
	}
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func fingerprintConfidence(score int) string {
	switch {
	case score >= 5:
		return "high"
	case score >= 3:
		return "medium"
	default:
		return "low"
	}
}

func toFingerprintEvidence(match fingerprint.Match) model.FingerprintEvidence {
	return model.FingerprintEvidence{
		Fingerprint: match.Name,
		Sources:     normalizeFingerprintSources(match.Sources),
		Confidence:  fingerprintConfidence(match.Score),
		Score:       match.Score,
	}
}

func mergeFingerprintEvidence(left, right model.FingerprintEvidence) model.FingerprintEvidence {
	if left.Fingerprint == "" {
		return right
	}
	left.Sources = mergeStrings(left.Sources, right.Sources)
	if right.Score > left.Score {
		left.Score = right.Score
	}
	if confidenceRank(right.Confidence) > confidenceRank(left.Confidence) {
		left.Confidence = right.Confidence
	}
	if left.Confidence == "" {
		left.Confidence = fingerprintConfidence(left.Score)
	}
	return left
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func evidenceMatches(evidence map[string]model.FingerprintEvidence) []fingerprint.Match {
	result := make([]fingerprint.Match, 0, len(evidence))
	for _, item := range evidence {
		if item.Fingerprint == "" {
			continue
		}
		result = append(result, fingerprint.Match{Name: item.Fingerprint, Sources: item.Sources, Score: item.Score})
	}
	return result
}

func (e *Engine) recordFingerprintQualityLocked(host string, observedAt time.Time, matches []fingerprint.Match) {
	if len(matches) == 0 {
		return
	}
	if e.fingerprintQuality == nil {
		e.fingerprintQuality = make(map[string]*fingerprintQualityState)
	}
	// The regular match limit is 40, but quality associations are bounded to
	// the first dozen ordered products to avoid a noisy rule explosion.
	if len(matches) > 12 {
		matches = matches[:12]
	}
	for index, match := range matches {
		key := fingerprintKey(match.Name)
		if key == "" {
			continue
		}
		state := e.fingerprintQuality[key]
		if state == nil {
			state = &fingerprintQualityState{name: match.Name, assets: make(map[string]struct{}), cooccurrences: make(map[string]int)}
			e.fingerprintQuality[key] = state
		}
		if state.name == "" {
			state.name = match.Name
		}
		state.hits++
		state.assets[strings.ToLower(host)] = struct{}{}
		if confidenceRank(fingerprintConfidence(match.Score)) > confidenceRank(state.confidence) {
			state.confidence = fingerprintConfidence(match.Score)
		}
		if observedAt.After(state.lastSeen) {
			state.lastSeen = observedAt
		}
		for otherIndex, other := range matches {
			if index == otherIndex || fingerprintKey(other.Name) == "" {
				continue
			}
			state.cooccurrences[fingerprintKey(other.Name)]++
		}
	}
}

// FingerprintQuality returns a privacy-preserving session summary that can be
// used to review noisy or unusually common fingerprint rules.
func (e *Engine) FingerprintQuality() []model.FingerprintRuleQuality {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]model.FingerprintRuleQuality, 0, len(e.fingerprintQuality))
	for key, state := range e.fingerprintQuality {
		if state == nil {
			continue
		}
		name := state.name
		if name == "" {
			name = key
		}
		quality := model.FingerprintRuleQuality{Fingerprint: name, Hits: state.hits, Assets: len(state.assets), Confidence: state.confidence, LastSeen: state.lastSeen}
		associations := make([]model.FingerprintAssociation, 0, len(state.cooccurrences))
		for associationKey, count := range state.cooccurrences {
			associationName := associationKey
			if associationState := e.fingerprintQuality[associationKey]; associationState != nil && associationState.name != "" {
				associationName = associationState.name
			}
			associations = append(associations, model.FingerprintAssociation{Fingerprint: associationName, Count: count})
		}
		sort.Slice(associations, func(i, j int) bool {
			if associations[i].Count == associations[j].Count {
				return associations[i].Fingerprint < associations[j].Fingerprint
			}
			return associations[i].Count > associations[j].Count
		})
		if len(associations) > maxFingerprintCooccurrences {
			associations = associations[:maxFingerprintCooccurrences]
		}
		quality.Cooccurrences = associations
		result = append(result, quality)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Hits == result[j].Hits {
			return result[i].Fingerprint < result[j].Fingerprint
		}
		return result[i].Hits > result[j].Hits
	})
	return result
}
