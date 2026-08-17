package features

import (
	"path"
	"sort"
	"strings"
)

func excludedPathPatternsMatch(observedPath string, patterns []string) bool {
	for _, pattern := range patterns {
		candidate := observedPath
		if !strings.HasPrefix(pattern, "/") {
			candidate = strings.TrimPrefix(candidate, "/")
		}
		// Treat /assets/** as including the /assets base itself. This is the
		// behavior users normally expect when excluding a route tree.
		if strings.HasSuffix(pattern, "/**") && candidate == strings.TrimSuffix(pattern, "/**") {
			return true
		}
		if matchPathGlob(pattern, candidate) {
			return true
		}
	}
	return false
}

// matchPathGlob implements the small, predictable glob dialect documented in
// the settings UI: * stays inside one segment and ** crosses slash boundaries.
func matchPathGlob(pattern, value string) bool {
	type state struct{ pattern, value int }
	memo := make(map[state]bool)
	seen := make(map[state]bool)
	var match func(int, int) bool
	match = func(patternIndex, valueIndex int) bool {
		current := state{pattern: patternIndex, value: valueIndex}
		if seen[current] {
			return memo[current]
		}
		seen[current] = true
		matched := false
		switch {
		case patternIndex == len(pattern):
			matched = valueIndex == len(value)
		case pattern[patternIndex] == '*':
			doubleStar := patternIndex+1 < len(pattern) && pattern[patternIndex+1] == '*'
			nextPattern := patternIndex + 1
			if doubleStar {
				nextPattern++
			}
			matched = match(nextPattern, valueIndex)
			if !matched && valueIndex < len(value) && (doubleStar || value[valueIndex] != '/') {
				matched = match(patternIndex, valueIndex+1)
			}
		case valueIndex < len(value) && pattern[patternIndex] == value[valueIndex]:
			matched = match(patternIndex+1, valueIndex+1)
		}
		memo[current] = matched
		return matched
	}
	return match(0, 0)
}

func excludedParameterMatch(raw string, parameters []string) bool {
	normalized, err := normalizeExcludedParameter(raw)
	if err != nil {
		return false
	}
	index := sort.SearchStrings(parameters, normalized)
	return index < len(parameters) && parameters[index] == normalized
}

// swaggerPrefixExcluded reports whether a captured path prefix should be
// skipped by the swagger documentation probe. Plain patterns (no wildcard)
// use prefix-with-segment-boundary semantics so "/js" excludes "/js",
// "/js/123" and "/js/foo" but not "/json" or "/foo/js". Patterns containing
// "*" reuse the traffic-filter glob matcher where "*" stays inside a segment
// and "**" crosses separators.
func swaggerPrefixExcluded(prefix string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if strings.ContainsAny(pattern, "*") {
			candidate := prefix
			if !strings.HasPrefix(pattern, "/") {
				candidate = strings.TrimPrefix(candidate, "/")
			}
			if strings.HasSuffix(pattern, "/**") && candidate == strings.TrimSuffix(pattern, "/**") {
				return true
			}
			if matchPathGlob(pattern, candidate) {
				return true
			}
			continue
		}
		if prefix == pattern || strings.HasPrefix(prefix, pattern+"/") {
			return true
		}
	}
	return false
}

func excludedContentTypeMatch(actual, pattern string) bool {
	if actual == pattern {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(actual, strings.TrimSuffix(pattern, "*"))
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(actual, strings.TrimPrefix(pattern, "*"))
	}
	return false
}

func excludedDomainMatch(host, pattern string) bool {
	matched, err := path.Match(pattern, host)
	return err == nil && matched
}
