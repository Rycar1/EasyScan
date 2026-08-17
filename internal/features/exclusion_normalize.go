package features

import (
	"errors"
	"fmt"
	"mime"
	"net"
	"path"
	"sort"
	"strings"
)

func NormalizeExcludedDomains(domains []string) ([]string, error) {
	seen := make(map[string]struct{}, len(domains))
	result := make([]string, 0, len(domains))
	for _, raw := range domains {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		normalized, err := normalizeExcludedDomain(raw)
		if err != nil {
			return nil, fmt.Errorf("excluded domain %q: %w", raw, err)
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result, nil
}

func NormalizeExcludedSuffixes(suffixes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(suffixes))
	result := make([]string, 0, len(suffixes))
	for _, raw := range suffixes {
		for _, value := range splitFilterValues(raw) {
			if strings.TrimSpace(value) == "" {
				continue
			}
			normalized, err := normalizeExcludedSuffix(value)
			if err != nil {
				return nil, fmt.Errorf("excluded suffix %q: %w", value, err)
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result, nil
}

func NormalizeExcludedContentTypes(contentTypes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(contentTypes))
	result := make([]string, 0, len(contentTypes))
	for _, raw := range contentTypes {
		for _, value := range splitFilterValues(raw) {
			if strings.TrimSpace(value) == "" {
				continue
			}
			normalized, err := normalizeExcludedContentType(value)
			if err != nil {
				return nil, fmt.Errorf("excluded Content-Type %q: %w", value, err)
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result, nil
}

// NormalizeExcludedPaths accepts one path glob per item, with optional
// comma/newline separation. Paths are slash-normalized, lowercased, sorted,
// and deduplicated. "*" matches one segment and "**" may cross segments.
func NormalizeExcludedPaths(paths []string) ([]string, error) {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, raw := range paths {
		for _, value := range splitExcludedPathValues(raw) {
			if strings.TrimSpace(value) == "" {
				continue
			}
			normalized, err := normalizeExcludedPath(value)
			if err != nil {
				return nil, fmt.Errorf("路径规则 %q: %w", value, err)
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result, nil
}

// NormalizeCustomProbePaths trims, de-duplicates and coerces user-supplied
// probe paths into root-relative form. Query strings and fragments are
// stripped because the probe issues a plain GET against the path only.
func NormalizeCustomProbePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, raw := range paths {
		for _, value := range splitExcludedPathValues(raw) {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			if index := strings.IndexAny(trimmed, "?#"); index >= 0 {
				trimmed = trimmed[:index]
			}
			trimmed = strings.TrimSpace(trimmed)
			if trimmed == "" {
				continue
			}
			if !strings.HasPrefix(trimmed, "/") {
				trimmed = "/" + trimmed
			}
			if _, exists := seen[trimmed]; exists {
				continue
			}
			seen[trimmed] = struct{}{}
			result = append(result, trimmed)
		}
	}
	return result
}

func NormalizeExcludedQueryParameters(parameters []string) ([]string, error) {
	return normalizeExcludedParameters(parameters, "Query")
}

func NormalizeExcludedPostParameters(parameters []string) ([]string, error) {
	return normalizeExcludedParameters(parameters, "POST/JSON")
}

func normalizeExcludedParameters(parameters []string, label string) ([]string, error) {
	seen := make(map[string]struct{}, len(parameters))
	result := make([]string, 0, len(parameters))
	for _, raw := range parameters {
		for _, value := range splitParameterFilterValues(raw) {
			if strings.TrimSpace(value) == "" {
				continue
			}
			normalized, err := normalizeExcludedParameter(value)
			if err != nil {
				return nil, fmt.Errorf("%s 参数 %q: %w", label, value, err)
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result, nil
}

func splitExcludedPathValues(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == '\uFF0C' || r == '\uFF1B' || r == '\u3001'
	})
}

func splitParameterFilterValues(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == '\uFF0C' || r == '\uFF1B' || r == '\u3001'
	})
}

func splitFilterValues(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		// Query markers are invalid in suffix/content-type filters and must
		// remain part of the value so the normalizer can reject them. Splitting
		// on '?' would silently turn ".png?download=1" into ".png".
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == '\uFF0C' || r == '\uFF1B' || r == '\u951B'
	})
}

func normalizeExcludedPath(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/")))
	if value == "" {
		return "", errors.New("路径为空")
	}
	if len(value) > 1024 {
		return "", errors.New("路径过长")
	}
	if strings.ContainsAny(value, "?#%\t\r\n ") {
		return "", errors.New("路径规则不能包含查询串、片段、百分号编码或空格")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return "", errors.New("路径规则包含控制字符")
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("路径规则不能包含 . 或 ..")
		}
	}
	if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "*") {
		value = "/" + value
	}
	value = path.Clean(value)
	if value == "." || value == "" {
		return "", errors.New("路径为空")
	}
	return value, nil
}

func normalizeObservedExcludedPath(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "/", true
	}
	if strings.ContainsAny(value, "\\?#\t\r\n") {
		return "", false
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", false
		}
	}
	return path.Clean(value), true
}

func normalizeExcludedParameter(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", errors.New("参数名为空")
	}
	if len(value) > 256 {
		return "", errors.New("参数名过长")
	}
	if strings.ContainsAny(value, "&=,;?#%/\\\t\r\n ") {
		return "", errors.New("参数名包含无效分隔符")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("参数名包含控制字符")
		}
	}
	return value, nil
}

func normalizeExcludedSuffix(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimLeft(value, ".")
	if value == "" {
		return "", errors.New("filter value is empty")
	}
	if len(value) > 255 {
		return "", errors.New("filter value is too long")
	}
	if strings.ContainsAny(value, " /\\?&#%:@\t\r\n") {
		return "", errors.New("filter value must be a URL suffix")
	}
	return "." + value, nil
}

func normalizeExcludedContentType(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", errors.New("Content-Type filter is empty")
	}
	if len(value) > 255 {
		return "", errors.New("filter value is too long")
	}
	if strings.ContainsAny(value, " \\?&#%:@\t\r\n") {
		return "", errors.New("Content-Type filter must be a media-type pattern")
	}
	if strings.HasPrefix(value, "*") {
		if len(value) == 1 || strings.Count(value, "*") != 1 || strings.Contains(value, "/") || !contentTypeToken(value[1:]) {
			return "", errors.New("invalid Content-Type filter")
		}
		return value, nil
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || !contentTypeToken(parts[0]) || (parts[1] != "*" && !contentTypeToken(parts[1])) {
		return "", errors.New("use application/pdf, image/*, or *zip")
	}
	return value, nil
}

func contentTypeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$&^_.+-", r) {
			continue
		}
		return false
	}
	return true
}

func normalizeObservedContentType(raw string) string {
	value := strings.TrimSpace(strings.Split(raw, "\n")[0])
	if value == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(value, ";")[0])
	}
	mediaType = strings.ToLower(mediaType)
	parts := strings.Split(mediaType, "/")
	if len(parts) != 2 || !contentTypeToken(parts[0]) || !contentTypeToken(parts[1]) {
		return ""
	}
	return mediaType
}

func normalizeExcludedHost(host string) (string, bool) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	normalized, err := normalizeExcludedDomain(host)
	if err != nil || strings.ContainsAny(normalized, "*?[]^") {
		return "", false
	}
	return normalized, true
}

func normalizeExcludedDomain(raw string) (string, error) {
	value := strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
	if value == "" {
		return "", errors.New("domain is empty")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if len(value) > 253 {
		return "", errors.New("domain is too long")
	}
	if strings.ContainsAny(value, "/\\@?#%:\t\r\n ") {
		return "", errors.New("domain must be a hostname, wildcard, or IP address")
	}
	if _, err := path.Match(value, ""); err != nil {
		return "", fmt.Errorf("invalid wildcard: %w", err)
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return "", errors.New("domain has an empty label")
		}
		if len(label) > 63 {
			return "", errors.New("domain label is too long")
		}
		for index := 0; index < len(label); index++ {
			if !domainPatternByte(label[index]) {
				return "", errors.New("domain has an invalid character")
			}
		}
		if !strings.ContainsAny(label, "*?[]^") && (label[0] == '-' || label[len(label)-1] == '-') {
			return "", errors.New("domain label cannot start or end with a hyphen")
		}
	}
	return value, nil
}

func domainPatternByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || strings.ContainsRune("-*?[]^", rune(value))
}
