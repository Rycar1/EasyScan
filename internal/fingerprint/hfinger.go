package fingerprint

import (
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/example/easyscan/internal/model"
	hrules "hfinger/rules"
	"hfinger/rulesets"
)

// Match is the normalized fingerprint result consumed by EasyScan's asset
// inventory. HFinger confidence is mapped to the compact score used by the
// existing desktop evidence and quality views.
type Match struct {
	Name        string
	Category    string
	Sources     []string
	Score       int
	Reliability int
}

// HFingerStats is safe to expose through the desktop binding. Errors contain
// file names and validation messages only; response contents never enter it.
type HFingerStats struct {
	Source       string   `json:"source"`
	CustomDir    string   `json:"custom_dir"`
	Loaded       int      `json:"loaded"`
	Products     int      `json:"products"`
	BuiltinRules int      `json:"builtin_rules"`
	CustomRules  int      `json:"custom_rules"`
	CustomFiles  int      `json:"custom_files"`
	FailedFiles  int      `json:"failed_files"`
	Errors       []string `json:"errors,omitempty"`
}

// HFingerDatabase adapts HackAllSec/hfinger's embedded core rules to an
// already-observed EasyScan HTTP transaction. It never performs networking.
// Reload builds and validates a complete immutable rule slice before swapping
// it under the lock, so MITM matching continues while custom YAML is reloaded.
type HFingerDatabase struct {
	mu         sync.RWMutex
	customDir  string
	maxMatches int
	rules      []hrules.Rule
	stats      HFingerStats
}

var (
	titlePattern   = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)
	htmlTagPattern = regexp.MustCompile(`<[^>]+>`)
)

// LoadHFinger loads the upstream embedded core rules plus valid .yaml/.yml
// files from customDir. One invalid custom file is isolated and reported while
// the remaining rules stay available.
func LoadHFinger(customDir string, maxMatches int) (*HFingerDatabase, error) {
	if maxMatches <= 0 {
		maxMatches = 40
	}
	database := &HFingerDatabase{customDir: strings.TrimSpace(customDir), maxMatches: maxMatches}
	if err := database.Reload(); err != nil {
		return nil, err
	}
	return database, nil
}

// Reload re-reads custom YAML and atomically replaces the active HFinger rule
// set. Embedded-rule failures are fatal; custom-file failures are retained in
// Stats and do not disable other files.
func (d *HFingerDatabase) Reload() error {
	core, err := hrules.LoadYAMLFS(rulesets.CoreFS, "core")
	if err != nil {
		return fmt.Errorf("load embedded HFinger rules: %w", err)
	}
	core = hrules.NormalizeRules(core)
	if err := hrules.ValidateRules(core); err != nil {
		return fmt.Errorf("validate embedded HFinger rules: %w", err)
	}

	merged := append([]hrules.Rule(nil), core...)
	index := make(map[string]int, len(merged))
	for i, rule := range merged {
		index[rule.ID] = i
	}

	stats := HFingerStats{
		Source:       "内置指纹库",
		CustomDir:    d.customDir,
		BuiltinRules: len(core),
	}
	files, listErrors := hFingerYAMLFiles(d.customDir)
	stats.Errors = append(stats.Errors, listErrors...)
	stats.FailedFiles += len(listErrors)
	for _, filename := range files {
		loaded, loadErr := hrules.LoadYAMLFile(filename)
		if loadErr == nil {
			loaded = hrules.NormalizeRules(loaded)
			loadErr = hrules.ValidateRules(loaded)
		}
		if loadErr != nil {
			stats.FailedFiles++
			stats.Errors = append(stats.Errors, fmt.Sprintf("%s: %v", filepath.Base(filename), loadErr))
			continue
		}
		stats.CustomFiles++
		stats.CustomRules += len(loaded)
		for _, rule := range loaded {
			if existing, ok := index[rule.ID]; ok {
				merged[existing] = rule
				continue
			}
			index[rule.ID] = len(merged)
			merged = append(merged, rule)
		}
	}

	stats.Loaded = len(merged)
	stats.Products = uniqueHFingerProducts(merged)
	d.mu.Lock()
	d.rules = merged
	d.stats = stats
	d.mu.Unlock()
	return nil
}

// ValidateFile applies HFinger's YAML parser and schema validator before the
// desktop importer copies a user-selected file into the custom directory.
func (d *HFingerDatabase) ValidateFile(filename string) (int, error) {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(filename)))
	if ext != ".yaml" && ext != ".yml" {
		return 0, fmt.Errorf("HFinger rule file must use .yaml or .yml")
	}
	ruleSet, err := hrules.LoadYAMLFile(filename)
	if err != nil {
		return 0, err
	}
	ruleSet = hrules.NormalizeRules(ruleSet)
	if err := hrules.ValidateRules(ruleSet); err != nil {
		return 0, err
	}
	return len(ruleSet), nil
}

func (d *HFingerDatabase) Stats() HFingerStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := d.stats
	result.Errors = append([]string(nil), d.stats.Errors...)
	return result
}

// MatchDetails evaluates one observed proxy response with HFinger. CDN and
// WAF categories remain connected to their existing MITM feature switches.
func (d *HFingerDatabase) MatchDetails(tx model.Transaction, detectCDN, detectWAF bool) []Match {
	return d.MatchDetailsMulti([]model.Transaction{tx}, detectCDN, detectWAF)
}

// MatchDetailsMulti evaluates several responses for the same host together, so
// that favicon-hash, path-based and error-page rules can be satisfied by
// actively probed responses (for example /favicon.ico and a 404 page) that a
// single passive response would never carry. Evidence is aggregated across all
// supplied responses before the strategy threshold is applied.
func (d *HFingerDatabase) MatchDetailsMulti(txs []model.Transaction, detectCDN, detectWAF bool) []Match {
	d.mu.RLock()
	ruleSet := d.rules
	limit := d.maxMatches
	d.mu.RUnlock()
	if len(ruleSet) == 0 || len(txs) == 0 {
		return nil
	}

	responses := make([]hrules.Response, 0, len(txs))
	allErrorPages := true
	for _, tx := range txs {
		responses = append(responses, hFingerResponse(tx))
		if tx.Response.Status < 400 {
			allErrorPages = false
		}
	}
	results := hrules.MatchRules(responses, ruleSet)
	matches := make([]Match, 0, min(len(results), limit))
	for _, result := range results {
		if !result.Matched || lowValueHFingerProduct(result.Rule.Name) {
			continue
		}
		category := strings.ToLower(strings.TrimSpace(result.Rule.Category))
		if category == "cdn" && !detectCDN || category == "waf" && !detectWAF {
			continue
		}
		// Error pages frequently reflect a requested path or product keyword.
		// Only when every supplied response was a 4xx/5xx page do we require
		// independent header, cookie, server, TLS, or DNS evidence before
		// accepting the product; a mixed set already carries a normal page.
		if allErrorPages && !hasStrongErrorPageEvidence(result) {
			continue
		}
		name := strings.TrimSpace(result.Rule.Name)
		if category == "cdn" || category == "waf" {
			prefix := strings.ToUpper(category) + " · "
			if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				name = prefix + name
			}
		}
		matches = append(matches, Match{
			Name:        name,
			Category:    category,
			Sources:     hFingerEvidenceSources(result),
			Score:       hFingerConfidenceScore(result.Confidence),
			Reliability: hFingerReliability(result.Confidence),
		})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return strings.ToLower(matches[i].Name) < strings.ToLower(matches[j].Name)
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches
}

func hFingerYAMLFiles(directory string) ([]string, []string) {
	if strings.TrimSpace(directory) == "" {
		return nil, nil
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, []string{fmt.Sprintf("create custom rule directory: %v", err)}
	}
	files := make([]string, 0)
	errorsFound := make([]string, 0)
	err := filepath.WalkDir(directory, func(item string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			errorsFound = append(errorsFound, fmt.Sprintf("%s: %v", filepath.Base(item), walkErr))
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(item))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, item)
		}
		return nil
	})
	if err != nil {
		errorsFound = append(errorsFound, err.Error())
	}
	sort.Strings(files)
	return files, errorsFound
}

func hFingerResponse(tx model.Transaction) hrules.Response {
	rawURL := strings.TrimSpace(tx.Request.URL)
	pathValue := "/"
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Path != "" {
		pathValue = parsed.Path
	}
	headers := make(http.Header, len(tx.Response.Headers))
	for name, value := range tx.Response.Headers {
		for _, item := range splitObservedHeaderValue(name, value) {
			headers.Add(name, item)
		}
	}
	// Cookie-based fingerprints (e.g. PHPSESSID -> PHP, JSESSIONID -> Java)
	// otherwise only match on the single response that issues Set-Cookie. Once
	// the browser holds the session, the server stops re-issuing it and the
	// request carries the cookie instead, making recognition non-deterministic.
	// Mirror the request Cookie NAMES into Set-Cookie so those rules match
	// stably regardless of which side currently carries the cookie. Only names
	// are copied; the (sensitive) values are dropped.
	for _, name := range requestCookieNames(tx.Request.Headers) {
		headers.Add("Set-Cookie", name+"=")
	}
	body := []byte(tx.Response.Body)
	response := hrules.Response{
		URL:        rawURL,
		Path:       pathValue,
		StatusCode: tx.Response.Status,
		Server:     headers.Get("Server"),
		Title:      observedHTMLTitle(tx.Response.Body),
		Header:     headers,
		Body:       body,
		Behavior: hrules.BehaviorInfo{
			Compression: headers.Get("Content-Encoding"),
			AltSvc:      headers.Get("Alt-Svc"),
			Cache:       strings.TrimSpace(headers.Get("Cache-Control") + " " + headers.Get("Expires")),
		},
		TLS: observedTLSInfo(tx.Response.Certificate),
	}
	if len(body) > 0 && isObservedFavicon(pathValue, headers.Get("Content-Type")) && tx.Response.Status >= 200 && tx.Response.Status < 400 {
		response.Favicon = body
	}
	return response
}

func splitObservedHeaderValue(name, value string) []string {
	if strings.EqualFold(name, "Set-Cookie") {
		// Flattened proxy headers may join independent cookies with a newline.
		parts := strings.FieldsFunc(value, func(r rune) bool { return r == '\r' || r == '\n' })
		if len(parts) > 0 {
			return parts
		}
	}
	return []string{value}
}

// requestCookieNames extracts the cookie names from the request Cookie
// header(s). A request Cookie header packs pairs as "a=1; b=2"; only the names
// are returned so cookie-based fingerprints can match while sensitive values
// are discarded.
func requestCookieNames(headers map[string]string) []string {
	var names []string
	seen := make(map[string]struct{})
	for name, value := range headers {
		if !strings.EqualFold(name, "Cookie") {
			continue
		}
		for _, line := range splitObservedHeaderValue(name, value) {
			for _, pair := range strings.Split(line, ";") {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				cookieName := pair
				if idx := strings.IndexByte(pair, '='); idx >= 0 {
					cookieName = pair[:idx]
				}
				cookieName = strings.TrimSpace(cookieName)
				if cookieName == "" {
					continue
				}
				if _, ok := seen[cookieName]; ok {
					continue
				}
				seen[cookieName] = struct{}{}
				names = append(names, cookieName)
			}
		}
	}
	return names
}

func observedHTMLTitle(body string) string {
	match := titlePattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	value := htmlTagPattern.ReplaceAllString(match[1], " ")
	return strings.Join(strings.Fields(html.UnescapeString(value)), " ")
}

// observedTLSInfo maps the compact certificate summary captured by the MITM
// transport into HFinger's TLS fields. The proxy has already observed this
// certificate; parsing the summary never opens another connection.
//
// The producer joins "key=value" parts with "; ", but a certificate subject or
// issuer distinguished name legitimately contains ';' and '=' of its own (for
// example "CN=a; O=b"). Splitting naively on ';' would therefore truncate such
// values and discard the tail. Fields are instead delimited only at "; "
// boundaries that introduce a known key, and any fragment without a recognized
// key prefix is treated as a continuation of the previous value.
func observedTLSInfo(summary string) hrules.TLSInfo {
	var result hrules.TLSInfo
	if strings.TrimSpace(summary) == "" {
		return result
	}
	knownKeys := []string{"subject", "issuer", "serial", "dns"}
	fragments := strings.Split(summary, "; ")
	var key, value string
	flush := func() {
		if key == "" {
			return
		}
		value = strings.TrimSpace(value)
		switch key {
		case "subject":
			result.Subject = value
		case "issuer":
			result.Issuer = value
		case "dns":
			if value != "" {
				result.DNSNames = append(result.DNSNames, value)
			}
		}
	}
	for _, fragment := range fragments {
		matchedKey := ""
		for _, k := range knownKeys {
			if strings.HasPrefix(fragment, k+"=") {
				matchedKey = k
				break
			}
		}
		if matchedKey == "" {
			// Continuation of the previous field's value (the "; " that split
			// it belonged to the DN, not to the summary framing).
			if key != "" {
				value += "; " + fragment
			}
			continue
		}
		flush()
		key = matchedKey
		value = strings.TrimPrefix(fragment, matchedKey+"=")
	}
	flush()
	return result
}

func isObservedFavicon(pathValue, contentType string) bool {
	pathValue = strings.ToLower(pathValue)
	contentType = strings.ToLower(contentType)
	if strings.Contains(pathValue, "favicon") || strings.HasSuffix(pathValue, ".ico") {
		return true
	}
	switch {
	case strings.Contains(contentType, "image/x-icon"),
		strings.Contains(contentType, "image/vnd.microsoft.icon"),
		strings.Contains(contentType, "image/png"),
		strings.Contains(contentType, "image/svg"),
		strings.Contains(contentType, "image/gif"):
		return true
	}
	return false
}

func hasStrongErrorPageEvidence(result hrules.MatchResult) bool {
	for _, evidence := range result.Evidence {
		kind := strings.ToLower(strings.TrimSpace(evidence.MatcherType))
		switch {
		case strings.HasPrefix(kind, "header."),
			kind == "cookie.contains",
			strings.HasPrefix(kind, "server.banner."),
			strings.HasPrefix(kind, "tls."),
			strings.HasPrefix(kind, "dns."):
			return true
		}
	}
	return false
}

func hFingerEvidenceSources(result hrules.MatchResult) []string {
	seen := make(map[string]struct{}, len(result.Evidence)+1)
	sources := make([]string, 0, len(result.Evidence)+1)
	for _, evidence := range result.Evidence {
		source := strings.TrimSpace(evidence.MatcherType)
		if source == "" {
			source = strings.TrimSpace(evidence.Source)
		}
		if source == "" {
			continue
		}
		key := strings.ToLower(source)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		sources = append(sources, "指纹 · "+source)
	}
	if len(sources) == 0 {
		sources = append(sources, "指纹")
	}
	return sources
}

func hFingerConfidenceScore(confidence int) int {
	switch {
	case confidence >= 80:
		return 5
	case confidence >= 60:
		return 3
	default:
		return 2
	}
}

func hFingerReliability(confidence int) int {
	switch {
	case confidence >= 90:
		return 4
	case confidence >= 80:
		return 3
	case confidence >= 60:
		return 2
	default:
		return 1
	}
}

func lowValueHFingerProduct(name string) bool {
	key := strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(name)))
	switch key {
	case "jquery", "jqueryofficialwebsitecdn", "bootstrap", "bootstrapcdn", "gzip", "gzipencode", "gse":
		return true
	default:
		return false
	}
}

func uniqueHFingerProducts(ruleSet []hrules.Rule) int {
	seen := make(map[string]struct{}, len(ruleSet))
	for _, rule := range ruleSet {
		name := strings.ToLower(strings.TrimSpace(rule.Name))
		if name != "" && !lowValueHFingerProduct(name) {
			seen[name] = struct{}{}
		}
	}
	return len(seen)
}
