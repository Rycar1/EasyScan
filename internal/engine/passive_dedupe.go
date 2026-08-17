package engine

import (
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/easyscan/internal/model"
)

const (
	defaultPassiveDedupCapacity = 4096
	defaultPassiveDedupTTL      = 5 * time.Minute
	maxPassiveParameterNames    = 2048
)

// passiveTransactionDeduper is a bounded, short-lived LRU of passive HTTP
// transaction shapes. It deliberately stores only SHA-256 keys: request or
// response contents never outlive Analyze, and repeated traffic cannot grow
// memory without bound.
type passiveTransactionDeduper struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	entries  map[[sha256.Size]byte]*list.Element
	lru      list.List
}

type passiveDedupEntry struct {
	key      [sha256.Size]byte
	lastSeen time.Time
}

func newPassiveTransactionDeduper(capacity int, ttl time.Duration) *passiveTransactionDeduper {
	if capacity < 0 {
		capacity = 0
	}
	return &passiveTransactionDeduper{
		capacity: capacity,
		ttl:      ttl,
		entries:  make(map[[sha256.Size]byte]*list.Element, capacity),
	}
}

// SeenOrAdd atomically reports whether the same passive transaction shape was
// seen recently. A hit refreshes its lifetime, which keeps a noisy repeating
// endpoint suppressed while allowing it to be analyzed again after it becomes
// quiet for the configured TTL.
func (d *passiveTransactionDeduper) SeenOrAdd(tx model.Transaction, parsed *url.URL) bool {
	if d == nil || d.capacity == 0 || d.ttl <= 0 || parsed == nil {
		return false
	}
	key := passiveTransactionShapeKey(tx, parsed)
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeExpiredLocked(now)
	if element := d.entries[key]; element != nil {
		entry := element.Value.(*passiveDedupEntry)
		entry.lastSeen = now
		d.lru.MoveToFront(element)
		return true
	}

	entry := &passiveDedupEntry{key: key, lastSeen: now}
	d.entries[key] = d.lru.PushFront(entry)
	for d.lru.Len() > d.capacity {
		d.removeElementLocked(d.lru.Back())
	}
	return false
}

func (d *passiveTransactionDeduper) Reset() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.entries = make(map[[sha256.Size]byte]*list.Element, d.capacity)
	d.lru.Init()
	d.mu.Unlock()
}

func (d *passiveTransactionDeduper) removeExpiredLocked(now time.Time) {
	for {
		oldest := d.lru.Back()
		if oldest == nil {
			return
		}
		entry := oldest.Value.(*passiveDedupEntry)
		if now.Sub(entry.lastSeen) < d.ttl {
			return
		}
		d.removeElementLocked(oldest)
	}
}

func (d *passiveTransactionDeduper) removeElementLocked(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*passiveDedupEntry)
	delete(d.entries, entry.key)
	d.lru.Remove(element)
}

// passiveTransactionShapeKey intentionally ignores all request parameter
// values. It retains enough response identity to avoid suppressing a changed
// page: status, exact captured body hash, and stable response headers all
// participate in the signature.
func passiveTransactionShapeKey(tx model.Transaction, parsed *url.URL) [sha256.Size]byte {
	var shape strings.Builder
	appendPassiveShapePart(&shape, normalizedPassiveMethod(tx.Request.Method))
	appendPassiveShapePart(&shape, normalizedPassiveOrigin(parsed))
	requestPath := parsed.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	appendPassiveShapePart(&shape, requestPath)

	queryNames := passiveQueryParameterNames(parsed.RawQuery)
	appendPassiveShapePart(&shape, strconv.Itoa(len(queryNames)))
	for _, name := range queryNames {
		appendPassiveShapePart(&shape, name)
	}

	bodyKind, postNames := passivePOSTParameterShape(tx.Request)
	appendPassiveShapePart(&shape, bodyKind)
	appendPassiveShapePart(&shape, strconv.Itoa(len(postNames)))
	for _, name := range postNames {
		appendPassiveShapePart(&shape, name)
	}

	appendPassiveShapePart(&shape, strconv.Itoa(tx.Response.Status))
	bodyHash := sha256.Sum256([]byte(tx.Response.Body))
	appendPassiveShapePart(&shape, string(bodyHash[:]))
	responseHeaders := stablePassiveResponseHeaders(tx.Response.Headers)
	appendPassiveShapePart(&shape, strconv.Itoa(len(responseHeaders)))
	for _, item := range responseHeaders {
		appendPassiveShapePart(&shape, item.name)
		appendPassiveShapePart(&shape, item.value)
	}
	return sha256.Sum256([]byte(shape.String()))
}

func appendPassiveShapePart(shape *strings.Builder, value string) {
	shape.WriteString(strconv.Itoa(len(value)))
	shape.WriteByte(':')
	shape.WriteString(value)
}

func normalizedPassiveMethod(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "GET"
	}
	return value
}

func normalizedPassiveOrigin(parsed *url.URL) string {
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := scheme + "://" + host
	if port != "" {
		origin += ":" + port
	}
	return origin
}

func passiveQueryParameterNames(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	names := make(map[string]struct{})
	values, _ := url.ParseQuery(rawQuery)
	for name := range values {
		if name != "" {
			names[name] = struct{}{}
		}
	}
	// ParseQuery can return useful partial results with malformed escaping or
	// unescaped semicolons. Recover the remaining raw names without retaining
	// any associated value.
	for _, field := range strings.Split(rawQuery, "&") {
		rawName, _, _ := strings.Cut(field, "=")
		if name, err := url.QueryUnescape(rawName); err == nil && name != "" {
			names[name] = struct{}{}
		}
	}
	return sortedPassiveNames(names)
}

// passivePOSTParameterShape extracts only form/JSON names and never values.
// Unsupported POST bodies still receive a body-kind marker, so they do not
// collide with an empty form or JSON object.
func passivePOSTParameterShape(request model.Message) (string, []string) {
	if normalizedPassiveMethod(request.Method) != "POST" {
		return "", nil
	}
	rawContentType := header(request.Headers, "Content-Type")
	mediaType, parameters, err := mime.ParseMediaType(rawContentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(rawContentType, ";")[0]))
	} else {
		mediaType = strings.ToLower(mediaType)
	}

	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return "form", passiveQueryParameterNames(request.Body)
	case mediaType == "multipart/form-data":
		return "multipart", passiveMultipartParameterNames(request.Body, parameters["boundary"])
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") || mediaType == "text/json":
		if names, ok := passiveJSONParameterNames(request.Body); ok {
			return "json", names
		}
		return "json-invalid", nil
	}

	trimmedBody := strings.TrimSpace(request.Body)
	if strings.HasPrefix(trimmedBody, "{") || strings.HasPrefix(trimmedBody, "[") {
		if names, ok := passiveJSONParameterNames(trimmedBody); ok {
			return "json", names
		}
	}
	if trimmedBody == "" {
		return "empty", nil
	}
	return "other", nil
}

func passiveMultipartParameterNames(body, boundary string) []string {
	boundary = strings.TrimSpace(boundary)
	if boundary == "" || body == "" {
		return nil
	}
	names := make(map[string]struct{})
	reader := multipart.NewReader(strings.NewReader(body), boundary)
	for len(names) < maxPassiveParameterNames {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		name := part.FormName()
		_ = part.Close()
		if name != "" {
			names[name] = struct{}{}
		}
	}
	return sortedPassiveNames(names)
}

func passiveJSONParameterNames(body string) ([]string, bool) {
	var value any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	names := make(map[string]struct{})
	collectPassiveJSONNames(value, names, "", 0)
	return sortedPassiveNames(names), true
}

// collectPassiveJSONNames retains both each literal property name and its
// dotted path. A filter for "token" therefore applies globally, while
// "auth.token" can target only the nested field documented in the UI.
func collectPassiveJSONNames(value any, names map[string]struct{}, prefix string, depth int) {
	if depth >= 64 || len(names) >= maxPassiveParameterNames {
		return
	}
	switch current := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(current))
		for name := range current {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			if name != "" {
				names[name] = struct{}{}
				qualified := name
				if prefix != "" {
					qualified = prefix + "." + name
				}
				names[qualified] = struct{}{}
				collectPassiveJSONNames(current[name], names, qualified, depth+1)
			} else {
				collectPassiveJSONNames(current[name], names, prefix, depth+1)
			}
			if len(names) >= maxPassiveParameterNames {
				return
			}
		}
	case []any:
		for _, child := range current {
			collectPassiveJSONNames(child, names, prefix, depth+1)
			if len(names) >= maxPassiveParameterNames {
				return
			}
		}
	}
}

func sortedPassiveNames(names map[string]struct{}) []string {
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

type passiveStableHeader struct {
	name  string
	value string
}

func stablePassiveResponseHeaders(headers map[string]string) []passiveStableHeader {
	valuesByName := make(map[string][]string)
	for rawName, rawValue := range headers {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" || volatilePassiveResponseHeader(name) {
			continue
		}
		for _, value := range strings.Split(strings.ReplaceAll(rawValue, "\r\n", "\n"), "\n") {
			valuesByName[name] = append(valuesByName[name], normalizePassiveHeaderValue(value))
		}
	}
	names := make([]string, 0, len(valuesByName))
	for name := range valuesByName {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]passiveStableHeader, 0, len(names))
	for _, name := range names {
		values := valuesByName[name]
		sort.Strings(values)
		result = append(result, passiveStableHeader{name: name, value: strings.Join(values, "\n")})
	}
	return result
}

func normalizePassiveHeaderValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// volatilePassiveResponseHeader excludes per-request clocks, identifiers,
// tracing data, cookies and latency/rate counters. Their values change even
// when the endpoint and response are otherwise identical, making them poor
// transaction-shape signals.
func volatilePassiveResponseHeader(name string) bool {
	switch name {
	case "date", "age", "expires", "retry-after", "set-cookie",
		"request-id", "correlation-id", "traceparent", "tracestate", "baggage",
		"cf-ray", "server-timing", "x-request-id", "x-correlation-id", "x-correlationid",
		"x-amzn-requestid", "x-amzn-trace-id", "x-amz-request-id", "x-amz-id-2",
		"x-amz-cf-id", "x-cloud-trace-context", "x-ot-span-context", "x-runtime",
		"x-response-time", "x-upstream-response-time", "x-envoy-upstream-service-time",
		"x-kong-proxy-latency", "x-kong-upstream-latency", "x-cache-hits":
		return true
	}
	return strings.HasPrefix(name, "x-b3-") ||
		strings.HasPrefix(name, "x-datadog-") ||
		strings.HasPrefix(name, "x-ratelimit-") ||
		strings.HasPrefix(name, "x-rate-limit-") ||
		strings.HasPrefix(name, "ratelimit-") ||
		strings.Contains(name, "request-id") ||
		strings.HasSuffix(name, "requestid") ||
		strings.Contains(name, "trace-id") ||
		strings.HasSuffix(name, "-span-id")
}
