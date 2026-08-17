package engine

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/example/easyscan/internal/model"
)

type endpointState struct {
	method, path        string
	parameters, sources map[string]struct{}
}

func observedEndpoints(base *url.URL, tx model.Transaction) []endpointState {
	states := map[string]*endpointState{}
	add := func(method, path, source string, names []string) {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			method = "GET"
		}
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		key := method + "\x00" + path
		state := states[key]
		if state == nil {
			state = &endpointState{method: method, path: path, parameters: map[string]struct{}{}, sources: map[string]struct{}{}}
			states[key] = state
		}
		state.sources[source] = struct{}{}
		for _, name := range names {
			if name = strings.TrimSpace(name); name != "" && len(name) <= 120 {
				state.parameters[name] = struct{}{}
			}
		}
	}
	add(tx.Request.Method, base.EscapedPath(), "observed-request", queryKeys(base.Query()))
	for _, name := range requestParameterNames(tx) {
		add(tx.Request.Method, base.EscapedPath(), "observed-request", []string{name})
	}
	for _, form := range extractForms(base, tx.Response.Body) {
		add(form.method, form.path, "html-form", form.parameters)
	}
	result := make([]endpointState, 0, len(states))
	for _, state := range states {
		result = append(result, *state)
	}
	return result
}

func endpointModel(state endpointState) model.Endpoint {
	endpoint := model.Endpoint{Method: state.method, Path: state.path}
	for value := range state.parameters {
		endpoint.Parameters = append(endpoint.Parameters, value)
	}
	for value := range state.sources {
		endpoint.Sources = append(endpoint.Sources, value)
	}
	sort.Strings(endpoint.Parameters)
	sort.Strings(endpoint.Sources)
	return endpoint
}
func queryKeys(values url.Values) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
func requestParameterNames(tx model.Transaction) []string {
	contentType := strings.ToLower(header(tx.Request.Headers, "Content-Type"))
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(tx.Request.Body)
		if err == nil {
			return queryKeys(values)
		}
	}
	if strings.Contains(contentType, "application/json") {
		var value any
		if json.Unmarshal([]byte(tx.Request.Body), &value) == nil {
			return jsonKeys(value, nil)
		}
	}
	return nil
}
func jsonKeys(value any, prefix []string) []string {
	var result []string
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			path := append(append([]string(nil), prefix...), key)
			result = append(result, strings.Join(path, "."))
			result = append(result, jsonKeys(child, path)...)
		}
	case []any:
		for _, child := range typed {
			result = append(result, jsonKeys(child, prefix)...)
		}
	}
	return result
}

type htmlForm struct {
	method, path string
	parameters   []string
}

var formPattern = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
var attributePattern = regexp.MustCompile(`(?is)\b([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
var inputNamePattern = regexp.MustCompile(`(?is)<(?:input|select|textarea)\b([^>]*)>`)

func extractForms(base *url.URL, body string) []htmlForm {
	if len(body) == 0 || len(body) > 2<<20 {
		return nil
	}
	var result []htmlForm
	for _, match := range formPattern.FindAllStringSubmatch(body, -1) {
		attrs := htmlAttributes(match[1])
		method := strings.ToUpper(attrs["method"])
		if method == "" {
			method = "GET"
		}
		action := attrs["action"]
		target, err := base.Parse(action)
		if err != nil || target.Hostname() != base.Hostname() {
			continue
		}
		form := htmlForm{method: method, path: target.EscapedPath()}
		for _, input := range inputNamePattern.FindAllStringSubmatch(match[2], -1) {
			if name := htmlAttributes(input[1])["name"]; name != "" {
				form.parameters = append(form.parameters, name)
			}
		}
		result = append(result, form)
	}
	return result
}
func htmlAttributes(raw string) map[string]string {
	result := map[string]string{}
	for _, match := range attributePattern.FindAllStringSubmatch(raw, -1) {
		value := match[2]
		if value == "" {
			value = match[3]
		}
		result[strings.ToLower(match[1])] = strings.TrimSpace(value)
	}
	return result
}
