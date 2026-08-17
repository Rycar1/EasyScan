package xssprobe

import (
	"net/http"
	"testing"

	"github.com/example/easyscan/internal/model"
)

func TestExtractParametersIncludesCookieHeaderAndPath(t *testing.T) {
	tx := model.Transaction{
		Request: model.Message{
			Method: http.MethodGet,
			URL:    "https://app.example.test/users/42/profile",
			Headers: map[string]string{
				"Cookie":   "session=abc123; theme=dark",
				"Referer":  "https://attacker.example.test/",
				"X-Forwarded-For": "1.2.3.4",
			},
		},
	}
	params := extractParameters(tx)
	locations := make(map[string]int)
	for _, p := range params {
		locations[p.location]++
	}
	if locations["cookie"] == 0 {
		t.Errorf("expected cookie parameters, got %v", locations)
	}
	if locations["header"] == 0 {
		t.Errorf("expected header parameters (Referer/X-Forwarded-For), got %v", locations)
	}

	pathOnly := model.Transaction{
		Request: model.Message{
			Method: http.MethodGet,
			URL:    "https://app.example.test/users/42",
		},
	}
	pathParams := extractParameters(pathOnly)
	hasPath := false
	for _, p := range pathParams {
		if p.location == "path" {
			hasPath = true
		}
	}
	if !hasPath {
		t.Errorf("expected path parameter for RESTful URL, got %v", pathParams)
	}
}

func TestExtractParametersStillCoversQueryFormJson(t *testing.T) {
	tx := model.Transaction{
		Request: model.Message{
			Method: http.MethodPost,
			URL:    "https://app.example.test/api?id=1",
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: "name=alice",
		},
	}
	params := extractParameters(tx)
	locations := make(map[string]bool)
	for _, p := range params {
		locations[p.location] = true
	}
	if !locations["query"] {
		t.Errorf("expected query parameter, got %v", locations)
	}
	if !locations["form"] {
		t.Errorf("expected form parameter, got %v", locations)
	}
}

func TestObserveAcceptsPutAndPatch(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			tx := model.Transaction{
				Source:  model.SourceHTTPProxy,
				Request: model.Message{Method: method, URL: "https://app.example.test/api?id=1"},
			}
			params := extractParameters(tx)
			if len(params) == 0 {
				t.Fatalf("extractParameters must return query params for %s", method)
			}
		})
	}
}
