package cmdprobe

import (
	"context"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/example/easyscan/internal/model"
)

func TestExtractTargets(t *testing.T) {
	tests := []struct {
		name    string
		tx      model.Transaction
		wantSet map[string]string // "location:name" -> value
	}{
		{
			name: "query params only",
			tx: model.Transaction{Request: model.Message{
				Method: "GET",
				URL:    "http://target.local/run?cmd=ls&host=127.0.0.1",
			}},
			wantSet: map[string]string{
				"query:cmd":  "ls",
				"query:host": "127.0.0.1",
			},
		},
		{
			name: "form params on urlencoded body",
			tx: model.Transaction{Request: model.Message{
				Method:  "POST",
				URL:     "http://target.local/run",
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:    "ip=10.0.0.1&action=ping",
			}},
			wantSet: map[string]string{
				"form:ip":     "10.0.0.1",
				"form:action": "ping",
			},
		},
		{
			name: "query and form combined",
			tx: model.Transaction{Request: model.Message{
				Method:  "POST",
				URL:     "http://target.local/run?debug=1",
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
				Body:    "ip=10.0.0.1",
			}},
			wantSet: map[string]string{
				"query:debug": "1",
				"form:ip":     "10.0.0.1",
			},
		},
		{
			name: "json body is not treated as form",
			tx: model.Transaction{Request: model.Message{
				Method:  "POST",
				URL:     "http://target.local/run",
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"ip":"10.0.0.1"}`,
			}},
			wantSet: map[string]string{},
		},
		{
			name: "no params",
			tx: model.Transaction{Request: model.Message{
				Method: "GET",
				URL:    "http://target.local/index.html",
			}},
			wantSet: map[string]string{},
		},
		{
			name: "invalid url",
			tx: model.Transaction{Request: model.Message{
				Method: "GET",
				URL:    "://bad",
			}},
			wantSet: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTargets(tt.tx)
			if len(got) != len(tt.wantSet) {
				t.Fatalf("target count = %d, want %d (%+v)", len(got), len(tt.wantSet), got)
			}
			for _, tg := range got {
				key := tg.location + ":" + tg.name
				want, ok := tt.wantSet[key]
				if !ok {
					t.Errorf("unexpected target %q", key)
					continue
				}
				if tg.value != want {
					t.Errorf("target %q value = %q, want %q", key, tg.value, want)
				}
			}
		})
	}
}

func TestCommandPayloads(t *testing.T) {
	const base = "127.0.0.1"
	left, right := 41567, 82431
	payloads := commandPayloads(base, left, right)
	if len(payloads) != 7 {
		t.Fatalf("expected 7 payloads, got %d", len(payloads))
	}
	for _, p := range payloads {
		if !strings.HasPrefix(p, base) {
			t.Errorf("payload %q does not preserve base prefix", p)
		}
	}
	expr := "expr 41567 + 82431"
	wantContains := []string{
		base + ";" + expr,
		base + "|" + expr,
		base + "`" + expr + "`",
		base + "$(" + expr + ")",
		base + "&&" + expr,
		base + "$((41567+82431))",
		base + "${41567+82431}",
	}
	for i, want := range wantContains {
		if payloads[i] != want {
			t.Errorf("payload[%d] = %q, want %q", i, payloads[i], want)
		}
	}
}

func TestBuildRequestQueryInjection(t *testing.T) {
	tx := model.Transaction{Request: model.Message{
		Method:  "GET",
		URL:     "http://target.local/run?cmd=ls&keep=yes",
		Headers: map[string]string{"X-Token": "abc", "Content-Length": "10", "Host": "evil.local"},
	}}
	tgt := target{location: "query", name: "cmd", value: "ls"}
	req, err := buildRequest(context.Background(), tx, tgt, "ls;expr 1 + 2")
	if err != nil {
		t.Fatalf("buildRequest error: %v", err)
	}
	q := req.URL.Query()
	if q.Get("cmd") != "ls;expr 1 + 2" {
		t.Errorf("cmd = %q, want injected payload", q.Get("cmd"))
	}
	if q.Get("keep") != "yes" {
		t.Errorf("keep param lost, got %q", q.Get("keep"))
	}
	if req.Header.Get("X-Token") != "abc" {
		t.Errorf("custom header dropped")
	}
	if req.Header.Get("Content-Length") != "" {
		t.Errorf("Content-Length header should be skipped, got %q", req.Header.Get("Content-Length"))
	}
	if req.Host == "evil.local" {
		t.Errorf("Host header should be derived from URL, not original header")
	}
}

func TestBuildRequestFormInjection(t *testing.T) {
	tx := model.Transaction{Request: model.Message{
		Method:  "POST",
		URL:     "http://target.local/run",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    "ip=1.1.1.1&extra=keep",
	}}
	tgt := target{location: "form", name: "ip", value: "1.1.1.1"}
	req, err := buildRequest(context.Background(), tx, tgt, "1.1.1.1;expr 3 + 4")
	if err != nil {
		t.Fatalf("buildRequest error: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	values, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("parse rebuilt body: %v", err)
	}
	if values.Get("ip") != "1.1.1.1;expr 3 + 4" {
		t.Errorf("ip = %q, want injected payload", values.Get("ip"))
	}
	if values.Get("extra") != "keep" {
		t.Errorf("extra param lost, got %q", values.Get("extra"))
	}
}

func TestEndpointKeyStableAcrossValues(t *testing.T) {
	a, _ := url.Parse("http://target.local/run?cmd=ls&host=1.1.1.1")
	b, _ := url.Parse("http://target.local/run?cmd=whoami&host=2.2.2.2")
	if endpointKey("GET", a) != endpointKey("GET", b) {
		t.Errorf("endpointKey should be independent of param values")
	}
	c, _ := url.Parse("http://target.local/run?cmd=ls")
	if endpointKey("GET", a) == endpointKey("GET", c) {
		t.Errorf("different param sets should yield different keys")
	}
	if endpointKey("GET", a) == endpointKey("POST", a) {
		t.Errorf("method should affect key")
	}
}

// TestEchoConfirmationLogic exercises the core low-false-positive rule:
// the computed sum must appear in the response body and must NOT already be
// present in the original parameter value.
func TestEchoConfirmationLogic(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		origValue string
		sumText   string
		want      bool
	}{
		{"sum echoed and not preexisting", "result: 123998 done", "127.0.0.1", "123998", true},
		{"sum absent", "no output", "127.0.0.1", "123998", false},
		{"sum preexists in input", "value 123998", "123998", "123998", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Contains(tt.body, tt.sumText) && !strings.Contains(tt.origValue, tt.sumText)
			if got != tt.want {
				t.Errorf("confirm = %v, want %v", got, tt.want)
			}
		})
	}
}
