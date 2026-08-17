package fastjsonprobe

import (
	"strings"
	"testing"
)

func TestRemoveOneBrace(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"removes last closing brace", `{"a":1}`, `{"a":1`},
		{"removes only closing brace", `{"nested":{"b":2}}`, `{"nested":{"b":2}`},
		{"no closing brace falls back to opening", `{"a":1`, `"a":1`},
		{"empty returns empty", "", ""},
		{"no braces returns empty", "plain text", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := removeOneBrace(tt.input); got != tt.want {
				t.Fatalf("removeOneBrace(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRemoveOneBraceProducesMalformed(t *testing.T) {
	input := `{"user":"a","id":1}`
	malformed := removeOneBrace(input)
	if malformed == input {
		t.Fatalf("expected malformed body to differ from input")
	}
	if strings.Count(malformed, "{") != strings.Count(input, "{") || strings.Count(malformed, "}") != strings.Count(input, "}")-1 {
		t.Fatalf("expected exactly one closing brace removed, got %q", malformed)
	}
}

func TestLooksLikeJSONObject(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        bool
	}{
		{"json content type object", "application/json", `{"a":1}`, true},
		{"json content type array", "application/json;charset=utf-8", `[1,2]`, true},
		{"json content type non json body", "application/json", "not json", false},
		{"no content type but object body", "", `{"a":1}`, true},
		{"no content type array body", "", `[1,2]`, false},
		{"form content type object body", "application/x-www-form-urlencoded", `{"a":1}`, true},
		{"empty body", "application/json", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{}
			if tt.contentType != "" {
				headers["Content-Type"] = tt.contentType
			}
			if got := looksLikeJSONObject(headers, tt.body); got != tt.want {
				t.Fatalf("looksLikeJSONObject(%q,%q) = %v, want %v", tt.contentType, tt.body, got, tt.want)
			}
		})
	}
}

func TestMatchFastjsonSignature(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"fastjson exception", "com.alibaba.fastjson.JSONException: syntax error", true},
		{"fastjson package", "at com.alibaba.fastjson.parser.DefaultJSONParser.parse", true},
		{"uppercase", "COM.ALIBABA.FASTJSON.JSONException", true},
		{"generic json error", "org.json.JSONException: expected", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchFastjsonSignature(tt.body) != ""; got != tt.want {
				t.Fatalf("matchFastjsonSignature(%q) present=%v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
