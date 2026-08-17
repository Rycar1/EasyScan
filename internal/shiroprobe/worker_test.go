package shiroprobe

import (
	"testing"
)

func TestExtractCookieValue(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"present", "a=1; rememberMe=abc123; b=2", "abc123"},
		{"first", "rememberMe=xyz; a=1", "xyz"},
		{"only", "rememberMe=only", "only"},
		{"absent", "a=1; b=2", ""},
		{"empty header", "", ""},
		{"case insensitive name", "RememberMe=CaseVal", "CaseVal"},
		{"deleteMe value", "rememberMe=deleteMe", "deleteMe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractCookieValue(tt.header, rememberMeCookieName); got != tt.want {
				t.Fatalf("extractCookieValue(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestResponseHasRememberMe(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"deleteMe set-cookie", map[string]string{"Set-Cookie": "rememberMe=deleteMe; Path=/"}, true},
		{"rememberMe set-cookie", map[string]string{"Set-Cookie": "rememberMe=abc; Path=/"}, true},
		{"lowercase header name", map[string]string{"set-cookie": "rememberMe=deleteMe"}, true},
		{"no rememberMe", map[string]string{"Set-Cookie": "session=xyz"}, false},
		{"no set-cookie", map[string]string{"Content-Type": "text/html"}, false},
		{"empty", map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responseHasRememberMe(tt.headers); got != tt.want {
				t.Fatalf("responseHasRememberMe(%v) = %v, want %v", tt.headers, got, tt.want)
			}
		})
	}
}

type stubPolicy struct {
	enabled  bool
	qps      int
	shiroKeys []string
}

func (s stubPolicy) Enabled(string) bool            { return s.enabled }
func (s stubPolicy) PassiveShiroProbeQPS() int      { return s.qps }
func (s stubPolicy) ShiroKeys() []string            { return s.shiroKeys }

func TestCandidateKeysMergesAndDedupes(t *testing.T) {
	w := &Worker{policy: stubPolicy{shiroKeys: []string{"kPH+bIxk5D2deZiIxcaaaA==", "customKey==", "  ", ""}}}
	keys := w.candidateKeys()

	// The built-in dictionary includes kPH+bIxk5D2deZiIxcaaaA==; the custom
	// duplicate must not appear twice and blanks must be dropped.
	count := map[string]int{}
	for _, k := range keys {
		count[k]++
	}
	if count["kPH+bIxk5D2deZiIxcaaaA=="] != 1 {
		t.Fatalf("expected built-in key once, got %d", count["kPH+bIxk5D2deZiIxcaaaA=="])
	}
	if count["customKey=="] != 1 {
		t.Fatalf("expected custom key once, got %d", count["customKey=="])
	}
	for _, k := range keys {
		if k == "" {
			t.Fatalf("unexpected empty key in candidate list")
		}
	}
	// The merged list must contain no duplicates even though the custom input
	// repeats a built-in key.
	if len(keys) != len(count) {
		t.Fatalf("expected no duplicate keys, got %d entries for %d unique", len(keys), len(count))
	}
}

func TestBuiltinKeysNonEmpty(t *testing.T) {
	if len(builtinKeys) == 0 {
		t.Fatalf("expected a non-empty built-in Shiro key dictionary")
	}
	if got := BuiltinKeys(); len(got) != len(builtinKeys) {
		t.Fatalf("BuiltinKeys() returned %d keys, want %d", len(got), len(builtinKeys))
	}
}
