package fileprobe

import "testing"

func TestExtractPrefixesStripsLeafAndReturnsAncestors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "page in subdirectory yields its directory",
			input: "/admin/index.html",
			want:  []string{"/admin"},
		},
		{
			name:  "nested asset yields all ancestors excluding root",
			input: "/js/123/file.js",
			want:  []string{"/js/123", "/js"},
		},
		{
			name:  "static asset filename is stripped, never used as a prefix",
			input: "/assets/index-C_HOOOpe.js",
			want:  []string{"/assets"},
		},
		{
			name:  "root path yields no prefixes",
			input: "/",
			want:  nil,
		},
		{
			name:  "top level file yields no prefixes",
			input: "/index.html",
			want:  nil,
		},
		{
			name:  "deeply nested path is capped at maxPrefixDepth",
			input: "/a/b/c/d/e/f/file.js",
			want:  []string{"/a/b/c/d/e/f", "/a/b/c/d/e", "/a/b/c/d", "/a/b/c"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPrefixes(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("extractPrefixes(%q) = %#v, want %#v", tc.input, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("extractPrefixes(%q)[%d] = %q, want %q (full: %#v)", tc.input, i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestHTMLFallbackAlreadyReportedCollapsesPerOrigin(t *testing.T) {
	w := &Worker{htmlSeen: make(map[string]struct{})}
	originA := "https://blog.example.test"
	originB := "https://other.example.test"
	if w.htmlFallbackAlreadyReported(originA) {
		t.Fatal("first HTML fallback for an origin must be reported")
	}
	if !w.htmlFallbackAlreadyReported(originA) {
		t.Fatal("second HTML fallback for the same origin must be collapsed")
	}
	if w.htmlFallbackAlreadyReported(originB) {
		t.Fatal("a different origin must still report its first HTML fallback")
	}
}

func TestJoinPrefixPathConcatenatesPrefixAndRelativePath(t *testing.T) {
	cases := []struct {
		prefix string
		path   string
		want   string
	}{
		{"", "/v1/swagger.json", "/v1/swagger.json"},
		{"/admin", "/v1/swagger.json", "/admin/v1/swagger.json"},
		{"/admin/", "/v1/swagger.json", "/admin/v1/swagger.json"},
		{"/js/123", "/openapi.json", "/js/123/openapi.json"},
	}
	for _, tc := range cases {
		if got := joinPrefixPath(tc.prefix, tc.path); got != tc.want {
			t.Fatalf("joinPrefixPath(%q, %q) = %q, want %q", tc.prefix, tc.path, got, tc.want)
		}
	}
}

func TestCapPrefixesByBudgetKeepsDeepest(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
		budget   int
		want     []string
	}{
		{
			name:     "budget zero keeps all",
			prefixes: []string{"/a", "/a/b"},
			budget:   0,
			want:     []string{"/a", "/a/b"},
		},
		{
			name:     "budget larger than prefixes keeps all",
			prefixes: []string{"/a"},
			budget:   5,
			want:     []string{"/a"},
		},
		{
			name:     "budget two keeps deepest two ancestors",
			prefixes: []string{"/a/b/c/d/e", "/a/b/c/d", "/a/b/c", "/a/b"},
			budget:   2,
			want:     []string{"/a/b/c/d/e", "/a/b/c/d"},
		},
		{
			name:     "empty prefixes stays empty",
			prefixes: nil,
			budget:   3,
			want:     nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capPrefixesByBudget(tc.prefixes, tc.budget)
			if len(got) != len(tc.want) {
				t.Fatalf("capPrefixesByBudget(%v, %d) = %#v, want %#v", tc.prefixes, tc.budget, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("capPrefixesByBudget(%v, %d)[%d] = %q, want %q", tc.prefixes, tc.budget, i, got[i], tc.want[i])
				}
			}
		})
	}
}
