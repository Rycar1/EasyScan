package fingerprintprobe

import (
	"net/url"
	"testing"
)

func mustParseBase(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse base %q: %v", raw, err)
	}
	return u
}

func TestDeclaredFaviconPathExtractsSameOriginDeclarations(t *testing.T) {
	base := mustParseBase(t, "https://example.com")
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "relative custom path",
			body: `<html><head><link rel="icon" href="/static/logo.png"></head></html>`,
			want: "/static/logo.png",
		},
		{
			name: "shortcut icon rel with single quotes",
			body: `<link rel='shortcut icon' href='/assets/fav.ico'>`,
			want: "/assets/fav.ico",
		},
		{
			name: "absolute same-origin url reduces to path",
			body: `<link rel="icon" href="https://example.com/brand/icon.svg">`,
			want: "/brand/icon.svg",
		},
		{
			name: "attributes before rel",
			body: `<link type="image/png" sizes="32x32" rel="icon" href="/favicon-32.png">`,
			want: "/favicon-32.png",
		},
		{
			name: "relative reference resolves against root",
			body: `<link rel="icon" href="favicon.png">`,
			want: "/favicon.png",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := declaredFaviconPath(base, tc.body)
			if got != tc.want {
				t.Fatalf("declaredFaviconPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeclaredFaviconPathRejectsUnusableDeclarations(t *testing.T) {
	base := mustParseBase(t, "https://example.com")
	cases := []struct {
		name string
		body string
	}{
		{name: "no link tag", body: `<html><head><title>hi</title></head></html>`},
		{name: "link without icon rel", body: `<link rel="stylesheet" href="/app.css">`},
		{name: "cross origin favicon", body: `<link rel="icon" href="https://cdn.other.com/fav.ico">`},
		{name: "data uri", body: `<link rel="icon" href="data:image/png;base64,AAAA">`},
		{name: "default favicon path", body: `<link rel="icon" href="/favicon.ico">`},
		{name: "root reference", body: `<link rel="icon" href="/">`},
		{name: "empty body", body: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := declaredFaviconPath(base, tc.body); got != "" {
				t.Fatalf("declaredFaviconPath() = %q, want empty", got)
			}
		})
	}
}
