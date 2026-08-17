package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMITMRequiresExplicitScope(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "easyscan.yaml")
	if err := os.WriteFile(filename, []byte("proxy:\n  mitm: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filename); err == nil {
		t.Fatal("expected MITM scope validation error")
	}
}

func TestWebScanDefaultsAndBounds(t *testing.T) {
	cfg := Default()
	if cfg.WebScan.HTTP.MaxQPS != 4 || !cfg.WebScan.HTTP.StrictSameOrigin || cfg.WebScan.Crawler.MaxDepth != 2 {
		t.Fatalf("unexpected webscan defaults: %#v", cfg.WebScan)
	}
	filename := filepath.Join(t.TempDir(), "easyscan.yaml")
	if err := os.WriteFile(filename, []byte("webscan:\n  http:\n    retry: 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filename); err == nil {
		t.Fatal("expected retry bounds error")
	}
}

func TestWebScanRejectsUnsafeHeaderSyntax(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "easyscan.yaml")
	if err := os.WriteFile(filename, []byte("webscan:\n  http:\n    headers:\n      X-Test: ok\n      Bad Header: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filename); err == nil {
		t.Fatal("expected invalid header error")
	}
}

func TestLoadResolvesResourcePathsAgainstConfigFile(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "easyscan.yaml")
	contents := []byte("proxy:\n  ca_dir: certs\nstorage:\n  path: state/easyscan.db\nreports:\n  html_path: result.html\nfeatures:\n  path: policy.yaml\nrules:\n  files: [rules/example.yaml]\nfingerprints:\n  hfinger:\n    custom_dir: fingerprints/custom\n")
	if err := os.WriteFile(filename, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(filename)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.CADir != filepath.Join(dir, "certs") {
		t.Fatalf("unexpected CA directory: %q", cfg.Proxy.CADir)
	}
	if cfg.Storage.Path != filepath.Join(dir, "state", "easyscan.db") {
		t.Fatalf("unexpected storage path: %q", cfg.Storage.Path)
	}
	if cfg.Reports.HTMLPath != filepath.Join(dir, "result.html") {
		t.Fatalf("unexpected report path: %q", cfg.Reports.HTMLPath)
	}
	if cfg.Features.Path != filepath.Join(dir, "policy.yaml") {
		t.Fatalf("unexpected feature policy path: %q", cfg.Features.Path)
	}
	if got := cfg.Rules.Files; len(got) != 1 || got[0] != filepath.Join(dir, "rules", "example.yaml") {
		t.Fatalf("unexpected rules path: %#v", got)
	}
	if cfg.Fingerprints.HFinger.CustomDir != filepath.Join(dir, "fingerprints", "custom") {
		t.Fatalf("unexpected HFinger custom directory: %q", cfg.Fingerprints.HFinger.CustomDir)
	}
}
