package proxy

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCAAndHostCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, path, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	certificate, err := ca.Certificate("app.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if certificate == nil || len(certificate.Certificate) < 2 {
		t.Fatalf("expected leaf plus CA chain: %#v", certificate)
	}
	if _, err := tls.X509KeyPair(mustRead(t, path), mustRead(t, filepath.Join(dir, "easyscan-ca-key.pem"))); err != nil {
		t.Fatal(err)
	}
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
