package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertificateAuthority owns a local root CA and short-lived per-host leaf
// certificates for the optional HTTPS interception mode. Its private key stays
// in ca_dir and is written with owner-only permissions.
type CertificateAuthority struct {
	certificate *x509.Certificate
	key         *rsa.PrivateKey
	tlsCert     tls.Certificate
	mu          sync.Mutex
	cache       map[string]*tls.Certificate
}

func LoadOrCreateCA(directory string) (*CertificateAuthority, string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, "", err
	}
	certPath, keyPath := filepath.Join(directory, "easyscan-ca.pem"), filepath.Join(directory, "easyscan-ca-key.pem")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := parseCA(certPEM, keyPEM)
		return ca, certPath, err
	}
	if !errors.Is(certErr, os.ErrNotExist) && certErr != nil {
		return nil, "", certErr
	}
	if !errors.Is(keyErr, os.ErrNotExist) && keyErr != nil {
		return nil, "", keyErr
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, "", err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "EasyScan Local Inspection CA", Organization: []string{"EasyScan"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, "", err
	}
	ca, err := parseCA(certPEM, keyPEM)
	return ca, certPath, err
}

func parseCA(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("invalid EasyScan CA PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &CertificateAuthority{certificate: certificate, key: key, tlsCert: tlsCert, cache: map[string]*tls.Certificate{}}, nil
}
func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
func (ca *CertificateAuthority) Certificate(host string) (*tls.Certificate, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return nil, errors.New("empty certificate host")
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert := ca.cache[host]; cert != nil {
		return cert, nil
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, 30), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der, ca.tlsCert.Certificate[0]}, PrivateKey: key}
	ca.cache[host] = &cert
	return &cert, nil
}
