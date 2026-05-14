package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestForgeCertificate_RSA2048(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, certKey, err := ForgeCertificate(caKey, "admin@corp.local")
	if err != nil {
		t.Fatalf("ForgeCertificate: %v", err)
	}

	rsaKey, ok := certKey.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key, got %T", certKey.Public())
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit RSA key, got %d", rsaKey.N.BitLen())
	}

	if cert.Subject.CommonName != "admin" {
		t.Errorf("expected CN=admin, got %s", cert.Subject.CommonName)
	}
}

func TestForgeGoldenCertificate(t *testing.T) {
	// Create a CA
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Corp CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Forge golden cert
	cert, certKey, err := ForgeGoldenCertificate(caKey, caCert, "admin@corp.local")
	if err != nil {
		t.Fatalf("ForgeGoldenCertificate: %v", err)
	}
	if certKey == nil {
		t.Fatal("expected non-nil key")
	}

	// Verify issuer matches CA
	if cert.Issuer.CommonName != "Corp CA" {
		t.Errorf("expected issuer CN='Corp CA', got %s", cert.Issuer.CommonName)
	}

	// Verify NOT self-signed (issued by CA)
	if IsSelfSigned(cert) {
		t.Error("golden cert should NOT be self-signed")
	}
}

func TestWriteCertKeyPEM(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, certKey, _ := ForgeCertificate(caKey, "test@corp.local")

	dir := t.TempDir()
	basePath := dir + "/test"
	if err := WriteCertKeyPEM(cert, certKey, basePath); err != nil {
		t.Fatalf("WriteCertKeyPEM: %v", err)
	}

	// Check cert PEM
	certData, err := os.ReadFile(basePath + ".crt")
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	certStr := string(certData)
	if !strings.Contains(certStr, "-----BEGIN CERTIFICATE-----") {
		t.Error("cert file missing CERTIFICATE PEM header")
	}
	if !strings.Contains(certStr, "-----END CERTIFICATE-----") {
		t.Error("cert file missing CERTIFICATE PEM footer")
	}

	// Check key PEM
	keyData, err := os.ReadFile(basePath + ".key")
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyStr := string(keyData)
	if !strings.Contains(keyStr, "-----BEGIN PRIVATE KEY-----") {
		t.Error("key file missing PRIVATE KEY PEM header")
	}
	if !strings.Contains(keyStr, "-----END PRIVATE KEY-----") {
		t.Error("key file missing PRIVATE KEY PEM footer")
	}

	// Should NOT be EC PRIVATE KEY
	if strings.Contains(keyStr, "EC PRIVATE KEY") {
		t.Error("key file should use PKCS8 'PRIVATE KEY', not 'EC PRIVATE KEY'")
	}
}

func TestLoadPFX_WithPassword(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, certKey, _ := ForgeCertificate(caKey, "test@corp.local")

	pfxPath := t.TempDir() + "/test.pfx"
	password := "hunter2"

	if err := WritePFX(cert, certKey, pfxPath, password); err != nil {
		t.Fatalf("WritePFX: %v", err)
	}

	// Load with correct password
	loadedCert, loadedKey, err := LoadPFX(pfxPath, password)
	if err != nil {
		t.Fatalf("LoadPFX with correct password: %v", err)
	}
	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("loaded cert CN doesn't match")
	}
	if loadedKey == nil {
		t.Error("loaded key is nil")
	}

	// Load with wrong password should fail
	_, _, err = LoadPFX(pfxPath, "wrongpass")
	if err == nil {
		t.Error("LoadPFX with wrong password should fail")
	}
}

func TestLoadPFX_EmptyPassword(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, certKey, _ := ForgeCertificate(caKey, "test@corp.local")

	pfxPath := t.TempDir() + "/nopass.pfx"
	if err := WritePFX(cert, certKey, pfxPath, ""); err != nil {
		t.Fatalf("WritePFX empty pass: %v", err)
	}

	loadedCert, _, err := LoadPFX(pfxPath, "")
	if err != nil {
		t.Fatalf("LoadPFX empty pass: %v", err)
	}
	if loadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("serial number mismatch after round-trip")
	}
}

func TestLoadPFXInfo(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, certKey, _ := ForgeCertificate(caKey, "test@corp.local")

	pfxPath := t.TempDir() + "/info.pfx"
	if err := WritePFX(cert, certKey, pfxPath, "pass"); err != nil {
		t.Fatalf("WritePFX: %v", err)
	}

	info, err := LoadPFXInfo(pfxPath, "pass")
	if err != nil {
		t.Fatalf("LoadPFXInfo: %v", err)
	}
	if info == nil {
		t.Fatal("LoadPFXInfo returned nil")
	}
	if info.Subject == "" {
		t.Error("PFXInfo subject should not be empty")
	}
}

func TestIsSelfSigned(t *testing.T) {
	// Self-signed cert
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Self-Signed"},
		Issuer:       pkix.Name{CommonName: "Self-Signed"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	selfDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	selfCert, _ := x509.ParseCertificate(selfDER)

	if !IsSelfSigned(selfCert) {
		t.Error("IsSelfSigned should return true for self-signed cert")
	}

	// CA-signed cert
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	childTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Child"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	childDER, _ := x509.CreateCertificate(rand.Reader, childTemplate, caCert, &key.PublicKey, caKey)
	childCert, _ := x509.ParseCertificate(childDER)

	if IsSelfSigned(childCert) {
		t.Error("IsSelfSigned should return false for CA-signed cert")
	}
}
