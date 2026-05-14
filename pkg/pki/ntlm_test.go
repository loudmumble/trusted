package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestNTHashFromPassword(t *testing.T) {
	// Known test vector: "Password" -> a4f49c406510bdcab6824ee7c30fd852
	hash := ntHashFromPassword("Password")
	got := hex.EncodeToString(hash)
	expected := "a4f49c406510bdcab6824ee7c30fd852"
	if got != expected {
		t.Errorf("ntHashFromPassword('Password') = %s, want %s", got, expected)
	}
}

func TestNTHashFromPassword_Empty(t *testing.T) {
	// Known: empty password -> 31d6cfe0d16ae931b73c59d7e0c089c0
	hash := ntHashFromPassword("")
	got := hex.EncodeToString(hash)
	expected := "31d6cfe0d16ae931b73c59d7e0c089c0"
	if got != expected {
		t.Errorf("ntHashFromPassword('') = %s, want %s", got, expected)
	}
}

func TestGetNTHash_FromHex(t *testing.T) {
	transport := &NTLMTransport{
		Hash: "a4f49c406510bdcab6824ee7c30fd852",
	}
	h, err := transport.getNTHash()
	if err != nil {
		t.Fatalf("getNTHash: %v", err)
	}
	if len(h) != 16 {
		t.Errorf("expected 16-byte hash, got %d", len(h))
	}
	if hex.EncodeToString(h) != "a4f49c406510bdcab6824ee7c30fd852" {
		t.Error("hash round-trip mismatch")
	}
}

func TestGetNTHash_FromPassword(t *testing.T) {
	transport := &NTLMTransport{
		Password: "Password",
	}
	h, err := transport.getNTHash()
	if err != nil {
		t.Fatalf("getNTHash: %v", err)
	}
	expected := "a4f49c406510bdcab6824ee7c30fd852"
	if hex.EncodeToString(h) != expected {
		t.Errorf("getNTHash from password: got %s, want %s", hex.EncodeToString(h), expected)
	}
}

func TestGetNTHash_InvalidHex(t *testing.T) {
	transport := &NTLMTransport{Hash: "not-valid-hex"}
	_, err := transport.getNTHash()
	if err == nil {
		t.Error("expected error for invalid hex hash")
	}
}

func TestGetNTHash_WrongLength(t *testing.T) {
	transport := &NTLMTransport{Hash: "aabb"}
	_, err := transport.getNTHash()
	if err == nil {
		t.Error("expected error for too-short hash")
	}
}

func TestGetNTHash_NoCredentials(t *testing.T) {
	transport := &NTLMTransport{}
	_, err := transport.getNTHash()
	if err == nil {
		t.Error("expected error when no password or hash provided")
	}
}

func TestUTF16LEEncode(t *testing.T) {
	result := utf16LEEncode("Hi")
	expected := []byte{0x48, 0x00, 0x69, 0x00}
	if len(result) != len(expected) {
		t.Fatalf("expected %d bytes, got %d", len(expected), len(result))
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], expected[i])
		}
	}
}

func TestGenerateCSR_WithUPN(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, err := GenerateCSR(key, "admin@corp.local", "User")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if len(csrDER) == 0 {
		t.Fatal("CSR is empty")
	}

	// Parse CSR to verify
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}

	// Verify SAN extension is present (OID 2.5.29.17)
	hasSAN := false
	for _, ext := range csr.Extensions {
		if ext.Id.String() == "2.5.29.17" {
			hasSAN = true
		}
	}
	if !hasSAN {
		t.Error("CSR should contain SAN extension with UPN")
	}
}

func TestGenerateCSR_EmptyUPN(t *testing.T) {
	// GenerateCSR always embeds a SAN extension (even with empty UPN),
	// because callers control whether to pass a UPN. The CSR should still
	// be valid and parseable.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, err := GenerateCSR(key, "", "User")
	if err != nil {
		t.Fatalf("GenerateCSR empty UPN: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	// CSR should have empty CN
	if csr.Subject.CommonName != "" {
		t.Errorf("expected empty CN for empty UPN, got %q", csr.Subject.CommonName)
	}

	// Signature should still be valid
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
}

func TestHMACMD5(t *testing.T) {
	// Simple test that hmacMD5 produces 16-byte output
	result := hmacMD5([]byte("key"), []byte("data"))
	if len(result) != 16 {
		t.Errorf("expected 16-byte HMAC-MD5, got %d", len(result))
	}
}
