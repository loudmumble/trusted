package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestBuildCertTemplateBaseDN(t *testing.T) {
	expected := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
	got := buildCertTemplateBaseDN("corp.local")
	if got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}
}

func TestBuildBindDN(t *testing.T) {
	tests := []struct {
		user, domain, expected string
	}{
		{"admin", "corp.local", "admin@corp.local"},
		{"admin@corp.local", "corp.local", "admin@corp.local"},
		{"CN=admin,DC=corp", "corp.local", "CN=admin,DC=corp"},
	}
	for _, tc := range tests {
		got := buildBindDN(tc.user, tc.domain)
		if got != tc.expected {
			t.Errorf("buildBindDN(%q, %q) = %q, want %q", tc.user, tc.domain, got, tc.expected)
		}
	}
}

func TestHasAuthenticationEKU(t *testing.T) {
	if !hasAuthenticationEKU(nil) {
		t.Error("nil EKUs should allow authentication")
	}
	if !hasAuthenticationEKU([]string{ekuClientAuth}) {
		t.Error("ClientAuth EKU should be authentication")
	}
	if hasAuthenticationEKU([]string{"1.2.3.4.5"}) {
		t.Error("Random OID should not be authentication EKU")
	}
}

func TestScoreESC(t *testing.T) {
	// ESC1: enrollee supplies subject + auth EKU + no approval + no signatures
	tmpl := CertTemplate{
		EnrolleeSuppliesSubject: true,
		AuthenticationEKU:       true,
		RequiresManagerApproval: false,
		AuthorizedSignatures:    0,
	}
	scoreESC(&tmpl)
	found := false
	for _, v := range tmpl.ESCVulns {
		if v == "ESC1" {
			found = true
		}
	}
	if !found {
		t.Error("Expected ESC1 vulnerability for template with all ESC1 conditions")
	}
	if tmpl.ESCScore < 10 {
		t.Errorf("Expected ESC score >= 10 for ESC1, got %d", tmpl.ESCScore)
	}
}

func TestForgeCertificate(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	upn := "admin@corp.local"
	cert, certKey, err := ForgeCertificate(caKey, upn)
	if err != nil {
		t.Fatalf("ForgeCertificate failed: %v", err)
	}

	if certKey == nil {
		t.Fatal("Expected private key, got nil")
	}
	if cert == nil {
		t.Fatal("Expected certificate, got nil")
	}
	if cert.SerialNumber.Int64() != 1337 {
		t.Errorf("Expected serial number 1337, got %d", cert.SerialNumber.Int64())
	}
	if cert.IsCA {
		t.Error("Certificate should not be marked as CA")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Missing DigitalSignature key usage")
	}

	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("Missing ClientAuth EKU")
	}
}

func TestForgeCertificate_WithDifferentUPNs(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, upn := range []string{"user@domain.local", "administrator@corp.internal", "svc@test.lab"} {
		t.Run(upn, func(t *testing.T) {
			cert, certKey, err := ForgeCertificate(caKey, upn)
			if err != nil {
				t.Errorf("ForgeCertificate failed for UPN %s: %v", upn, err)
			}
			if cert == nil {
				t.Errorf("Expected certificate for UPN %s", upn)
			}
			if certKey == nil {
				t.Errorf("Expected private key for UPN %s", upn)
			}
		})
	}
}

func TestWritePFX(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, certKey, err := ForgeCertificate(caKey, "testuser@corp.local")
	if err != nil {
		t.Fatalf("ForgeCertificate: %v", err)
	}

	pfxPath := t.TempDir() + "/test.pfx"
	if err := WritePFX(cert, certKey, pfxPath, "testpass"); err != nil {
		t.Fatalf("WritePFX: %v", err)
	}

	data, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) < 32 {
		t.Errorf("PFX file too small: %d bytes", len(data))
	}
}

// TestForgeCertificate_UPN_SAN_Encoding validates that the forged certificate
// contains a correctly encoded UPN OtherName SAN that can be parsed back.
// This is the exact encoding that certipy/Rubeus check when extracting identities.
func TestForgeCertificate_UPN_SAN_Encoding(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	upn := "administrator@corp.local"
	cert, _, err := ForgeCertificate(caKey, upn)
	if err != nil {
		t.Fatalf("ForgeCertificate: %v", err)
	}

	// Find the SAN extension (OID 2.5.29.17)
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	var sanExt []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sanOID) {
			sanExt = ext.Value
			break
		}
	}
	if sanExt == nil {
		t.Fatal("no SAN extension found in certificate")
	}

	// Parse SEQUENCE OF GeneralName
	var rawSAN asn1.RawValue
	if _, err := asn1.Unmarshal(sanExt, &rawSAN); err != nil {
		t.Fatalf("unmarshal SAN SEQUENCE: %v", err)
	}
	if rawSAN.Tag != asn1.TagSequence {
		t.Fatalf("SAN outer tag: got 0x%02X, want 0x10 (SEQUENCE)", rawSAN.Tag)
	}

	// Parse GeneralName — must be [0] CONTEXT-SPECIFIC CONSTRUCTED (OtherName)
	var gn asn1.RawValue
	if _, err := asn1.Unmarshal(rawSAN.Bytes, &gn); err != nil {
		t.Fatalf("unmarshal GeneralName: %v", err)
	}
	if gn.Tag != 0 || gn.Class != asn1.ClassContextSpecific || !gn.IsCompound {
		t.Fatalf("GeneralName: tag=%d class=%d constructed=%v, want tag=0 class=2 constructed=true",
			gn.Tag, gn.Class, gn.IsCompound)
	}

	// Parse OtherName OID — must be szOID_NT_PRINCIPAL_NAME
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(gn.Bytes, &oid)
	if err != nil {
		t.Fatalf("unmarshal OtherName OID: %v", err)
	}
	expectedOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	if !oid.Equal(expectedOID) {
		t.Fatalf("OID: got %s, want %s", oid, expectedOID)
	}

	// Parse [0] EXPLICIT { UTF8String }
	var explicit0 asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &explicit0); err != nil {
		t.Fatalf("unmarshal [0] EXPLICIT: %v", err)
	}

	var extractedUPN string
	if _, err := asn1.Unmarshal(explicit0.Bytes, &extractedUPN); err != nil {
		t.Fatalf("unmarshal UTF8String: %v", err)
	}
	if extractedUPN != upn {
		t.Fatalf("UPN: got %q, want %q", extractedUPN, upn)
	}
}

// TestPFX_RoundTrip validates forge → PFX export → PFX import → cert matches.
func TestPFX_RoundTrip(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	upn := "svc_scan@bruno.vl"
	cert, certKey, err := ForgeCertificate(caKey, upn)
	if err != nil {
		t.Fatalf("ForgeCertificate: %v", err)
	}

	// Export to PFX
	pfxPath := t.TempDir() + "/roundtrip.pfx"
	password := "test123"
	if err := WritePFX(cert, certKey, pfxPath, password); err != nil {
		t.Fatalf("WritePFX: %v", err)
	}

	// Read PFX back
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Decode PFX
	privKey, parsedCert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		t.Fatalf("pkcs12.Decode: %v", err)
	}

	// Verify the cert matches
	if parsedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("CN mismatch: got %q, want %q", parsedCert.Subject.CommonName, cert.Subject.CommonName)
	}
	if parsedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("serial mismatch: got %s, want %s", parsedCert.SerialNumber, cert.SerialNumber)
	}

	// Verify the key matches
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", privKey)
	}
	pubKey, ok := certKey.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey from certKey.Public(), got %T", certKey.Public())
	}
	if !rsaKey.PublicKey.Equal(pubKey) {
		t.Error("public key mismatch between exported and imported PFX")
	}

	// Verify SAN is preserved through PFX round-trip
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	hasSAN := false
	for _, ext := range parsedCert.Extensions {
		if ext.Id.Equal(sanOID) {
			hasSAN = true
		}
	}
	if !hasSAN {
		t.Error("SAN extension lost during PFX round-trip")
	}
}
