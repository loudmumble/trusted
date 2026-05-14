package c2

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

func TestGenerateCertAuthImplant(t *testing.T) {
	dir := t.TempDir()
	config, err := GenerateCertAuthImplant("https://c2.example.com:8443", "admin@corp.local", dir)
	if err != nil {
		t.Fatalf("GenerateCertAuthImplant: %v", err)
	}

	// Verify config fields
	if config.ID == "" {
		t.Error("expected non-empty ID")
	}
	if config.C2URL != "https://c2.example.com:8443" {
		t.Errorf("expected C2URL, got %s", config.C2URL)
	}
	if config.UPN != "admin@corp.local" {
		t.Errorf("expected UPN admin@corp.local, got %s", config.UPN)
	}
	if !config.UseMTLS {
		t.Error("expected UseMTLS=true")
	}
	if config.Interval != 5 {
		t.Errorf("expected interval 5, got %d", config.Interval)
	}
	if config.Jitter != 20 {
		t.Errorf("expected jitter 20, got %d", config.Jitter)
	}

	// Verify cert PEM file exists and is valid
	certData, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("cert PEM decode returned nil")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE PEM block, got %s", block.Type)
	}

	// Verify key PEM file exists and is valid
	keyData, err := os.ReadFile(config.KeyFile)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		t.Fatal("key PEM decode returned nil")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("expected EC PRIVATE KEY PEM block, got %s", keyBlock.Type)
	}

	// Verify config JSON file exists
	configPath := dir + "/admin-implant.json"
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config JSON: %v", err)
	}
	var parsedConfig CertAuthImplantConfig
	if err := json.Unmarshal(configData, &parsedConfig); err != nil {
		t.Fatalf("parse config JSON: %v", err)
	}
	if parsedConfig.C2URL != "https://c2.example.com:8443" {
		t.Errorf("config JSON C2URL mismatch: %s", parsedConfig.C2URL)
	}
}

func TestLoadCertAuthTLSConfig(t *testing.T) {
	// Generate a cert-auth implant to get valid cert/key files
	dir := t.TempDir()
	config, err := GenerateCertAuthImplant("https://test:443", "test@corp.local", dir)
	if err != nil {
		t.Fatalf("generate implant: %v", err)
	}

	// Load TLS config
	tlsConfig, err := LoadCertAuthTLSConfig(config.CertFile, config.KeyFile)
	if err != nil {
		t.Fatalf("LoadCertAuthTLSConfig: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
}

func TestLoadCertAuthTLSConfig_NonexistentFiles(t *testing.T) {
	_, err := LoadCertAuthTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for non-existent files")
	}
}

func TestLoadCertAuthTLSConfig_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := dir + "/bad.pem"
	keyPath := dir + "/bad-key.pem"
	os.WriteFile(certPath, []byte("not a PEM"), 0600)
	os.WriteFile(keyPath, []byte("not a PEM"), 0600)

	_, err := LoadCertAuthTLSConfig(certPath, keyPath)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// Ensure tls.Config is usable (not just constructable)
func TestCertAuthTLSConfig_IsUsable(t *testing.T) {
	dir := t.TempDir()
	config, _ := GenerateCertAuthImplant("https://test:443", "test@corp.local", dir)
	tlsConfig, err := LoadCertAuthTLSConfig(config.CertFile, config.KeyFile)
	if err != nil {
		t.Fatalf("LoadCertAuthTLSConfig: %v", err)
	}

	// Verify the config can produce a valid TLS client config
	if len(tlsConfig.Certificates) == 0 {
		t.Fatal("no certificates in TLS config")
	}
	if len(tlsConfig.Certificates[0].Certificate) == 0 {
		t.Fatal("no DER certificate data")
	}

	// Parse the leaf cert from DER
	leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Verify it has Client Auth EKU
	hasClientAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("cert should have ClientAuth EKU for mTLS")
	}
}
