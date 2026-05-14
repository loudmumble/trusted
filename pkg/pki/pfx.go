package pki

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// LoadPFX reads a PKCS#12/PFX file and returns the certificate, private key, and any
// CA certificates bundled in the archive. The password can be empty for unencrypted PFX files.
//
// This is the inverse of WritePFX — useful for importing certificates obtained via
// ntlmrelayx, certipy, or other external tools into Trusted for further operations.
func LoadPFX(path, password string) (*x509.Certificate, crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read PFX file %s: %w", path, err)
	}

	key, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decode PFX: %w", err)
	}

	fmt.Printf("[+] PFX loaded: %s\n", path)
	fmt.Printf("    Subject:    %s\n", cert.Subject.CommonName)
	fmt.Printf("    Issuer:     %s\n", cert.Issuer.CommonName)
	fmt.Printf("    Serial:     %s\n", cert.SerialNumber.String())
	fmt.Printf("    Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("    Not After:  %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))

	if len(cert.DNSNames) > 0 {
		fmt.Printf("    DNS SANs:   %v\n", cert.DNSNames)
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("    Email SANs: %v\n", cert.EmailAddresses)
	}

	ekuNames := make([]string, 0, len(cert.ExtKeyUsage))
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			ekuNames = append(ekuNames, "Client Authentication")
		case x509.ExtKeyUsageServerAuth:
			ekuNames = append(ekuNames, "Server Authentication")
		case x509.ExtKeyUsageCodeSigning:
			ekuNames = append(ekuNames, "Code Signing")
		default:
			ekuNames = append(ekuNames, fmt.Sprintf("OID(%d)", eku))
		}
	}
	if len(ekuNames) > 0 {
		fmt.Printf("    EKUs:       %v\n", ekuNames)
	}

	if len(caCerts) > 0 {
		fmt.Printf("    CA certs:   %d bundled\n", len(caCerts))
		for i, ca := range caCerts {
			fmt.Printf("      [%d] %s\n", i, ca.Subject.CommonName)
		}
	}

	// Identify key type
	switch k := key.(type) {
	case interface{ Public() crypto.PublicKey }:
		_ = k
		fmt.Printf("    Key type:   %T\n", key)
	default:
		fmt.Printf("    Key type:   %T\n", key)
	}

	return cert, key, nil
}

// PFXInfo holds parsed metadata from a PFX file for JSON output.
type PFXInfo struct {
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	Serial      string   `json:"serial"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DNSNames    []string `json:"dns_names,omitempty"`
	EKUs        []string `json:"ekus,omitempty"`
	KeyType     string   `json:"key_type"`
	CACertCount int      `json:"ca_cert_count"`
}

// LoadPFXInfo loads a PFX file and returns structured metadata suitable for JSON output.
func LoadPFXInfo(path, password string) (*PFXInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read PFX file %s: %w", path, err)
	}

	key, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("decode PFX: %w", err)
	}

	info := &PFXInfo{
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		Serial:      cert.SerialNumber.String(),
		NotBefore:   cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:    cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		DNSNames:    cert.DNSNames,
		KeyType:     fmt.Sprintf("%T", key),
		CACertCount: len(caCerts),
	}

	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			info.EKUs = append(info.EKUs, "Client Authentication")
		case x509.ExtKeyUsageServerAuth:
			info.EKUs = append(info.EKUs, "Server Authentication")
		case x509.ExtKeyUsageCodeSigning:
			info.EKUs = append(info.EKUs, "Code Signing")
		default:
			info.EKUs = append(info.EKUs, fmt.Sprintf("OID(%d)", eku))
		}
	}

	return info, nil
}
