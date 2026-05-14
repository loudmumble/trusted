package pki

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"strings"

	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"

	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
)

// buildKrb5Config generates a minimal Kerberos configuration programmatically.
// This avoids requiring a /etc/krb5.conf file on disk.
func buildKrb5Config(cfg *ADCSConfig) (*krb5config.Config, error) {
	realm := strings.ToUpper(cfg.Domain)
	kdc := cfg.TargetDC
	if cfg.KDCIP != "" {
		kdc = cfg.KDCIP
	}
	domainLower := strings.ToLower(cfg.Domain)

	confStr := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
  forwardable = true
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
  permitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac

[realms]
  %s = {
    kdc = %s:88
    admin_server = %s:88
  }

[domain_realm]
  .%s = %s
  %s = %s
`, realm, realm, kdc, kdc, domainLower, realm, domainLower, realm)

	return krb5config.NewFromString(confStr)
}

// newKerberosClient creates a gokrb5 client from the ADCSConfig.
// Credential source priority: ccache > keytab > password.
// If ccache flag is empty, checks KRB5CCNAME env var.
func newKerberosClient(cfg *ADCSConfig) (*krb5client.Client, error) {
	krb5conf, err := buildKrb5Config(cfg)
	if err != nil {
		return nil, fmt.Errorf("build krb5 config: %w", err)
	}

	realm := strings.ToUpper(cfg.Domain)

	// Priority 1: ccache (flag or KRB5CCNAME env)
	ccachePath := cfg.CCache
	if ccachePath == "" {
		ccachePath = os.Getenv("KRB5CCNAME")
	}
	if ccachePath != "" {
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
		ccache, err := credentials.LoadCCache(ccachePath)
		if err != nil {
			return nil, fmt.Errorf("load ccache %s: %w", ccachePath, err)
		}
		cl, err := krb5client.NewFromCCache(ccache, krb5conf)
		if err != nil {
			clientPrincipal := ccache.GetClientPrincipalName().PrincipalNameString()
			kdcHost := cfg.TargetDC
			if cfg.KDCIP != "" {
				kdcHost = cfg.KDCIP
			}
			fmt.Printf("[!] Kerberos ccache diagnostics:\n")
			fmt.Printf("    CCache file:      %s\n", ccachePath)
			fmt.Printf("    Client principal: %s\n", clientPrincipal)
			fmt.Printf("    Expected realm:  %s\n", realm)
			fmt.Printf("    KDC:              %s:88\n", kdcHost)
			fmt.Printf("    Hint: Ensure the ccache was created for realm %s (e.g. kinit -C FILE:%s user@%s)\n", realm, ccachePath, realm)
			return nil, fmt.Errorf("client from ccache: %w", err)
		}
		fmt.Printf("[+] Kerberos: loaded TGT from ccache %s\n", ccachePath)
		return cl, nil
	}

	// Priority 2: keytab
	if cfg.Keytab != "" {
		kt, err := keytab.Load(cfg.Keytab)
		if err != nil {
			return nil, fmt.Errorf("load keytab %s: %w", cfg.Keytab, err)
		}
		krbUser := normalizeUsername(cfg.Username)
		cl := krb5client.NewWithKeytab(krbUser, realm, kt, krb5conf)
		if err := cl.Login(); err != nil {
			return nil, fmt.Errorf("Kerberos login with keytab for %s@%s: %w", krbUser, realm, err)
		}
		fmt.Printf("[+] Kerberos: authenticated %s@%s via keytab\n", krbUser, realm)
		return cl, nil
	}

	if cfg.Password != "" {
		krbUser := normalizeUsername(cfg.Username)
		cl := krb5client.NewWithPassword(krbUser, realm, cfg.Password, krb5conf)
		if err := cl.Login(); err != nil {
			return nil, fmt.Errorf("Kerberos AS-REQ for %s@%s: %w", krbUser, realm, err)
		}
		fmt.Printf("[+] Kerberos: TGT acquired for %s@%s\n", krbUser, realm)
		return cl, nil
	}

	return nil, fmt.Errorf("Kerberos requires --ccache, --keytab, or -p <password> for TGT acquisition")
}

// newGSSAPIClient creates a go-ldap GSSAPIClient for use with conn.GSSAPIBind().
func newGSSAPIClient(cfg *ADCSConfig) (*ldapgssapi.Client, error) {
	krbClient, err := newKerberosClient(cfg)
	if err != nil {
		return nil, err
	}
	return &ldapgssapi.Client{Client: krbClient}, nil
}

// KerberosTransport implements http.RoundTripper with SPNEGO/Negotiate auth.
// Parallel to NTLMTransport for Kerberos-based HTTP authentication.
type KerberosTransport struct {
	client    *krb5client.Client
	transport http.RoundTripper
}

// RoundTrip performs SPNEGO HTTP authentication.
func (t *KerberosTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Set the SPNEGO Negotiate header using the SPN derived from the request URL
	if err := spnego.SetSPNEGOHeader(t.client, req, ""); err != nil {
		return nil, fmt.Errorf("set SPNEGO header: %w", err)
	}
	return t.transport.RoundTrip(req)
}

// newKerberosHTTPClient creates an *http.Client with SPNEGO transport auth.
// Parallel to newNTLMClient() in enroll.go.
func newKerberosHTTPClient(cfg *ADCSConfig) (*http.Client, error) {
	krbClient, err := newKerberosClient(cfg)
	if err != nil {
		return nil, err
	}

	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // pen-test tool targeting internal AD with self-signed certs
		},
	}

	return &http.Client{
		Transport: &KerberosTransport{
			client:    krbClient,
			transport: baseTransport,
		},
	}, nil
}

// sessionSetupKerberos performs Kerberos-authenticated SMB2 session setup.
// Parallel to sessionSetupNTLM() — sends AP-REQ in a SPNEGO NegTokenInit
// instead of NTLMSSP messages.
func (s *smbSession) sessionSetupKerberos(cfg *ADCSConfig, targetHost string) error {
	krbClient, err := newKerberosClient(cfg)
	if err != nil {
		return fmt.Errorf("Kerberos client: %w", err)
	}

	// Get service ticket for cifs/<hostname>
	spn := fmt.Sprintf("cifs/%s", targetHost)
	tkt, ekey, err := krbClient.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("get service ticket for %s: %w", spn, err)
	}

	// Build SPNEGO NegTokenInit wrapping the AP-REQ
	token, err := spnego.NewKRB5TokenAPREQ(krbClient, tkt, ekey, []int{}, []int{})
	if err != nil {
		return fmt.Errorf("build AP-REQ token: %w", err)
	}
	tokenBytes, err := token.Marshal()
	if err != nil {
		return fmt.Errorf("marshal SPNEGO token: %w", err)
	}

	// Send in SMB2 SESSION_SETUP (same frame format as NTLM)
	hdr := s.smb2Header(0x0001) // SESSION_SETUP
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25) // StructureSize
	secOffset := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body[12:14], secOffset)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(tokenBytes)))
	body = append(body, tokenBytes...)

	pkt := smbPacket(hdr, body)
	if _, err := s.conn.Write(pkt); err != nil {
		return fmt.Errorf("send Kerberos session setup: %w", err)
	}

	resp, err := readSMB2Response(s.conn)
	if err != nil {
		return fmt.Errorf("Kerberos session setup response: %w", err)
	}

	if len(resp) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp[40:48])
	}

	return nil
}
