package pki

import (
	"context"
	"crypto/tls"
	"fmt"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/loudmumble/trusted/pkg/util"
)

// ADCSConfig defines the target information for Active Directory Certificate Services.
type ADCSConfig struct {
	TargetDC    string
	Domain      string
	Username    string
	Password    string
	Hash        string
	Kerberos    bool   // -k: use Kerberos authentication (GSSAPI/SPNEGO)
	CCache      string // path to ccache file (default: KRB5CCNAME env)
	Keytab      string // path to keytab file
	KDCIP       string // KDC IP address (if different from TargetDC)
	UseTLS      bool
	UseStartTLS bool
	OutputJSON  bool
	Stealth     bool
	Timeout     int // network timeout in seconds (0 = default 10s)
}

// stealthDelay introduces a random delay between 1-3 seconds when stealth mode is active.
// Used to reduce detection signatures from rapid sequential LDAP queries and HTTP probes.
func stealthDelay(cfg *ADCSConfig) {
	if !cfg.Stealth {
		return
	}
	delay := time.Duration(1000+mathrand.Intn(2000)) * time.Millisecond
	fmt.Printf("[*] Stealth: sleeping %v\n", delay)
	time.Sleep(delay)
}

// networkTimeout returns the configured timeout duration, defaulting to 10 seconds.
func networkTimeout(cfg *ADCSConfig) time.Duration {
	if cfg != nil && cfg.Timeout > 0 {
		return time.Duration(cfg.Timeout) * time.Second
	}
	return 10 * time.Second
}

// stealthPageSize returns the LDAP search page size based on stealth mode.
// In stealth mode, uses smaller page sizes to blend with normal AD traffic patterns.
func stealthPageSize(cfg *ADCSConfig) int {
	if cfg.Stealth {
		return 50 + mathrand.Intn(50) // 50-99 results per page
	}
	return 0 // 0 = no paging, return all results
}

// stealthPageDelay introduces a small random delay between LDAP pages when
// stealth mode is active. Reduces burst traffic patterns.
func stealthPageDelay(cfg *ADCSConfig) {
	if !cfg.Stealth {
		return
	}
	time.Sleep(time.Duration(100+mathrand.Intn(300)) * time.Millisecond)
}

func buildCertTemplateBaseDN(domain string) string {
	return util.BuildLDAPBaseDN(domain, "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration")
}

func buildBindDN(username, domain string) string {
	return util.BuildBindDN(username, domain)
}

func normalizeUsername(username string) string {
	return util.NormalizeUsername(username)
}

func buildCABaseDN(domain string) string {
	return util.BuildLDAPBaseDN(domain, "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration")
}

// ConnectLDAP establishes a connection to the DC's LDAP service with context.
// Supports plaintext LDAP (389), LDAPS (636), and StartTLS (389 upgraded).
// Falls back to KDCIP if TargetDC DNS resolution fails.
func ConnectLDAP(ctx context.Context, cfg *ADCSConfig) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional
		ServerName:         cfg.TargetDC,
	}

	timeout := networkTimeout(cfg)
	dialer := &net.Dialer{Timeout: timeout}

	ldapHost := cfg.TargetDC
	var lastErr error

	connectAttempt := func(host string) error {
		switch {
		case cfg.UseTLS:
			fmt.Printf("[*] Connecting to LDAPS %s:636 (TLS, cert verification disabled)\n", host)
			netConn, dialErr := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:636", host))
			if dialErr != nil {
				return fmt.Errorf("dial context: %w", dialErr)
			}
			tlsConn := tls.Client(netConn, tlsCfg)
			conn = ldap.NewConn(tlsConn, true)
			conn.Start()
		case cfg.UseStartTLS:
			fmt.Printf("[*] Connecting to LDAP %s:389 with StartTLS upgrade\n", host)
			netConn, dialErr := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:389", host))
			if dialErr != nil {
				return fmt.Errorf("dial context: %w", dialErr)
			}
			conn = ldap.NewConn(netConn, false)
			conn.Start()
			if err = conn.StartTLS(tlsCfg); err != nil {
				conn.Close()
				return fmt.Errorf("StartTLS on %s:389: %w", host, err)
			}
			fmt.Printf("[+] StartTLS negotiated successfully on %s:389\n", host)
		default:
			netConn, dialErr := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:389", host))
			if dialErr != nil {
				return fmt.Errorf("dial context: %w", dialErr)
			}
			conn = ldap.NewConn(netConn, false)
			conn.Start()
		}
		return nil
	}

	lastErr = connectAttempt(ldapHost)
	if lastErr != nil && cfg.KDCIP != "" && cfg.KDCIP != cfg.TargetDC {
		fmt.Printf("[!] Cannot reach %s, falling back to --dc-ip %s\n", ldapHost, cfg.KDCIP)
		ldapHost = cfg.KDCIP
		tlsCfg.ServerName = ldapHost
		lastErr = connectAttempt(ldapHost)
	}
	if lastErr != nil {
		return nil, lastErr
	}

	// Bind with credentials
	if cfg.Kerberos {
		gssClient, err := newGSSAPIClient(cfg)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("Kerberos GSSAPI client: %w", err)
		}

		spnCandidates := buildSPNCandidates(cfg.TargetDC)
		var bindErr error
		for _, spn := range spnCandidates {
			bindErr = conn.GSSAPIBind(gssClient, spn, "")
			if bindErr == nil {
				fmt.Printf("[+] Kerberos GSSAPI bind successful: %s (SPN: %s)\n", cfg.Username, spn)
				break
			}
		}
		if bindErr != nil {
			gssClient.Close()
			conn.Close()
			return nil, fmt.Errorf("Kerberos GSSAPI bind (tried SPNs %v): %w", spnCandidates, bindErr)
		}
	} else if cfg.Username != "" && cfg.Hash != "" {
		ntlmUser := normalizeUsername(cfg.Username)
		req := &ldap.NTLMBindRequest{
			Domain:   cfg.Domain,
			Username: ntlmUser,
			Hash:     cfg.Hash,
		}
		if _, err := conn.NTLMChallengeBind(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("NTLM pass-the-hash bind as %s\\%s: %w", cfg.Domain, ntlmUser, err)
		}
		fmt.Printf("[+] NTLM pass-the-hash bind successful: %s\\%s\n", cfg.Domain, ntlmUser)
	} else if cfg.Username != "" && cfg.Password != "" {
		bindDN := buildBindDN(cfg.Username, cfg.Domain)
		if err := conn.Bind(bindDN, cfg.Password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP bind as %s: %w", bindDN, err)
		}
		fmt.Printf("[+] LDAP bind successful: %s\n", bindDN)
	}

	return conn, nil
}

func buildSPNCandidates(targetDC string) []string {
	short := strings.SplitN(targetDC, ".", 2)[0]
	candidates := []string{"ldap/" + targetDC}
	if short != targetDC {
		candidates = append(candidates, "ldap/"+short)
	}
	return candidates
}

// ValidateCredentials performs a quick LDAP bind to verify credentials before
// running a full enumeration. Returns a descriptive error if authentication fails.
func ValidateCredentials(cfg *ADCSConfig) error {
	fmt.Printf("[*] Validating credentials against %s...\n", cfg.TargetDC)
	conn, err := ConnectLDAP(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("credential validation failed: %w", err)
	}
	conn.Close()
	fmt.Println("[+] Credentials validated successfully")
	return nil
}

func ValidateConnectionConfig(cfg *ADCSConfig) error {
	if cfg.TargetDC == "" {
		return fmt.Errorf("--target-dc is required")
	}
	if cfg.Domain == "" {
		return fmt.Errorf("--domain is required")
	}
	if !cfg.Kerberos && (cfg.Username == "" || (cfg.Password == "" && cfg.Hash == "")) {
		return fmt.Errorf("LDAP authentication required: use -u <user> -p <pass> (or --hash <NT_HASH> or -k for Kerberos)")
	}
	return nil
}
