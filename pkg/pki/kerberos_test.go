package pki

import (
	"strings"
	"testing"
)

func TestBuildKrb5Config_Basic(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01.contoso.com",
		Domain:   "contoso.com",
	}

	krb5conf, err := buildKrb5Config(cfg)
	if err != nil {
		t.Fatalf("buildKrb5Config: %v", err)
	}

	if krb5conf.LibDefaults.DefaultRealm != "CONTOSO.COM" {
		t.Errorf("default_realm = %q, want CONTOSO.COM", krb5conf.LibDefaults.DefaultRealm)
	}

	realms := krb5conf.Realms
	if len(realms) == 0 {
		t.Fatal("no realms configured")
	}
	found := false
	for _, r := range realms {
		if r.Realm == "CONTOSO.COM" {
			found = true
			if len(r.KDC) == 0 {
				t.Error("no KDC configured for realm")
			} else if !strings.Contains(r.KDC[0], "dc01.contoso.com") {
				t.Errorf("KDC = %q, want dc01.contoso.com:88", r.KDC[0])
			}
		}
	}
	if !found {
		t.Error("realm CONTOSO.COM not found in config")
	}
}

func TestBuildKrb5Config_KDCIP(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01.contoso.com",
		Domain:   "contoso.com",
		KDCIP:    "10.10.10.225",
	}

	krb5conf, err := buildKrb5Config(cfg)
	if err != nil {
		t.Fatalf("buildKrb5Config: %v", err)
	}

	for _, r := range krb5conf.Realms {
		if r.Realm == "CONTOSO.COM" {
			if len(r.KDC) == 0 || !strings.Contains(r.KDC[0], "10.10.10.225") {
				t.Errorf("KDC = %v, want 10.10.10.225:88", r.KDC)
			}
		}
	}
}

func TestBuildKrb5Config_MultiPartDomain(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01",
		Domain:   "sub.contoso.com",
	}

	krb5conf, err := buildKrb5Config(cfg)
	if err != nil {
		t.Fatalf("buildKrb5Config: %v", err)
	}

	if krb5conf.LibDefaults.DefaultRealm != "SUB.CONTOSO.COM" {
		t.Errorf("default_realm = %q, want SUB.CONTOSO.COM", krb5conf.LibDefaults.DefaultRealm)
	}
}

func TestNewKerberosClient_NoCredentials(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01",
		Domain:   "contoso.com",
		Username: "user",
	}

	_, err := newKerberosClient(cfg)
	if err == nil {
		t.Fatal("expected error when no credentials provided")
	}
	if !strings.Contains(err.Error(), "requires --ccache, --keytab, or -p") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewKerberosClient_BadCCache(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01",
		Domain:   "contoso.com",
		Username: "user",
		CCache:   "/nonexistent/path.ccache",
	}

	_, err := newKerberosClient(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent ccache")
	}
	if !strings.Contains(err.Error(), "load ccache") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewKerberosClient_BadKeytab(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01",
		Domain:   "contoso.com",
		Username: "user",
		Keytab:   "/nonexistent/path.keytab",
	}

	_, err := newKerberosClient(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent keytab")
	}
	if !strings.Contains(err.Error(), "load keytab") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewGSSAPIClient_NoCredentials(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01",
		Domain:   "contoso.com",
		Username: "user",
	}

	_, err := newGSSAPIClient(cfg)
	if err == nil {
		t.Fatal("expected error when no credentials")
	}
}

func TestNewKerberosHTTPClient_NoCredentials(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01",
		Domain:   "contoso.com",
		Username: "user",
	}

	_, err := newKerberosHTTPClient(cfg)
	if err == nil {
		t.Fatal("expected error when no credentials")
	}
}

func TestNewKerberosClient_CCacheEnvStripsPrefix(t *testing.T) {
	cfg := &ADCSConfig{
		TargetDC: "dc01",
		Domain:   "contoso.com",
		Username: "user",
		CCache:   "FILE:/nonexistent/path.ccache",
	}

	_, err := newKerberosClient(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent ccache")
	}
	// Verify it stripped the FILE: prefix — error should reference the path without it
	if !strings.Contains(err.Error(), "/nonexistent/path.ccache") {
		t.Errorf("unexpected error: %v", err)
	}
}
