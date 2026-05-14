package pki

import (
	"encoding/binary"
	"testing"
)

// buildMinimalSD constructs a minimal self-relative security descriptor with a DACL
// containing the given ACEs. Used to build synthetic test fixtures.
func buildMinimalSD(aces []testACE) []byte {
	// Build ACE list bytes
	var aceBytes []byte
	for _, a := range aces {
		ace := buildACEBytes(a.aceType, a.mask, a.sid)
		aceBytes = append(aceBytes, ace...)
	}

	// DACL: revision(1) + pad(1) + size(2) + aceCount(2) + pad(2) + aces
	daclSize := uint16(8 + len(aceBytes))
	dacl := make([]byte, 8)
	dacl[0] = 2 // ACL revision
	binary.LittleEndian.PutUint16(dacl[2:], daclSize)
	binary.LittleEndian.PutUint16(dacl[4:], uint16(len(aces)))
	dacl = append(dacl, aceBytes...)

	// SD header: 20 bytes
	// Revision(1) + Sbz1(1) + Control(2) + OwnerOff(4) + GroupOff(4) + SaclOff(4) + DaclOff(4)
	daclOffset := uint32(20)
	sd := make([]byte, 20)
	sd[0] = 1                                          // revision
	binary.LittleEndian.PutUint16(sd[2:], 0x8004)      // SE_SELF_RELATIVE | SE_DACL_PRESENT
	binary.LittleEndian.PutUint32(sd[16:], daclOffset) // DaclOffset
	return append(sd, dacl...)
}

type testACE struct {
	aceType uint8
	mask    uint32
	sid     []byte
}

// buildSID creates a SID byte slice from a string representation.
// Supports simple S-1-X-Y... forms.
func buildSIDBytes(subAuthority ...uint32) []byte {
	b := make([]byte, 8+4*len(subAuthority))
	b[0] = 1 // revision
	b[1] = byte(len(subAuthority))
	b[7] = 5 // NT authority (identifier authority = 5)
	for i, s := range subAuthority {
		binary.LittleEndian.PutUint32(b[8+i*4:], s)
	}
	return b
}

func buildACEBytes(aceType uint8, mask uint32, sid []byte) []byte {
	aceSize := uint16(4 + 4 + len(sid)) // header(4) + mask(4) + sid
	b := make([]byte, 4+4)
	b[0] = aceType
	binary.LittleEndian.PutUint16(b[2:], aceSize)
	binary.LittleEndian.PutUint32(b[4:], mask)
	return append(b, sid...)
}

// ── ParseSecurityDescriptor ───────────────────────────────────────────────────

func TestParseSecurityDescriptor_TooShort(t *testing.T) {
	_, err := ParseSecurityDescriptor([]byte{1, 0, 0, 0})
	if err == nil {
		t.Error("expected error for too-short SD")
	}
}

func TestParseSecurityDescriptor_EmptyData(t *testing.T) {
	_, err := ParseSecurityDescriptor([]byte{})
	if err == nil {
		t.Error("expected error for empty SD")
	}
}

func TestParseSecurityDescriptor_NilDACL(t *testing.T) {
	// SD with zero DaclOffset — DACL absent
	sd := make([]byte, 20)
	sd[0] = 1
	// All offsets zero — no owner, group, sacl, dacl
	parsed, err := ParseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.DACL != nil {
		t.Error("expected nil DACL when offset is 0")
	}
}

func TestParseSecurityDescriptor_WithACEs(t *testing.T) {
	// Everyone (S-1-1-0) with GenericAll
	everyoneSID := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0} // S-1-1-0
	aces := []testACE{
		{aceTypeAccessAllowed, accessGenericAll, everyoneSID},
	}
	data := buildMinimalSD(aces)

	parsed, err := ParseSecurityDescriptor(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.DACL == nil {
		t.Fatal("expected DACL to be parsed")
	}
	if len(parsed.DACL.ACEs) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(parsed.DACL.ACEs))
	}
	ace := parsed.DACL.ACEs[0]
	if ace.Mask != accessGenericAll {
		t.Errorf("expected GenericAll mask, got 0x%08x", ace.Mask)
	}
}

// ── sidToString ───────────────────────────────────────────────────────────────

func TestSIDToString_Everyone(t *testing.T) {
	// S-1-1-0: Revision=1, SubAuthCount=1, Authority=1, SubAuth=0
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	got := sidToString(sid)
	if got != "S-1-1-0" {
		t.Errorf("expected S-1-1-0, got %q", got)
	}
}

func TestSIDToString_AuthenticatedUsers(t *testing.T) {
	// S-1-5-11: Authority=5, SubAuth=11
	sid := make([]byte, 12)
	sid[0] = 1
	sid[1] = 1 // SubAuthCount=1
	sid[7] = 5 // Authority=5
	binary.LittleEndian.PutUint32(sid[8:], 11)
	got := sidToString(sid)
	if got != "S-1-5-11" {
		t.Errorf("expected S-1-5-11, got %q", got)
	}
}

func TestSIDToString_TooShort(t *testing.T) {
	got := sidToString([]byte{1, 0})
	if got != "" {
		t.Errorf("expected empty string for short SID, got %q", got)
	}
}

// ── isPrivilegedSID ───────────────────────────────────────────────────────────

func TestIsPrivilegedSID(t *testing.T) {
	cases := []struct {
		sid  string
		want bool
	}{
		{"S-1-5-18", true},                  // Local System
		{"S-1-5-19", true},                  // Local Service
		{"S-1-5-20", true},                  // Network Service
		{"S-1-5-32-544", true},              // BUILTIN\Administrators
		{"S-1-5-9", true},                   // Enterprise Domain Controllers
		{"S-1-5-21-100-200-300-512", true},  // Domain Admins
		{"S-1-5-21-100-200-300-519", true},  // Enterprise Admins
		{"S-1-5-21-100-200-300-518", true},  // Schema Admins
		{"S-1-1-0", false},                  // Everyone
		{"S-1-5-11", false},                 // Authenticated Users
		{"S-1-5-32-545", false},             // BUILTIN\Users
		{"S-1-5-21-100-200-300-513", false}, // Domain Users
	}
	for _, tc := range cases {
		got := isPrivilegedSID(tc.sid)
		if got != tc.want {
			t.Errorf("isPrivilegedSID(%q) = %v, want %v", tc.sid, got, tc.want)
		}
	}
}

// ── isDangerousTrustee ────────────────────────────────────────────────────────

func TestIsDangerousTrustee(t *testing.T) {
	cases := []struct {
		sid  string
		want bool
	}{
		{"S-1-1-0", true},                  // Everyone
		{"S-1-5-11", true},                 // Authenticated Users
		{"S-1-5-32-545", true},             // BUILTIN\Users
		{"S-1-5-4", true},                  // Interactive
		{"S-1-5-2", true},                  // Network
		{"S-1-5-21-100-200-300-513", true}, // Domain Users
		{"S-1-5-18", false},                // Local System — not a dangerous trustee
		{"S-1-5-32-544", false},            // Admins — not a dangerous trustee
	}
	for _, tc := range cases {
		got := isDangerousTrustee(tc.sid)
		if got != tc.want {
			t.Errorf("isDangerousTrustee(%q) = %v, want %v", tc.sid, got, tc.want)
		}
	}
}

// ── DangerousRights ───────────────────────────────────────────────────────────

func TestDangerousRights_AllSet(t *testing.T) {
	mask := accessGenericAll | accessGenericWrite | accessWriteDACL | accessWriteOwner
	rights := DangerousRights(mask)
	if len(rights) != 4 {
		t.Errorf("expected 4 rights, got %v", rights)
	}
}

func TestDangerousRights_NoneSet(t *testing.T) {
	rights := DangerousRights(0x00000001) // read-only
	if len(rights) != 0 {
		t.Errorf("expected 0 rights, got %v", rights)
	}
}

func TestDangerousRights_WriteDACLOnly(t *testing.T) {
	rights := DangerousRights(accessWriteDACL)
	if len(rights) != 1 || rights[0] != "WriteDACL" {
		t.Errorf("expected [WriteDACL], got %v", rights)
	}
}

// ── CheckESC4 ─────────────────────────────────────────────────────────────────

func TestCheckESC4_EmptySD(t *testing.T) {
	findings, err := CheckESC4("TestTemplate", "CN=TestTemplate,CN=Templates", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty SD, got %d", len(findings))
	}
}

func TestCheckESC4_PrivilegedTrusteeNotFlagged(t *testing.T) {
	adminSID := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0} // S-1-5-32-544
	aces := []testACE{
		{aceTypeAccessAllowed, accessGenericAll, adminSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC4("TestTemplate", "CN=TestTemplate", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("privileged trustee should not be flagged, got findings: %+v", findings)
	}
}

func TestCheckESC4_EveryoneWithWriteDACL(t *testing.T) {
	everyoneSID := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0} // S-1-1-0
	aces := []testACE{
		{aceTypeAccessAllowed, accessWriteDACL, everyoneSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC4("VulnTemplate", "CN=VulnTemplate", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 ESC4 finding, got %d", len(findings))
	}
	if findings[0].TemplateName != "VulnTemplate" {
		t.Errorf("wrong TemplateName: %s", findings[0].TemplateName)
	}
	if findings[0].Rights[0] != "WriteDACL" {
		t.Errorf("expected WriteDACL, got %v", findings[0].Rights)
	}
}

func TestCheckESC4_DeniedACENotFlagged(t *testing.T) {
	everyoneSID := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	aces := []testACE{
		{aceTypeAccessDenied, accessWriteDACL, everyoneSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC4("TestTemplate", "CN=TestTemplate", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("ACCESS_DENIED ACE should not be flagged, got %d findings", len(findings))
	}
}

func TestCheckESC4_ReadOnlyNotFlagged(t *testing.T) {
	everyoneSID := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	aces := []testACE{
		{aceTypeAccessAllowed, accessReadControl, everyoneSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC4("SafeTemplate", "CN=SafeTemplate", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("read-only ACE should not be flagged, got %d findings", len(findings))
	}
}

// ── CheckESC5 ─────────────────────────────────────────────────────────────────

func TestCheckESC5_EmptySD(t *testing.T) {
	findings, err := CheckESC5("TestCA", "CN=TestCA,DC=corp,DC=local", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty SD, got %d", len(findings))
	}
}

func TestCheckESC5_PrivilegedTrusteeNotFlagged(t *testing.T) {
	// BUILTIN\Administrators with GenericAll — should NOT be flagged
	adminSID := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0} // S-1-5-32-544
	aces := []testACE{
		{aceTypeAccessAllowed, accessGenericAll, adminSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC5("TestCA", "CN=TestCA,DC=corp,DC=local", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("privileged trustee should not be flagged, got findings: %+v", findings)
	}
}

func TestCheckESC5_EveryoneWithGenericAll(t *testing.T) {
	// Everyone (S-1-1-0) with GenericAll — CRITICAL ESC5
	everyoneSID := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0} // S-1-1-0
	aces := []testACE{
		{aceTypeAccessAllowed, accessGenericAll, everyoneSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC5("VulnCA", "CN=VulnCA,DC=corp,DC=local", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 ESC5 finding, got %d", len(findings))
	}
	if findings[0].CAName != "VulnCA" {
		t.Errorf("wrong CAName: %s", findings[0].CAName)
	}
	if findings[0].AccessMask != accessGenericAll {
		t.Errorf("wrong access mask: 0x%08x", findings[0].AccessMask)
	}
}

func TestCheckESC5_DeniedACENotFlagged(t *testing.T) {
	// Denied ACE should not trigger ESC5
	everyoneSID := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	aces := []testACE{
		{aceTypeAccessDenied, accessGenericAll, everyoneSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC5("TestCA", "CN=TestCA,DC=corp,DC=local", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("ACCESS_DENIED ACE should not be flagged, got %d findings", len(findings))
	}
}

func TestCheckESC5_WriteOwnerFlagged(t *testing.T) {
	// Authenticated Users (S-1-5-11) with WriteOwner
	authUsersSID := make([]byte, 12)
	authUsersSID[0] = 1
	authUsersSID[1] = 1
	authUsersSID[7] = 5
	binary.LittleEndian.PutUint32(authUsersSID[8:], 11)

	aces := []testACE{
		{aceTypeAccessAllowed, accessWriteOwner, authUsersSID},
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC5("VulnCA", "CN=VulnCA,DC=corp,DC=local", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for WriteOwner, got %d", len(findings))
	}
	if findings[0].Rights[0] != "WriteOwner" {
		t.Errorf("expected WriteOwner right, got %v", findings[0].Rights)
	}
}

func TestCheckESC5_ReadOnlyNotFlagged(t *testing.T) {
	// Everyone with read-only access — safe
	everyoneSID := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	aces := []testACE{
		{aceTypeAccessAllowed, accessReadControl, everyoneSID}, // read control only
	}
	data := buildMinimalSD(aces)
	findings, err := CheckESC5("SafeCA", "CN=SafeCA,DC=corp,DC=local", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("read-only ACE should not be flagged, got %d findings", len(findings))
	}
}

// ── buildCABaseDN ─────────────────────────────────────────────────────────────

func TestBuildCABaseDN(t *testing.T) {
	got := buildCABaseDN("corp.local")
	want := "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
	if got != want {
		t.Errorf("buildCABaseDN mismatch:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestBuildCABaseDN_MultiPart(t *testing.T) {
	got := buildCABaseDN("sub.corp.example.com")
	want := "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=sub,DC=corp,DC=example,DC=com"
	if got != want {
		t.Errorf("buildCABaseDN multi-part mismatch:\n  got:  %s\n  want: %s", got, want)
	}
}
