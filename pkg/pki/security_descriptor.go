package pki

import (
	"encoding/binary"
	"fmt"
)

// Windows Self-Relative Security Descriptor (binary format)
// Ref: https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors

// Access mask constants for ADCS ESC5 detection.
const (
	// Generic rights
	accessGenericAll   uint32 = 0x10000000
	accessGenericWrite uint32 = 0x40000000
	accessGenericRead  uint32 = 0x20000000

	// Standard rights
	accessWriteDACL   uint32 = 0x00040000
	accessWriteOwner  uint32 = 0x00080000
	accessReadControl uint32 = 0x00020000

	// ADCS-specific: Manage CA and Manage Certificates extended rights
	accessManageCA          uint32 = 0x00000002 // Certificate-Enrollment
	accessCertificateEnroll uint32 = 0x00000100

	// DS extended right
	accessDSControlAccess uint32 = 0x00000100
)

// dangerousCAMask is the bitmask of rights that allow ESC5 exploitation on a CA object.
const dangerousCAMask = accessGenericAll | accessGenericWrite | accessWriteDACL | accessWriteOwner

// ACE types
const (
	aceTypeAccessAllowed = 0x00
	aceTypeAccessDenied  = 0x01
)

// SecurityDescriptor is the parsed form of a Windows self-relative SD.
type SecurityDescriptor struct {
	OwnerSID []byte
	GroupSID []byte
	DACL     *ACL
}

// ACL holds parsed access control entries.
type ACL struct {
	Revision uint8
	ACEs     []ACE
}

// ACE is a parsed access control entry.
type ACE struct {
	Type    uint8
	Flags   uint8
	Mask    uint32
	SID     []byte
	SIDText string // human-readable if well-known
}

// ParseSecurityDescriptor parses a binary Windows self-relative security descriptor.
// Returns an error if the data is too short or malformed.
func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	// Minimum header: Revision(1) + Sbz1(1) + Control(2) + OwnerOffset(4) + GroupOffset(4) + SaclOffset(4) + DaclOffset(4) = 20
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short (%d bytes)", len(data))
	}

	revision := data[0]
	if revision != 1 {
		return nil, fmt.Errorf("unexpected SD revision: %d", revision)
	}

	// control := binary.LittleEndian.Uint16(data[2:4]) // SE_SELF_RELATIVE must be set
	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	groupOffset := binary.LittleEndian.Uint32(data[8:12])
	// saclOffset := binary.LittleEndian.Uint32(data[12:16])  // SACL not needed for ESC5
	daclOffset := binary.LittleEndian.Uint32(data[16:20])

	sd := &SecurityDescriptor{}

	if ownerOffset != 0 && int(ownerOffset) < len(data) {
		sid, err := parseSID(data, int(ownerOffset))
		if err == nil {
			sd.OwnerSID = sid
		}
	}

	if groupOffset != 0 && int(groupOffset) < len(data) {
		sid, err := parseSID(data, int(groupOffset))
		if err == nil {
			sd.GroupSID = sid
		}
	}

	if daclOffset != 0 && int(daclOffset) < len(data) {
		acl, err := parseACL(data, int(daclOffset))
		if err == nil {
			sd.DACL = acl
		}
	}

	return sd, nil
}

// parseSID reads a SID at the given offset in data and returns its raw bytes.
func parseSID(data []byte, offset int) ([]byte, error) {
	// SID: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority[N](4 each)
	if offset+8 > len(data) {
		return nil, fmt.Errorf("SID offset %d out of bounds", offset)
	}
	revision := data[offset]
	if revision != 1 {
		return nil, fmt.Errorf("unexpected SID revision %d", revision)
	}
	subAuthCount := int(data[offset+1])
	sidLen := 8 + subAuthCount*4
	if offset+sidLen > len(data) {
		return nil, fmt.Errorf("SID at offset %d truncated (need %d bytes)", offset, sidLen)
	}
	return data[offset : offset+sidLen], nil
}

// parseACL reads an ACL at the given offset in data.
func parseACL(data []byte, offset int) (*ACL, error) {
	// ACL: AclRevision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2) = 8 bytes header
	if offset+8 > len(data) {
		return nil, fmt.Errorf("ACL offset %d out of bounds", offset)
	}

	acl := &ACL{
		Revision: data[offset],
	}

	aceCount := int(binary.LittleEndian.Uint16(data[offset+4 : offset+6]))
	aceOffset := offset + 8

	for i := 0; i < aceCount; i++ {
		// ACE header: Type(1) + Flags(1) + Size(2) = 4 bytes
		if aceOffset+4 > len(data) {
			break
		}
		aceType := data[aceOffset]
		aceFlags := data[aceOffset+1]
		aceSize := int(binary.LittleEndian.Uint16(data[aceOffset+2 : aceOffset+4]))

		if aceSize < 8 || aceOffset+aceSize > len(data) {
			break
		}

		// Access mask is the 4 bytes following the ACE header
		mask := binary.LittleEndian.Uint32(data[aceOffset+4 : aceOffset+8])

		var sid []byte
		if aceOffset+8 < aceOffset+aceSize {
			parsed, err := parseSID(data, aceOffset+8)
			if err == nil {
				sid = parsed
			}
		}

		ace := ACE{
			Type:  aceType,
			Flags: aceFlags,
			Mask:  mask,
			SID:   sid,
		}
		if sid != nil {
			ace.SIDText = sidToString(sid)
		}

		acl.ACEs = append(acl.ACEs, ace)
		aceOffset += aceSize
	}

	return acl, nil
}

// sidToString converts a raw SID to S-1-X-Y-... notation.
func sidToString(sid []byte) string {
	if len(sid) < 8 {
		return ""
	}
	subAuthCount := int(sid[1])
	// Identifier authority: bytes 2-7 (big-endian 48-bit)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(sid[i])
	}

	result := fmt.Sprintf("S-1-%d", authority)
	for i := 0; i < subAuthCount; i++ {
		off := 8 + i*4
		if off+4 > len(sid) {
			break
		}
		sub := binary.LittleEndian.Uint32(sid[off : off+4])
		result += fmt.Sprintf("-%d", sub)
	}
	return result
}

// ESC5Finding represents a dangerous ACE found on a CA object.
type ESC5Finding struct {
	CADN       string
	CAName     string
	Trustee    string // SID string
	AccessMask uint32
	Rights     []string // human-readable right names
}

// DangerousRights returns the list of dangerous right names set in mask.
func DangerousRights(mask uint32) []string {
	var rights []string
	if mask&accessGenericAll != 0 {
		rights = append(rights, "GenericAll")
	}
	if mask&accessGenericWrite != 0 {
		rights = append(rights, "GenericWrite")
	}
	if mask&accessWriteDACL != 0 {
		rights = append(rights, "WriteDACL")
	}
	if mask&accessWriteOwner != 0 {
		rights = append(rights, "WriteOwner")
	}
	return rights
}

// isPrivilegedSID returns true for well-known administrative SIDs that legitimately
// hold write access on CA objects (not interesting for ESC5 detection).
func isPrivilegedSID(sidStr string) bool {
	privileged := map[string]bool{
		// Local System
		"S-1-5-18": true,
		// Local Service
		"S-1-5-19": true,
		// Network Service
		"S-1-5-20": true,
		// BUILTIN\Administrators
		"S-1-5-32-544": true,
		// NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
		"S-1-5-9": true,
		// Creator Owner
		"S-1-3-0": true,
	}
	if privileged[sidStr] {
		return true
	}
	// Domain Admins (S-1-5-21-*-512), Enterprise Admins (*-519), Schema Admins (*-518)
	// These end with the RID as the last component
	for _, adminRID := range []string{"-512", "-519", "-518", "-500", "-516"} {
		if len(sidStr) > len(adminRID) && sidStr[len(sidStr)-len(adminRID):] == adminRID {
			return true
		}
	}
	return false
}

// isDangerousTrustee returns true for SIDs that should NOT have write access on CA objects.
// Covers: Everyone, Authenticated Users, Domain Users, BUILTIN\Users.
func isDangerousTrustee(sidStr string) bool {
	dangerous := map[string]bool{
		// Everyone
		"S-1-1-0": true,
		// Authenticated Users
		"S-1-5-11": true,
		// BUILTIN\Users
		"S-1-5-32-545": true,
		// Anonymous Logon
		"S-1-5-7": true,
		// Interactive
		"S-1-5-4": true,
		// Network
		"S-1-5-2": true,
	}
	if dangerous[sidStr] {
		return true
	}
	// Domain Users: S-1-5-21-*-513 — any domain RID 513 is Domain Users
	if len(sidStr) > 4 && sidStr[len(sidStr)-4:] == "-513" {
		return true
	}
	return false
}

// ESC4Finding represents a dangerous ACE found on a certificate template object.
type ESC4Finding struct {
	TemplateDN   string
	TemplateName string
	Trustee      string // SID string
	AccessMask   uint32
	Rights       []string // human-readable right names
}

// CheckESC4 parses the nTSecurityDescriptor of a certificate template and returns
// ESC4 findings where non-privileged trustees have dangerous write access (WriteDACL,
// WriteOwner, GenericAll, GenericWrite) that would allow template modification.
func CheckESC4(templateName, templateDN string, rawSD []byte) ([]ESC4Finding, error) {
	if len(rawSD) == 0 {
		return nil, nil
	}

	sd, err := ParseSecurityDescriptor(rawSD)
	if err != nil {
		return nil, fmt.Errorf("parse SD for template %s: %w", templateName, err)
	}

	if sd.DACL == nil {
		return nil, nil
	}

	var findings []ESC4Finding
	for _, ace := range sd.DACL.ACEs {
		if ace.Type != aceTypeAccessAllowed {
			continue
		}
		if ace.Mask&dangerousCAMask == 0 {
			continue
		}
		if ace.SIDText == "" {
			continue
		}
		if isPrivilegedSID(ace.SIDText) {
			continue
		}
		rights := DangerousRights(ace.Mask)
		if len(rights) == 0 {
			continue
		}
		findings = append(findings, ESC4Finding{
			TemplateDN:   templateDN,
			TemplateName: templateName,
			Trustee:      ace.SIDText,
			AccessMask:   ace.Mask,
			Rights:       rights,
		})
	}

	return findings, nil
}

// CheckESC5 parses the nTSecurityDescriptor of a CA LDAP object and returns
// ESC5 findings where non-privileged trustees have dangerous write access.
func CheckESC5(caName, caDN string, rawSD []byte) ([]ESC5Finding, error) {
	if len(rawSD) == 0 {
		return nil, nil
	}

	sd, err := ParseSecurityDescriptor(rawSD)
	if err != nil {
		return nil, fmt.Errorf("parse SD for %s: %w", caName, err)
	}

	if sd.DACL == nil {
		return nil, nil
	}

	var findings []ESC5Finding
	for _, ace := range sd.DACL.ACEs {
		// Only care about allow ACEs with dangerous rights
		if ace.Type != aceTypeAccessAllowed {
			continue
		}
		if ace.Mask&dangerousCAMask == 0 {
			continue
		}
		if ace.SIDText == "" {
			continue
		}
		// Skip privileged trustees — they are expected to have these rights
		if isPrivilegedSID(ace.SIDText) {
			continue
		}
		rights := DangerousRights(ace.Mask)
		if len(rights) == 0 {
			continue
		}
		// Flag the finding — dangerous trustee or any non-privileged trustee
		findings = append(findings, ESC5Finding{
			CADN:       caDN,
			CAName:     caName,
			Trustee:    ace.SIDText,
			AccessMask: ace.Mask,
			Rights:     rights,
		})
	}

	return findings, nil
}
