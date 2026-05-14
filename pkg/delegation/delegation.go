package delegation

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	flagTrustedForDelegation       = 0x80000
	flagTrustedToAuthForDelegation = 0x1000000
)

type DelegationType string

const (
	DelegationNone           DelegationType = "None"
	DelegationUnconstrained  DelegationType = "Unconstrained"
	DelegationConstrained    DelegationType = "Constrained"
	DelegationConstrainedRCB DelegationType = "Constrained (RCB)"
	DelegationResourceBased  DelegationType = "Resource-Based Constrained"
)

type DelegationTarget struct {
	Name               string
	DN                 string
	Type               DelegationType
	IsComputer         bool
	UserAccountControl uint32
	AllowedSPNs        []string
	DelegatedTo        []string
	DelegatedBy        []string
	MSDSAllowedToAct   string
	RBCDSIDs           []SIDEntry
	HasDelegation      bool
}

type SIDEntry struct {
	SID        string
	RID        uint32
	ObjectSID  []byte
	AccessMask uint32
}

type ConstrainedDelegationConfig struct {
	TargetSPN        string
	Username         string
	Domain           string
	Password         string
	Hash             string
	TargetUser       string
	DomainController string
	Cache            string
}

type RBCDConfig struct {
	TargetComputer   string
	ComputerName     string
	ComputerPassword string
	Domain           string
	Username         string
	Password         string
	Hash             string
	DomainController string
	Cache            string
}

type UnconstrainedConfig struct {
	TargetComputer   string
	Username         string
	Domain           string
	Password         string
	Hash             string
	DomainController string
	Cache            string
	MonitorMode      bool
}

type DelegationEnumResult struct {
	Targets            []DelegationTarget `json:"targets"`
	UnconstrainedCount int                `json:"unconstrained_count"`
	ConstrainedCount   int                `json:"constrained_count"`
	RBCDCount          int                `json:"rbcd_count"`
	WritableForRBCD    []string           `json:"writable_for_rbcd,omitempty"`
}

type TicketResult struct {
	TGT        []byte
	TGS        []byte
	SessionKey []byte
	CachePath  string
}

func ParseUserAccountControl(uac uint32) map[string]bool {
	return map[string]bool{
		"SCRIPT":                         uac&0x0001 != 0,
		"ACCOUNTDISABLE":                 uac&0x0002 != 0,
		"HOMEDIR_REQUIRED":               uac&0x0008 != 0,
		"LOCKOUT":                        uac&0x0010 != 0,
		"PASSWD_NOTREQD":                 uac&0x0020 != 0,
		"PASSWD_CANT_CHANGE":             uac&0x0040 != 0,
		"ENCRYPTED_PWD_ALLOWED":          uac&0x0080 != 0,
		"TEMP_DUPLICATE_ACCOUNT":         uac&0x0100 != 0,
		"NORMAL_ACCOUNT":                 uac&0x0200 != 0,
		"MNS_LOGON_ACCOUNT":              uac&0x0400 != 0,
		"INTERDOMAIN_TRUST":              uac&0x0800 != 0,
		"WORKSTATION_TRUST":              uac&0x1000 != 0,
		"SERVER_TRUST":                   uac&0x2000 != 0,
		"DONT_EXPIRE_PASSWD":             uac&0x10000 != 0,
		"ACCOUNT_AUTO_LOCKED":            uac&0x20000 != 0,
		"ENCRYPTED_TEXT_PWD":             uac&0x40000 != 0,
		"TRUSTED_FOR_DELEGATION":         uac&flagTrustedForDelegation != 0,
		"TRUSTED_TO_AUTH_FOR_DELEGATION": uac&flagTrustedToAuthForDelegation != 0,
		"DONT_REQ_PREAUTH":               uac&0x400000 != 0,
		"PASSWORD_EXPIRED":               uac&0x800000 != 0,
		"HAS_SPN":                        uac&0x10000000 != 0,
		"USE_DES_KEY_ONLY":               uac&0x20000000 != 0,
		"DONT_REQ_PREAUTH2":              uac&0x40000000 != 0,
	}
}

func HasDelegationCapability(uac uint32) bool {
	return uac&flagTrustedForDelegation != 0 || uac&flagTrustedToAuthForDelegation != 0
}

func BuildDelegationReport(targets []DelegationTarget) string {
	var sb strings.Builder

	sb.WriteString("# Delegation Analysis Report\n\n")

	unconstrained := filterByType(targets, DelegationUnconstrained)
	constrained := filterByType(targets, DelegationConstrained)
	rbcd := filterByType(targets, DelegationResourceBased)

	if len(unconstrained) > 0 {
		sb.WriteString(fmt.Sprintf("## Unconstrained Delegation (%d)\n\n", len(unconstrained)))
		for _, t := range unconstrained {
			sb.WriteString(fmt.Sprintf("- **%s** (%s)\n", t.Name, t.DN))
			if t.IsComputer {
				sb.WriteString("  - Type: Computer\n")
			} else {
				sb.WriteString("  - Type: User\n")
			}
		}
		sb.WriteString("\n")
	}

	if len(constrained) > 0 {
		sb.WriteString(fmt.Sprintf("## Constrained Delegation (%d)\n\n", len(constrained)))
		for _, t := range constrained {
			sb.WriteString(fmt.Sprintf("- **%s** (%s)\n", t.Name, t.DN))
			sb.WriteString(fmt.Sprintf("  - Allowed SPNs: %s\n", strings.Join(t.AllowedSPNs, ", ")))
			sb.WriteString(fmt.Sprintf("  - Can impersonate: %s\n", strings.Join(t.DelegatedTo, ", ")))
		}
		sb.WriteString("\n")
	}

	if len(rbcd) > 0 {
		sb.WriteString(fmt.Sprintf("## Resource-Based Constrained Delegation (%d)\n\n", len(rbcd)))
		for _, t := range rbcd {
			sb.WriteString(fmt.Sprintf("- **%s** (%s)\n", t.Name, t.DN))
			if len(t.RBCDSIDs) > 0 {
				sb.WriteString("  - Allowed SIDs:\n")
				for _, sid := range t.RBCDSIDs {
					sb.WriteString(fmt.Sprintf("    - %s (RID: %d)\n", sid.SID, sid.RID))
				}
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Attack Paths\n\n")
	sb.WriteString("1. **Unconstrained Delegation**: Monitor for TGTs on compromised hosts\n")
	sb.WriteString("2. **Constrained Delegation**: Use S4U2Self/S4U2Proxy to impersonate users\n")
	sb.WriteString("3. **RBCD**: Create machine account, add to target's msDS-AllowedToActOnBehalfOfOtherIdentity\n")
	sb.WriteString("4. **SeEnableDelegationPrivilege**: Grant via GPO to enable delegation configuration\n")

	return sb.String()
}

func filterByType(targets []DelegationTarget, dtype DelegationType) []DelegationTarget {
	var result []DelegationTarget
	for _, t := range targets {
		if t.Type == dtype {
			result = append(result, t)
		}
	}
	return result
}

func ParseObjectSID(data []byte) (string, uint32) {
	if len(data) < 8 {
		return "", 0
	}

	revision := data[0]
	if revision != 1 {
		return "", 0
	}

	subAuthCount := int(data[1])
	sidLen := 8 + subAuthCount*4
	if len(data) < sidLen {
		return "", 0
	}

	authority := uint64(0)
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(data[i])
	}

	sid := fmt.Sprintf("S-1-%d", authority)
	var rid uint32
	for i := 0; i < subAuthCount; i++ {
		off := 8 + i*4
		sub := binary.LittleEndian.Uint32(data[off : off+4])
		sid += fmt.Sprintf("-%d", sub)
		rid = sub
	}

	return sid, rid
}

func SIDToBytes(sidStr string) ([]byte, error) {
	parts := strings.Split(sidStr, "-")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SID: %s", sidStr)
	}

	var authority uint64
	fmt.Sscanf(parts[1], "%d", &authority)

	var subAuths []uint32
	for i := 2; i < len(parts); i++ {
		var sub uint32
		fmt.Sscanf(parts[i], "%d", &sub)
		subAuths = append(subAuths, sub)
	}

	sid := make([]byte, 8+len(subAuths)*4)
	sid[0] = 1
	sid[1] = byte(len(subAuths))

	for i := 0; i < 6; i++ {
		sid[2+i] = byte(authority >> (8 * (5 - i)))
	}

	for i, sub := range subAuths {
		binary.LittleEndian.PutUint32(sid[8+i*4:], sub)
	}

	return sid, nil
}

func FormatSIDHex(sidStr string) (string, error) {
	sidBytes, err := SIDToBytes(sidStr)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sidBytes), nil
}
