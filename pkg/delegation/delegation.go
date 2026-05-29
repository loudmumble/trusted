package delegation

import (
	"encoding/binary"
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


