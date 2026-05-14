package gpo

import (
	"encoding/binary"
	"fmt"
)

const (
	GPOGenericAll   uint32 = 0x10000000
	GPOGenericWrite uint32 = 0x40000000
	GPOGenericRead  uint32 = 0x20000000
	GPOWriteDACL    uint32 = 0x00040000
	GPOWriteOwner   uint32 = 0x00080000
	GPOReadControl  uint32 = 0x00020000
	GPODelete       uint32 = 0x00010000
	GPOSynchronize  uint32 = 0x00100000

	GPOWritePropFirst uint32 = 0x00000001
	GPOWritePropLast  uint32 = 0x00080000

	GPOControlAccess uint32 = 0x00000100
	GPOMaxAllowed    uint32 = 0x00000200

	ACETypeAccessAllowed       = 0x00
	ACETypeAccessDenied        = 0x01
	ACETypeAccessAllowedObject = 0x05
	ACETypeAccessDeniedObject  = 0x06
	ACETypeSystemAudit         = 0x09
	ACETypeSystemAuditObject   = 0x0D

	ACEFlagInheritOnly       = 0x02
	ACEFlagNoPropInherit     = 0x04
	ACEFlagInheritOnlyNoProp = 0x06
)

var gpoRightNames = map[uint32]string{
	GPOGenericAll:    "GenericAll",
	GPOGenericWrite:  "GenericWrite",
	GPOGenericRead:   "GenericRead",
	GPOWriteDACL:     "WriteDACL",
	GPOWriteOwner:    "WriteOwner",
	GPOReadControl:   "ReadControl",
	GPODelete:        "Delete",
	GPOSynchronize:   "Synchronize",
	GPOControlAccess: "ControlAccess",
}

type GPOACLResult struct {
	GPOName     string
	GPOGUID     string
	OwnerSID    string
	OwnerName   string
	GroupSID    string
	DACEs       []GPOACEResult
	IsWritable  bool
	WriteRights []string
}

type GPOACEResult struct {
	Type     uint8
	TypeName string
	SID      string
	SIDName  string
	Mask     uint32
	Rights   []string
	IsAllow  bool
}

func parseGPOACL(data []byte) *GPOACL {
	if len(data) < 20 {
		return nil
	}

	sd := &GPOACL{}

	sd.Revision = data[0]
	control := binary.LittleEndian.Uint16(data[2:4])

	hasOwner := (control & 0x0001) != 0
	hasGroup := (control & 0x0002) != 0
	hasDACL := (control & 0x0004) != 0

	offset := 20

	if hasOwner && offset+4 <= len(data) {
		ownerOffset := int(binary.LittleEndian.Uint32(data[offset-4 : offset]))
		if ownerOffset > 0 && ownerOffset < len(data) {
			sd.OwnerSID = parseSIDString(data, ownerOffset)
		}
	}

	if hasGroup && offset+4 <= len(data) {
		groupOffset := int(binary.LittleEndian.Uint32(data[offset-4 : offset]))
		if groupOffset > 0 && groupOffset < len(data) {
			sd.GroupSID = parseSIDString(data, groupOffset)
		}
	}

	if hasDACL && offset+4 <= len(data) {
		daclOffset := int(binary.LittleEndian.Uint32(data[offset-4 : offset]))
		if daclOffset > 0 && daclOffset < len(data) {
			sd.DACL = parseDACL(data, daclOffset)
		}
	}

	return sd
}

func parseDACL(data []byte, offset int) *ACL {
	if offset+8 > len(data) {
		return nil
	}

	acl := &ACL{
		Revision: data[offset],
	}

	aceCount := int(binary.LittleEndian.Uint16(data[offset+4 : offset+6]))
	aceOffset := offset + 8

	for i := 0; i < aceCount; i++ {
		if aceOffset+4 > len(data) {
			break
		}

		aceType := data[aceOffset]
		aceFlags := data[aceOffset+1]
		aceSize := int(binary.LittleEndian.Uint16(data[aceOffset+2 : aceOffset+4]))

		if aceSize < 8 || aceOffset+aceSize > len(data) {
			break
		}

		var mask uint32
		if aceType == ACETypeAccessAllowed || aceType == ACETypeAccessDenied {
			if aceOffset+8 <= len(data) {
				mask = binary.LittleEndian.Uint32(data[aceOffset+4 : aceOffset+8])
			}
		} else if aceType == ACETypeAccessAllowedObject || aceType == ACETypeAccessDeniedObject {
			if aceOffset+36 <= len(data) {
				mask = binary.LittleEndian.Uint32(data[aceOffset+4 : aceOffset+8])
			}
		}

		var sidText string
		if aceType == ACETypeAccessAllowed || aceType == ACETypeAccessDenied {
			if aceOffset+8 < aceOffset+aceSize {
				sidText = parseSIDString(data, aceOffset+8)
			}
		} else if aceType == ACETypeAccessAllowedObject || aceType == ACETypeAccessDeniedObject {
			if aceOffset+36 < aceOffset+aceSize {
				sidText = parseSIDString(data, aceOffset+36)
			}
		}

		ace := ACE{
			Type:    aceType,
			Flags:   aceFlags,
			Mask:    mask,
			SIDText: sidText,
			Rights:  decodeGPRights(mask),
		}

		acl.ACEs = append(acl.ACEs, ace)
		aceOffset += aceSize
	}

	return acl
}

func parseSIDString(data []byte, offset int) string {
	if offset+8 > len(data) {
		return ""
	}

	revision := data[offset]
	if revision != 1 {
		return ""
	}

	subAuthCount := int(data[offset+1])
	sidLen := 8 + subAuthCount*4
	if offset+sidLen > len(data) {
		return ""
	}

	authority := uint64(0)
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(data[offset+i])
	}

	sid := fmt.Sprintf("S-1-%d", authority)
	for i := 0; i < subAuthCount; i++ {
		off := offset + 8 + i*4
		if off+4 > len(data) {
			break
		}
		sub := binary.LittleEndian.Uint32(data[off : off+4])
		sid += fmt.Sprintf("-%d", sub)
	}

	if name, ok := wellKnownSIDs[sid]; ok {
		return name
	}
	return sid
}

func decodeGPRights(mask uint32) []string {
	var rights []string
	for bit, name := range gpoRightNames {
		if mask&bit != 0 {
			rights = append(rights, name)
		}
	}
	return rights
}

func AnalyzeGPOACL(acl *GPOACL, userName, userSID string) *GPOACLResult {
	result := &GPOACLResult{
		OwnerSID: acl.OwnerSID,
	}

	if acl.DACL == nil {
		return result
	}

	for _, ace := range acl.DACL.ACEs {
		acR := GPOACEResult{
			Type:     ace.Type,
			TypeName: aceTypeName(ace.Type),
			SID:      ace.SIDText,
			Mask:     ace.Mask,
			Rights:   ace.Rights,
			IsAllow:  ace.Type == ACETypeAccessAllowed,
		}

		if ace.SIDText == userName || ace.SIDText == userSID {
			result.WriteRights = append(result.WriteRights, ace.Rights...)
		}

		result.DACEs = append(result.DACEs, acR)
	}

	for _, right := range result.WriteRights {
		if right == "GenericAll" || right == "GenericWrite" || right == "WriteDACL" || right == "WriteOwner" {
			result.IsWritable = true
			break
		}
	}

	return result
}

func aceTypeName(t uint8) string {
	switch t {
	case ACETypeAccessAllowed:
		return "ACCESS_ALLOWED"
	case ACETypeAccessDenied:
		return "ACCESS_DENIED"
	case ACETypeAccessAllowedObject:
		return "ACCESS_ALLOWED_OBJECT"
	case ACETypeAccessDeniedObject:
		return "ACCESS_DENIED_OBJECT"
	case ACETypeSystemAudit:
		return "SYSTEM_AUDIT"
	case ACETypeSystemAuditObject:
		return "SYSTEM_AUDIT_OBJECT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func CheckGPOWriteAccess(aclResult *GPOACLResult, trusteeSID string) (bool, []string) {
	if aclResult == nil {
		return false, nil
	}

	var rights []string
	for _, ace := range aclResult.DACEs {
		if !ace.IsAllow {
			continue
		}
		if ace.SID != trusteeSID {
			continue
		}
		for _, right := range ace.Rights {
			switch right {
			case "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner":
				rights = append(rights, right)
			}
		}
	}

	return len(rights) > 0, rights
}
