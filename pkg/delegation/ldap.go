package delegation

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/loudmumble/trusted/pkg/pki"
	"github.com/loudmumble/trusted/pkg/util"
)

func ConnectLDAP(ctx context.Context, cfg *pki.ADCSConfig) (*ldap.Conn, error) {
	return pki.ConnectLDAP(ctx, cfg)
}

func EnumerateDelegation(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn) (*DelegationEnumResult, error) {
	result := &DelegationEnumResult{}

	targets, err := enumerateUsersWithDelegation(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate users: %w", err)
	}
	result.Targets = append(result.Targets, targets...)

	compTargets, err := enumerateComputersWithDelegation(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate computers: %w", err)
	}
	result.Targets = append(result.Targets, compTargets...)

	rbcdTargets, err := enumerateRBCDTargets(ctx, cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("enumerate RBCD targets: %w", err)
	}
	result.Targets = append(result.Targets, rbcdTargets...)

	for _, t := range result.Targets {
		switch t.Type {
		case DelegationUnconstrained:
			result.UnconstrainedCount++
		case DelegationConstrained, DelegationConstrainedRCB:
			result.ConstrainedCount++
		case DelegationResourceBased:
			result.RBCDCount++
		}
	}

	writable, err := enumerateWritableForRBCD(ctx, cfg, conn)
	if err == nil {
		result.WritableForRBCD = writable
	}

	return result, nil
}

func enumerateUsersWithDelegation(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn) ([]DelegationTarget, error) {
	baseDN := buildDomainDN(cfg.Domain)
	filter := "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16777216))"
	attrs := []string{
		"sAMAccountName", "distinguishedName", "userAccountControl",
		"servicePrincipalName", "msDS-AllowedToDelegateTo",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
	}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}

	var targets []DelegationTarget
	for _, entry := range result.Entries {
		target := DelegationTarget{
			Name:       entry.GetAttributeValue("sAMAccountName"),
			DN:         entry.GetAttributeValue("distinguishedName"),
			IsComputer: false,
		}

		if v := entry.GetRawAttributeValue("userAccountControl"); len(v) >= 4 {
			target.UserAccountControl = binary.LittleEndian.Uint32(v[:4])
		}

		target.AllowedSPNs = entry.GetAttributeValues("servicePrincipalName")
		target.DelegatedTo = entry.GetAttributeValues("msDS-AllowedToDelegateTo")

		if msDS := entry.GetAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity"); msDS != "" {
			target.MSDSAllowedToAct = msDS
			target.RBCDSIDs = parseMSDSSIDs(msDS)
		}

		if target.UserAccountControl&flagTrustedForDelegation != 0 {
			target.Type = DelegationUnconstrained
			target.HasDelegation = true
		} else if target.UserAccountControl&flagTrustedToAuthForDelegation != 0 {
			if len(target.DelegatedTo) > 0 {
				target.Type = DelegationConstrained
			} else {
				target.Type = DelegationConstrainedRCB
			}
			target.HasDelegation = true
		}

		if target.HasDelegation {
			targets = append(targets, target)
		}
	}

	return targets, nil
}

func enumerateComputersWithDelegation(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn) ([]DelegationTarget, error) {
	baseDN := buildDomainDN(cfg.Domain)
	filter := "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=16777216))"
	attrs := []string{
		"sAMAccountName", "distinguishedName", "userAccountControl",
		"servicePrincipalName", "msDS-AllowedToDelegateTo",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
	}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}

	var targets []DelegationTarget
	for _, entry := range result.Entries {
		target := DelegationTarget{
			Name:       entry.GetAttributeValue("sAMAccountName"),
			DN:         entry.GetAttributeValue("distinguishedName"),
			IsComputer: true,
		}

		if v := entry.GetRawAttributeValue("userAccountControl"); len(v) >= 4 {
			target.UserAccountControl = binary.LittleEndian.Uint32(v[:4])
		}

		target.AllowedSPNs = entry.GetAttributeValues("servicePrincipalName")
		target.DelegatedTo = entry.GetAttributeValues("msDS-AllowedToDelegateTo")

		if msDS := entry.GetAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity"); msDS != "" {
			target.MSDSAllowedToAct = msDS
			target.RBCDSIDs = parseMSDSSIDs(msDS)
		}

		if target.UserAccountControl&flagTrustedForDelegation != 0 {
			target.Type = DelegationUnconstrained
			target.HasDelegation = true
		} else if target.UserAccountControl&flagTrustedToAuthForDelegation != 0 {
			if len(target.DelegatedTo) > 0 {
				target.Type = DelegationConstrained
			} else {
				target.Type = DelegationConstrainedRCB
			}
			target.HasDelegation = true
		}

		if len(target.RBCDSIDs) > 0 && target.Type != DelegationResourceBased {
			target.Type = DelegationResourceBased
			target.HasDelegation = true
		}

		if target.HasDelegation {
			targets = append(targets, target)
		}
	}

	return targets, nil
}

func enumerateRBCDTargets(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn) ([]DelegationTarget, error) {
	baseDN := buildDomainDN(cfg.Domain)
	filter := "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
	attrs := []string{
		"sAMAccountName", "distinguishedName",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
	}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}

	var targets []DelegationTarget
	for _, entry := range result.Entries {
		msDS := entry.GetAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
		if msDS == "" {
			continue
		}

		target := DelegationTarget{
			Name:             entry.GetAttributeValue("sAMAccountName"),
			DN:               entry.GetAttributeValue("distinguishedName"),
			IsComputer:       true,
			Type:             DelegationResourceBased,
			MSDSAllowedToAct: msDS,
			RBCDSIDs:         parseMSDSSIDs(msDS),
			HasDelegation:    true,
		}
		targets = append(targets, target)
	}

	return targets, nil
}

func enumerateWritableForRBCD(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn) ([]string, error) {
	baseDN := buildDomainDN(cfg.Domain)
	filter := "(objectClass=computer)"
	attrs := []string{"sAMAccountName", "nTSecurityDescriptor"}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}

	var writable []string
	for _, entry := range result.Entries {
		sd := entry.GetRawAttributeValue("nTSecurityDescriptor")
		if len(sd) == 0 {
			continue
		}
		if isWritableForRBCD(sd, cfg.Username) {
			writable = append(writable, entry.GetAttributeValue("sAMAccountName"))
		}
	}

	return writable, nil
}

func isWritableForRBCD(sd []byte, username string) bool {
	return false
}

func parseMSDSSIDs(msDS string) []SIDEntry {
	var entries []SIDEntry
	parts := strings.Split(msDS, "B:")
	if len(parts) < 2 {
		return entries
	}
	for _, part := range parts[1:] {
		subParts := strings.SplitN(part, ":", 3)
		if len(subParts) < 3 {
			continue
		}
		sidHex := subParts[1]
		if len(sidHex) < 2 {
			continue
		}
		entry := SIDEntry{
			SID: sidHex,
		}
		entries = append(entries, entry)
	}
	return entries
}

func buildDomainDN(domain string) string {
	return util.BuildDomainDN(domain)
}

func SetConstrainedDelegation(conn *ldap.Conn, targetDN, spn string) error {
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Add("msDS-AllowedToDelegateTo", []string{spn})
	return conn.Modify(modReq)
}

func RemoveConstrainedDelegation(conn *ldap.Conn, targetDN, spn string) error {
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Delete("msDS-AllowedToDelegateTo", []string{spn})
	return conn.Modify(modReq)
}

func SetRBCD(conn *ldap.Conn, targetDN, allowedSID string) error {
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Add("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{allowedSID})
	return conn.Modify(modReq)
}

func RemoveRBCD(conn *ldap.Conn, targetDN, allowedSID string) error {
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Delete("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{allowedSID})
	return conn.Modify(modReq)
}

func CreateMachineAccount(conn *ldap.Conn, domain, name, password string) (string, error) {
	dn := fmt.Sprintf("CN=%s,CN=Computers,%s", name, buildDomainDN(domain))

	uc := uint32(0x1000 | 0x20000000 | 0x1000000)
	ucBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ucBytes, uc)

	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"computer"})
	addReq.Attribute("sAMAccountName", []string{name + "$"})
	addReq.Attribute("userAccountControl", []string{fmt.Sprintf("%d", uc)})
	addReq.Attribute("unicodePwd", []string{fmt.Sprintf("%s", password)})

	if err := conn.Add(addReq); err != nil {
		return "", fmt.Errorf("create machine account: %w", err)
	}

	return dn, nil
}

func FindComputerDN(conn *ldap.Conn, baseDN, samAccountName string) (string, error) {
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s))", ldap.EscapeFilter(samAccountName)),
		[]string{"distinguishedName"},
		nil,
	)
	res, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("search computer: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("computer not found: %s", samAccountName)
	}
	return res.Entries[0].DN, nil
}

func DeleteMachineAccount(conn *ldap.Conn, dn string) error {
	delReq := ldap.NewDelRequest(dn, nil)
	return conn.Del(delReq)
}

func SetMachinePassword(conn *ldap.Conn, dn, password string) error {
	modReq := ldap.NewModifyRequest(dn, nil)
	modReq.Replace("unicodePwd", []string{fmt.Sprintf("%s", password)})
	return conn.Modify(modReq)
}
