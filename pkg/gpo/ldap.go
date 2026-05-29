package gpo

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/loudmumble/trusted/pkg/pki"
)

func ConnectLDAP(ctx context.Context, cfg *pki.ADCSConfig) (*ldap.Conn, error) {
	return pki.ConnectLDAP(ctx, cfg)
}

func EnumerateGPOs(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn) ([]GPO, error) {
	baseDN := buildGPOBaseDN(cfg.Domain)
	filter := "(objectClass=groupPolicyContainer)"
	attrs := []string{
		attributeDisplayName, attributeGUID, attributeDN,
		attributeFlags, attributeVersion, attributeFuncVer,
		attributeFileSysPath, attributeGPLink, attributeGPOptions,
		attributeSecurity, attributeWMIFilter, attributeWMIFilterPath,
	}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for GPOs: %w", err)
	}

	var gpos []GPO
	for _, entry := range result.Entries {
		gpo := GPO{
			GUID:          entry.GetAttributeValue(attributeGUID),
			Name:          entry.GetAttributeValue(attributeDisplayName),
			DN:            entry.GetAttributeValue(attributeDN),
			Domain:        cfg.Domain,
			FileSysPath:   entry.GetAttributeValue(attributeFileSysPath),
			WMIFilter:     entry.GetAttributeValue(attributeWMIFilter),
			WMIFilterPath: entry.GetAttributeValue(attributeWMIFilterPath),
		}

		if v := entry.GetRawAttributeValue(attributeFlags); len(v) >= 4 {
			gpo.Flags = binary.LittleEndian.Uint32(v[:4])
		}
		gpo.UserEnabled = (gpo.Flags & flagUserDisabled) == 0
		gpo.ComputerEnabled = (gpo.Flags & flagComputerDisabled) == 0

		if v := entry.GetRawAttributeValue(attributeVersion); len(v) >= 4 {
			gpo.Version = int(binary.LittleEndian.Uint32(v[:4]))
		}
		if v := entry.GetRawAttributeValue(attributeFuncVer); len(v) >= 4 {
			gpo.FuncVersion = int(binary.LittleEndian.Uint32(v[:4]))
		}

		gplink := entry.GetAttributeValue(attributeGPLink)
		gpo.Links = parseGPLinkString(gplink)

		rawSD := entry.GetRawAttributeValue(attributeSecurity)
		if len(rawSD) > 0 {
			gpo.ACL = parseGPOACL(rawSD)
		}

		gpos = append(gpos, gpo)
	}

	return gpos, nil
}

func EnumerateOUs(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn) ([]map[string]string, error) {
	baseDN := buildDomainDN(cfg.Domain)
	filter := "(objectClass=organizationalUnit)"
	attrs := []string{attributeDN, attributeDisplayName, attributeGPLink, attributeSecurity}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for OUs: %w", err)
	}

	var ous []map[string]string
	for _, entry := range result.Entries {
		ou := map[string]string{
			"dn":     entry.DN,
			"name":   entry.GetAttributeValue(attributeDisplayName),
			"gplink": entry.GetAttributeValue(attributeGPLink),
		}
		ous = append(ous, ou)
	}

	return ous, nil
}

func GetGPOLinks(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn, targetDN string) ([]GPLink, error) {
	searchReq := ldap.NewSearchRequest(
		targetDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{attributeGPLink, attributeDisplayName},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for links: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, nil
	}

	gplink := result.Entries[0].GetAttributeValue(attributeGPLink)
	return parseGPLinkString(gplink), nil
}

func GetGPOACL(ctx context.Context, cfg *pki.ADCSConfig, conn *ldap.Conn, gpoDN string) (*GPOACL, error) {
	searchReq := ldap.NewSearchRequest(
		gpoDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{attributeSecurity},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for GPO ACL: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("GPO not found: %s", gpoDN)
	}

	rawSD := result.Entries[0].GetRawAttributeValue(attributeSecurity)
	if len(rawSD) == 0 {
		return nil, fmt.Errorf("no security descriptor on GPO: %s", gpoDN)
	}

	return parseGPOACL(rawSD), nil
}

func ModifyGPLink(conn *ldap.Conn, targetDN, gpoDN string, enabled bool, order int) error {
	existingLinks, err := getExistingLinks(conn, targetDN)
	if err != nil {
		return fmt.Errorf("get existing links: %w", err)
	}

	newLink := fmt.Sprintf("[%s;%d]", gpoDN, encodeLinkOptions(enabled, order))
	existingLinks = append(existingLinks, newLink)

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace(attributeGPLink, []string{strings.Join(existingLinks, "")})
	return conn.Modify(modReq)
}

func RemoveGPLink(conn *ldap.Conn, targetDN, gpoDN string) error {
	existingLinks, err := getExistingLinks(conn, targetDN)
	if err != nil {
		return fmt.Errorf("get existing links: %w", err)
	}

	var newLinks []string
	for _, link := range existingLinks {
		if !strings.Contains(link, gpoDN) {
			newLinks = append(newLinks, link)
		}
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	if len(newLinks) == 0 {
		modReq.Replace(attributeGPLink, []string{""})
	} else {
		modReq.Replace(attributeGPLink, []string{strings.Join(newLinks, "")})
	}
	return conn.Modify(modReq)
}

func getExistingLinks(conn *ldap.Conn, targetDN string) ([]string, error) {
	searchReq := ldap.NewSearchRequest(
		targetDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{attributeGPLink},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return nil, nil
	}

	gplink := result.Entries[0].GetAttributeValue(attributeGPLink)
	if gplink == "" {
		return nil, nil
	}

	var links []string
	depth := 0
	start := 0
	for i, c := range gplink {
		if c == '[' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if c == ']' {
			depth--
			if depth == 0 {
				links = append(links, gplink[start:i+1])
			}
		}
	}
	return links, nil
}

func encodeLinkOptions(enabled bool, order int) int {
	opts := 0
	if !enabled {
		opts |= 1
	}
	opts |= (order << 2)
	return opts
}

func CreateGPO(conn *ldap.Conn, domain, name string) (string, error) {
	gpoGUID := generateGUID()
	gpoDN := fmt.Sprintf("CN={%s},CN=Policies,CN=System,%s", gpoGUID, buildDomainDN(domain))

	addReq := ldap.NewAddRequest(gpoDN, nil)
	addReq.Attribute(attributeObjectClass, []string{"groupPolicyContainer"})
	addReq.Attribute(attributeDisplayName, []string{name})
	addReq.Attribute(attributeGUID, []string{fmt.Sprintf("{%s}", gpoGUID)})
	addReq.Attribute(attributeVersion, []string{"1"})
	addReq.Attribute(attributeFuncVer, []string{"2"})
	addReq.Attribute(attributeFlags, []string{"0"})

	if err := conn.Add(addReq); err != nil {
		return "", fmt.Errorf("create GPO: %w", err)
	}

	return gpoGUID, nil
}

func generateGUID() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}


