// Package util provides shared utility functions used across the Trusted codebase.
// This eliminates duplication of common patterns like domain DN building,
// username normalization, and input validation.
package util

import (
	"fmt"
	"regexp"
	"strings"
)

// BuildDomainDN constructs an LDAP distinguished name from a dotted domain name.
// Example: "corp.local" → "DC=corp,DC=local"
func BuildDomainDN(domain string) string {
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	dcParts := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			dcParts = append(dcParts, "DC="+p)
		}
	}
	return strings.Join(dcParts, ",")
}

// BuildLDAPBaseDN constructs an LDAP base DN by prepending a container path to the domain DN.
// Example: BuildLDAPBaseDN("corp.local", "CN=Users") → "CN=Users,DC=corp,DC=local"
func BuildLDAPBaseDN(domain, containerPath string) string {
	domainDN := BuildDomainDN(domain)
	if containerPath == "" {
		return domainDN
	}
	return containerPath + "," + domainDN
}

// NormalizeUsername strips domain prefix (domain\user, domain/user) and returns
// the bare sAMAccountName. Used for NTLM auth and Kerberos principal construction.
// Examples:
//
//	"DOMAIN\user" → "user"
//	"domain/user" → "user"
//	"user@domain.com" → "user" (strips @domain part too)
//	"CN=Admin,CN=Users,DC=corp,DC=local" → "CN=Admin,CN=Users,DC=corp,DC=local" (DNs passed through)
func NormalizeUsername(username string) string {
	if username == "" {
		return ""
	}
	// If it's a DN, return as-is
	if strings.HasPrefix(strings.ToUpper(username), "CN=") {
		return username
	}
	// Strip domain\user or domain/user prefix
	if idx := strings.LastIndexAny(username, "\\/"); idx >= 0 {
		return username[idx+1:]
	}
	// Strip @domain suffix (user@domain.com → user)
	if idx := strings.Index(username, "@"); idx > 0 {
		return username[:idx]
	}
	return username
}

// BuildBindDN constructs a bind DN from username and domain.
// Supports: user, user@domain, domain\user, domain/user, CN=user,...
func BuildBindDN(username, domain string) string {
	if strings.HasPrefix(strings.ToUpper(username), "CN=") {
		return username
	}
	if strings.Contains(username, "@") {
		return username
	}
	if idx := strings.LastIndexAny(username, "\\/"); idx >= 0 {
		return username[idx+1:] + "@" + domain
	}
	return username + "@" + domain
}

// ValidateDomain checks if a domain string is in a valid format.
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	// Basic validation: must contain at least one dot
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("domain %q is not in FQDN format (expected e.g. corp.local)", domain)
	}
	// Check for invalid characters
	if strings.ContainsAny(domain, " \t\n\r,") {
		return fmt.Errorf("domain %q contains invalid characters", domain)
	}
	return nil
}

// ValidateUPN checks if a UPN is in a valid format (user@domain).
func ValidateUPN(upn string) error {
	if upn == "" {
		return fmt.Errorf("UPN cannot be empty")
	}
	if !strings.Contains(upn, "@") {
		return fmt.Errorf("UPN %q must be in user@domain format", upn)
	}
	parts := strings.SplitN(upn, "@", 2)
	if parts[0] == "" {
		return fmt.Errorf("UPN %q has empty username part", upn)
	}
	if parts[1] == "" {
		return fmt.Errorf("UPN %q has empty domain part", upn)
	}
	return nil
}

// ValidateNTHash checks if an NT hash is valid (32 hex chars = 16 bytes).
func ValidateNTHash(hash string) error {
	if hash == "" {
		return nil // empty is OK (not using hash auth)
	}
	if len(hash) != 32 {
		return fmt.Errorf("NT hash must be 32 hex characters (16 bytes), got %d", len(hash))
	}
	if !regexp.MustCompile(`^[0-9a-fA-F]{32}$`).MatchString(hash) {
		return fmt.Errorf("NT hash must be hexadecimal, got %q", hash)
	}
	return nil
}

// ShortID truncates an ID string to 8 chars for display/logging.
func ShortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// TruncateString truncates a string to maxLen characters, adding "..." if truncated.
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}


