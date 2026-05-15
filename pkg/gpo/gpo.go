package gpo

import (
	"fmt"
	"strings"

	"github.com/loudmumble/trusted/pkg/util"
)

const (
	gpoBaseDN              = "CN=Policies,CN=System"
	ouBaseDN               = "CN=Partitions,CN=Configuration"
	attributeDisplayName   = "displayName"
	attributeFlags         = "flags"
	attributeGPLink        = "gPLink"
	attributeGPOptions     = "gPOptions"
	attributeVersion       = "versionNumber"
	attributeFuncVer       = "gPCFunctionalityVersion"
	attributeFileSysPath   = "gPCFileSysPath"
	attributeSecurity      = "nTSecurityDescriptor"
	attributeGUID          = "objectGUID"
	attributeDN            = "distinguishedName"
	attributeObjectClass   = "objectClass"
	attributeSAM           = "sAMAccountName"
	attributeMember        = "member"
	attributeGPOFilter     = "gPOFilter"
	attributeWMIFilter     = "msWMI-Name"
	attributeWMIFilterPath = "msWMI-Parm1"
)

const (
	flagUserDisabled     = 1 << 0
	flagComputerDisabled = 1 << 1
)

const (
	gpoScopeDomain = "[Domain]"
	gpoScopeOU     = "[OU]"
	gpoScopeSite   = "[Site]"
	gpoScopeStale  = "[Stale]"
	gpoScopeEmpty  = "[Empty]"
)

type GPO struct {
	GUID            string
	Name            string
	DN              string
	Domain          string
	Flags           uint32
	Version         int
	FuncVersion     int
	FileSysPath     string
	UserEnabled     bool
	ComputerEnabled bool
	Links           []GPLink
	SecurityFilter  []string
	WMIFilter       string
	WMIFilterPath   string
	Settings        *GPOSettings
	ACL             *GPOACL
}

type GPLink struct {
	TargetDN   string
	TargetName string
	Scope      string
	Enabled    bool
	Order      int
}

type GPOACL struct {
	Revision uint8
	OwnerSID string
	GroupSID string
	DACL     *ACL
}

type ACL struct {
	Revision uint8
	ACEs     []ACE
}

type ACE struct {
	Type    uint8
	Flags   uint8
	Mask    uint32
	SID     []byte
	SIDText string
	Rights  []string
}

type GPOSettings struct {
	RegistrySettings []RegistrySetting
	ScheduledTasks   []ScheduledTask
	Scripts          []GPOScript
	LocalGroups      []LocalGroup
	UserRights       []UserRight
	Files            []FileDeployment
	Services         []ServiceConfig
	SecurityPolicies *SecurityPolicy
}

type RegistrySetting struct {
	Hive   string
	Key    string
	Value  string
	Type   string
	Data   string
	Action string
}

type ScheduledTask struct {
	Name           string
	Command        string
	Arguments      string
	Author         string
	RunAs          string
	LogonType      string
	TriggerType    string
	Enabled        bool
	UserContext    bool
	TargetUser     string
	TargetComputer string
}

type GPOScript struct {
	Name    string
	Content string
	Type    string
	Phase   string
}

type LocalGroup struct {
	Group   string
	Members []string
}

type UserRight struct {
	Privilege string
	Users     []string
}

type FileDeployment struct {
	Source      string
	Destination string
	Action      string
}

type ServiceConfig struct {
	Name      string
	Path      string
	Account   string
	StartType string
	ErrorMode string
}

type SecurityPolicy struct {
	MinimumPasswordLength     int
	PasswordComplexity        bool
	LockoutThreshold          int
	AuditAccountLogon         string
	AuditObjectAccess         string
	RestrictAnonymous         int
	ForceLogoffWhenHourExpire bool
}

type EnumResult struct {
	GPOs            []GPO         `json:"gpos"`
	TotalCount      int           `json:"total_count"`
	WritableCount   int           `json:"writable_count"`
	LinkedToDCCount int           `json:"linked_to_dc_count"`
	GPPPasswords    []GPPPassword `json:"gpp_passwords,omitempty"`
	Errors          []string      `json:"errors,omitempty"`
}

type GPPPassword struct {
	GPOName   string
	FilePath  string
	Username  string
	Password  string
	CPassword string
	Decrypted bool
}

type ExploitConfig struct {
	GPOName         string
	GPOGUID         string
	AttackType      string
	TaskName        string
	Command         string
	Arguments       string
	ScriptName      string
	ScriptContent   string
	UserAccount     string
	GroupName       string
	GroupNameLocal  string
	Privileges      []string
	FilterEnabled   bool
	TargetUsername  string
	TargetUserSID   string
	TargetDNSName   string
	Author          string
	RunAs           string
	UserContext     bool
	RegistryHive    string
	RegistryKey     string
	RegistryValue   string
	RegistryData    string
	RegistryType    string
	ServiceName     string
	ServicePath     string
	ServiceAccount  string
	FileSource      string
	FileDestination string
}

type LinkConfig struct {
	GPOName    string
	GPOGUID    string
	TargetDN   string
	TargetName string
	LinkType   string
	Enable     bool
	Order      int
}

type OUConfig struct {
	Name    string
	BaseDN  string
	Protect bool
}

type CoerceConfig struct {
	Target       string
	ListenerIP   string
	ListenerPort int
	Method       string
}

type RestoreConfig struct {
	GPOGUID     string
	BackupPath  string
	FullRestore bool
}

type AttackPath struct {
	ID          string
	Name        string
	Steps       []AttackStep
	Risk        string
	Description string
}

type AttackStep struct {
	Action      string
	Target      string
	Description string
	Tool        string
}

func buildGPOBaseDN(domain string) string {
	return util.BuildLDAPBaseDN(domain, gpoBaseDN)
}

func buildDomainDN(domain string) string {
	return util.BuildDomainDN(domain)
}

func parseGPLinkString(gplink string) []GPLink {
	var links []GPLink
	if gplink == "" {
		return links
	}
	parts := strings.Split(gplink, "]")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = strings.TrimPrefix(part, "[")
		if part == "" {
			continue
		}
		parts2 := strings.SplitN(part, ";", 2)
		if len(parts2) < 2 {
			continue
		}
		dn := strings.TrimSpace(parts2[0])
		enabled := true
		order := 0
		if len(parts2) > 1 {
			opts := strings.TrimSpace(parts2[1])
			if len(opts) >= 1 {
				if opts[0] == '0' {
					enabled = false
				}
			}
			if len(opts) > 1 {
				fmt.Sscanf(opts[1:], "%d", &order)
			}
		}
		if dn == "" {
			continue
		}
		links = append(links, GPLink{
			TargetDN: dn,
			Enabled:  enabled,
			Order:    order,
		})
	}
	return links
}

func (g *GPO) String() string {
	status := ""
	if !g.UserEnabled && !g.ComputerEnabled {
		status = " [DISABLED]"
	} else if !g.UserEnabled {
		status = " [Computer Only]"
	} else if !g.ComputerEnabled {
		status = " [User Only]"
	}
	return fmt.Sprintf("%s (%s)%s", g.Name, g.GUID, status)
}

func (g *GPO) IsLinkedToDC() bool {
	for _, link := range g.Links {
		if strings.Contains(strings.ToLower(link.TargetDN), "domain controllers") {
			return true
		}
	}
	return false
}

func (g *GPO) HasWritableACL() bool {
	if g.ACL == nil || g.ACL.DACL == nil {
		return false
	}
	for _, ace := range g.ACL.DACL.ACEs {
		if ace.Type != 0 {
			continue
		}
		for _, right := range ace.Rights {
			if right == "GenericAll" || right == "GenericWrite" || right == "WriteDACL" || right == "WriteOwner" {
				return true
			}
		}
	}
	return false
}

var knownPrivileges = map[string]string{
	"SeAssignPrimaryTokenPrivilege":   "Replace a process level token",
	"SeAuditPrivilege":                "Manage auditing and security log",
	"SeBackupPrivilege":               "Back up files and directories",
	"SeBatchLogonRight":               "Log on as a batch job",
	"SeChangeNotifyPrivilege":         "Bypass traverse checking",
	"SeCreateGlobalPrivilege":         "Create global objects",
	"SeCreatePagefilePrivilege":       "Create a pagefile",
	"SeCreatePermanentPrivilege":      "Create permanent shared objects",
	"SeCreateTokenPrivilege":          "Create a token object",
	"SeDebugPrivilege":                "Debug programs",
	"SeDenyBatchLogonRight":           "Deny log on as a batch job",
	"SeDenyInteractiveLogonRight":     "Deny log on locally",
	"SeDenyNetworkLogonRight":         "Deny access to this computer from the network",
	"SeDenyServiceLogonRight":         "Deny log on as a service",
	"SeEnableDelegationPrivilege":     "Enable computer and user accounts to be trusted for delegation",
	"SeImpersonatePrivilege":          "Impersonate a client after authentication",
	"SeIncreaseBasePriorityPrivilege": "Increase scheduling priority",
	"SeIncreaseQuotaPrivilege":        "Adjust memory quotas for a process",
	"SeInteractiveLogonRight":         "Log on locally",
	"SeLoadDriverPrivilege":           "Load and unload device drivers",
	"SeLockMemoryPrivilege":           "Lock pages in memory",
	"SeMachineAccountPrivilege":       "Add workstations to domain",
	"SeManageVolumePrivilege":         "Manage the security log",
	"SeProfileSingleProcessPrivilege": "Profile single process",
	"SeRelabelPrivilege":              "Replace a process level token",
	"SeRemoteInteractiveLogonRight":   "Allow log on through Remote Desktop Services",
	"SeRemoteShutdownPrivilege":       "Force shutdown from a remote system",
	"SeRestorePrivilege":              "Restore files and directories",
	"SeSecurityPrivilege":             "Manage auditing and security log",
	"SeServiceLogonRight":             "Log on as a service",
	"SeShutdownPrivilege":             "Shut down the system",
	"SeSyncAgentPrivilege":            "Synchronize directory service data",
	"SeSystemEnvironmentPrivilege":    "Modify firmware environment values",
	"SeSystemProfilePrivilege":        "Profile system performance",
	"SeSystemtimePrivilege":           "Change the system time",
	"SeTakeOwnershipPrivilege":        "Take ownership of files or other objects",
	"SeTcbPrivilege":                  "Act as part of the operating system",
	"SeTrustedCredManAccessPrivilege": "Access Credential Manager as a trusted caller",
	"SeUndockPrivilege":               "Remove computer from docking station",
	"SeUnlockPipelinePrivilege":       "Unpark pipeline after deferred unlock",
	"SeCreateSymbolicLinkPrivilege":   "Create symbolic links",
	"SeIncBasePriorityPrivilege":      "Increase scheduling priority",
}

var wellKnownSIDs = map[string]string{
	"S-1-0-0":      "Nobody",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-2-1":      "Console Logon",
	"S-1-3-0":      "Creator Owner",
	"S-1-3-1":      "Creator Group",
	"S-1-5-7":      "Anonymous Logon",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-18":     "LOCAL SYSTEM",
	"S-1-5-19":     "NT Authority - Local Service",
	"S-1-5-20":     "NT Authority - Network Service",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-552": "BUILTIN\\Replicators",
}
