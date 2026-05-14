# Trusted GPO Module — Comprehensive Design Spec

## Overview

A unified GPO attack framework covering the full lifecycle: enumerate → identify → exploit → execute → persist → cleanup. Combines capabilities from SharpGPOAbuse, GroupPolicyBackdoor, SharpGPO, GPOwned, and Synacktiv's research into a single coherent Go tool.

## Attack Surface Coverage

### 1. GPO Enumeration (`trusted gpo --enum`)

| Feature | Description |
|---------|-------------|
| Enumerate all GPOs | List all GPOs with GUIDs, names, versions, links |
| Enumerate GPO links | Show all gPLinks on OUs, sites, domains |
| Enumerate writable GPOs | Check current user's effective permissions on each GPO |
| Enumerate GPO scope | Which users/computers are affected (security filters, WMI, OUs) |
| Enumerate GPO settings | Parse GPT files for scripts, tasks, registry, preferences |
| Detect GPP passwords | Find and decrypt cpassword values in SYSVOL |
| Detect privileged GPOs | GPOs linked to Domain Controllers OU or containing admin tasks |
| JSON output | Structured output for pipeline integration |

### 2. GPO Permission Analysis (`trusted gpo --acl`)

| Feature | Description |
|---------|-------------|
| Parse GPO DACLs | Full binary SD parsing (reuse existing security_descriptor.go) |
| Identify dangerous ACEs | WriteDACL, WriteOwner, GenericAll, GenericWrite, WriteProperty |
| Map effective permissions | Calculate what the current user can do to each GPO |
| Detect misconfigurations | Authenticated Users with write access, Domain Users with tasks |
| BloodHound integration | Export as BloodHound edges (CanModifyGPO, GPOContainsTask) |

### 3. GPO Modification (`trusted gpo --exploit <TYPE>`)

| Attack Type | Description | Target |
|-------------|-------------|--------|
| `--add-computer-task` | Add immediate scheduled task to computer GPO | Computer |
| `--add-user-task` | Add immediate scheduled task to user GPO | User |
| `--add-computer-script` | Add startup/shutdown script | Computer |
| `--add-user-script` | Add logon/logoff script | User |
| `--add-local-admin` | Add user to local Administrators via Restricted Groups | Computer |
| `--add-user-rights` | Add privilege (SeDebug, SeBackup, etc.) via User Rights Assignment | Computer |
| `--add-local-group` | Add user to any local group (Remote Desktop Users, etc.) | Computer |
| `--add-registry` | Add/modify registry key/value | Computer/User |
| `--add-service` | Create/modify a Windows service | Computer |
| `--deploy-file` | Copy file to target via GPO | Computer |
| `--add-dll-hijack` | Plant DLL for hijack via GPO | Computer |

### 4. GPO Creation (`trusted gpo --create`)

| Feature | Description |
|---------|-------------|
| Create new GPO | Create a GPO with a name |
| Configure GPO | Set computer/user configuration |
| Set security filtering | Control who the GPO applies to |
| Set WMI filter | Conditional targeting by OS, hardware, etc. |
| Set comments | Document the GPO purpose |

### 5. GPO Linking (`trusted gpo --link`)

| Feature | Description |
|---------|-------------|
| Link to OU | Link GPO to an Organizational Unit |
| Link to Site | Link GPO to an AD site |
| Link to Domain | Link GPO to domain root |
| Unlink GPO | Remove a GPO link from an object |
| Modify link order | Change GPO processing priority |
| Set link status | Enable/disable a GPO link (availability attack) |

### 6. OU Manipulation (`trusted gpo --ou`)

| Feature | Description |
|---------|-------------|
| Create OU | Create a new Organizational Unit |
| Delete OU | Remove an OU (if not protected) |
| Move object | Move a user/computer to a different OU (changes GPO scope) |
| Modify OU ACL | Add malicious ACEs to OU (WriteDACL, GenericAll) |
| Enumerate OU membership | List users/computers in an OU |
| Enumerate OU GPO links | Show all GPOs linked to an OU |

### 7. SCF/LNK File Attacks (`trusted gpo --smb-coerce`)

| Feature | Description |
|---------|-------------|
| Generate SCF file | Create Shell Command File targeting attacker SMB server |
| Generate LNK file | Create malicious shortcut file |
| Deploy via GPO | Use GPO to copy SCF/LNK to target shares |
| Capture NTLM | Integrate with C2 listener for hash capture |
| Relay to GPO | Chain with NTLM relay to GPO web enrollment |

### 8. Authentication Coercion (`trusted gpo --coerce`)

| Feature | Description |
|---------|-------------|
| PetitPotam | MS-EFSRPC coercion to DC |
| PrinterBug | MS-RPRN coercion via print spooler |
| DFSCoerce | MS-DFSNM coercion via DFS |
| ShadowCoerce | MS-FSRVP coercion via file server |
| WebDAV coercion | HTTP-based coercion for non-admin pivots |
| Coerce → Relay → GPO | Full chain: coerce auth → relay to GPO endpoint → modify GPO |

### 9. TGT Extraction (`trusted gpo --get-tgt`)

| Feature | Description |
|---------|-------------|
| CoerceToTGT | Coerce NTLM auth → relay to GPO → obtain certificate → PKINIT → TGT |
| CoerceToHash | Coerce → relay → certificate → UnPAC-the-hash → NT hash |
| Chain with Trusted PKI | Leverage existing ESC8/ESC11/ESC12 relay infrastructure |
| CoerceToCCache | Full chain to ccache file for pass-the-ticket |

### 10. Security Policy Attacks (`trusted gpo --policy`)

| Feature | Description |
|---------|-------------|
| Add user to local admin | Via Restricted Groups in GPO |
| Add user rights assignment | SeDebugPrivilege, SeBackupPrivilege, SeImpersonate, etc. |
| Modify audit policy | Disable audit logging |
| Modify firewall rules | Open ports for lateral movement |
| Disable Windows Defender | Via registry preference |
| Disable UAC | Via registry modification |
| Disable ETW | Via registry modification |

### 11. Cleanup & Restoration (`trusted gpo --restore`)

| Feature | Description |
|---------|-------------|
| Restore GPO | Revert GPO to pre-exploitation state |
| Remove injected tasks | Clean up scheduled tasks |
| Remove injected scripts | Clean up startup/logon scripts |
| Remove GPO links | Unlink malicious GPOs |
| Delete created GPOs | Remove GPOs created during engagement |
| Restore ACLs | Revert DACL modifications |
| Export audit log | Document all changes made for engagement report |

## Implementation Plan

### Phase 1: Core Infrastructure (High Priority)
1. `pkg/gpo/` package structure
2. GPO enumeration via LDAP (pKIEnrollmentService → GPO objects)
3. SYSVOL access via SMB (parse GPT files)
4. Binary SD parsing for GPO DACLs (reuse security_descriptor.go)
5. CLI entry point (`cmd/trusted/gpo.go`)

### Phase 2: Enumeration & Analysis
1. GPO listing with metadata
2. GPO link enumeration (gPLink attribute parsing)
3. WMI filter enumeration
4. Security filter enumeration
5. GPO settings parsing (Registry, Scripts, ScheduledTasks, Groups)
6. GPP password detection and decryption
7. Writable GPO detection

### Phase 3: Exploitation
1. Modify existing GPO (tasks, scripts, registry, groups)
2. Create new GPO with malicious config
3. Link/unlink GPOs
4. Security filtering manipulation
5. OU manipulation (create, move objects)

### Phase 4: Advanced Chains
1. SCF/LNK generation and deployment
2. Coercion integration (PetitPotam, PrinterBug, DFS, ShadowCoerce)
3. CoerceToTGT chain (coerce → relay → cert → PKINIT)
4. Security policy modification

### Phase 5: Cleanup & Reporting
1. GPO state backup before modification
2. Restore functionality
3. Audit logging
4. Integration with Trusted report generator

## File Structure

```
pkg/gpo/
├── gpo.go              # Core types and constants
├── ldap.go             # LDAP queries for GPO objects
├── sysvol.go           # SYSVOL file access and GPT parsing
├── acl.go              # GPO DACL parsing and permission checks
├── exploit.go          # GPO modification (tasks, scripts, registry)
├── create.go           # GPO creation
├── link.go             # GPO link manipulation
├── ou.go               # OU manipulation
├── coerce.go           # Authentication coercion (PetitPotam, etc.)
├── smb.go              # SMB operations for SCF/LNK deployment
├── gpp.go              # GPP password extraction and decryption
├── policy.go           # Security policy modifications
├── restore.go          # Cleanup and restoration
├── report.go           # GPO-specific engagement reporting
└── output.go           # Structured output types

cmd/trusted/
└── gpo.go              # CLI entry point
```

## Integration with Existing Trusted

| Module | Integration |
|--------|-------------|
| `pkg/pki/` | ESC8/ESC11 relay for CoerceToTGT chains |
| `pkg/pki/ldap.go` | LDAP connection and authentication |
| `pkg/pki/kerberos.go` | Kerberos auth for SYSVOL access |
| `pkg/pki/ntlm.go` | NTLM relay transport |
| `pkg/pki/coerce.go` | PetitPotam/PrinterBug coercion |
| `pkg/pki/security_descriptor.go` | SD/ACE/SID parsing |
| `pkg/c2/` | C2 listener for hash capture |
| `internal/mcp/` | MCP tools for agentic integration |
