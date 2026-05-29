# Trusted Architecture

ADCS exploitation and PKI attack framework with integrated cert-auth C2. Pure Go, CGO-free.

## Core Design

1. **Pure Go**: Zero CGO dependencies — cross-compiles to any platform.
2. **Library-Driven**: Core logic in `pkg/` packages, CLI is a thin wrapper.
3. **Safety-Minded**: Validates credentials, checks existing entries, auto-restores modifications.
4. **Comprehensive**: ESC1–ESC14, GPO attacks, delegation abuse, C2 with cert-auth persistence.

## Project Structure

```
cmd/trusted/          CLI entry points (cobra commands)
  main.go                Root command with `ted` alias + 14 persistent connection flags
  pki.go                 esc/enum/forge/import/report/theft commands
  autopwn.go             Auto-pwn orchestration
  shadow.go              Shadow credentials CLI (add/list/rm)
  c2.go                  C2 listener, stager/implant generation, deploy
  agent.go               Polling agent entry point
  gpo.go                 GPO attack toolkit (enum/exploit/create/link/coerce/tgt/scf/lnk/policy/backup/restore/bloodhound)
  deleg.go               Delegation attack framework (enum/constrained/unconstrained/rbcd/create/delete/set/remove)
  mcp_cmd.go             MCP stdio server
  deploy.go              runDeploy helper (shared with c2.go)
  console.go             runConsole helper (shared with c2.go)

pkg/pki/               ADCS/PKI core logic
  template.go            Certificate template enumeration and parsing
  ca.go                  CA enumeration, flag parsing, flag modification
  output.go              EnumerationResult struct, EnumerateAll aggregator
  ldap.go                LDAP connection (plain/LDAPS/StartTLS), GSSAPI/NTLM/simple bind, credential validation
  kerberos.go            Kerberos client setup (ccache/keytab/password), SPNEGO, GSSAPI bind
  ntlm.go                NTLMv2 HTTP RoundTripper with pass-the-hash (inline MD4)
  enroll.go              Certificate enrollment via CA web endpoint (/certsrv/) with NTLM/Kerberos auth
  rpc_enroll.go          Certificate enrollment via ICertPassage RPC over SMB
  forge.go               Golden certificate forging (self-signed or CA-key signed), PEM/PFX export
  pkinit.go              PKINIT authentication (RFC 4556 DH mode, CMS SignedData, AS-REQ/REP, ccache output)
  unpac.go               UnPAC-the-hash (U2U TGS-REQ, PAC_CREDENTIAL_INFO decryption, NT hash extraction)
  esc1.go                ESC1 — misconfigured templates (enrollee supplies subject + auth EKU)
  esc2.go                ESC2 — any purpose EKU templates
  esc3.go                ESC3 — enrollment agent templates (two-stage CMC co-signed enrollment)
  esc4.go                ESC4 — vulnerable template ACLs (binary ACE parsing, WriteDACL/WriteOwner, LDAP modify + restore)
  esc6.go                ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 (SAN injection)
  esc7.go                ESC7 — vulnerable CA ACLs (ManageCA → enable ESC6 → enroll → restore)
  esc9.go                ESC9 — CT_FLAG_NO_SECURITY_EXTENSION (UPN swap + restore)
  esc10.go               ESC10 — weak certificate mapping detection
  esc13.go               ESC13 — OID group link abuse
  esc14.go               ESC14 — weak explicit mappings via altSecurityIdentities
  esc_relay.go           ESC8/ESC11/ESC12 relay scanning (HTTP probe, RPC flag check, DCOM probe)
  relay.go               Built-in HTTP-to-HTTP NTLM relay server for ESC8
  smb_relay.go           Native SMB NTLM TCP relay (ESC11/ESC12, no external deps)
  coerce.go              PetitPotam MS-EFSRPC + PrinterBug MS-RPRN coercion
  smb.go                 Native SMB2 session setup (negotiate, auth, tree connect, file ops)
  smb_helpers.go         SMB/RPC binary protocol helpers
  smbexec.go             Remote command execution via SMB service creation
  shadow_credentials.go  msDS-KeyCredentialLink add/list/remove, TLV blob generation
  security_descriptor.go Binary SD/ACE/SID parsing for ESC4/ESC5 ACL analysis
  chain.go               Attack path analysis and prioritization
  autopwn.go             Auto-pwn engine (enumerate → prioritize → exploit → PKINIT → UnPAC)
  report.go              Markdown engagement report generation
  certtheft.go           THEFT1–THEFT5 playbook (local guidance + THEFT4 LDAP extraction)
  pfx.go                 PFX import/export

pkg/gpo/               GPO attack toolkit
  gpo.go                 GPO types, constants, parsing helpers
  ldap.go                LDAP discovery, GPO/OU CRUD, ACL query, link manipulation
  exploit.go             GPO modification (tasks, scripts, restricted groups, user rights, registry, services, files)
  acl.go                 Binary ACE/SID parsing and write-permission analysis
  sysvol.go              GPT.INI parsing, GPP template discovery, GPP password decryption
  smb.go                 SCF/LNK generation, SMB file system operations
  policy.go              Security policy modification (password, firewall, Defender, UAC, ETW)
  bloodhound.go          BloodHound JSON export, GPO-BH correlation, attack path analysis
  restore.go             GPO backup, restore, cleanup, audit log export

pkg/delegation/        Delegation attack framework
  delegation.go          Delegation types, UAC flag parsing, SID encoding, report generation
  ldap.go                LDAP delegation enumeration, attribute manipulation, machine account CRUD
  s4u.go                 S4U2Self/S4U2Proxy implementation (Kerberos S4U extensions)

pkg/c2/                C2 framework
  listener.go            HTTP/HTTPS C2 listener with session management, auto-TLS, mTLS support
  agent.go               Polling agent with mTLS, file delivery, 10MB output cap
  deploy.go              File delivery endpoints (upload + deploy)
  certauth.go            Cert-auth implant generation (CA + client certs, mTLS config)

pkg/util/              Shared utilities
  util.go                Domain DN building, username normalization, input validation

internal/mcp/          MCP integration
  server.go              MCP JSON-RPC stdio server (5 tools: pki_enumerate, pki_forge, c2_list_sessions, c2_queue_command, c2_get_results)

internal/tui/          Operator console
  app.go                 Bubbletea TUI with live C2 polling, 5 views (sessions, commands, results, health, deploy)

implants/smartpotato/  Windows privilege escalation (separate Go module)
  main.go                Entry point with technique selection
  potato_windows.go      JuicyPotato (BITS COM), SweetPotato (PrintSpoofer), RoguePotato (DCOM OXID)
  potato_other.go        Cross-platform stubs for non-Windows builds
```

## Key Subsystems

### 1. Authentication Layer (`pkg/pki/ldap.go`, `kerberos.go`, `ntlm.go`)
- LDAP connections with plain/LDAPS/StartTLS support
- Three auth methods: simple bind, NTLM pass-the-hash, Kerberos GSSAPI
- Kerberos: ccache, keytab, or password-based TGT acquisition
- NTLM: built-in NTLMv2 with inline MD4 (no external crypto deps)
- Credential validation before any operation

### 2. Enumeration Engine (`pkg/pki/template.go`, `ca.go`, `output.go`)
- LDAP-based template and CA discovery
- Binary security descriptor parsing (SD → DACL → ACE → SID)
- ESC scoring: ranks templates by exploitability (EKU flags, enrollment rights, manager rights)
- Aggregated `EnumerationResult` with all findings

### 3. Exploitation Engine (`pkg/pki/esc1.go`–`esc14.go`)
- ESC1–ESC3, ESC4, ESC6–ESC7, ESC9, ESC13–ESC14: full exploitation with certificate enrollment
- ESC4/ESC7/ESC9: auto-restore of LDAP modifications after exploitation
- ESC5, ESC10, ESC11, ESC12: detection-only (scan + guidance)
- ESC8: built-in HTTP-to-HTTP NTLM relay + PetitPotam/PrinterBug coercion
- ESC3: two-stage CMC co-signed enrollment via RPC (ICertPassage)
- Certificate enrollment via HTTP web endpoint (`/certsrv/`) or RPC (`\\pipe\\cert`)

### 4. PKINIT + UnPAC (`pkg/pki/pkinit.go`, `unpac.go`)
- Real RFC 4556 DH key exchange with CMS SignedData signing
- Full AS-REQ/AS-REP handling with KDC error parsing
- ccache file output compatible with MIT Kerberos
- UnPAC-the-hash: U2U TGS-REQ → PAC_CREDENTIAL_INFO → NT hash extraction

### 5. AutoPwn Orchestrator (`pkg/pki/autopwn.go`)
- Enumerate → build priority-sorted candidate list → exploit → PKINIT → UnPAC
- Interactive mode (prompt per path) or fully autonomous
- Dry-run mode for planning without exploitation
- Chains: ESC exploit → certificate → PKINIT → TGT → UnPAC → NT hash

### 6. GPO Attack Framework (`pkg/gpo/`)
- LDAP-based GPO discovery, ACL analysis, link enumeration
- GPO modification: scheduled tasks, scripts, restricted groups, user rights, registry, services, files
- GPO creation, linking to OUs/sites/domains
- SCF/LNK file deployment for NTLM hash capture
- Security policy modification (password, firewall, Defender, UAC, ETW)
- GPP password extraction from SYSVOL
- BloodHound JSON export/import with GPO correlation
- Backup, restore, and cleanup with audit logging
- CoerceToTGT chain: coerce → relay → cert → PKINIT → TGT

### 7. Delegation Framework (`pkg/delegation/`)
- Enumeration: unconstrained, constrained, resource-based constrained delegation
- S4U2Self/S4U2Proxy for constrained delegation exploitation
- Machine account lifecycle: create, delete, set password
- RBCD: set/remove `msDS-AllowedToActOnBehalfOfOtherIdentity`

### 8. C2 Framework (`pkg/c2/`)
- HTTP/HTTPS listeners with auto-generated TLS certificates
- Session management: registration, polling, command queue, result collection
- Certificate persistence: cert-auth implants via forged certificates (Schannel mTLS)
- Polling agent: cross-platform, mTLS support, signal-aware shutdown, 10MB output cap
- File delivery: upload and deploy binaries with optional execution
- Operator API: RESTful endpoints for session/command/result management

### 9. MCP Server (`internal/mcp/`)
- JSON-RPC over stdio for agentic integration
- 5 tools: `pki_enumerate`, `pki_forge`, `c2_list_sessions`, `c2_queue_command`, `c2_get_results`
- Stateless design — PKI tools work independently, C2 tools require active listener

## Data Flow

### ADCS Exploitation
1. **Discovery**: `enum` or `auto` enumerates templates, CAs, and ACLs via LDAP
2. **Analysis**: Findings scored and ranked by exploitability
3. **Exploitation**: ESC exploit modifies LDAP (if needed) → enrolls certificate → restores
4. **Authentication**: PKINIT with certificate → TGT → UnPAC → NT hash
5. **Output**: Certificates (PEM/PFX), ccache files, engagement report

### GPO Attack
1. **Discovery**: LDAP enumeration of GPOs, links, ACLs, GPP passwords
2. **Modification**: Write malicious XML/scripts to SYSVOL via SMB
3. **Persistence**: GPO auto-applies on next `gpupdate` cycle
4. **Coercion**: PetitPotam/PrinterBug forces NTLM auth for relay chains

### C2 Operation
1. **Setup**: Start HTTPS listener with auto-TLS or custom certs
2. **Implant**: Generate cert-auth implant config with mTLS client certificate
3. **Agent**: Polling agent checks in, receives commands, returns results
4. **Deploy**: Upload and execute payloads on active sessions
