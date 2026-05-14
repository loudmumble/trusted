# Ralph Progress Log

Started: 2026-04-03
Task: Verify all trusted follow-up command and key generation fixes

## Codebase Patterns

- Pure Go, CGO_ENABLED=0 — no cgo dependencies
- PKI exploit functions return (cert, key, error) where key is crypto.Signer
- Follow-up commands printed by individual ESC exploit functions AND pkinit.go/unpac.go
- Autopwn orchestrates enumeration → candidate scoring → exploitation loop
- C2 and shadow credentials use ECDSA intentionally (not for AD auth)

## Key Files

- `pkg/pki/enroll.go` — Certificate enrollment, key generation, CSR
- `pkg/pki/adcs.go` — ForgeCertificate, WriteCertKeyPEM, WritePFX, ExploitESC1/4
- `pkg/pki/autopwn.go` — AutoPwn orchestration, candidate building
- `pkg/pki/pkinit.go` — PKINIT follow-up command output
- `pkg/pki/unpac.go` — UnPAC-the-hash follow-up command output
- `pkg/pki/esc{2,3,6,7,9,13}.go` — Individual ESC exploit functions
- `cmd/trusted/pki.go` — CLI command handler for --esc and enum output
- `cmd/trusted/autopwn.go` — CLI command handler for auto

---

## 2026-04-03 - Initial Session

### Changes Applied

1. **RSA 2048 keys** — switched all PKI exploit paths from ECDSA P256 to RSA 2048
2. **crypto.Signer** — all exploit function return types changed from *ecdsa.PrivateKey
3. **certipy-ad** — all follow-up commands now use certipy-ad (not certipy)
4. **PKINITtools** — replaced getTGT.py -pfx with gettgtpkinit.py -cert-pfx
5. **DC_IP placeholder** — all -dc-ip args use <DC_IP> placeholder (not hostname)
6. **Duplicate output** — removed second PKINIT/UnPAC print from cmd handler
7. **Self-signed skip** — autopwn skips self-signed certs, tries next candidate
8. **Interactive selection** — added -i flag for path selection in autopwn
9. **ESC12 fix** — enum now shows ntlmrelayx command instead of trusted

---

## Iteration 1 — V-001 Verified ✓

All 9 acceptance criteria confirmed:
- RSA 2048 in enroll.go (line 72), ForgeCertificate (line 638), ForgeGoldenCertificate (line 768)
- No ecdsa.GenerateKey in PKI paths (enroll.go, adcs.go, mcp/server.go)
- C2 + shadow_credentials correctly retain ECDSA
- WriteCertKeyPEM uses MarshalPKCS8PrivateKey with "PRIVATE KEY" PEM type
- All 8 ExploitESC* functions return crypto.Signer
- TestPFX_RoundTrip asserts *rsa.PrivateKey
- Build + tests pass

## Iteration 2 — V-002 Verified ✓

All 7 acceptance criteria confirmed:
- No bare `certipy auth`/`certipy relay`/`certipy cert` commands in any .go file
- pkinit.go uses certipy-ad throughout (lines 31-32, 42-43, 75-77, 89-90)
- unpac.go uses certipy-ad (lines 20-21)
- All ESC exploit files (esc2, esc3, esc6, esc7, esc9, esc13, adcs.go) use certipy-ad in next steps
- pki.go scan-only handlers use certipy-ad for ESC8 (line 639), ESC11 (line 720), ESC12 (line 658)
- shadow_credentials.go uses certipy-ad (line 161)
- GeneratePKINITScript uses certipy-ad (lines 75-77, 89-90)
- Two generic "certipy" references in adcs.go comments (lines 495, 530) are documentation, not commands
- Build + tests pass

## Iteration 3 — V-003 Verified ✓

All 4 acceptance criteria confirmed:
- No `getTGT.py -pfx` anywhere in .go files (zero matches)
- pkinit.go uses `gettgtpkinit.py -cert-pfx` (lines 37-38, 81-83)
- PKINIT script uses gettgtpkinit.py not getTGT.py (lines 81-83, 89)
- secretsdump.py uses `-dc-ip <DC_IP>` and domain (line 48: `%s/%s@%s` with domain)
- unpac.go also correctly uses gettgtpkinit.py (line 29)
- Build + tests pass

## Iteration 4 — V-004 Verified ✓

All 3 acceptance criteria confirmed:
- pkg/pki/autopwn.go prints PKINIT commands in two mutually exclusive paths: dry-run (line 111) and success (line 167)
- pkg/pki/autopwn.go prints UnPAC commands once on success path only (line 176)
- cmd/trusted/autopwn.go does NOT call PrintPKINITCommands or PrintUnPACCommands (line 70 comment confirms)
- Output appears exactly once per execution path — no duplication
- Build + tests pass

## Iteration 5 — V-005 Verified ✓

All 4 acceptance criteria confirmed:
- IsSelfSigned function exists in enroll.go (line 161), checks Issuer.CommonName == Subject.CommonName
- autopwn.go checks IsSelfSigned(cert) after executeExploit (line 152)
- Self-signed certs print skipping message and `continue` to next candidate (lines 153-155)
- Only CA-signed certs reach AutoPwn SUCCESS (line 166), after passing self-signed guard
- Build + tests pass

## Iteration 6 — V-006 Verified ✓

All 4 acceptance criteria confirmed:
- AutoPwnConfig has `Interactive bool` field (autopwn.go:22)
- promptPathSelection function exists (autopwn.go:338)
- cmd/trusted/autopwn.go registers `--interactive` / `-i` flag via BoolP (line 87)
- Flag value read at line 31, passed to AutoPwnConfig at line 58
- Interactive mode gated behind `cfg.Interactive && !cfg.DryRun` (line 85)
- Build + tests pass

## Iteration 7 — V-007 Verified + Fixed ✓

Both acceptance criteria confirmed:
- pki.go ESC12 enum output (line 315) uses `ntlmrelayx.py -t dcom://` — correct
- pki.go case '12' handler (line 653) uses `ntlmrelayx.py -t dcom://` — correct
- Found and fixed chain.go ESC12 attack chain steps (line 196): was still using `trusted pki --esc 12`, changed to `ntlmrelayx.py -t dcom://`
- Build + tests pass

## Iteration 8 — V-008 Verified ✓

All 3 acceptance criteria confirmed:
- `CGO_ENABLED=0 go build -o /dev/null ./cmd/trusted` succeeds with no output (clean build)
- `CGO_ENABLED=0 go test ./...` passes all 4 test packages (mcp, tui, c2, pki)
- No compilation warnings or errors
- All 8 verification tasks now pass — loop complete

## Iteration 9 — V-009 Verified ✓

All 6 acceptance criteria confirmed:
- ICertPassage interface UUID exists in rpc_enroll.go (line 15, UUID 91ae6020-9e3c-11cf-8d7c-00aa00c091be)
- SMB named pipe connection to `\pipe\cert` implemented (rpc_enroll.go:60-63, via smbSession from coerce.go)
- RPC enrollment calls CertServerRequest opnum 0 (rpc_enroll.go:74-75)
- Auto-detection: tries RPC first, falls back to HTTP web enrollment (enroll.go:129-139)
- Build passes with CGO_ENABLED=0
- Tests added in rpc_enroll_test.go covering: UUID, NDR stub building, CertTransBlob round-trip, UTF-16LE decode, security buffer extraction, RPC data extraction, PKCS7 cert extraction, interface smoke test

## Iteration 10 — V-010 Verified ✓

All 6 acceptance criteria confirmed:
- Web enrollment passes UPN SAN via CertAttrib, not CSR: when sanInject=true, csrUPN="" (enroll.go:79-80), UPN omitted from CSR
- CertAttrib includes `SAN:upn=<UPN>` (enroll.go:146), appended to certAttrib (enroll.go:216-218), sent in form data (enroll.go:224)
- ESC6 calls EnrollCertificate with sanInject=true (esc6.go:113) — SAN injection works
- ESC7 also calls with sanInject=true (esc7.go:233) — same path
- ESC1 calls with sanInject=false (adcs.go:409) — no regression, UPN stays in CSR
- ESC2/3/9/13 all call with sanInject=false — no regression
- Build passes with CGO_ENABLED=0
- All tests pass

## Iteration 11 — V-011 Verified ✓

All 4 acceptance criteria confirmed:
- Exploit ESCs (1-4,6,7,9,13) share common handler (pki.go:753-805) writing .crt/.key/.pfx and output references exactly those extensions (pki.go:800)
- Scan-only ESCs (5,8,10,11,12,14) print appropriate next-step commands; relay ESCs (8,12) use `<cert.pfx>` placeholder for post-relay auth — correct since file doesn't exist yet
- PKINIT commands (pkinit.go:32) use actual PFXPath passed from handler, not hardcoded names
- No `.pem` extension references in user-facing output (WriteCertKeyPEM writes .crt/.key despite the function name)
- Follow-up commands are consistent: all use certipy-ad auth -pfx with correct path
- Build + tests pass

## Iteration 12 — V-012 Fixed ✓

Fix applied:
- pkinit.go:42 had wrong certipy-ad cert syntax: `certipy-ad cert -pfx -cert ... -key ... -out ...`
- Replaced with `openssl pkcs12 -export -in <cert> -inkey <key> -out <pfx> -passout pass:`
- openssl is more universally available and has stable syntax
- This is in the fallback branch where PFX doesn't exist but cert+key files do
- Build + tests pass

## Iteration 13 — V-013 Fixed ✓

Fixed Rubeus /user: to use sAMAccountName instead of full UPN in two locations:
- unpac.go:25 — changed `upn` to `user` (already stripped at line 12-15)
- cmd/trusted/pki.go:804 — added sAMAccountName extraction (strip @domain) before Rubeus command
- pkinit.go:35 was already correct (uses `user` variable)
- All three Rubeus commands now consistently use sAMAccountName format
- Build + tests pass

## Iteration 14 — V-014 Fixed ✓

Fixed chain.go ESC11/ESC12 ntlmrelayx commands to use `<CA_NAME>` placeholder instead of `tmpl.Name`:
- chain.go:188 (ESC11): `-icpr-ca-name` was using `tmpl.Name` (template name) — changed to `<CA_NAME>` placeholder
- chain.go:196 (ESC12): `-icpr-ca-name` was using `tmpl.Name` — changed to `<CA_NAME>` placeholder
- CA name is not available in `buildSteps()` context (it lives in ESC11Finding/ESC12Finding, not CertTemplate or ADCSConfig)
- Placeholder approach consistent with ESC7 which already uses `<CA_NAME>` pattern
- autopwn.go:262 was already correct — uses `f.CAName` from ESC11Finding
- `-dcom-mode ICPR` flag kept as-is — matches pki.go:315 (verified correct in prior iteration)
- Build + tests pass

## Iteration 15 — V-015 Verified ✓

All 4 acceptance criteria confirmed:
- `CGO_ENABLED=0 go build -o /dev/null ./cmd/trusted` succeeds with no output (clean build)
- `CGO_ENABLED=0 go test ./...` passes all 4 test packages (mcp, tui, c2, pki)
- No compilation warnings or errors
- `go vet ./...` passes clean (no output)
- All 15 verification tasks (V-001 through V-015) now pass — RC verification loop complete
