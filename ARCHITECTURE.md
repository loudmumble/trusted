# Trusted Architecture

Trusted is a production-grade PKI exploitation and ADCS orchestration framework.

## Core Design

1. **Automation First**: Standardized JSON output for all commands to support pipeline integration.
2. **Library-Driven**: Core logic is contained in `pkg/pki` for reuse.
3. **Safety-Minded**: Validates credentials and checks for existing entries before modification.
4. **Comprehensive**: Covers ESC1 through ESC14, Shadow Credentials, and Remote Certificate Theft.

## Project Structure

- `cmd/trusted/`: CLI entry points.
  - `pki.go`: Main ADCS attack suite.
  - `shadow.go`: Shadow Credentials management.
  - `autopwn.go`: High-level orchestration loop.
- `pkg/pki/`: Reusable Go packages.
  - `adcs.go`: Template enumeration and parsing.
  - `exploit_*.go`: ESC-specific exploitation logic.
  - `shadow_credentials.go`: TLV blob generation and LDAP modification.
  - `crypto.go`: Key generation and PEM/PFX handling.
  - `relay.go`: Built-in NTLM relay server for ESC8/11.

## Key Subsystems

### 1. Enumeration Engine
- Connects to LDAP/LDAPS.
- Parses `nTSecurityDescriptor` on CA objects and certificate templates.
- Calculates an "ESC Score" to prioritize vulnerable paths.

### 2. Exploitation Engine
- Handles certificate request generation (CSR).
- Communicates with CA web enrollment and RPC interfaces.
- Manages PFX creation with proper EKU extensions.

### 3. Shadow Credentials
- Implements MS-ADTS 2.2.14 TLV formatting.
- Generates ECDSA P256 keypairs.
- Performs atomic LDAP modifications to `msDS-KeyCredentialLink`.

### 4. AutoPwn Orchestrator
- Correlates enumeration findings into executable attack plans.
- Supports interactive confirmation or fully autonomous execution.
- Integrates with external tools (Certipy, Rubeus) for final authentication.

## Data Flow

1. **Discovery**: `auto` command enumerates ADCS environment.
2. **Analysis**:findings are ranked by severity and ease of exploit.
3. **Execution**: Selected ESC exploits are triggered via `pkg/pki`.
4. **Persistence**: Recovered certificates and keys are saved to the output directory.
5. **Reporting**: Findings are synthesized into a structured engagement report.
