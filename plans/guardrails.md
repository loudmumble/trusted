# Ralph Guardrails (Signs)

Learned constraints that prevent repeated failures.

> "Progress should persist. Failures should evaporate." - The Ralph philosophy

---

## Verification Signs

### SIGN-001: Verify Before Complete
**Trigger:** About to output completion promise
**Instruction:** ALWAYS run `CGO_ENABLED=0 go build -o /dev/null ./cmd/trusted && CGO_ENABLED=0 go test ./...` and confirm it passes before outputting `<promise>COMPLETE</promise>`
**Reason:** Build or test failures invalidate all work

### SIGN-002: Check All Tasks Before Complete
**Trigger:** Completing a task in multi-task mode
**Instruction:** Re-read prd.json and count remaining `passes: false` tasks. Only output completion promise when ALL tasks pass, not just the current one.
**Reason:** Premature completion exits loop with work remaining

---

## Progress Signs

### SIGN-003: Document Learnings
**Trigger:** Completing any task
**Instruction:** Update progress.md with what was learned before ending iteration
**Reason:** Future iterations need context

### SIGN-004: Small Focused Changes
**Trigger:** Making changes per iteration
**Instruction:** Keep changes small and focused. These are VERIFICATION tasks — don't change code unless a check fails.
**Reason:** The code changes are already done. Only fix if verification reveals an issue.

---

## Project-Specific Signs

### SIGN-007: Don't Touch C2 or Shadow Credentials ECDSA
**Trigger:** Checking for ECDSA usage
**Instruction:** ECDSA is CORRECT in pkg/c2/ and pkg/pki/shadow_credentials.go. Only PKI exploit paths should use RSA.
**Reason:** C2 uses ECDSA for TLS, shadow creds use ECDSA for NGC keys. Neither needs AD tool compatibility.

### SIGN-008: Grep Patterns Must Be Precise
**Trigger:** Searching for certipy without -ad
**Instruction:** Use pattern `"certipy [^-]` or `certipy auth` to find bare certipy. Don't match certipy-ad as a false positive.
**Reason:** Imprecise grep creates false failures

### SIGN-009: Verification Tasks Are Read-Only
**Trigger:** Starting a verification task
**Instruction:** These tasks verify that existing code changes are correct. Read and grep files to confirm. Do NOT modify code unless verification reveals it's wrong.
**Reason:** Code was already changed. The Ralph loop verifies it.
