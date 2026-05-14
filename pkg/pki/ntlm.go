package pki

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"
)

// NTLMTransport implements http.RoundTripper with NTLMv2 authentication.
// Supports both plaintext password and raw NT hash (pass-the-hash).
type NTLMTransport struct {
	Domain   string
	Username string
	Password string // plaintext password (used to compute NT hash)
	Hash     string // hex-encoded NT hash (16 bytes = 32 hex chars)

	Transport http.RoundTripper // underlying transport (default: http.DefaultTransport with InsecureSkipVerify)
}

func (t *NTLMTransport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}
	t.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: pen-test tool targeting internal AD CAs with self-signed certs
		},
	}
	return t.Transport
}

// RoundTrip performs NTLM HTTP authentication (negotiate/challenge/authenticate).
func (t *NTLMTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Step 1: Send initial request to provoke a 401
	resp, err := t.transport().RoundTrip(cloneRequest(req))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || !hasNTLMChallenge(resp) {
		return resp, nil
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Step 2: Send negotiate message
	negMsg := buildNegotiateMessage()
	req2 := cloneRequest(req)
	req2.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negMsg))
	resp2, err := t.transport().RoundTrip(req2)
	if err != nil {
		return nil, err
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		return resp2, nil
	}

	// Step 3: Parse challenge, build authenticate message
	challengeB64 := extractNTLMToken(resp2)
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if challengeB64 == "" {
		return nil, fmt.Errorf("ntlm: no challenge token in 401 response")
	}
	challenge, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return nil, fmt.Errorf("ntlm: decode challenge: %w", err)
	}

	authMsg, err := t.buildAuthenticateMessage(challenge)
	if err != nil {
		return nil, fmt.Errorf("ntlm: build authenticate: %w", err)
	}

	req3 := cloneRequest(req)
	req3.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authMsg))
	return t.transport().RoundTrip(req3)
}

// hasNTLMChallenge checks if the 401 response advertises NTLM or Negotiate authentication.
func hasNTLMChallenge(resp *http.Response) bool {
	for _, v := range resp.Header.Values("WWW-Authenticate") {
		upper := strings.ToUpper(v)
		if strings.HasPrefix(upper, "NTLM") || strings.HasPrefix(upper, "NEGOTIATE") {
			return true
		}
	}
	return false
}

// extractNTLMToken extracts the base64 NTLM token from the WWW-Authenticate header.
// Checks for both "NTLM" and "Negotiate" schemes (many IIS/AD endpoints use Negotiate).
func extractNTLMToken(resp *http.Response) string {
	for _, v := range resp.Header.Values("WWW-Authenticate") {
		upper := strings.ToUpper(v)
		if strings.HasPrefix(upper, "NTLM ") {
			return strings.TrimSpace(v[5:])
		}
		if strings.HasPrefix(upper, "NEGOTIATE ") {
			return strings.TrimSpace(v[10:])
		}
	}
	return ""
}

// cloneRequest creates a shallow clone of the request, re-reading the body
// via GetBody if available.
func cloneRequest(req *http.Request) *http.Request {
	r2 := req.Clone(req.Context())
	if req.Body != nil && req.GetBody != nil {
		r2.Body, _ = req.GetBody()
	}
	return r2
}

// buildNegotiateMessage creates an NTLM Type 1 (Negotiate) message.
func buildNegotiateMessage() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 0x00000001)  // Type 1
	binary.LittleEndian.PutUint32(msg[12:16], 0xa0088207) // Flags: NEGOTIATE_56|128|NTLM|UNICODE|REQUEST_TARGET
	// DomainNameFields (8 bytes zero) and WorkstationFields (8 bytes zero) already zero
	return msg
}

// buildAuthenticateMessage parses a Type 2 challenge and constructs a Type 3
// Authenticate message using NTLMv2.
func (t *NTLMTransport) buildAuthenticateMessage(challenge []byte) ([]byte, error) {
	if len(challenge) < 32 {
		return nil, fmt.Errorf("challenge too short: %d bytes", len(challenge))
	}

	// Verify signature
	if string(challenge[0:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLM signature")
	}
	if binary.LittleEndian.Uint32(challenge[8:12]) != 2 {
		return nil, fmt.Errorf("not a Type 2 message")
	}

	// Extract server challenge (8 bytes at offset 24)
	serverChallenge := challenge[24:32]

	// Extract target info (TargetInfoFields at offset 40: Len=2, MaxLen=2, Offset=4 → need 48 bytes minimum)
	var targetInfo []byte
	if len(challenge) >= 48 {
		tiLen := binary.LittleEndian.Uint16(challenge[40:42])
		tiOff := binary.LittleEndian.Uint32(challenge[44:48])
		if tiOff > 0 && tiLen > 0 && int(tiOff) <= len(challenge) && int(tiOff)+int(tiLen) <= len(challenge) {
			targetInfo = challenge[tiOff : tiOff+uint32(tiLen)]
		}
	}

	// Compute NT hash
	ntHash, err := t.getNTHash()
	if err != nil {
		return nil, err
	}

	// Compute NTLMv2 hash: HMAC_MD5(ntHash, UTF16LE(UPPER(username) + domain))
	identity := utf16LEEncode(strings.ToUpper(t.Username) + t.Domain)
	ntlmv2Hash := hmacMD5(ntHash, identity)

	// Build client challenge (8 random bytes)
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, fmt.Errorf("generate client challenge: %w", err)
	}

	// Build blob
	timestamp := filetime(time.Now())
	blob := make([]byte, 0, 28+len(targetInfo)+4)
	blob = append(blob, 0x01, 0x01, 0x00, 0x00) // BlobSignature
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // Reserved
	blob = append(blob, timestamp...)           // TimeStamp (8 bytes)
	blob = append(blob, clientChallenge...)     // ClientChallenge (8 bytes)
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // Reserved
	blob = append(blob, targetInfo...)          // TargetInfo
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // End padding

	// Compute NTProofStr = HMAC_MD5(ntlmv2Hash, serverChallenge + blob)
	temp := make([]byte, 0, len(serverChallenge)+len(blob))
	temp = append(temp, serverChallenge...)
	temp = append(temp, blob...)
	ntProofStr := hmacMD5(ntlmv2Hash, temp)

	// NtChallengeResponse = ntProofStr + blob
	ntResponse := append(ntProofStr, blob...)

	// LMv2 response = HMAC_MD5(ntlmv2Hash, serverChallenge + clientChallenge) + clientChallenge
	lmHash := hmacMD5(ntlmv2Hash, append(serverChallenge, clientChallenge...))
	lmResponse := append(lmHash, clientChallenge...)

	// Build Type 3 message
	domainUTF16 := utf16LEEncode(t.Domain)
	userUTF16 := utf16LEEncode(t.Username)
	workstationUTF16 := utf16LEEncode("")

	// Field layout: fixed header (88 bytes) + LmResponse + NtResponse + Domain + User + Workstation
	headerLen := uint32(88)
	offset := headerLen

	lmOff := offset
	offset += uint32(len(lmResponse))
	ntOff := offset
	offset += uint32(len(ntResponse))
	domOff := offset
	offset += uint32(len(domainUTF16))
	userOff := offset
	offset += uint32(len(userUTF16))
	wsOff := offset
	offset += uint32(len(workstationUTF16))
	sessOff := offset
	// EncryptedRandomSessionKey: empty
	sessLen := uint16(0)

	msg := make([]byte, headerLen)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 0x00000003) // Type 3

	// LmChallengeResponseFields
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint32(msg[16:20], lmOff)

	// NtChallengeResponseFields
	binary.LittleEndian.PutUint16(msg[20:22], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint16(msg[22:24], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint32(msg[24:28], ntOff)

	// DomainNameFields
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint32(msg[32:36], domOff)

	// UserNameFields
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint32(msg[40:44], userOff)

	// WorkstationFields
	binary.LittleEndian.PutUint16(msg[44:46], uint16(len(workstationUTF16)))
	binary.LittleEndian.PutUint16(msg[46:48], uint16(len(workstationUTF16)))
	binary.LittleEndian.PutUint32(msg[48:52], wsOff)

	// EncryptedRandomSessionKeyFields
	binary.LittleEndian.PutUint16(msg[52:54], sessLen)
	binary.LittleEndian.PutUint16(msg[54:56], sessLen)
	binary.LittleEndian.PutUint32(msg[56:60], sessOff)

	// NegotiateFlags
	binary.LittleEndian.PutUint32(msg[60:64], 0xa0088207)

	// MIC (16 bytes zero) at offset 72-88 — already zero
	// Version (8 bytes) at offset 64-72 — leave zero

	// Append payload fields
	msg = append(msg, lmResponse...)
	msg = append(msg, ntResponse...)
	msg = append(msg, domainUTF16...)
	msg = append(msg, userUTF16...)
	msg = append(msg, workstationUTF16...)

	return msg, nil
}

// getNTHash returns the 16-byte NT hash, either from the hex-encoded Hash field
// or computed from the plaintext Password via MD4(UTF16LE(password)).
func (t *NTLMTransport) getNTHash() ([]byte, error) {
	if t.Hash != "" {
		h, err := hex.DecodeString(t.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode NT hash: %w", err)
		}
		if len(h) != 16 {
			return nil, fmt.Errorf("NT hash must be 16 bytes (32 hex chars), got %d", len(h))
		}
		return h, nil
	}
	if t.Password != "" {
		return ntHashFromPassword(t.Password), nil
	}
	return nil, fmt.Errorf("no password or hash provided for NTLM auth")
}

// ntHashFromPassword computes MD4(UTF16LE(password)).
func ntHashFromPassword(password string) []byte {
	encoded := utf16LEEncode(password)
	sum := md4Sum(encoded)
	return sum[:]
}

// utf16LEEncode encodes a string to UTF-16LE bytes.
func utf16LEEncode(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// hmacMD5 computes HMAC-MD5.
func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// filetime converts a time.Time to a Windows FILETIME (100-nanosecond intervals
// since January 1, 1601).
func filetime(t time.Time) []byte {
	// Epoch difference: 1601-01-01 to 1970-01-01 = 116444736000000000 100ns intervals
	const epochDiff = 116444736000000000
	ft := uint64(t.UnixNano()/100) + epochDiff
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ft)
	return b
}

// md4Sum computes the MD4 hash of the input per RFC 1320.
func md4Sum(data []byte) [16]byte {
	// Padding
	origLen := len(data)
	bitLen := uint64(origLen) * 8

	// Append 0x80
	data = append(data, 0x80)
	// Pad to 56 mod 64
	for len(data)%64 != 56 {
		data = append(data, 0x00)
	}
	// Append original length in bits as 64-bit LE
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], bitLen)
	data = append(data, lenBuf[:]...)

	// Initial hash values
	a0 := uint32(0x67452301)
	b0 := uint32(0xefcdab89)
	c0 := uint32(0x98badcfe)
	d0 := uint32(0x10325476)

	// Auxiliary functions
	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	rotl := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

	// Process each 64-byte block
	for i := 0; i < len(data); i += 64 {
		block := data[i : i+64]
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(block[j*4:])
		}

		a, b, c, d := a0, b0, c0, d0

		// Round 1
		for _, r := range []struct {
			k int
			s uint
		}{
			{0, 3}, {1, 7}, {2, 11}, {3, 19},
			{4, 3}, {5, 7}, {6, 11}, {7, 19},
			{8, 3}, {9, 7}, {10, 11}, {11, 19},
			{12, 3}, {13, 7}, {14, 11}, {15, 19},
		} {
			a = rotl(a+f(b, c, d)+x[r.k], r.s)
			a, b, c, d = d, a, b, c
		}

		// Round 2
		for _, r := range []struct {
			k int
			s uint
		}{
			{0, 3}, {4, 5}, {8, 9}, {12, 13},
			{1, 3}, {5, 5}, {9, 9}, {13, 13},
			{2, 3}, {6, 5}, {10, 9}, {14, 13},
			{3, 3}, {7, 5}, {11, 9}, {15, 13},
		} {
			a = rotl(a+g(b, c, d)+x[r.k]+0x5a827999, r.s)
			a, b, c, d = d, a, b, c
		}

		// Round 3
		for _, r := range []struct {
			k int
			s uint
		}{
			{0, 3}, {8, 9}, {4, 11}, {12, 15},
			{2, 3}, {10, 9}, {6, 11}, {14, 15},
			{1, 3}, {9, 9}, {5, 11}, {13, 15},
			{3, 3}, {11, 9}, {7, 11}, {15, 15},
		} {
			a = rotl(a+h(b, c, d)+x[r.k]+0x6ed9eba1, r.s)
			a, b, c, d = d, a, b, c
		}

		a0 += a
		b0 += b
		c0 += c
		d0 += d
	}

	var digest [16]byte
	binary.LittleEndian.PutUint32(digest[0:], a0)
	binary.LittleEndian.PutUint32(digest[4:], b0)
	binary.LittleEndian.PutUint32(digest[8:], c0)
	binary.LittleEndian.PutUint32(digest[12:], d0)
	return digest
}
