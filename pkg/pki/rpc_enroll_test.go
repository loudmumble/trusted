package pki

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestICertPassageUUID(t *testing.T) {
	// MS-ICPR interface UUID: 91ae6020-9e3c-11cf-8d7c-00aa00c091be
	// Verify the byte-level encoding matches the canonical UUID.
	expected := [16]byte{
		0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11,
		0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe,
	}
	if icertPassageUUID != expected {
		t.Fatalf("ICertPassage UUID mismatch: got %x, want %x", icertPassageUUID, expected)
	}
}

func TestBuildCertServerRequestStub(t *testing.T) {
	caName := "TestCA"
	attribs := "CertificateTemplate:User"
	csrDER := []byte{0x30, 0x82, 0x01, 0x00} // minimal fake DER

	stub := buildCertServerRequestStubWithFlags(caName, attribs, csrDER, 0x00000102)
	if len(stub) == 0 {
		t.Fatal("stub is empty")
	}

	// First 4 bytes should be dwFlags = 0x00000102
	flags := binary.LittleEndian.Uint32(stub[0:4])
	if flags != 0x00000102 {
		t.Errorf("dwFlags: got 0x%08X, want 0x00000102", flags)
	}
}

func TestNdrUniqueString(t *testing.T) {
	// Empty string → null pointer (4 bytes of zeros)
	result := ndrUniqueString(nil, "")
	if len(result) != 4 {
		t.Fatalf("empty string: expected 4 bytes, got %d", len(result))
	}
	if binary.LittleEndian.Uint32(result) != 0 {
		t.Error("empty string: expected null pointer")
	}

	// Non-empty string should have referent ID, max_count, offset, actual_count, then UTF-16LE data
	result = ndrUniqueString(nil, "CA")
	if len(result) < 16 {
		t.Fatalf("non-empty string: expected at least 16 bytes, got %d", len(result))
	}
	refID := binary.LittleEndian.Uint32(result[0:4])
	if refID == 0 {
		t.Error("non-empty string: referent ID should be non-zero")
	}
	maxCount := binary.LittleEndian.Uint32(result[4:8])
	// "CA" = 2 chars + 1 null terminator = 3
	if maxCount != 3 {
		t.Errorf("max_count: got %d, want 3", maxCount)
	}
	// Result should be 4-byte aligned
	if len(result)%4 != 0 {
		t.Errorf("result not 4-byte aligned: %d bytes", len(result))
	}
}

func TestNdrCertTransBlob(t *testing.T) {
	// Empty blob
	result := ndrCertTransBlob(nil, nil)
	if len(result) < 8 {
		t.Fatalf("empty blob: expected at least 8 bytes, got %d", len(result))
	}
	cb := binary.LittleEndian.Uint32(result[0:4])
	if cb != 0 {
		t.Errorf("empty blob cb: got %d, want 0", cb)
	}

	// Non-empty blob
	data := []byte{0x01, 0x02, 0x03}
	result = ndrCertTransBlob(nil, data)
	cb = binary.LittleEndian.Uint32(result[0:4])
	if cb != 3 {
		t.Errorf("non-empty blob cb: got %d, want 3", cb)
	}
	// Should have referent ID and max count after cb
	refID := binary.LittleEndian.Uint32(result[4:8])
	if refID == 0 {
		t.Error("non-empty blob: referent ID should be non-zero")
	}
	maxCount := binary.LittleEndian.Uint32(result[8:12])
	if maxCount != 3 {
		t.Errorf("non-empty blob max_count: got %d, want 3", maxCount)
	}
	// Data bytes should follow
	if !bytes.Equal(result[12:15], data) {
		t.Errorf("blob data mismatch: got %x, want %x", result[12:15], data)
	}
	// 4-byte aligned
	if len(result)%4 != 0 {
		t.Errorf("result not 4-byte aligned: %d bytes", len(result))
	}
}

func TestReadCertTransBlob(t *testing.T) {
	// Build a blob and read it back
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	encoded := ndrCertTransBlob(nil, data)

	decoded, newOffset, err := readCertTransBlob(encoded, 0)
	if err != nil {
		t.Fatalf("readCertTransBlob: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("round-trip mismatch: got %x, want %x", decoded, data)
	}
	if newOffset == 0 {
		t.Error("offset should advance past the blob")
	}

	// Empty blob
	emptyEncoded := ndrCertTransBlob(nil, nil)
	decoded, _, err = readCertTransBlob(emptyEncoded, 0)
	if err != nil {
		t.Fatalf("readCertTransBlob empty: %v", err)
	}
	if decoded != nil {
		t.Errorf("empty blob should decode to nil, got %x", decoded)
	}

	// Too short → error
	_, _, err = readCertTransBlob([]byte{0x01}, 0)
	if err == nil {
		t.Error("expected error for truncated input")
	}
}

func TestExtractRPCFromReadResponse(t *testing.T) {
	// Build minimal SMB2 READ response
	// Header(64) + Body: StructureSize(2) + DataOffset(1) + reserved(1) + DataLength(4) + ...
	rpcPayload := []byte{0x05, 0x00, 0x02, 0x03} // DCE/RPC response header fragment
	resp := make([]byte, 96)
	resp[64+2] = 80                                                         // DataOffset
	binary.LittleEndian.PutUint32(resp[64+4:64+8], uint32(len(rpcPayload))) // DataLength
	copy(resp[80:], rpcPayload)

	result, err := extractRPCFromReadResponse(resp)
	if err != nil {
		t.Fatalf("extractRPCFromReadResponse: %v", err)
	}
	if !bytes.Equal(result, rpcPayload) {
		t.Errorf("RPC data mismatch: got %x, want %x", result, rpcPayload)
	}

	// Too short
	_, err = extractRPCFromReadResponse([]byte{0x01})
	if err == nil {
		t.Error("expected error for short response")
	}
}

func TestEnrollCertificateRPC_Interface(t *testing.T) {
	// Verify that EnrollCertificateRPC exists and has the expected signature
	// by calling it with an unreachable host (should fail at TCP connect).
	cfg := &ADCSConfig{
		TargetDC: "127.0.0.1",
		Domain:   "test.local",
		Username: "user",
		Password: "pass",
	}
	_, err := EnrollCertificateRPC(cfg, "127.0.0.1:1", "TestCA", "User", []byte{0x30})
	if err == nil {
		t.Fatal("expected connection error for unreachable host")
	}
	// Error should mention connect failure
	t.Logf("Expected error: %v", err)
}
