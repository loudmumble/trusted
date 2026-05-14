package pki

import (
	"encoding/binary"
	"testing"
)

func TestGenerateKeyCredential(t *testing.T) {
	entry, err := GenerateKeyCredential()
	if err != nil {
		t.Fatalf("GenerateKeyCredential: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}

	// KeyID should be 32 hex chars (16 bytes)
	if len(entry.KeyID) != 32 {
		t.Errorf("expected 32-char KeyID, got %d (%s)", len(entry.KeyID), entry.KeyID)
	}

	// DeviceID should be a GUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
	if len(entry.DeviceID) != 36 {
		t.Errorf("expected 36-char DeviceID (GUID), got %d (%s)", len(entry.DeviceID), entry.DeviceID)
	}
	if entry.DeviceID[8] != '-' || entry.DeviceID[13] != '-' {
		t.Errorf("DeviceID should be GUID format, got %s", entry.DeviceID)
	}

	// RawValue should be non-empty DER blob
	if len(entry.RawValue) < 20 {
		t.Errorf("RawValue too short: %d bytes", len(entry.RawValue))
	}

	// First 4 bytes should be version 0x0200
	ver := binary.LittleEndian.Uint32(entry.RawValue[0:4])
	if ver != uint32(kcVersion) {
		t.Errorf("version mismatch: got 0x%04x, want 0x%04x", ver, kcVersion)
	}

	// PrivateKey should be non-nil
	if entry.PrivateKey == nil {
		t.Error("PrivateKey is nil")
	}

	// CreatedAt should be recent
	if entry.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestGenerateKeyCredential_Uniqueness(t *testing.T) {
	entry1, _ := GenerateKeyCredential()
	entry2, _ := GenerateKeyCredential()

	if entry1.KeyID == entry2.KeyID {
		t.Error("two generated key credentials should have different KeyIDs")
	}
	if entry1.DeviceID == entry2.DeviceID {
		t.Error("two generated key credentials should have different DeviceIDs")
	}
}
