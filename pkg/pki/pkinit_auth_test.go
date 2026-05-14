package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/types"
)

func TestDHKeyExchange(t *testing.T) {
	// Generate two key pairs and verify shared secret matches
	priv1, pub1, err := generateDHKeyPair()
	if err != nil {
		t.Fatalf("generateDHKeyPair 1: %v", err)
	}
	priv2, pub2, err := generateDHKeyPair()
	if err != nil {
		t.Fatalf("generateDHKeyPair 2: %v", err)
	}

	// Both sides compute the shared secret: g^(ab) mod p
	shared1 := new(big.Int).Exp(pub2, priv1, dhGroup14Prime)
	shared2 := new(big.Int).Exp(pub1, priv2, dhGroup14Prime)

	if shared1.Cmp(shared2) != 0 {
		t.Fatal("DH shared secret mismatch")
	}

	// Verify key properties
	if pub1.Sign() <= 0 || pub2.Sign() <= 0 {
		t.Fatal("DH public keys should be positive")
	}
	if pub1.Cmp(dhGroup14Prime) >= 0 || pub2.Cmp(dhGroup14Prime) >= 0 {
		t.Fatal("DH public keys should be less than prime")
	}
}

func TestOctetstring2key(t *testing.T) {
	input := []byte("test input for key derivation")

	// AES-256 key size = 32 bytes
	key32 := octetstring2key(input, 32)
	if len(key32) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key32))
	}

	// AES-128 key size = 16 bytes
	key16 := octetstring2key(input, 16)
	if len(key16) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(key16))
	}

	// The first 16 bytes of key32 should match key16 (same SHA1 chain)
	for i := 0; i < 16; i++ {
		if key32[i] != key16[i] {
			t.Fatalf("key prefix mismatch at byte %d: %02x vs %02x", i, key32[i], key16[i])
		}
	}

	// Deterministic: same input should produce same key
	key32b := octetstring2key(input, 32)
	for i := range key32 {
		if key32[i] != key32b[i] {
			t.Fatalf("key derivation not deterministic at byte %d", i)
		}
	}

	// Different input should produce different key
	key32c := octetstring2key([]byte("different input"), 32)
	same := true
	for i := range key32 {
		if key32[i] != key32c[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different inputs should produce different keys")
	}
}

func TestBuildDHSubjectPublicKeyInfo(t *testing.T) {
	_, pub, err := generateDHKeyPair()
	if err != nil {
		t.Fatalf("generateDHKeyPair: %v", err)
	}

	spki, err := buildDHSubjectPublicKeyInfo(pub)
	if err != nil {
		t.Fatalf("buildDHSubjectPublicKeyInfo: %v", err)
	}

	// Should be valid ASN.1
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(spki, &raw)
	if err != nil {
		t.Fatalf("SPKI is not valid ASN.1: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("trailing bytes after SPKI: %d", len(rest))
	}
	if raw.Tag != 16 { // SEQUENCE
		t.Errorf("expected SEQUENCE tag (16), got %d", raw.Tag)
	}
}

func TestBuildCMSSignedData(t *testing.T) {
	// Generate a test certificate and key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// Build CMS SignedData
	authPack := []byte("test AuthPack content")
	cms, err := buildCMSSignedData(authPack, cert, key)
	if err != nil {
		t.Fatalf("buildCMSSignedData: %v", err)
	}

	// Should be valid ASN.1 (ContentInfo SEQUENCE)
	var ci contentInfoASN
	_, err = asn1.Unmarshal(cms, &ci)
	if err != nil {
		t.Fatalf("CMS is not valid ASN.1: %v", err)
	}

	// Content type should be id-signedData
	if !ci.ContentType.Equal(oidSignedData) {
		t.Errorf("contentType should be id-signedData, got %v", ci.ContentType)
	}
}

func TestPadBigInt(t *testing.T) {
	n := big.NewInt(0xFF)
	padded := padBigInt(n, 4)
	if len(padded) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(padded))
	}
	expected := []byte{0x00, 0x00, 0x00, 0xFF}
	for i, b := range padded {
		if b != expected[i] {
			t.Errorf("byte %d: expected %02x, got %02x", i, expected[i], b)
		}
	}
}

func TestWriteCCache(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/test.ccache"

	sessionKey := types.EncryptionKey{
		KeyType:  18, // AES256
		KeyValue: make([]byte, 32),
	}
	rand.Read(sessionKey.KeyValue)

	now := time.Now()
	ticketDER := []byte{0x61, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05} // minimal fake ticket

	err := writeCCache(path, "admin", "CORP.LOCAL",
		sessionKey, 0x40810010,
		now, now, now.Add(10*time.Hour), now.Add(7*24*time.Hour),
		ticketDER)
	if err != nil {
		t.Fatalf("writeCCache: %v", err)
	}

	// Read and verify basic format
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ccache: %v", err)
	}

	// Should start with version 0x0504
	if len(data) < 4 {
		t.Fatal("ccache too short")
	}
	if data[0] != 0x05 || data[1] != 0x04 {
		t.Errorf("expected version 0x0504, got 0x%02x%02x", data[0], data[1])
	}

	// Header length should be 0 (no header fields)
	headerLen := int(data[2])<<8 | int(data[3])
	if headerLen != 0 {
		t.Errorf("expected header length 0, got %d", headerLen)
	}

	// File should be non-trivial size
	if len(data) < 100 {
		t.Errorf("ccache seems too small: %d bytes", len(data))
	}

	t.Logf("ccache written: %d bytes", len(data))
}

func TestAddASN1AppTag(t *testing.T) {
	data := []byte{0x30, 0x03, 0x02, 0x01, 0x05} // SEQUENCE { INTEGER 5 }
	tagged := addASN1AppTag(data, 10)            // APPLICATION 10

	// Should start with 0x6A (APPLICATION 10, CONSTRUCTED)
	if tagged[0] != 0x6A {
		t.Errorf("expected tag 0x6A, got 0x%02x", tagged[0])
	}

	// Length should be length of original data
	if tagged[1] != byte(len(data)) {
		t.Errorf("expected length %d, got %d", len(data), tagged[1])
	}
}

func TestCheckKRBError_NotError(t *testing.T) {
	// AS-REP starts with 0x6B (APPLICATION 11)
	data := []byte{0x6B, 0x03, 0x30, 0x01, 0x00}
	err := checkKRBError(data)
	if err != nil {
		t.Errorf("non-error data should return nil, got: %v", err)
	}
}
