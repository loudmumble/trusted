package pki

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

var icertPassageUUID = [16]byte{
	0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11,
	0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe,
}

const (
	crDispIssued          = 3
	crDispUnderSubmission = 5
)

const (
	crInBinary = 0x02
	crInPKCS10 = 0x100
	crInCMC    = 0x300
)

func EnrollCertificateRPC(cfg *ADCSConfig, caHostname, caName, templateName string, csrDER []byte) (*x509.Certificate, error) {
	return EnrollCertificateRPCWithFlags(cfg, caHostname, caName, templateName, csrDER, crInBinary|crInPKCS10)
}

func EnrollCertificateRPCWithFlags(cfg *ADCSConfig, caHostname, caName, templateName string, requestBlob []byte, requestFlags uint32) (*x509.Certificate, error) {
	fmt.Printf("[*] RPC enrollment via ICertPassage on %s (flags=0x%X)\n", caHostname, requestFlags)

	conn, err := net.DialTimeout("tcp", caHostname+":445", 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s:445: %w", caHostname, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	s := &smbSession{conn: conn}
	if err := s.negotiate(); err != nil {
		return nil, fmt.Errorf("SMB negotiate: %w", err)
	}

	if cfg.Kerberos {
		if err := s.sessionSetupKerberos(cfg, caHostname); err != nil {
			return nil, fmt.Errorf("SMB Kerberos auth: %w", err)
		}
	} else {
		if err := s.sessionSetupNTLM(cfg); err != nil {
			return nil, fmt.Errorf("SMB NTLM auth: %w", err)
		}
	}

	if err := s.treeConnect(caHostname, "IPC$"); err != nil {
		return nil, fmt.Errorf("SMB tree connect IPC$: %w", err)
	}
	if err := s.createPipe("cert"); err != nil {
		return nil, fmt.Errorf("open \\pipe\\cert: %w", err)
	}
	if err := rpcBind(s, icertPassageUUID); err != nil {
		return nil, fmt.Errorf("RPC bind ICertPassage: %w", err)
	}

	attribs := fmt.Sprintf("CertificateTemplate:%s", templateName)
	certDER, disposition, err := certServerRequestWithFlags(s, caName, attribs, requestBlob, requestFlags)
	if err != nil {
		return nil, fmt.Errorf("CertServerRequest: %w", err)
	}

	if disposition != crDispIssued {
		return nil, fmt.Errorf("enrollment failed (disposition=%d)", disposition)
	}

	return x509.ParseCertificate(certDER)
}

func certServerRequestWithFlags(s *smbSession, caName, attribs string, requestBlob []byte, flags uint32) ([]byte, uint32, error) {
	callID := rand.Uint32()
	stub := buildCertServerRequestStubWithFlags(caName, attribs, requestBlob, flags)

	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub)))
	binary.LittleEndian.PutUint16(reqHdr[6:8], 0)

	fragLen := uint16(16 + len(reqHdr) + len(stub))
	hdr := make([]byte, 16)
	hdr[0] = 5
	hdr[2] = 0x00
	hdr[3] = 0x03
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], fragLen)
	binary.LittleEndian.PutUint32(hdr[12:16], callID)

	var rpcReq []byte
	rpcReq = append(rpcReq, hdr...)
	rpcReq = append(rpcReq, reqHdr...)
	rpcReq = append(rpcReq, stub...)

	if err := s.writePipe(rpcReq); err != nil {
		return nil, 0, err
	}
	resp, err := s.readPipe()
	if err != nil {
		return nil, 0, err
	}
	return parseCertServerResponse(resp)
}

func buildCertServerRequestStubWithFlags(caName, attribs string, requestBlob []byte, flags uint32) []byte {
	var stub []byte
	stub = appendLE32(stub, flags)
	stub = ndrUniqueString(stub, caName)
	stub = appendLE32(stub, 0)
	stub = ndrCertTransBlob(stub, utf16LEEncode(attribs))
	stub = ndrCertTransBlob(stub, requestBlob)
	return stub
}

func ndrUniqueString(buf []byte, s string) []byte {
	if s == "" {
		return appendLE32(buf, 0)
	}
	utf16 := utf16LEEncode(s)
	charCount := uint32(len(utf16)/2 + 1)
	buf = appendLE32(buf, 0x00020000)
	buf = appendLE32(buf, charCount)
	buf = appendLE32(buf, 0)
	buf = appendLE32(buf, charCount)
	buf = append(buf, utf16...)
	buf = append(buf, 0, 0)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func ndrCertTransBlob(buf []byte, data []byte) []byte {
	cb := uint32(len(data))
	buf = appendLE32(buf, cb)
	if cb == 0 {
		return appendLE32(buf, 0)
	}
	buf = appendLE32(buf, 0x00020004)
	buf = appendLE32(buf, cb)
	buf = append(buf, data...)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func parseCertServerResponse(resp []byte) ([]byte, uint32, error) {
	rpcData, err := extractRPCFromReadResponse(resp)
	if err != nil {
		return nil, 0, err
	}
	if len(rpcData) < 24 {
		return nil, 0, fmt.Errorf("RPC response too short")
	}
	stub := rpcData[24:]
	if len(stub) < 8 {
		return nil, 0, fmt.Errorf("stub too short")
	}
	disposition := binary.LittleEndian.Uint32(stub[4:8])
	offset := 8
	var skipBlob []byte
	skipBlob, offset, err = readCertTransBlob(stub, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("skip request ID blob: %w", err)
	}
	_ = skipBlob
	certData, _, err := readCertTransBlob(stub, offset)
	return certData, disposition, err
}

func readCertTransBlob(stub []byte, offset int) ([]byte, int, error) {
	if offset+4 > len(stub) {
		return nil, offset, fmt.Errorf("offset overflow")
	}
	cb := binary.LittleEndian.Uint32(stub[offset : offset+4])
	offset += 4
	if cb == 0 {
		if offset+4 <= len(stub) {
			offset += 4
		}
		return nil, offset, nil
	}
	offset += 4
	if offset+4 > len(stub) {
		return nil, offset, fmt.Errorf("offset overflow")
	}
	maxCount := binary.LittleEndian.Uint32(stub[offset : offset+4])
	offset += 4
	dataLen := int(maxCount)
	if dataLen > int(cb) {
		dataLen = int(cb)
	}
	if offset+dataLen > len(stub) {
		return nil, offset, fmt.Errorf("data overflow")
	}
	data := make([]byte, dataLen)
	copy(data, stub[offset:offset+dataLen])
	offset += dataLen
	for offset%4 != 0 {
		offset++
	}
	return data, offset, nil
}
