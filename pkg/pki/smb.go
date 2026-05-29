package pki

import (
	"encoding/binary"
	"fmt"
	"net"
)

type smbSession struct {
	conn      net.Conn
	sessionID uint64
	treeID    uint32
	fileID    [16]byte
	messageID uint64
}

func (s *smbSession) smb2Header(command uint16) []byte {
	hdr := make([]byte, 64)
	hdr[0] = 0xFE
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[12:14], command)
	binary.LittleEndian.PutUint16(hdr[14:16], 31)
	binary.LittleEndian.PutUint64(hdr[28:36], s.messageID)
	binary.LittleEndian.PutUint32(hdr[36:40], s.treeID)
	binary.LittleEndian.PutUint64(hdr[40:48], s.sessionID)
	s.messageID++
	return hdr
}

func (s *smbSession) negotiate() error {
	hdr := s.smb2Header(0x0000)
	neg := make([]byte, 36+4)
	binary.LittleEndian.PutUint16(neg[0:2], 36)
	binary.LittleEndian.PutUint16(neg[2:4], 2)
	binary.LittleEndian.PutUint16(neg[4:6], 0x01)
	binary.LittleEndian.PutUint16(neg[36:38], 0x0202)
	binary.LittleEndian.PutUint16(neg[38:40], 0x0210)
	pkt := smbPacket(hdr, neg)
	if _, err := s.conn.Write(pkt); err != nil {
		return err
	}
	_, err := readSMB2Response(s.conn)
	return err
}

func (s *smbSession) treeConnect(target, share string) error {
	hdr := s.smb2Header(0x0003)
	path := fmt.Sprintf(`\\%s\%s`, target, share)
	pathUTF16 := coerceUTF16LE(path)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	pathOffset := uint16(64 + 8)
	binary.LittleEndian.PutUint16(body[4:6], pathOffset)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathUTF16)))
	body = append(body, pathUTF16...)
	pkt := smbPacket(hdr, body)
	if _, err := s.conn.Write(pkt); err != nil {
		return err
	}
	resp, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}
	if len(resp) >= 40 {
		s.treeID = binary.LittleEndian.Uint32(resp[36:40])
	}
	return nil
}

func (s *smbSession) createPipe(name string) error {
	hdr := s.smb2Header(0x0005)
	nameUTF16 := coerceUTF16LE(name)
	body := make([]byte, 57)
	binary.LittleEndian.PutUint16(body[0:2], 57)
	binary.LittleEndian.PutUint32(body[24:28], 0x001F01FF)
	binary.LittleEndian.PutUint32(body[32:36], 0x07)
	binary.LittleEndian.PutUint32(body[36:40], 0x01)
	binary.LittleEndian.PutUint32(body[40:44], 0x00400040)
	nameOffset := uint16(64 + 57)
	binary.LittleEndian.PutUint16(body[44:46], nameOffset)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameUTF16)))
	body = append(body, nameUTF16...)
	pkt := smbPacket(hdr, body)
	if _, err := s.conn.Write(pkt); err != nil {
		return err
	}
	resp, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}
	if len(resp) >= 128+16 {
		copy(s.fileID[:], resp[128:144])
	}
	return nil
}

func (s *smbSession) writePipe(data []byte) error {
	hdr := s.smb2Header(0x0009)
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:2], 49)
	binary.LittleEndian.PutUint16(body[2:4], uint16(64+49))
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	copy(body[16:32], s.fileID[:])
	body = append(body, data...)
	pkt := smbPacket(hdr, body)
	_, err := s.conn.Write(pkt)
	return err
}

func (s *smbSession) readPipe() ([]byte, error) {
	hdr := s.smb2Header(0x0008)
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:2], 49)
	binary.LittleEndian.PutUint32(body[4:8], 4096)
	copy(body[16:32], s.fileID[:])
	pkt := smbPacket(hdr, body)
	if _, err := s.conn.Write(pkt); err != nil {
		return nil, err
	}
	return readSMB2Response(s.conn)
}

func (s *smbSession) sessionSetupNTLM(cfg *ADCSConfig) error {
	hdr1 := s.smb2Header(0x0001)
	body1 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body1[0:2], 25)
	ntlmNeg := buildNTLMSSPNegotiate()
	secOffset1 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body1[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body1[14:16], uint16(len(ntlmNeg)))
	body1 = append(body1, ntlmNeg...)
	if _, err := s.conn.Write(smbPacket(hdr1, body1)); err != nil {
		return err
	}
	resp1, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}
	if len(resp1) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp1[40:48])
	}
	secOffset := binary.LittleEndian.Uint16(resp1[64+12 : 64+14])
	secLen := binary.LittleEndian.Uint16(resp1[64+14 : 64+16])
	challenge := resp1[secOffset : secOffset+secLen]
	t := &NTLMTransport{Domain: cfg.Domain, Username: normalizeUsername(cfg.Username), Password: cfg.Password, Hash: cfg.Hash}
	authMsg, err := t.buildAuthenticateMessage(challenge)
	if err != nil {
		return err
	}
	hdr2 := s.smb2Header(0x0001)
	body2 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body2[0:2], 25)
	binary.LittleEndian.PutUint16(body2[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body2[14:16], uint16(len(authMsg)))
	body2 = append(body2, authMsg...)
	if _, err := s.conn.Write(smbPacket(hdr2, body2)); err != nil {
		return err
	}
	resp2, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}
	if len(resp2) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp2[40:48])
	}
	return nil
}

func (s *smbSession) sessionSetupRelayPhase1(ntlmType1 []byte) ([]byte, error) {
	hdr1 := s.smb2Header(0x0001)
	body1 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body1[0:2], 25)
	secOffset1 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body1[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body1[14:16], uint16(len(ntlmType1)))
	body1 = append(body1, ntlmType1...)
	if _, err := s.conn.Write(smbPacket(hdr1, body1)); err != nil {
		return nil, err
	}
	resp1, err := readSMB2Response(s.conn)
	if err != nil {
		return nil, err
	}
	if len(resp1) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp1[40:48])
	}
	if len(resp1) < 64+24 {
		return nil, fmt.Errorf("short session setup response")
	}
	secOffset := binary.LittleEndian.Uint16(resp1[64+12 : 64+14])
	secLen := binary.LittleEndian.Uint16(resp1[64+14 : 64+16])
	if int(secOffset+secLen) > len(resp1) {
		return nil, fmt.Errorf("security blob offset out of range")
	}
	challenge := make([]byte, secLen)
	copy(challenge, resp1[secOffset:secOffset+secLen])
	return challenge, nil
}

func (s *smbSession) sessionSetupRelayPhase2(ntlmType3 []byte) error {
	hdr2 := s.smb2Header(0x0001)
	body2 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body2[0:2], 25)
	secOffset1 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body2[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body2[14:16], uint16(len(ntlmType3)))
	body2 = append(body2, ntlmType3...)
	if _, err := s.conn.Write(smbPacket(hdr2, body2)); err != nil {
		return err
	}
	resp2, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}
	if len(resp2) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp2[40:48])
	}
	return nil
}

func (s *smbSession) sessionSetupAnonymous() error {
	hdr1 := s.smb2Header(0x0001)
	body1 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body1[0:2], 25)
	ntlmNeg := buildNTLMSSPNegotiate()
	secOffset1 := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body1[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body1[14:16], uint16(len(ntlmNeg)))
	body1 = append(body1, ntlmNeg...)
	if _, err := s.conn.Write(smbPacket(hdr1, body1)); err != nil {
		return err
	}
	resp1, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}
	if len(resp1) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp1[40:48])
	}
	hdr2 := s.smb2Header(0x0001)
	body2 := make([]byte, 24)
	binary.LittleEndian.PutUint16(body2[0:2], 25)
	ntlmAuth := buildNTLMSSPAuth()
	binary.LittleEndian.PutUint16(body2[12:14], secOffset1)
	binary.LittleEndian.PutUint16(body2[14:16], uint16(len(ntlmAuth)))
	body2 = append(body2, ntlmAuth...)
	if _, err := s.conn.Write(smbPacket(hdr2, body2)); err != nil {
		return err
	}
	resp2, err := readSMB2Response(s.conn)
	if err != nil {
		return err
	}
	if len(resp2) >= 48 {
		s.sessionID = binary.LittleEndian.Uint64(resp2[40:48])
	}
	return nil
}

func (s *smbSession) downloadFile(name string) ([]byte, error) {
	hdr := s.smb2Header(0x0005)
	nameUTF16 := coerceUTF16LE(name)
	body := make([]byte, 57)
	binary.LittleEndian.PutUint16(body[0:2], 57)
	binary.LittleEndian.PutUint32(body[24:28], 0x00100081)
	binary.LittleEndian.PutUint32(body[32:36], 0x07)
	binary.LittleEndian.PutUint32(body[36:40], 0x01)
	binary.LittleEndian.PutUint32(body[40:44], 0x00000040)
	nameOffset := uint16(64 + 57)
	binary.LittleEndian.PutUint16(body[44:46], nameOffset)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameUTF16)))
	body = append(body, nameUTF16...)
	if _, err := s.conn.Write(smbPacket(hdr, body)); err != nil {
		return nil, err
	}
	resp, err := readSMB2Response(s.conn)
	if err != nil {
		return nil, err
	}
	copy(s.fileID[:], resp[128:144])
	hdrR := s.smb2Header(0x0008)
	bodyR := make([]byte, 49)
	binary.LittleEndian.PutUint16(bodyR[0:2], 49)
	binary.LittleEndian.PutUint32(bodyR[4:8], 65536)
	copy(bodyR[16:32], s.fileID[:])
	if _, err := s.conn.Write(smbPacket(hdrR, bodyR)); err != nil {
		return nil, err
	}
	respR, err := readSMB2Response(s.conn)
	if err != nil {
		return nil, err
	}
	hdrC := s.smb2Header(0x0006)
	bodyC := make([]byte, 24)
	binary.LittleEndian.PutUint16(bodyC[0:2], 24)
	copy(bodyC[8:24], s.fileID[:])
	s.conn.Write(smbPacket(hdrC, bodyC))
	readSMB2Response(s.conn)
	if len(respR) < 80 {
		return nil, fmt.Errorf("short read response")
	}
	dataLen := binary.LittleEndian.Uint32(respR[64+4 : 64+8])
	return respR[80 : 80+dataLen], nil
}
