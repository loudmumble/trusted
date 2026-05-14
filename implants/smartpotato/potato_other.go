//go:build !windows

package main

import (
	"fmt"
	"runtime"
)

func patchAMSI() {
	fmt.Println("[*] AMSI: Requires Windows (current: " + runtime.GOOS + ")")
}

func patchETW() {
	fmt.Println("[*] ETW: Requires Windows (current: " + runtime.GOOS + ")")
}

func detectBestTechnique() string {
	fmt.Println("[!] Potato techniques require Windows with SeImpersonatePrivilege")
	fmt.Println("[*] Defaulting to sweet for technique flow display")
	return "sweet"
}

func sweetPotato(command string) error {
	return fmt.Errorf("SweetPotato/PrintSpoofer requires Windows — cross-compile with GOOS=windows GOARCH=amd64")
}

func juicyPotato(command string) error {
	return fmt.Errorf("JuicyPotato requires Windows — cross-compile with GOOS=windows GOARCH=amd64")
}

func roguePotato(command string) error {
	return fmt.Errorf("RoguePotato requires Windows — cross-compile with GOOS=windows GOARCH=amd64")
}
