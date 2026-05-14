#!/bin/bash
set -e

echo "=== SmartPotato Installer ==="
echo ""

# Build binaries
echo "[*] Building SmartPotato..."
make build

# Install
echo ""
echo "[*] Installing to /usr/local/bin/..."
sudo install -m 755 smartpotato.exe /usr/local/bin/ 2>/dev/null || true
sudo install -m 755 smartpotato_linux /usr/local/bin/ 2>/dev/null || true

echo ""
echo "[+] Installed:"
echo "    /usr/local/bin/smartpotato.exe   — Windows binary"
echo "    /usr/local/bin/smartpotato_linux — Linux binary"
echo ""
echo "Usage:"
echo "    Transfer smartpotato.exe to target Windows host"
echo "    Run: smartpotato.exe <command>"
