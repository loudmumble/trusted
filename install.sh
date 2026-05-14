#!/bin/bash
set -e

echo "[*] Removing old binaries..."
sudo rm -f /usr/local/bin/trusted
sudo rm -f /usr/local/bin/ted

echo "[*] Building Trusted..."
CGO_ENABLED=0 go build -o trusted ./cmd/trusted
echo "[+] Built: ./trusted"

echo "[*] Installing..."
sudo cp trusted /usr/local/bin/
sudo ln -sf /usr/local/bin/trusted /usr/local/bin/ted
echo "[+] Installed to /usr/local/bin/trusted"
echo "[+] Alias: /usr/local/bin/ted → trusted"
