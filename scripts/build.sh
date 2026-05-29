#!/bin/bash
set -e

echo "==> Building Trusted..."
make build

echo ""
echo "==> Building SmartPotato implant..."
make smartpotato

echo ""
echo "==> Build complete!"
echo "    trusted: $(pwd)/trusted"
echo "    ted: $(pwd)/ted"
echo "    smartpotato: $(pwd)/implants/smartpotato/smartpotato"
