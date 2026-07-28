#!/bin/bash
#
# WiFi-Nightmare APT Repository Setup
#
# Usage: curl -sSL https://userjoo9.github.io/WiFi-Nightmare/install.sh | sudo bash
#
# This script:
#   1. Adds the WiFi-Nightmare APT repository (unsigned, HTTPS-served)
#   2. Installs the wifi-nightmare package

set -e

REPO_BASE="https://userjoo9.github.io/WiFi-Nightmare"
SOURCES_LIST="/etc/apt/sources.list.d/wifi-nightmare.list"

echo "========================================"
echo "  WiFi-Nightmare APT Repository Setup"
echo "========================================"
echo ""

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script must be run as root (sudo)."
    echo "    Usage: curl -sSL $REPO_BASE/install.sh | sudo bash"
    exit 1
fi

echo "[*] Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq curl 2>/dev/null || true

echo "[*] Adding APT repository (unsigned)..."
echo "deb [trusted=yes] $REPO_BASE stable main" | tee "$SOURCES_LIST" > /dev/null

echo "[*] Updating package list..."
apt-get update -qq

echo "[*] Installing WiFi-Nightmare..."
apt-get install -y wifi-nightmare

echo ""
echo "========================================"
echo "  Installation complete!"
echo "========================================"
echo ""
echo "  Run: sudo wifi-nightmare wlan0"
echo "  With ESP: sudo wifi-nightmare wlan0 /dev/ttyUSB0"
echo "  Flash ESP: sudo wifi-nightmare flash-esp /dev/ttyUSB0 --board esp32"
echo ""
echo "  Update: sudo apt update && sudo apt upgrade wifi-nightmare"
echo "========================================"
