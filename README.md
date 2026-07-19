# WiFi-Nightmare

**v2.1.0**

Advanced WiFi security auditing and penetration testing tool. Combines a Python CLI on Linux with ESP32/ESP8266 firmware for Evil Twin, Deauthentication, Handshake capture, WPS Pixie Dust, and captive portal attacks.

## Features

- **Network Scanning**: Discover WiFi networks and connected clients with MAC vendor lookup
- **Deauthentication Attacks**: Disconnect clients from target networks (scapy → mdk4 → aireplay-ng fallback chain)
- **Handshake Capture**: Capture WPA/WPA2 handshakes for offline cracking
- **Hashcat File Generation**: Convert handshakes to `.hc22000` format (Hashcat Mode 22000)
- **SSID Reveal**: Decloak hidden networks by capturing probe responses
- **Evil Twin Attack**: Fake access point to capture credentials (ESP or software-only)
- **Software Evil Twin**: No ESP needed — works with any VIF-capable WiFi adapter
- **Pixie Dust Attack (WPS)**: WPS PIN recovery using reaver + pixiewps with timeout monitor
- **Captive Portal Auto-Detection**: Multi-device support across all major OEMs (Apple, Samsung, Android, Windows)
- **CAPPORT API (RFC 8908)**: Modern Android 12+ captive portal protocol support
- **Custom Captive Portal**: Upload your own HTML portal page without reflashing the ESP
- **9 Built-in Branded Portal Templates**: TP-Link, Huawei, ZTE, D-Link, Tenda, Vodafone, Etisalat, WE, Orange
- **Mass Attack**: Automated deauth on multiple hidden networks
- **Database**: Persistent JSON store for captured networks, handshakes, and WPS data
- **Client Monitor**: Live view of clients connecting/disconnecting
- **Thread-Safe Vendor Lookup**: 300+ OUI database with async HTTP fallback to macvendors.com
- **SignalManager**: Graceful Ctrl+C handling for all attack operations
- **Hybrid Mode**: Standalone (WiFi adapter only) or paired with ESP for enhanced attacks

---

## Project Structure

```
WiFi-Nightmare/                     # Git root
├── wifi_nightmare/                 # Python package
│   ├── __init__.py                 # Package version & metadata
│   ├── __main__.py                 # python -m wifi_nightmare support
│   ├── main.py                     # Main orchestrator & menus
│   ├── config.py                   # Configuration loader + path resolution
│   ├── flash_esp.py                # ESP firmware flashing command
│   ├── scanner.py                  # Network scanning & client monitor
│   ├── attacks.py                  # Compatibility shim
│   ├── deauth.py                   # Deauth frame injection
│   ├── handshake.py                # Handshake capture & SSID reveal
│   ├── eviltwin.py                 # Evil Twin attack via ESP
│   ├── evil_twin_software.py       # Software Evil Twin (hostapd + dnsmasq + Python portal)
│   ├── pixie_dust.py               # WPS Pixie Dust attack
│   ├── capture_native.py           # Native handshake capture
│   ├── esp_driver.py               # Serial communication with ESP
│   ├── portals.py                  # 9 branded captive portal HTML templates
│   ├── vif_check.py                # Virtual Interface support detection
│   ├── database.py                 # Network database (JSON with atomic writes)
│   ├── vendors.py                  # MAC vendor lookup (OUI DB → cache → HTTP)
│   ├── utils.py                    # System utilities, iw wrapper, SignalManager
│   ├── ui.py                       # CLI display & menus
│   ├── dep_check.py                # Runtime dependency checker
│   ├── config.yaml                 # Default runtime configuration
│   └── mac-vendor.txt              # OUI vendor database
├── esp_firmware/                   # Pre-compiled ESP firmware binaries
│   ├── esp32/                      # ESP32 firmware (bootloader + partitions + app)
│   └── esp8266/                    # ESP8266 firmware
├── ESP32-DePortal2/                # ESP32 firmware source (PlatformIO)
├── ESP8266-DePortal2/              # ESP8266 firmware source (PlatformIO)
├── debian/                         # Debian packaging files
│   ├── control                     # Package metadata & dependencies
│   ├── rules                       # Build instructions
│   ├── postinst                    # Post-installation script
│   ├── install                     # File mapping
│   ├── changelog                   # Debian changelog
│   ├── copyright                   # License
│   └── source/format               # Source package format
├── tests/
│   └── test_core.py                # Unit tests
├── pyproject.toml                  # Python build configuration
├── setup.py                        # Setuptools shim for Debian build
├── install.sh                      # APT repo one-liner setup script
├── CHANGELOG.md                    # Version history
├── PROJECT_MAP.md                  # Architecture documentation
└── README.md                       # This file
```

---

## Installation

### 🧭 Installation Tutorial

This guide walks you through installing WiFi-Nightmare on Ubuntu/Debian/Kali Linux — from zero to running your first scan. You'll learn two install methods, how to verify, how to flash ESP hardware, how to update, and how to uninstall.

---

### ✅ Step 0: Prerequisites

Before you begin, make sure you have:

| Requirement | Details |
|------------|---------|
| **Supported OS** | Ubuntu 20.04+, Debian 11+, Kali Linux 2023+, Parrot OS |
| **WiFi Adapter** | Any adapter supporting **Monitor Mode** + **Packet Injection** |
| **Internet Connection** | Needed for installation (wired/Ethernet recommended) |
| **ESP Board** | (Optional) ESP32 or ESP8266 for hardware Evil Twin attacks |
| **USB Cable** | (Optional) **Data-capable** USB cable for ESP flashing |
| **Root Access** | `sudo` privileges on the machine |

**Check your WiFi adapter:**
```bash
# List your wireless interfaces
iw dev
# If nothing shows, you may need an external adapter
```

**Compatible adapters (recommended):**

| Chipset | Example | Monitor | Injection | Virtual AP |
|---------|---------|:-------:|:---------:|:----------:|
| RTL8812AU | Alfa AWUS036ACH | ✅ | ✅ | ✅ |
| RTL8814AU | Alfa AWUS1900 | ✅ | ✅ | ✅ |
| RTL8821AU | Comfast CF-912AC | ✅ | ✅ | ✅ |
| AR9271 | TP-Link TL-WN722N v1 | ✅ | ✅ | ❌ |
| RTL8187 | Alfa AWUS036H | ✅ | ✅ | ❌ |
| RTL8188EU | TP-Link TL-WN725N | ✅ | ✅ | ❌ |

> ⚠️ **Important:** Built-in laptop WiFi cards usually **don't support monitor mode**. You need an external USB adapter. If unsure, the Alfa AWUS036ACH (RTL8812AU) is the safest choice — it supports everything.

---

### 📦 Step 1: Choose an Install Method

#### Method A: Quick Install (Recommended)

One command — the simplest way:

```bash
curl -sSL https://youssefalkhodary.github.io/wifi-nightmare/install.sh | sudo bash
```

**What this does:**
1. Installs `curl` and `gnupg` if missing
2. Downloads the GPG signing key → `/usr/share/keyrings/wifi-nightmare.gpg`
3. Adds the APT repository → `/etc/apt/sources.list.d/wifi-nightmare.list`
4. Runs `apt update` to refresh package lists
5. Installs `wifi-nightmare` and all dependencies

⏱ **Expected time:** ~30–60 seconds

#### Method B: Manual APT Install

Prefer doing things step by step? Follow these commands:

```bash
# 1. Install prerequisites
sudo apt update
sudo apt install -y curl gnupg

# 2. Import the GPG signing key
curl -fsSL https://youssefalkhodary.github.io/wifi-nightmare/KEY.gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/wifi-nightmare.gpg

# 3. Add the APT repository
echo "deb [signed-by=/usr/share/keyrings/wifi-nightmare.gpg] \
    https://youssefalkhodary.github.io/wifi-nightmare/apt stable main" | \
    sudo tee /etc/apt/sources.list.d/wifi-nightmare.list

# 4. Install the package
sudo apt update
sudo apt install wifi-nightmare
```

---

### ✅ Step 2: Verify the Installation

After installing, run these checks to make sure everything works:

```bash
# Check the version
wifi-nightmare --version

# View help
wifi-nightmare --help

# Verify Python module loads
python3 -c "import wifi_nightmare; print('OK:', wifi_nightmare.__version__)"

# Check runtime directories exist
ls -la /usr/share/wifi-nightmare/   # Static data (firmware, vendor DB)
ls -la /var/lib/wifi-nightmare/    # Runtime data (handshakes, logs, DB)
ls -la /etc/wifi-nightmare/        # Configuration file

# Check key system dependencies
which aircrack-ng iw hcxpcapngtool && echo "System deps OK"

# Check Python dependencies
python3 -c "from scapy.all import *; print('scapy OK')"
python3 -c "import serial; print('pyserial OK')"
python3 -c "import yaml; print('PyYAML OK')"
```

**Expected output:**
```
2.1.0
OK: 2.1.0
... (directory listings) ...
/usr/bin/aircrack-ng
/usr/sbin/iw
/usr/bin/hcxpcapngtool
System deps OK
scapy OK
pyserial OK
PyYAML OK
```

---

### 🚀 Step 3: First Run

Now let's start the tool and scan for networks.

```bash
# Run with your WiFi adapter (replace wlan0 with your interface)
sudo wifi-nightmare wlan0
```

**If you have an ESP module:**
```bash
sudo wifi-nightmare wlan0 /dev/ttyUSB0
```

**What you should see — the Main Menu:**
```
╔══════════════════════════════════════════╗
║         WiFi Nightmare  v2.1.0           ║
║         Advanced WiFi Security Tool      ║
╠══════════════════════════════════════════╣
║                                          ║
║  [1] Scan & Reconnaissance               ║
║  [2] Client Monitor (Live View)          ║
║  [3] Mass Attack (Auto-Pilot)            ║
║  [4] Offline Database & Cracking         ║
║  [5] Evil Twin Portal (Customize)        ║
║  [0] Exit                                ║
║                                          ║
║    ESP Status : Connected (/dev/ttyUSB0) ║
║    VIF Status : Supported                ║
╚══════════════════════════════════════════╝
```

Select **option 1** to scan for nearby networks. After scanning, pick a target to enter the Target Menu and launch attacks.

> 💡 **Tip:** WiFi-Nightmare handles monitor mode automatically — just provide the interface name and it does the rest. No need to run `airmon-ng` manually.

---

### 🎮 Step 4: ESP Firmware Flashing (Optional)

If you have an ESP32 or ESP8266 board, flash it with one command — **no PlatformIO or Arduino IDE needed.**

#### 4a. Find the serial port

```bash
# Run this BEFORE plugging in the ESP
ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null

# Then plug in the ESP, wait 3 seconds, and run again:
ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null
```

The **new device** that appears is your ESP port.

| ESP Board | Typical Port |
|-----------|-------------|
| ESP32 DevKit | `/dev/ttyUSB0` |
| ESP32-CAM | `/dev/ttyUSB0` |
| ESP8266 NodeMCU | `/dev/ttyUSB0` or `/dev/ttyACM0` |
| ESP32-S3 | `/dev/ttyACM0` |

#### 4b. Flash the firmware

```bash
# For ESP32
sudo wifi-nightmare flash-esp /dev/ttyUSB0 --board esp32

# For ESP8266
sudo wifi-nightmare flash-esp /dev/ttyUSB0 --board esp8266
```

**What you'll see during flashing (ESP32 example):**
```
Flashing ESP32 firmware...
Connecting...
Chip is ESP32-D0WDQ6 (revision 1)
Features: WiFi, BT, Dual Core, 240MHz
Crystal is 40MHz
MAC: 24:6f:28:xx:xx:xx
Uploading stub...
Stub running...
Writing at 0x00001000... (100 %)
Writing at 0x00008000... (100 %)
Writing at 0x00010000... (100 %)
Hard resetting via RTS pin...
Done!
```

#### 4c. Verify the flash

Start WiFi-Nightmare with the ESP connected:

```bash
sudo wifi-nightmare wlan0 /dev/ttyUSB0
```

If the menu shows **`ESP Status: Connected (/dev/ttyUSB0)`** in green, the firmware is working.

#### 4d. ESP flashing troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| `Failed to connect` | Wrong serial port | Re-run the `ls /dev/tty*` test to find the right port |
| `Failed to connect` | Wrong board type | Try `--board esp8266` if `esp32` fails, or vice versa |
| `Failed to connect` | USB charge-only cable | Use a **data cable** — charge cables lack data wires |
| `Failed to connect` | Permission denied | Always use `sudo` (already in the command) |
| `A fatal error occurred` | ESP not in flash mode | Some ESP32 boards need the BOOT button held during connect |
| No port appears | Missing USB driver | Install CH340G/CP2102 driver for clone ESP boards |
| `Timed out waiting for packet header` | Wrong baud rate | Try a different USB port or shorter USB cable |

---

### 🔄 Step 5: Updating

When a new version is released, update like any other system package:

```bash
# Refresh the package index
sudo apt update

# Upgrade WiFi-Nightmare
sudo apt upgrade wifi-nightmare
```

**Check your current version:**
```bash
wifi-nightmare --version
```

**View the changelog:**
```bash
apt changelog wifi-nightmare
```

> 💡 The Python package updates independently from the ESP firmware. Only re-flash your ESP if the release notes mention firmware changes.

---

### ❌ Step 6: Uninstalling

```bash
# Remove the package (keeps config and data)
sudo apt remove wifi-nightmare

# Remove everything (config, handshakes, logs, database)
sudo apt purge wifi-nightmare

# Remove the APT repository (optional cleanup)
sudo rm /etc/apt/sources.list.d/wifi-nightmare.list
sudo rm /usr/share/keyrings/wifi-nightmare.gpg
sudo apt update
```

---

### 👨‍💻 Development Setup (From Source)

For contributors who want to modify the code or run the latest unreleased version:

```bash
# 1. Clone the repository
git clone https://github.com/YoussefAlkhodary/WiFi-Nightmare.git
cd WiFi-Nightmare

# 2. Install system dependencies
sudo apt-get install aircrack-ng hcxtools iw hostapd dnsmasq reaver pixiewps

# 3. Install the package in editable/development mode
pip install -e .

# 4. Run
sudo wifi-nightmare wlan0
```

**Run tests:**
```bash
pip install pytest
python3 -m pytest tests/
```

**Uninstall dev version:**
```bash
pip uninstall wifi-nightmare
```

---

### 📋 Command Quick Reference

```
┌────────────────────────────────────────────────────────────────┐
│  COMMAND                                │  WHAT IT DOES        │
├────────────────────────────────────────────────────────────────┤
│  curl ... install.sh | sudo bash        │  One-click install   │
│  sudo apt install wifi-nightmare        │  Install via APT     │
│  sudo apt upgrade wifi-nightmare        │  Update to latest    │
│  sudo apt purge wifi-nightmare          │  Full uninstall      │
│  sudo wifi-nightmare wlan0              │  Run (no ESP)        │
│  sudo wifi-nightmare wlan0 /dev/ttyUSB0 │  Run (with ESP)      │
│  wifi-nightmare flash-esp /dev/ttyUSB0  │  Flash ESP firmware  │
│  wifi-nightmare --version               │  Check version       │
│  wifi-nightmare --help                  │  Show usage help     │
│  python3 -m wifi_nightmare ...          │  Run via Python      │
└────────────────────────────────────────────────────────────────┘
```

---

### 🐛 Troubleshooting

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| `wifi-nightmare: command not found` | Package not installed | Run `sudo apt install wifi-nightmare` |
| `Permission denied` when running | Missing `sudo` | Always use `sudo wifi-nightmare ...` |
| `Interface wlan0 not found` | Wrong interface name | Run `iw dev` to list available interfaces |
| `Monitor mode failed` | Unsupported adapter | Get an RTL8812AU adapter (Alfa AWUS036ACH) |
| Menu shows greyed-out attacks | Missing hardware/deps | Check VIF support and install recommended packages |
| `No module named wifi_nightmare` (dev mode) | Not installed | Run `pip install -e .` from repo root |
| `esptool: command not found` | Missing after upgrade | `sudo apt install --reinstall wifi-nightmare esptool` |
| `Failed to connect to ESP` | Wrong serial port | Use `ls /dev/ttyUSB*` before/after plugging to find port |
| `No wifi adapter found` | No monitor-mode adapter | Buy a compatible adapter (see Prerequisites table) |

---

## Usage

### Standalone Mode (WiFi adapter only)

```bash
sudo wifi-nightmare wlan0
```

### Hybrid Mode (WiFi adapter + ESP)

```bash
sudo wifi-nightmare wlan0 /dev/ttyUSB0
```

Find your ESP serial port:
```bash
ls /dev/ttyUSB*    # Most common
ls /dev/ttyACM*    # Some boards
```

### Via Python Module

```bash
sudo python3 -m wifi_nightmare wlan0
sudo python3 -m wifi_nightmare wlan0 /dev/ttyUSB0
```

### Finding Your Interface Name

```bash
iw dev              # Shows wireless interfaces
ip link show        # Shows all network interfaces
```

Common names: `wlan0`, `wlan1`, `wlp2s0`, `wlp3s0`

---

## Hardware Compatibility

The app **auto-detects** your hardware capabilities at startup and shows only available attack options.

| Feature | Requires | Auto-Detected |
|---------|----------|:---:|
| Scanning / Deauth / Handshake | Monitor mode + injection | ✅ |
| SSID Reveal | Monitor mode | ✅ |
| Pixie Dust (WPS) | Monitor mode + `reaver` + `pixiewps` | ✅ |
| **Software Evil Twin** | VIF support + `hostapd` + `dnsmasq` | ✅ |
| **ESP Evil Twin** | ESP32/ESP8266 over serial | ✅ |
| Captive Portal | Works with both modes | ✅ |

### Adapter Compatibility Guide

| Chipset | Example Adapter | Monitor | Injection | VIF / AP | Rating |
|---------|----------------|:-------:|:---------:|:--------:|:------:|
| **RTL8812AU** | Alfa AWUS036ACH | ✅ | ✅ | ✅ | ⭐ Full |
| **RTL8814AU** | Alfa AWUS1900 | ✅ | ✅ | ✅ | ⭐ Full |
| **RTL8821AU** | Comfast CF-912AC | ✅ | ✅ | ✅ | ⭐ Full |
| **AR9271** | TP-Link TL-WN722N v1 | ✅ | ✅ | ❌ | ⚡ Basic |
| **RTL8187** | Alfa AWUS036H | ✅ | ✅ | ❌ | ⚡ Basic |
| **RTL8188EU** | TP-Link TL-WN725N | ✅ | ✅ | ❌ | ⚡ Basic |
| **RTL88x2BU** | Various | ✅ | ✅ | ⚠️ Varies | ⚡ Basic |

The menu shows availability at a glance:
- **White text** = Ready to use
- **Yellow text** = Tools missing (install `hostapd`/`dnsmasq`/`reaver`/`pixiewps`)
- **Grey text** = Hardware doesn't support it

---

## Main Menu

```
╔══════════════════════════════════════════╗
║         WiFi Nightmare  v2.1.0           ║
║         Advanced WiFi Security Tool      ║
╠══════════════════════════════════════════╣
║                                          ║
║  [1] Scan & Reconnaissance               ║
║  [2] Client Monitor (Live View)          ║
║  [3] Mass Attack (Auto-Pilot)            ║
║  [4] Offline Database & Cracking         ║
║  [5] Evil Twin Portal (Customize)        ║
║  [0] Exit                                ║
║                                          ║
║    ESP Status : Connected (/dev/ttyUSB0) ║
║    VIF Status : Supported                ║
╚══════════════════════════════════════════╝
```

### 1. Scan & Reconnaissance
Scans for nearby WiFi networks in monitor mode. Results show:
- BSSID (MAC address) with vendor name
- Signal strength (RSSI)
- Channel
- Encryption type (WPA2, WPA3, etc.)
- Whether WPS is enabled (Pixie Dust eligible)
- Connected client count
- Whether you already have a handshake saved

After scanning, select a target to enter the **Target Menu**.

### 2. Client Monitor
Live view of clients connecting/disconnecting from networks. Useful for identifying active targets and timing attacks.

### 3. Mass Attack
Automatically deauths all unknown hidden networks to reveal their SSIDs. Set a duration per target and the tool cycles through them unattended.

### 4. Database
View saved networks, handshake status, WPS PINs, and verify captured passwords against handshake files.

### 5. Evil Twin Portal
Customize the captive portal page — choose from 9 branded templates or upload your own HTML.

---

## Target Menu

After scanning and selecting a target:

```
═══ Target: MyWiFi (00:11:22:33:44:55) CH:6 ═══
Clients: 3
──────────────────────────────────────────
  [1] Capture Handshake (WPA/WPA2)
  [2] Reveal Hidden SSID
  [3] Deauth Attack (Disconnect)
  [4] Passive Monitor (Stealth)
  [5] Generate Hashcat File (hc22000)
  [6] Evil Twin (ESP)
  [7] Evil Twin (Software — No ESP needed)
  [8] Pixie Dust Attack (WPS)
──────────────────────────────────────────
  [0] Back to Scan
```

Options 6-8 show availability based on your hardware.

### Capture Handshake
Sends deauth packets to force clients to reconnect, then captures the 4-way handshake. Saved as `.pcap` and convertible to `.hc22000` for Hashcat.

### Reveal Hidden SSID
Targets hidden networks specifically to capture their SSID from probe responses.

### Evil Twin — Option 6 (ESP)
Requires ESP module. Steps:
1. Captures a handshake first if none exists
2. Creates a fake AP with the cloned SSID
3. Deauths clients from the real network
4. Clients connect to your fake AP
5. Serves a captive portal page asking for the password
6. Each attempt is verified against the captured handshake on-device
7. Correct password is saved to `cracked.txt`

### Evil Twin — Option 7 (Software — No ESP)
Works with any WiFi adapter that supports **Virtual Interfaces (VIF)**.

**Requirements:**
- WiFi adapter with VIF support (auto-detected at startup)
- `hostapd` — creates the fake access point
- `dnsmasq` — handles DHCP and DNS for connected clients

```bash
sudo apt-get install hostapd dnsmasq
```

**How it works:**
1. Creates a virtual AP interface (`wlan0_ap`) on your adapter
2. Runs hostapd to broadcast the fake AP with the target's SSID
3. Runs dnsmasq to give clients IP addresses and capture all DNS queries
4. Runs a **multi-threaded Python HTTP server** for the captive portal
5. Simultaneously deauths clients from the real network
6. Clients see the same SSID, connect to your AP, and get the portal
7. Password attempts are verified against the captured handshake via aircrack-ng

**Captive Portal Auto-Detection:**
The software Evil Twin supports captive portal detection across all major device types:

| Device / OS | Detection Method | Response Strategy |
|-------------|-----------------|-------------------|
| **Android / Google** | `GET /generate_204` → expects 204 | 200 + auto-redirect HTML |
| **Apple iOS / macOS** | `GET /hotspot-detect.html` → expects "Success" | Portal HTML (no "Success") |
| **Windows NCSI** | `GET /ncsi.txt` → expects "Microsoft NCSI" | Non-matching content |
| **Samsung One UI** | `GET /check_network_status.txt` | Portal HTML (200, not 302) |
| **Android 12+ (CAPPORT)** | `GET /.well-known/captiveportal/check` | JSON `{"captive":true}` |
| **Amazon Kindle** | `GET /kindle-wifi/wifistub.html` | Portal HTML |
| **Any other path** | iOS CaptiveNetworkSupport random URIs | Catch-all → portal HTML |

Key features:
- **ThreadingHTTPServer** handles concurrent requests from multiple devices
- **No 302 redirects** — Samsung One UI breaks on redirects; uses 200+HTML with meta refresh
- **CAPPORT (RFC 8908)** — `X-Captive-Portal-Status: login` header on all responses
- **All major OEM URLs** covered (Apple, Samsung, Windows, Android, Kindle, Chrome, Firefox)

### Pixie Dust — Option 8 (WPS)
WPS PIN recovery attack using `reaver` + `pixiewps`. Targets the WPS PIN brute-force vector.

**Requirements:**
```bash
sudo apt-get install reaver pixiewps
```

**How it works:**
1. Sets the adapter to the target channel and locks it
2. Runs reaver with pixiewps in a subprocess
3. A timeout monitor thread tracks progress and kills stalled sessions
4. On success: PIN and PSK are saved to the database
5. On timeout/failure: gracefully falls back with clean channel unlock

---

## Captive Portal Templates

**9 branded templates** are included:

| # | Template | Brand Color | Style |
|---|----------|-------------|-------|
| 1 | **TP-Link** | `#4ACBD6` (Teal) | Router login |
| 2 | **Huawei** | `#CF0A2C` (Red) | Telecom |
| 3 | **ZTE** | `#008ED3` (Blue) | Telecom |
| 4 | **D-Link** | `#0087A9` (Teal) | Router login |
| 5 | **Tenda** | `#E4002B` (Red) | Router login |
| 6 | **Vodafone** | `#E60000` (Red) | ISP portal |
| 7 | **Etisalat** | `#E00800` (Red) | ISP portal |
| 8 | **WE** | `#5B2C66` (Purple) | ISP portal |
| 9 | **Orange** | `#FF7900` (Orange) | ISP portal |

All templates feature:
- Inline SVG brand logos
- Accurate brand colors
- Mobile-responsive design with viewport meta tag
- Three-view flow: login → verifying → success
- POST to `/submit` with field `name`
- Poll `/status` every 1s for verification result

---

## Custom Portal

The Evil Twin attack serves a captive portal HTML page to victims. You can customize this page without reflashing the ESP firmware.

### Using Built-in Templates

1. Select **option 5** from the main menu
2. Pick a template by number (1-9)
3. Confirm to save locally
4. Optionally upload to ESP if connected — the portal is active immediately

### Using Your Own HTML

1. Select **option 5** from the main menu
2. Press **C** to load from file
3. Enter the path to your `.html` file
4. Confirm to save

**HTML Requirements:**
- **Max size (ESP):** `4096 bytes` — enforced by both Python and firmware
- **No size limit** for Software Evil Twin
- Must POST the password as a field named `password` or `name`
- Must poll `/status` for `OK` / `NO` / `WAIT` responses

Minimal example:
```html
<input type="password" id="password" placeholder="Password">
<button onclick="send()">Connect</button>
<script>
function send() {
  fetch('/submit', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'name=' + encodeURIComponent(document.getElementById('password').value)
  }).then(() => {
    setInterval(() => {
      fetch('/status').then(r => r.text()).then(s => {
        if (s === 'OK') alert('Connected!');
        else if (s === 'NO') alert('Wrong password');
      });
    }, 1000);
  });
}
</script>
```

### Reset to Default
Select **option 5** → **R** to clear the custom portal and revert to the built-in default.

---

## Serial Protocol (Python ↔ ESP)

| Command | Direction | Description |
|---------|-----------|-------------|
| `ATTACK <bssid> <ch> <dur>` | → ESP | Start deauth attack |
| `ATTACK OFF` | → ESP | Stop deauth attack |
| `HOST <ssid> <ch>` | → ESP | Start Evil Twin AP (supports multi-word SSID via `lastIndexOf`) |
| `OK` | → ESP | Accept captured password → reset system |
| `NO` | → ESP | Reject captured password |
| `STOP` | → ESP | Stop all operations immediately |
| `SET_HTML <length>` | → ESP | Upload custom portal HTML (up to `MAX_HTML_SIZE`) |
| `CLEAR_HTML` | → ESP | Remove custom portal → revert to default |
| `[CAPTURED] <data>` | ESP → | Password captured via captive portal |
| `[STATUS] TARGET_FOUND` | ESP → | Target BSSID verified on-channel |
| `[STATUS] TARGET_NOT_FOUND` | ESP → | Target not detected |
| `[READY] SEND_HTML` | ESP → | ESP ready to receive HTML bytes |
| `[SUCCESS] HTML_SAVED <n>` | ESP → | HTML saved to LittleFS |
| `[EVENT] VICTIM_CONNECTED` | ESP → | Client connected to fake AP |
| `[EVENT] VICTIM_DISCONNECTED` | ESP → | Client disconnected |

Key firmware details:
- Space-delimited protocol with `lastIndexOf(' ')` for HOST command → supports SSIDs with spaces
- MAX_HTML_SIZE (4096) synchronized between Python (`ESP_HTML_LIMIT`) and firmware (`definitions.h`)
- Verification phase: ESP sniffs 2 seconds before attack to confirm target is on-channel
- Auto-pause: Deauth pauses 30 seconds after a victim connects (allows portal interaction)

---

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
scanning:
  channel_hop_interval: 0.5   # Seconds between channel hops
  timeout: 60                  # Scan duration (seconds)

attacks:
  deauth_packets: 50           # Packets per deauth burst
  handshake_timeout: 120       # Max seconds to wait for handshake

pixie_dust:
  timeout: 120                 # Max seconds for Pixie Dust attack
  verbose: true                # Show reaver/pixiewps output

database:
  path: "wifi_db.json"         # Database file location

esp32:
  baudrate: 115200             # Serial communication speed

output:
  handshakes_dir: "handshakes" # Directory for .pcap and .hc22000 files
  log_file: "logs/wifinightmare.log"
```

---

## Running Tests

```bash
cd WiFi-Nightmare
python -m pytest tests/
# or
python -m unittest tests.test_core
```

---

## Dependencies

### Python
| Package | Version | Purpose |
|---------|---------|---------|
| scapy | 2.7.0 | Packet manipulation & injection |
| pyserial | 3.5 | Serial communication with ESP |
| PyYAML | 6.0.3 | Configuration file loading |

### System
| Tool | Purpose | Install |
|------|---------|---------|
| `iw` | Wireless interface config | `apt-get install iw` |
| `aircrack-ng` | Handshake verification & cracking | `apt-get install aircrack-ng` |
| `hcxpcapngtool` | Hashcat .hc22000 conversion (hcxtools) | `apt-get install hcxtools` |
| `hostapd` | Software Evil Twin AP | `apt-get install hostapd` (optional) |
| `dnsmasq` | Software Evil Twin DHCP/DNS | `apt-get install dnsmasq` (optional) |
| `reaver` | WPS Pixie Dust attack | `apt-get install reaver` (optional) |
| `pixiewps` | WPS offline PIN computation | `apt-get install pixiewps` (optional) |

---

## Architecture Notes

### Fallback Chains
The app uses a multi-tier fallback approach for fault tolerance:

**Deauth:** `scapy` → `mdk4` → `mdk3` → `aireplay-ng`
**AP Creation:** `iw phy` interface add → `iw dev` managed → airmon-ng native
**Vendor Lookup:** Internal OUI DB (300+ entries) → file cache → async HTTP (macvendors.com)

### Captive Portal Detection Flow
```
Device connects to fake AP
        ↓
Device sends DNS query → dnsmasq resolves ALL domains to 10.0.0.1
        ↓
Device sends GET /generate_204 (or Apple/Windows/Samsung URL)
        ↓
HTTP server returns OS-specific "portal required" response
        ↓
Device OS shows notification: "Sign in to Wi-Fi network"
        ↓
User opens notification → sees portal in WebView → enters password
        ↓
Password verified against captured handshake via aircrack-ng
```

### Synchronized Constants
The ESP_HTML_LIMIT (`config.py`) and MAX_HTML_SIZE (`definitions.h`) are kept in sync across all four files:
- `WiFi-Nightmare/config.py` — `ESP_HTML_LIMIT = 4096`
- `WiFi-Nightmare/main.py` — imports and uses `ESP_HTML_LIMIT`
- `WiFi-Nightmare/esp_driver.py` — validates HTML size before sending
- `ESP32-DePortal2/include/definitions.h` — `#define MAX_HTML_SIZE 4096`
- `ESP8266-DePortal2/include/definitions.h` — `#define MAX_HTML_SIZE 4096`

---

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Unauthorized access to computer networks is illegal. Always obtain explicit permission before testing on any network you do not own.

---

## Credits

- **Deportal2**: Firmware base — [CDFER/Captive-Portal-ESP32](https://github.com/CDFER/Captive-Portal-ESP32)
- **ESP32-Deauther**: Deauth framework — [tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther)
- Thanks to the open-source security community
