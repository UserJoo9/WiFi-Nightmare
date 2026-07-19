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
WiFi-Nightmare/
├── WiFi-Nightmare/              # Python CLI application
│   ├── main.py                  # Main orchestrator & menus
│   ├── scanner.py               # Network scanning & client monitor
│   ├── attacks.py               # Compatibility shim (deauth/handshake/eviltwin)
│   ├── deauth.py                # Deauth frame injection
│   ├── handshake.py             # Handshake capture & SSID reveal
│   ├── eviltwin.py              # Evil Twin attack via ESP
│   ├── evil_twin_software.py    # Software Evil Twin (hostapd + dnsmasq + Python portal)
│   ├── pixie_dust.py            # WPS Pixie Dust attack (reaver + pixiewps)
│   ├── capture_native.py        # Native handshake capture (airodump-ng)
│   ├── esp_driver.py            # Serial communication with ESP
│   ├── portals.py               # 9 branded captive portal HTML templates
│   ├── vif_check.py             # Virtual Interface support detection
│   ├── database.py              # Network database (JSON with atomic writes)
│   ├── vendors.py               # MAC vendor lookup (OUI DB → cache → HTTP)
│   ├── utils.py                 # System utilities, iw wrapper, SignalManager
│   ├── ui.py                    # CLI display & menus
│   ├── config.py                # Configuration loader + constants
│   ├── logger.py                # Logging with rotation
│   ├── dep_check.py             # Runtime dependency checker
│   ├── config.yaml              # Runtime configuration
│   ├── requirements.txt         # Python dependencies (pinned)
│   └── __init__.py              # Package marker
├── tests/
│   └── test_core.py             # Unit tests
├── ESP32-DePortal2/             # ESP32 firmware (PlatformIO)
│   ├── include/                 # Header files (definitions.h, types.h, serial_handler.h)
│   └── src/                     # Source files (serial_handler.cpp, state.cpp)
├── ESP8266-DePortal2/           # ESP8266 firmware (PlatformIO)
│   ├── include/                 # Header files (definitions.h, types.h, serial_handler.h)
│   └── src/                     # Source files (serial_handler.cpp, state.cpp)
├── CHANGELOG.md                 # Version history
├── PROJECT_MAP.md               # Architecture documentation
└── README.md                    # This file
```

---

## Installation

### Prerequisites

- **OS**: Linux (Kali, Parrot, Ubuntu recommended)
- **WiFi adapter** that supports Monitor Mode + Packet Injection
- **Python 3.9+**
- **System tools**: `aircrack-ng`, `hcxtools`, `iw`
- **For Software Evil Twin**: `hostapd`, `dnsmasq` (optional — VIF-capable adapter required)
- **For Pixie Dust**: `reaver`, `pixiewps` (optional)

### Step 1: Install System Dependencies

```bash
# Debian / Ubuntu / Kali
sudo apt-get update
sudo apt-get install aircrack-ng hcxtools iw python3-pip hostapd dnsmasq reaver pixiewps

# Arch Linux
sudo pacman -S aircrack-ng hcxtools iw python-pip hostapd dnsmasq reaver pixiewps

# Fedora / RHEL
sudo dnf install aircrack-ng hcxtools iw python3-pip hostapd dnsmasq reaver pixiewps
```

### Step 2: Install Python Dependencies

```bash
cd WiFi-Nightmare/WiFi-Nightmare
pip3 install -r requirements.txt
```

| Package | Version | Purpose |
|---------|---------|---------|
| scapy | 2.7.0 | Packet injection & sniffing |
| pyserial | 3.5 | ESP serial communication |
| PyYAML | 6.0.3 | Config file loading |

### Step 3: Flash ESP Firmware (Optional — for ESP Evil Twin)

Only needed for ESP-based Evil Twin attacks.

1. Install [VS Code](https://code.visualstudio.com/) + [PlatformIO IDE extension](https://marketplace.visualstudio.com/items?itemName=platformio.platformio-ide)
2. Open `ESP32-DePortal2` or `ESP8266-DePortal2` folder in VS Code
3. Connect your ESP board via USB
4. Click the **Upload** arrow in PlatformIO status bar
5. Wait for `SUCCESS` message

---

## Usage

### Standalone Mode (WiFi adapter only)

```bash
cd WiFi-Nightmare/WiFi-Nightmare
sudo python3 main.py wlan0
```

### Hybrid Mode (WiFi adapter + ESP)

```bash
cd WiFi-Nightmare/WiFi-Nightmare
sudo python3 main.py wlan0 /dev/ttyUSB0
```

Find your ESP serial port:
```bash
ls /dev/ttyUSB*    # Most common
ls /dev/ttyACM*    # Some boards
```

### Finding Your Interface Name

```bash
iw dev              # Shows managed interfaces
iwconfig            # Alternative (legacy)
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
