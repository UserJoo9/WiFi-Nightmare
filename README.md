# WiFi-Nightmare

**v2.0.2**

Advanced WiFi security auditing and penetration testing tool. Combines a Python CLI on Linux with ESP32/ESP8266 firmware for Evil Twin, Deauthentication, and Handshake capture attacks.

## Features

- **Network Scanning**: Discover WiFi networks and connected clients
- **Deauthentication Attacks**: Disconnect clients from target networks
- **Handshake Capture**: Capture WPA/WPA2 handshakes for offline cracking
- **Hashcat File Generation**: Convert handshakes to `.hc22000` format (Hashcat Mode 22000)
- **Evil Twin Attack**: Fake access point to capture credentials (ESP or software-only)
- **Software Evil Twin**: No ESP needed — works with any VIF-capable WiFi adapter
- **Custom Captive Portal**: Upload your own HTML portal page without reflashing the ESP
- **Built-in Portal Templates**: 5 ready-to-use templates (Facebook, Hotel, Corporate, etc.)
- **Mass Attack**: Automated deauth on multiple hidden networks
- **Database**: Store and manage captured network info
- **Hybrid Mode**: Standalone (WiFi adapter only) or paired with ESP for enhanced attacks

---

## Project Structure

```
WiFi-Nightmare/
├── WiFi-Nightmare/          # Python CLI application
│   ├── main.py              # Main orchestrator & menus
│   ├── scanner.py           # Network scanning & client monitor
│   ├── attacks.py           # Compatibility shim (deauth/handshake/eviltwin)
│   ├── deauth.py            # Deauth frame injection
│   ├── handshake.py         # Handshake capture & verification
│   ├── eviltwin.py          # Evil Twin attack via ESP
│   ├── evil_twin_software.py # Software Evil Twin (hostapd + dnsmasq)
│   ├── esp_driver.py        # Serial communication with ESP
│   ├── portals.py           # Built-in captive portal HTML templates
│   ├── vif_check.py         # Virtual Interface support detection
│   ├── database.py          # Network database (JSON)
│   ├── vendors.py           # MAC vendor lookup
│   ├── utils.py             # System utilities, iw wrapper, SignalManager
│   ├── ui.py                # CLI display & menus
│   ├── config.py            # Configuration loader
│   ├── logger.py            # Logging with rotation
│   ├── dep_check.py         # Runtime dependency checker
│   ├── config.yaml          # Runtime configuration
│   ├── requirements.txt     # Python dependencies (pinned)
│   └── __init__.py          # Package marker
├── tests/
│   └── test_core.py         # Unit tests
├── ESP32-DePortal2/         # ESP32 firmware (PlatformIO)
├── ESP8266-DePortal2/       # ESP8266 firmware (PlatformIO)
├── CHANGELOG.md             # Version history
└── PROJECT_MAP.md           # Architecture documentation
```

---

## Installation

### Prerequisites

- **OS**: Linux (Kali, Parrot, Ubuntu recommended)
- **WiFi adapter** that supports Monitor Mode
- **Python 3.9+**
- **System tools**: `aircrack-ng`, `hcxtools`, `iw`
- **For Software Evil Twin**: `hostapd`, `dnsmasq` (optional)

### Step 1: Install System Dependencies

```bash
# Debian / Ubuntu / Kali
sudo apt-get update
sudo apt-get install aircrack-ng hcxtools iw python3-pip hostapd dnsmasq

# Arch Linux
sudo pacman -S aircrack-ng hcxtools iw

# Fedora / RHEL
sudo dnf install aircrack-ng hcxtools iw
```

### Step 2: Install Python Dependencies

```bash
cd WiFi-Nightmare/WiFi-Nightmare
pip3 install -r requirements.txt
```

This installs:
| Package | Version | Purpose |
|---------|---------|---------|
| scapy | 2.7.0 | Packet injection & sniffing |
| pyserial | 3.5 | ESP serial communication |
| PyYAML | 6.0.3 | Config file loading |

### Step 3: Flash ESP Firmware (Optional — for Evil Twin)

Only needed if you want Evil Twin attacks.

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
iw dev         # Shows managed interfaces
iwconfig       # Alternative (legacy)
ip link show   # Shows all network interfaces
```

Common names: `wlan0`, `wlan1`, `wlp2s0`, `wlp3s0`

---

## Main Menu

When you start the tool, you'll see:

```
[1] Scan & Reconnaissance
[2] Client Monitor (Live View)
[3] Mass Attack (Auto-Pilot)
[4] Offline Database & Cracking
[5] Evil Twin Portal (Customize)
[0] Exit
```

### 1. Scan & Reconnaissance

Scans for nearby WiFi networks in monitor mode. Results show:
- BSSID (MAC address)
- Signal strength (RSSI)
- Channel
- Encryption type
- Vendor name
- Connected clients
- Whether you already have a handshake

After scanning, select a target to enter the **Target Menu**.

### 2. Client Monitor

Live view of clients connecting/disconnecting from networks. Useful for identifying active targets.

### 3. Mass Attack

Automatically attacks all unknown hidden networks. You set a duration per target and the tool cycles through them.

### 4. Database

View saved networks and verify captured passwords against handshakes.

### 5. Evil Twin Portal

Customize the captive portal page used in Evil Twin attacks. See [Custom Portal](#custom-portal) below.

---

## Target Menu

After scanning and selecting a target:

```
[1] Capture Handshake (WPA/WPA2)
[2] Reveal Hidden SSID
[3] Deauth Attack (Disconnect)
[4] Passive Monitor (Stealth)
[5] Generate Hashcat File (hc22000)
[6] Evil Twin (ESP)           — Requires ESP32/ESP8266
[7] Evil Twin (Software)     — Requires VIF support + hostapd + dnsmasq
[0] Back to Scan
```

Options 6 and 7 show availability based on your hardware:
- Green text = available
- Yellow text = partially available (missing tools)
- Grey text = not available

### Capture Handshake

Sends deauth packets to force clients to reconnect, then captures the 4-way handshake. Saved as `.pcap` and converted to `.hc22000` for Hashcat.

### Reveal Hidden SSID

Targets hidden networks specifically to discover their SSID name.

### Evil Twin — Option 6 (ESP)

Requires ESP module. Steps:
1. If no handshake exists, captures one first
2. Creates a fake AP with the target's SSID
3. Deauths clients from the real network
4. Clients connect to your fake AP
5. Serves a captive portal page asking for the password
6. Each password attempt is verified against the captured handshake
7. Correct password is saved

### Evil Twin — Option 7 (Software — No ESP)

Works with any WiFi adapter that supports **Virtual Interfaces (VIF)**. No ESP hardware needed.

**Requirements:**
- WiFi adapter with VIF support (detected automatically at startup)
- `hostapd` — creates the fake access point
- `dnsmasq` — handles DHCP and DNS for connected clients

```bash
sudo apt-get install hostapd dnsmasq
```

**How it works:**
1. Creates a virtual AP interface (`wlan0_ap`) on your adapter
2. Runs hostapd to broadcast the fake AP with the target's SSID
3. Runs dnsmasq to give clients IP addresses and redirect DNS
4. Runs a Python HTTP server for the captive portal
5. Simultaneously deauths clients from the real network
6. Clients see the same SSID, connect to your AP, and get the portal
7. Password attempts are verified against the captured handshake

**To check VIF support:**
The tool automatically checks at startup and shows VIF status in the main menu. You can also check manually:
```bash
iw list | grep "interface combinations"
# or
iw dev wlan0 interface add test_vif type monitor
iw dev test_vif del
```

---

## Custom Portal

The Evil Twin attack serves a captive portal HTML page to victims. You can customize this page without reflashing the ESP firmware.

### Using Built-in Templates

1. Select **option 5** from the main menu
2. Pick a template by number:

| # | Template | Description |
|---|----------|-------------|
| 1 | `wifi_update` | Generic Wi-Fi login page |
| 2 | `facebook` | Facebook-style login |
| 3 | `hotel` | Hotel guest Wi-Fi portal |
| 4 | `corporate` | Corporate 802.1X authentication |
| 5 | `minimal` | Clean minimal design |

3. Confirm to upload to ESP
4. The portal is active immediately

### Using Your Own HTML

1. Select **option 5** from the main menu
2. Press **C** to load from file
3. Enter the path to your `.html` file
4. Confirm to upload

**Requirements for custom HTML:**
- Max size: **4096 bytes**
- Must POST the password as a field named `name`
- Must poll `/status` for `OK` or `NO` response

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
| `ATTACK OFF` | → ESP | Stop attack |
| `HOST <ssid> <ch>` | → ESP | Start Evil Twin AP |
| `OK` | → ESP | Accept captured password |
| `NO` | → ESP | Reject captured password |
| `STOP` | → ESP | Stop all operations |
| `SET_HTML <length>` | → ESP | Upload custom portal HTML |
| `CLEAR_HTML` | → ESP | Revert to default portal |
| `[CAPTURED] <data>` | ESP → | Captured password |
| `[READY] SEND_HTML` | ESP → | Ready to receive HTML bytes |
| `[SUCCESS] HTML_SAVED <n>` | ESP → | HTML saved to LittleFS |
| `[EVENT] VICTIM_CONNECTED` | ESP → | Client connected to AP |

---

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
scanning:
  channel_hop_interval: 0.5   # Seconds between channel hops
  timeout: 60                  # Scan duration

attacks:
  deauth_packets: 50           # Packets per deauth burst
  handshake_timeout: 120       # Seconds to wait for handshake

database:
  path: "wifi_db.json"         # Database file location

esp32:
  baudrate: 115200             # Serial speed

output:
  handshakes_dir: "handshakes" # Where .pcap files are saved
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
| scapy | 2.7.0 | Packet manipulation |
| pyserial | 3.5 | Serial communication |
| PyYAML | 6.0.3 | Configuration |

### System
| Tool | Purpose | Install |
|------|---------|---------|
| iw | Wireless interface config | `apt-get install iw` |
| aircrack-ng | Handshake verification | `apt-get install aircrack-ng` |
| hcxpcapngtool | Hash conversion (hcxtools) | `apt-get install hcxtools` |
| hostapd | Software Evil Twin AP | `apt-get install hostapd` |
| dnsmasq | Software Evil Twin DHCP/DNS | `apt-get install dnsmasq` |

---

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Unauthorized access to computer networks is illegal. Always obtain explicit permission before testing on any network you do not own.

---

## Credits

- **Deportal2**: Firmware base — [CDFER/Captive-Portal-ESP32](https://github.com/CDFER/Captive-Portal-ESP32)
- **ESP32-Deauther**: Deauth framework — [tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther)
- Thanks to the open-source security community
