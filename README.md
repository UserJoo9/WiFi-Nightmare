# WiFi-Nightmare

**v3.0.0** — Advanced WiFi security auditing, multi-vector eviction, and penetration testing suite.

Combines modern 802.11 attack vectors (CSA/BTM eviction, WPS Push-Button sniffing, multi-card coordination) with an enterprise Captive Portal engine and optional ESP32/ESP8266 hardware acceleration.

## What's New in v3.0

- **PMKID Attack (Clientless WPA2)** — Active harvesting of PMKID hashes directly from AP Association frames without waiting for connected clients or sending deauth frames.
- **Karma Attack** — Automatically responds to device 802.11 Probe Requests to lure surrounding devices into connecting automatically.
- **Beacon Flooding** — High-speed transmission of thousands of fake AP beacons with common SSIDs or cloned target SSIDs.
- **WPA-Enterprise Fake RADIUS** — Harvests 802.1X corporate credentials (PEAP/TTLS) via an embedded rogue RADIUS authentication server.
- **Smart Wordlists & Auto-Rockyou** — Dynamic SSID-pattern password candidates, MENA/ISP vendor defaults (WE, Vodafone, Orange, Etisalat), and automatic rockyou.txt retrieval.
- **Session Export (JSON / CSV / Reports)** — Complete structured reporting and database export for post-engagement audits.
- **Rich TUI Live Dashboard** — High-resolution terminal visualization with RSSI signal bars, color-coded security badges, and live event monitoring.
- **Geo-Location BSSID Lookup** — Query physical coordinates and map URLs using Wigle.net and OpenWifi APIs.
- **Multi-Vector Eviction (Deauth + CSA + BTM)** — Bypasses 802.11w PMF (Protected Management Frames) by injecting Channel Switch Announcements (IE 37) and 802.11v BTM frames.
- **WPS Push-Button (PBC) Sniffer** — Automatically detects when someone presses the physical WPS button on the router and extracts plaintext credentials instantly.
- **Algorithmic Known-PINs** — Built-in generators for ComputePIN, D-Link, and EasyBox default PIN algorithms.
- **Multi-Card Aggregation Engine** — Automatic detection and coordination of dual adapters (Dedicated Sniffer + Dedicated Injector).
- **Enterprise Captive Portal (RFC 8908)** — Bypass CNA on modern devices (Samsung One UI, iOS 18, ColorOS, MIUI) with HTTPS Cloudflare tunnels.

---

## Quick Install

```bash
curl -sSL https://userjoo9.github.io/WiFi-Nightmare/install.sh | sudo bash
```

Or manually:
```bash
sudo apt update && sudo apt install -y curl
echo "deb [trusted=yes] https://userjoo9.github.io/WiFi-Nightmare stable main" | sudo tee /etc/apt/sources.list.d/wifi-nightmare.list
sudo apt update && sudo apt install wifi-nightmare
```

### Update
```bash
sudo apt update && sudo apt upgrade wifi-nightmare
```

### Uninstall
```bash
sudo apt purge wifi-nightmare
sudo rm -f /etc/apt/sources.list.d/wifi-nightmare.list /usr/share/keyrings/wifi-nightmare.gpg
```

---

## Usage

```bash
sudo wifi-nightmare wlan0              # Standalone mode
sudo wifi-nightmare wlan0 /dev/ttyUSB0 # With ESP module
sudo wifi-nightmare flash-esp /dev/ttyUSB0 --board esp32  # Flash ESP firmware
```

- The tool detects your hardware at startup and shows only available attacks
- No need to run `airmon-ng` — monitor mode is handled automatically
- Find your interface: `iw dev`
- Find your ESP port: `ls /dev/ttyUSB* /dev/ttyACM*`

---

## Target Menu Options

Once you select a network, the target menu offers:

| Option | Action | Requires |
|--------|--------|----------|
| `1` | Capture Handshake (WPA/WPA2/WPA3) | Monitor + injection |
| `2` | Reveal Hidden SSID | Monitor + injection |
| `3` | Multi-Vector Eviction (Deauth + CSA + BTM) | Monitor + injection |
| `4` | Passive Listen | Monitor |
| `5` | Generate hc22000 | Captured handshake |
| `6` | Evil Twin (ESP) | ESP connected |
| `7` | Evil Twin (Software) | VIF + hostapd + dnsmasq |
| `8` | WPS Suite (Pixie Dust / Push-Button PBC / Known-PIN) | reaver / pixiewps |
| `9` | Crack Handshake (aircrack-ng + Wordlist) | Captured handshake |
| `10` | WPA3 Downgrade Attack (Clone AP + CSA Eviction) | Monitor + injection |
| `11` | **PMKID Attack (Clientless WPA2 Harvesting)** | Monitor + injection |
| `12` | **Karma Attack (Probe Request Responder)** | Monitor + injection |
| `13` | **Beacon Flood (Clone / Common SSID Storm)** | Monitor + injection |
| `14` | **WPA-Enterprise Evil Twin (Fake RADIUS Harvest)** | hostapd + openssl |
| `15` | **Smart Crack (SSID-Smart Wordlist + Rockyou)** | Captured handshake |

---

## Hardware Compatibility

| Feature | Requires |
|---------|----------|
| Scanning / Deauth / Handshake | Monitor mode + packet injection |
| Software Evil Twin | VIF support + hostapd + dnsmasq |
| ESP Evil Twin | ESP32/ESP8266 over serial |
| Pixie Dust (WPS) | reaver + pixiewps |

### Adapter Compatibility Guide

| Chipset | Example Adapter | Monitor | Injection | VIF / AP | Rating |
|---------|----------------|:-------:|:---------:|:--------:|:------:|
| **RTL8812AU** | Alfa AWUS036ACH | ✅ | ✅ | ✅ | ⭐ Full |
| **RTL8814AU** | Alfa AWUS1900 | ✅ | ✅ | ✅ | ⭐ Full |
| **RTL8821AU** | Comfast CF-912AC | ✅ | ✅ | ✅ | ⭐ Full |
| **AR9271** | TP-Link TL-WN722N v1 | ✅ | ✅ | ✅ | ⭐ Full |
| **RTL8187** | Alfa AWUS036H | ✅ | ✅ | ❌ | ⚡ Basic |
| **RTL8188EU** | TP-Link TL-WN725N | ✅ | ✅ | ❌ | ⚡ Basic |

🟢 **Full** = All features including Software Evil Twin (AP + monitor VIFs simultaneously)<br>
⚡ **Basic** = Scanning, deauth, handshake, pixie dust — no Virtual AP

> Built-in laptop WiFi cards usually **don't support monitor mode**. Get an external USB adapter. For full support, pick RTL8812AU (Alfa AWUS036ACH) or TL-WN722N v1 (AR9271).

---

## Captive Portal Support

The software Evil Twin captive portal triggers automatically on:

| OS / OEM | Probe Path | Method |
|----------|-----------|--------|
| Android / Google | `/generate_204`, `/gen_204` | 302 Redirect |
| Samsung One UI | `/check_network_status.txt` | 302 Redirect |
| Apple iOS / macOS | `/hotspot-detect.html` | 302 Redirect |
| Oppo / ColorOS | `/mobile/status.php` | 302 Redirect |
| Xiaomi / MIUI / HyperOS | `/connectivity-check.html` | 302 Redirect |
| Vivo / Funtouch | `/checklink` | 302 Redirect |
| Windows NCSI | `/ncsi.txt`, `/connecttest.txt` | Non-matching body |
| RFC 8908 (CAPPORT API) | `/.well-known/captiveportal/api` | JSON `captive: true` |
| Amazon Kindle | `/kindle-wifi/wifistub.html` | Portal page |

> **Modern devices (Android 14+, One UI 6+, iOS 16+):** Port 443 is rejected with a TCP Reset so HTTPS-first probes fail fast and immediately fall back to the HTTP portal. DHCP option 114 (CAPPORT API) is only advertised when a valid public HTTPS tunnel (cloudflared) is active.

---

## Development Setup

```bash
git clone https://github.com/UserJoo9/WiFi-Nightmare.git
cd WiFi-Nightmare
sudo apt-get install aircrack-ng hcxtools iw hostapd dnsmasq reaver pixiewps
pip install -e .
sudo wifi-nightmare wlan0
```

**Run tests:**
```bash
pip install pytest && python3 -m pytest tests/
```

---

## Project Structure

```
WiFi-Nightmare/
├── wifi_nightmare/         # Python package (CLI, attacks, ESP driver, UI)
├── esp_firmware/           # Pre-compiled ESP32/ESP8266 firmware binaries
├── ESP32-DePortal2/        # ESP32 firmware source (PlatformIO project)
├── ESP8266-DePortal2/      # ESP8266 firmware source (PlatformIO project)
├── debian/                 # Debian packaging files
├── install.sh              # APT repo one-liner setup
└── pyproject.toml          # Python build configuration
```

---

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Unauthorized access to computer networks is illegal. Always obtain explicit permission before testing.

## License

Released under the [MIT License](LICENSE). See the [LICENSE](LICENSE) file for the full text.

## Credits

- **Deportal2**: [CDFER/Captive-Portal-ESP32](https://github.com/CDFER/Captive-Portal-ESP32)
- **ESP32-Deauther**: [tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther)