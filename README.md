# WiFi-Nightmare

**v2.1.0** — Advanced WiFi security auditing and penetration testing tool.

Combines a Python CLI with optional ESP32/ESP8266 firmware for Evil Twin, Deauthentication, Handshake capture, WPS Pixie Dust, and captive portal attacks.

## Features

- **Network Scanning** — Discover WiFi networks and connected clients
- **Deauthentication Attacks** — scapy → mdk4 → aireplay-ng fallback chain
- **Handshake Capture** — WPA/WPA2 handshakes + Hashcat `.hc22000` conversion
- **SSID Reveal** — Decloak hidden networks
- **Evil Twin** — Fake AP to capture credentials (ESP or software-only with VIF)
- **Pixie Dust (WPS)** — WPS PIN recovery via reaver + pixiewps
- **Captive Portal** — Auto-detection for all major OEMs (Apple, Android, Samsung, Windows)
- **9 Branded Portal Templates** — TP-Link, Huawei, ZTE, D-Link, Tenda, Vodafone, Etisalat, WE, Orange
- **Custom Portal** — Upload your own HTML without reflashing ESP
- **Database** — Persistent JSON store for networks, handshakes, and WPS data
- **Mass Attack** — Automated deauth on multiple hidden networks

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
| **AR9271** | TP-Link TL-WN722N v1 | ✅ | ✅ | ❌ | ⚡ Basic |
| **RTL8187** | Alfa AWUS036H | ✅ | ✅ | ❌ | ⚡ Basic |
| **RTL8188EU** | TP-Link TL-WN725N | ✅ | ✅ | ❌ | ⚡ Basic |

🟢 **Full** = All features including Software Evil Twin<br>
⚡ **Basic** = Scanning, deauth, handshake, pixie dust — no Virtual AP

> Built-in laptop WiFi cards usually **don't support monitor mode**. Get an external USB adapter. For full support, pick RTL8812AU (Alfa AWUS036ACH).

---

## Development Setup

```bash
git clone https://github.com/YoussefAlkhodary/WiFi-Nightmare.git
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

## Credits

- **Deportal2**: [CDFER/Captive-Portal-ESP32](https://github.com/CDFER/Captive-Portal-ESP32)
- **ESP32-Deauther**: [tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther)