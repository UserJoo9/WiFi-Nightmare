# WiFi-Nightmare

Advanced WiFi security auditing, multi-vector eviction, and penetration testing suite for Linux.

Combines standard 802.11 attack vectors (monitor mode & packet injection) with an automated captive portal engine and optional ESP32 / ESP8266 hardware acceleration.

---

## Features

- **Recon & Handshakes**: 2.4 GHz & 5 GHz scanning, WPA/WPA2/WPA3 4-way handshake capture, and clientless PMKID harvesting.
- **Eviction & Deauth**: Targeted and broadcast deauth flooding, CSA (Channel Switch Announcement), and BTM (802.11v) frames to bypass 802.11w PMF.
- **Rogue AP & Evil Twin**: Software Evil Twin with automated multi-OS captive portal (Android, iOS, Windows, macOS), or hardware-offloaded via ESP32/ESP8266.
- **WPS Suite**: Pixie Dust offline PIN recovery, Push-Button (PBC) sniffer, and algorithmic default PIN generators.
- **Specialized Attacks**: Karma probe-response attack, Beacon Flooding, and WPA-Enterprise rogue RADIUS credential harvesting.
- **Interface**: Rich TUI live dashboard with signal strength bars, manufacturer OUI resolution, and automated wordlist generation.

---

## Installation

### One-Line Install (Recommended)

```bash
curl -sSL https://userjoo9.github.io/WiFi-Nightmare/install.sh | sudo bash
```

### Manual APT Repository Setup

```bash
sudo apt update && sudo apt install -y curl
echo "deb [trusted=yes] https://userjoo9.github.io/WiFi-Nightmare stable main" | sudo tee /etc/apt/sources.list.d/wifi-nightmare.list
sudo apt update && sudo apt install -y wifi-nightmare
```

### Update

```bash
sudo apt update && sudo apt upgrade wifi-nightmare
```

### Uninstall

```bash
sudo apt purge wifi-nightmare
sudo rm -f /etc/apt/sources.list.d/wifi-nightmare.list
```

---

## Usage

```bash
# Launch with standard WiFi interface
sudo wifi-nightmare wlan0

# Launch with optional ESP hardware acceleration
sudo wifi-nightmare wlan0 /dev/ttyUSB0

# Flash firmware to connected ESP board
sudo wifi-nightmare flash-esp /dev/ttyUSB0 --board esp32
```

> **Note:** Monitor mode is handled automatically on startup. Run `iw dev` to find your wireless interface name.

---

## Hardware Requirements

- **Linux OS**: Kali Linux, Debian, Ubuntu, or ParrotOS.
- **Wireless Adapter**: Must support **Monitor Mode** and **Packet Injection**.
  - Recommended chipsets: **RTL8812AU** (e.g. Alfa AWUS036ACH), **AR9271** (e.g. TP-Link TL-WN722N v1), **MT7612U**.
  - Built-in laptop cards generally do not support packet injection; an external USB adapter is strongly recommended.
- **(Optional) ESP Board**: NodeMCU ESP8266 or ESP32 dev board (CP2102 / CH340 serial).

---

## Disclaimer

This software is designed solely for authorized network auditing and educational security research. Unauthorized use against networks without prior written permission is illegal.

---

## License

Released under the [MIT License](LICENSE).