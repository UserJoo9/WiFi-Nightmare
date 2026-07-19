# Changelog

All notable changes to WiFi-Nightmare will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.2.0] - 2026-07-19

### Added
- **Debian/APT packaging** — WiFi-Nightmare is now installable via `apt install wifi-nightmare`
- **APT repository** — Hosted on GitHub Pages, one-liner setup: `curl -sSL https://youssefalkhodary.github.io/wifi-nightmare/install.sh | sudo bash`
- **`wifi-nightmare` CLI command** — Console script entry point replaces `python3 main.py`
- **`python3 -m wifi_nightmare`** — Alternative execution method
- **`wifi-nightmare flash-esp`** — One-command ESP firmware flashing via esptool (no PlatformIO needed)
- **`esp_firmware/`** — Pre-compiled ESP32/ESP8266 firmware binaries bundled with the package
- **`debian/`** — Full Debian packaging directory with proper dependency declarations
- **`install.sh`** — APT repository setup script for one-liner install
- **`pyproject.toml`** — Python build configuration with setuptools
- **GitHub Actions workflow** — Automatic .deb build and APT repo update on version tags

### Changed
- Python package renamed from `WiFi-Nightmare/` → `wifi_nightmare/` (valid Python module name)
- All internal imports updated to use `from wifi_nightmare.xxx import ...` format
- Runtime data paths moved to `~/.wifi-nightmare/` (dev) or `/var/lib/wifi-nightmare/` (installed)
- Configuration loading: package defaults → `/etc/wifi-nightmare/config.yaml` override (installed mode)
- `requirements.txt` replaced by `pyproject.toml` `[project.dependencies]`
- `esptool>=4.0` added as a dependency for ESP firmware flashing

### Fixed
- `__init__.py` now correctly reports version `2.1.0` instead of stale `2.0.2`

### Added
- **Software Evil Twin (VIF)** — Run Evil Twin without ESP hardware if adapter supports Virtual Interfaces
- **VIF detection** — Automatic detection of Virtual Interface support at startup
- `vif_check.py` — Detects VIF via `iw list` and interface creation test
- `evil_twin_software.py` — Software Evil Twin using hostapd + dnsmasq + Python HTTP + scapy deauth
- Menu option 7 in target menu — Software Evil Twin (shows availability based on VIF support)
- Main menu now shows VIF status alongside ESP status
- `dep_check.py` — Now checks for optional hostapd/dnsmasq availability
- **Custom Captive Portal** — Upload your own HTML portal to ESP without reflashing
- **5 built-in portal templates**: wifi_update, facebook, hotel, corporate, minimal
- **Portal customization menu** (Option 5 in main menu)
- `SET_HTML <length>` serial command — receive raw HTML bytes and save to LittleFS
- `CLEAR_HTML` serial command — revert to default portal
- `send_custom_portal()` and `clear_custom_portal()` in esp_driver.py
- `portals.py` — template system with size validation (max 4096 bytes)
- `SignalManager` context manager — replaces manual signal.getsignal/signal.signal pattern
- `dep_check.py` — runtime dependency checker (aircrack-ng, hcxpcapngtool, iw)
- `__init__.py` — proper Python package marker
- `tests/test_core.py` — unit tests for database, vendors, config, SignalManager
- `PROJECT_MAP.md` — full architecture documentation
- `CHANGELOG.md` — this file
- ESP firmware: `SET_HTML` handler — reads exact byte count into LittleFS `/custom.html`
- ESP firmware: `CLEAR_HTML` handler — deletes `/custom.html` from LittleFS
- ESP firmware: Server checks `/custom.html` first, falls back to default
- ESP firmware: MAC validation in `strToMac()` — returns `bool`, rejects invalid octets
- ESP firmware: `volatile bool target_seen` → `std::atomic<bool>` for ESP32 dual-core safety

### Changed
- **Split `attacks.py`** into `deauth.py` (BaseAttacker), `handshake.py` (NetworkAttacker), `eviltwin.py` (EvilTwinAttack) — original retained as compatibility shim
- **Eliminated all wildcard imports** — `from config import *` replaced with explicit imports in all files
- **Standardized on `iw`** — removed all `iwconfig` calls from Python code (main.py, attacks.py, utils.py)
- **Pinned dependency versions** in requirements.txt — scapy==2.7.0, pyserial==3.5, PyYAML==6.0.3
- **RotatingFileHandler** logging — 1MB files, 5 backups, replaces timestamped log files
- **Non-blocking vendor lookup** — `vendors.py` HTTP API call moved to background thread
- **Signal handling** — `run_scanner_process()`, `run_attack()`, `run_mass_attack()` all use `SignalManager`
- `main.py` — menu option 5 added for portal customization
- `ui.py` — portal menu display function added
- `esp_driver.py` — added `_last_response`, `_response_event`, `_read_line()`, `send_custom_portal()`, `clear_custom_portal()`
- ESP firmware (both) — root handler serves `/custom.html` if exists, else `/index.html`
- README.md — completely rewritten with full usage guide

### Fixed
- `.gitignore` typo — `vendonrs_cache.json` → `vendors_cache.json`
- ESP firmware dead code — `state.cpp` files cleaned for both ESP32 and ESP8266
- Arabic comments removed from ESP firmware serial handlers
- Legacy `wireless-tools` references removed from requirements.txt

### Removed
- `iwconfig` usage from all Python files (replaced by `iw`)
- Manual `signal.getsignal/signal.signal` patterns (replaced by SignalManager)
- Blocking HTTP calls in vendor lookup (replaced by background thread)
- Dead code in ESP state.cpp files
