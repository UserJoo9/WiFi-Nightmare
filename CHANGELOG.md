# Changelog

All notable changes to WiFi-Nightmare will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.1.2] - 2026-09-29

### Added
- **Aircrack-ng wordlist cracking** (Option 9 in target menu) — crack a captured handshake directly from the target menu with a custom wordlist; live output streamed to terminal, result saved to `cracked.txt`
- **Captive portal detection for Oppo/ColorOS** — added `/mobile/status.php` and `/status.php` probe paths
- **Captive portal detection for Xiaomi/MIUI/HyperOS** — added `/connectivity-check.html` probe path
- **Captive portal detection for Vivo/Funtouch** — added `/checklink` probe path

### Fixed
- **Captive portal not triggering on modern devices** (Android 14/15, Samsung One UI 6/7, iOS, ColorOS)
  - Disabled DHCP Option 114 when no valid HTTPS tunnel is available (plain `http://` URL in option 114 suppresses Android 11+ captive-portal detection)
  - Port 443 now rejected with TCP Reset via iptables (`FORWARD` + `INPUT` chains) so HTTPS-first probes fail fast and immediately fall back to HTTP port 80
  - All OS probe endpoints (Android, Apple, Samsung, Windows, Kindle) now respond with `302 Found` + `Location` header instead of a plain `200 OK` page
- **Captive portal reporting password incorrect when it is correct** — removed `-b` / `-e` filters from `aircrack-ng` verification call; ESSID exact-match was silently zeroing the handshake on hidden networks and SSIDs with unusual characters or whitespace
- **Deauth not working with single-card setup (TL-WN722N v1 / Atheros AR9271)**
  - `_create_ap_interface()` now creates a dedicated AP interface (`wlan0_ap`) and a simultaneous monitor interface (`wlan0mon`) on the same physical chip via `iw phy … interface add`
  - Fallback path: convert base interface to `__ap` mode then add a virtual monitor interface
  - Second fallback: `airmon-ng start` for non-mac80211 drivers
  - `_cleanup()` removes both virtual interfaces and restores the card to managed mode cleanly
- **Hidden SSID not remembered after reveal** — `_refresh_ssid_from_db()` now syncs the live scan table from the database on every menu iteration so the revealed name persists without waiting for a new beacon
- **BSSID fully shown in Deauth output and other options** — `mask_bssid()` applied consistently across all print statements in `main.py`, `ui.py`, `scanner.py`, and attack modules; deauth summary and all attack logs now show masked form only
- **Spaces stripped from captured Evil Twin passwords** — password is preserved exactly as typed (only `\r\n` stripped, not leading/trailing spaces which are valid WPA passphrase characters)

## [2.1.1] - 2026-08-07

### Added
- **BSSID masking** — all BSSIDs masked to first/last octet only (e.g. `30:99:35:8e:16:6b` → `30:xx:xx:xx:xx:6b`) across the entire TUI and exported files for privacy
- **SSID-based export filenames** — handshakes, pixie dust logs, and hc22000 files named by network name instead of full BSSID
- **Deauth tool error surfacing** — mdk4/mdk3/aireplay-ng failures now printed instead of failing silently

### Changed
- **Faster handshake capture** — kick-once + long silent window strategy (burst then 30s quiet) with 1s polling, so slow-reconnecting clients aren't re-kicked mid-handshake
- **Pixie Dust** — accurate WPS lock-state parsing from wash table, quote-stripped PIN/PSK extraction, and post-mortem failure diagnosis (M1/M3/pixiewps)
- **VIF support check** — PHY-scoped `iw list` parsing so multi-interface support isn't misreported when any adapter on the machine advertises it
- **Menus** — removed emoji icons from all menus

## [2.1.0] - 2026-07-19

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
