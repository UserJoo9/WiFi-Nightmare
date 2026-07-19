# WiFi-Nightmare v2.0.2 — Project Map

> Last updated: 2025-12-22

## TECH_STACK

| Layer | Technology |
|-------|-----------|
| Language | Python 3.9+ |
| Packet injection | scapy 2.7.0 |
| Serial comm | pyserial 3.5 |
| Config | PyYAML 6.0.3 (optional) |
| Wireless mgmt | iw (CLI) |
| Handshake verify | aircrack-ng (CLI) |
| Hash conversion | hcxpcapngtool (CLI) |
| Native capture | airodump-ng + mdk4/mdk3/aireplay-ng |
| MCU firmware | C++ (Arduino/PlatformIO) |
| ESP32 lib | AsyncTCP, ESPAsyncWebServer |
| ESP8266 lib | ESPAsyncTCP, ESPAsyncWebServer |
| Flash storage | LittleFS |
| DNS captive portal | DNSServer |

## PROJECT STATS

| Category | Files | Lines |
|----------|-------|-------|
| Python (app + tests) | 20 | 4,684 |
| ESP8266 firmware (src+hdr+html) | 12 | 1,203 |
| ESP32 firmware (src+hdr) | 12 | 821 |
| Config files | 9 | 178 |
| **Total** | **53** | **6,886** |

## DIRECTORY STRUCTURE

```
WiFi-Nightmare/
├── .gitignore                          Project-level git ignore
├── CHANGELOG.md                        Version history
├── PROJECT_MAP.md                      This file
├── README.md                           Usage & installation guide
│
├── WiFi-Nightmare/                     Python application package
│   ├── __init__.py                     Package marker
│   ├── main.py              (856)      WifiGTR orchestrator + menu loop
│   ├── config.py            (87)       YAML loader + ANSI color constants
│   ├── config.yaml          (24)       User configuration
│   ├── requirements.txt     (26)       Pinned Python dependencies
│   ├── database.py          (102)      DatabaseHandler: JSON CRUD
│   ├── scanner.py           (249)      NetworkScanner + ClientMonitor
│   ├── deauth.py            (67)       BaseAttacker: raw deauth frames
│   ├── handshake.py         (299)      NetworkAttacker: handshake capture
│   ├── eviltwin.py          (269)      EvilTwinAttack: ESP-driven captive portal
│   ├── evil_twin_software.py (712)     SoftwareEvilTwin: hostapd+dnsmasq+httpd
│   ├── capture_native.py    (147)      Native handshake capture (airodump-ng+mdk4)
│   ├── esp_driver.py        (240)      ESP32Driver: serial protocol handler
│   ├── portals.py           (607)      9 real-brand captive portal templates + default
│   ├── attacks.py           (5)        Compatibility shim (re-exports)
│   ├── dep_check.py         (44)       Runtime dependency validator
│   ├── logger.py            (61)       RotatingFileHandler setup
│   ├── ui.py                (137)      CLI display (menu, tables, colors)
│   ├── utils.py             (334)      SignalManager, iw wrapper, monitor mode etc.
│   ├── vendors.py           (337)      MAC vendor lookup (file + cache + async HTTP)
│   ├── vif_check.py         (120)      Virtual Interface support detection
│   ├── mac-vendor.txt        —         Large OUI→vendor mapping file
│   ├── wifi_db.json                   Known networks database
│   ├── vendors_cache.json             MAC vendor cache
│   └── handshakes/                    Captured .pcap + .hc22000 files
│
├── tests/
│   └── test_core.py        (100)      Unit tests: DatabaseHandler, VendorLookup, etc.
│
├── ESP32-DePortal2/                   ESP32 firmware (PlatformIO)
│   ├── platformio.ini                 Build config
│   ├── src/main.cpp          (29)     setup()+loop()
│   ├── src/deauth.cpp         (7)     ieee80211_raw_frame_sanity_check bypass
│   ├── src/general.cpp       (13)     blink_led()
│   ├── src/serial_handler.cpp(457)    Serial protocol: ATTACK, HOST, SET_HTML etc.
│   ├── src/state.cpp          (3)     Global variable definitions
│   ├── include/definitions.h (34)     Macros: AP_SSID, LED, etc.
│   ├── include/types.h       (33)     Structs: deauth_frame_t, mac_hdr_t
│   ├── include/deauth.h      (16)     start_deauth/stop_deauth declarations
│   ├── include/serial_handler.h (9)   serial_cmd_init/handle declarations
│   ├── include/state.h       (13)     ScanMode enum, extern variables
│   ├── include/html_content.h(79)     Inline default captive portal HTML
│   └── include/web_html.h   (128)     Inline web UI HTML
│
└── ESP8266-DePortal2/                 ESP8266 firmware (PlatformIO)
    ├── platformio.ini                 Build config
    ├── src/main.cpp          (28)     setup()+loop()
    ├── src/deauth.cpp         (7)     Same bypass
    ├── src/general.cpp       (13)     blink_led()
    ├── src/serial_handler.cpp(477)    Same serial protocol (+8 lines vs ESP32)
    ├── src/state.cpp          (3)     Global variables
    ├── include/definitions.h (32)     Same as ESP32
    ├── include/types.h       (56)     Structs (+23 lines vs ESP32 for wifi_promiscuous_pkt_t)
    ├── include/serial_handler.h (9)   Same
    ├── include/state.h       (13)     Same
    ├── include/html_content.h(79)     Same inline HTML
    ├── include/web_html.h   (128)     Same web UI
    └── data/index.html      (358)     Arabic captive portal (LittleFS)
```

## ARCHITECTURE

### Module Responsibilities

| Module | Lines | Classes | Purpose |
|--------|-------|---------|---------|
| `main.py` | 856 | `WifiGTR` | Orchestrator: start → monitor mode → VIF check → main loop → menu dispatch |
| `scanner.py` | 249 | `NetworkScanner`, `ClientMonitor` | Passive beacon capture, channel hopping, client tracking |
| `deauth.py` | 67 | `BaseAttacker` | Low-level deauth frame generation (broadcast + targeted) |
| `handshake.py` | 299 | `NetworkAttacker` | Deauth loop + scapy sniff + aircrack-ng verify + hcxpcapngtool |
| `eviltwin.py` | 269 | `EvilTwinAttack` | ESP-driven Evil Twin: deauth, sniffer, ESP serial commands |
| `evil_twin_software.py` | 712 | `SoftwareEvilTwin`, `PortalHTTPHandler` | Pure-software Evil Twin: hostapd AP, dnsmasq, HTTP portal, deauth |
| `capture_native.py` | 147 | — | airodump-ng + mdk4/aireplay-ng handshake capture, fallback chain |
| `esp_driver.py` | 240 | `ESP32Driver` | Serial protocol: ATTACK, HOST, SET_HTML, background reader thread |
| `portals.py` | 607 | — | 9 real-brand templates (tp-link, huawei, zte, dlink, tenda, vodafone, etisalat, we, orange) + custom + default |
| `database.py` | 102 | `DatabaseHandler` | JSON CRUD: load/save/get_info/update_handshake with BSSID validation |
| `utils.py` | 334 | `SignalManager` | run_command, _get_iw_mode, enable_monitor_mode, restore_managed_mode, verify_password, generate_hc22000 |
| `vendors.py` | 337 | — | 3-tier vendor lookup: internal DB → file cache → async HTTP |
| `vif_check.py` | 120 | — | VIF detection via `iw list` parsing + interface creation test |
| `ui.py` | 137 | — | print_main_menu (4 options), print_target_menu (7+0), print_scan_table, etc. |
| `config.py` | 87 | — | load_config(), ANSI colors, constants |
| `dep_check.py` | 44 | — | Runtime dependency check (aircrack-ng, hcxpcapngtool, iw, hostapd, dnsmasq, mdk4, airodump-ng) |
| `logger.py` | 61 | `ColoredFormatter` | RotatingFileHandler (1MB × 5 backups) + colored console |
| `attacks.py` | 5 | — | Shim: `from deauth import *; from handshake import *; from eviltwin import *` |

### Dependency Graph

```
vendors.py ──> config.py
     │
     v
utils.py ───> config.py, logger.py, vendors.py
     │
     v
deauth.py ───> logger.py
  │
  v
handshake.py ──> deauth.py, config.py, utils.py, logger.py
  │
  v
eviltwin.py ──> deauth.py, config.py, utils.py, logger.py
  │
  v
capture_native.py ──> config.py, logger.py
  │
  v
scanner.py ──> config.py, utils.py, logger.py
  │
  v
esp_driver.py ──> config.py, logger.py
  │
  v
vif_check.py ──> logger.py
  │
  v
evil_twin_software.py ──> config.py, utils.py, logger.py, portals.py
  │
  v
database.py ──> config.py, logger.py
  │
  v
portals.py ──> (stdlib only)
  │
  v
ui.py ──> config.py
  │
  v
main.py ──> [EVERYTHING above]
```

### Attack Flow (Software Evil Twin)

```
main.py: scan_workflow()
  ├── enable_monitor_mode()           ← NEW: always restores monitor before scan
  ├── run_scanner_process()           → scanner.py: passive sniff
  ├── select_target_from_list()
  └── User selects option 7           → run_software_eviltwin()
        ├── Portal selection          → portals.py: pick template
        ├── SoftwareEvilTwin.run()
        │   ├── _create_ap_interface() → airmon-ng + iw phy + hostapd fallback
        │   ├── hostapd on wlan0       → managed mode (AP)
        │   ├── dnsmasq DHCP+DNS       → redirects all DNS to 10.0.0.1
        │   ├── HTTP server            → serves captive portal on :80
        │   └── deauth thread          → scapy → mdk4 → aireplay-ng fallback chain
        ├── _status_display()          → "AP clients: X | Tried: Y | Deauth:Z"
        └── PASSWORD found             → verify_password() → save to cracked.txt
```

### Signal Flow

```
SIGINT ──→ main.py catch KeyboardInterrupt ──→ self.cleanup()
   cleanup():
     ├── ESP stop_all() + close()
     ├── restore_managed_mode(original_interface)
     └── sys.exit()

evil_twin_software.py catch KeyboardInterrupt ──→ _cleanup()
   _cleanup():
     ├── stop_attack flag
     ├── HTTP server shutdown
     ├── kill hostapd + dnsmasq
     ├── iw del AP interface
     └── restore managed mode
```

## SERIAL PROTOCOL (Python ↔ ESP)

| Command | Direction | Description |
|---------|-----------|-------------|
| `ATTACK <bssid> <ch> <dur>` | Python→ESP | Start deauth attack on BSSID |
| `ATTACK OFF` | Python→ESP | Stop deauth attack |
| `HOST <ssid> <ch>` | Python→ESP | Start Evil Twin AP |
| `OK` | Python→ESP | Accept captured password |
| `NO` | Python→ESP | Reject captured password |
| `STOP` | Python→ESP | Stop all operations |
| `SET_HTML <length>` | Python→ESP | Upload custom portal HTML (max 4096 bytes) |
| `CLEAR_HTML` | Python→ESP | Revert to default (built-in) portal |
| `[CAPTURED] <data>` | ESP→Python | Captured password/data |
| `[READY] SEND_HTML` | ESP→Python | Ready to receive HTML bytes |
| `[SUCCESS] HTML_SAVED <n>` | ESP→Python | HTML saved to LittleFS |
| `[EVENT] VICTIM_CONNECTED` | ESP→Python | Client connected to fake AP |
| `[SYSTEM] READY` | ESP→Python | Boot complete, ready for commands |

## CURRENT FEATURES

### Scan & Reconnaissance
- Passive 802.11 beacon/probe capture via scapy on monitor mode
- Channel hopping (configurable interval: 0.5s)
- Client MAC tracking per network
- MAC → vendor resolution (3-tier lookup)
- Client monitor (live real-time view)

### Attacks
- **Deauth**: Broadcast + targeted deauth via scapy
- **Handshake capture** (2 methods):
  1. Scapy-based: deauth loop + sniff + aircrack-ng verify
  2. Native: airodump-ng background + mdk4/aireplay-ng + aircrack-ng poll
- **PMKID attack**: capture PMKID from RSNE
- **Evil Twin (ESP)**: ESP-driven AP + Python deauth coordinator
- **Evil Twin (Software)**: Pure Python: hostapd AP + dnsmasq + HTTP portal + scapy/mdk4 deauth

### Software Evil Twin Details
- **AP creation**: 4 fallback methods (iw phy → iw dev → managed switch → airmon-ng)
- **Hostapd**: Manages AP interface in managed mode
- **Dnsmasq**: DHCP + DNS (redirect all DNS to AP IP)
- **HTTP Server**: Serves captive portal, accepts password via POST, verifies against handshake
- **Deauth**: 3-method chain (scapy sendp → mdk4 → aireplay-ng)
- **Portal templates**: 9 real-brand templates + custom + default
- **Limitation**: AR9271 (ath9k_htc) doesn't support VIF — runs portal-only on same interface

### Captive Portals
- **9 real-brand templates**: TP-Link (teal #4ACBD6), Huawei (red #CF0A2C), ZTE (blue #008ED3), D-Link (teal #0087A9), Tenda (red #E4002B), Vodafone (red #E60000), e&/Etisalat (red #E00800), WE (purple #5B2C66), Orange (#FF7900)
- **Custom portal**: load from `custom_portal.html` file
- **Default**: built-in minimal portal
- Each template has inline SVG logo, brand colors, realistic model numbers, 3-state UI

### ESP Support
- ESP32 and ESP8266 dual firmware
- Serial protocol: deauth, Evil Twin AP, custom HTML upload
- LittleFS for persistent custom portal storage
- Custom HTML limit: 4096 bytes (ESP firmware hard limit)

### Utilities
- Database (JSON): save/load network info, handshake tracking
- Vendor lookup: 3-tier (internal DB → file cache → async HTTP)
- Dependency check at startup
- Rotating file logs (1MB × 5 backups)
- Signal handling via SignalManager context manager
- VIF detection for Software Evil Twin compatibility

## FILES CREATED THIS SESSION

- `WiFi-Nightmare/evil_twin_software.py` — Software Evil Twin engine
- `WiFi-Nightmare/capture_native.py` — Native handshake via airodump-ng+mdk4
- `WiFi-Nightmare/vif_check.py` — Virtual Interface support detection

## FILES MODIFIED THIS SESSION

- `WiFi-Nightmare/main.py` — enable_monitor_mode in scan_workflow, cleanup uses original_interface, global KbInterrupt handler, custom portal menu removed
- `WiFi-Nightmare/evil_twin_software.py` — simplified output, deauth always attempts (3 methods), real AP client count, password tracking
- `WiFi-Nightmare/portals.py` — complete rewrite: 9 real-brand SVG logos + accurate brand colors (TEAL, RED, BLUE, PURPLE, ORANGE)
- `WiFi-Nightmare/ui.py` — option 5 removed from main menu
- `WiFi-Nightmare/dep_check.py` — mdk4 and airodump-ng added as optional deps
- `WiFi-Nightmare/utils.py` — restore_managed_mode, original_interface tracking
- `README.md` — comprehensive rewrite
- `CHANGELOG.md` — all changes documented

## OUTSTANDING & PENDING

### Bugs
- AR9271 (ath9k_htc) can't create VIF — deauth may silently fail on managed mode
- No interface mode re-validation after long operations

### Missing Features
- No checksum/CRC on ESP serial commands
- No integration tests
- No CI/CD pipeline

### To Increase ESP HTML Limit
- `ESP32-DePortal2/src/serial_handler.cpp:400` — `4096` → `8192`
- `ESP8266-DePortal2/src/serial_handler.cpp:420` — `4096` → `8192`
- `WiFi-Nightmare/esp_driver.py:143-144` — `4096` → `8192`
- `WiFi-Nightmare/main.py:794-795,803` — `4096` → `8192`
