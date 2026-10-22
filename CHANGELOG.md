# Changelog

## [3.0.4] - 2026-10-22 — Evil Twin Interface-Corruption Disasters

### Bug fixes
- Handshake capture forgot previously-seen clients between deauth bursts,
  shrinking the target list and the on-screen client count (Bug 10)
- ESP-driven Evil Twin attack silently reverted the shared injector card to
  managed mode when it finished, breaking every later deauth/injection in
  the same run until the program was restarted (Bug 11)
- Software Evil Twin silently restored the primary radio to managed mode
  AND restarted NetworkManager when it finished, breaking every later
  scan/attack in the same run (Bug 12)
- WPA-Enterprise Evil Twin now checks the interface is in managed mode
  (and fixes it if not) before starting hostapd, instead of failing silently

## [3.0.3] - 2026-10-22 — Startup Adapter Detection Fix

### Bug fixes
- Startup: adapter-existence check silently accepted an unrelated, unrequested
  wireless card (hardcoded `wlan0`/`wlan0mon`/`mon0` fallback) instead of
  reporting that the requested antenna was missing or unplugged (Bug 9)
- Dual-card: monitor-mode "already enabled?" check could falsely match a
  leftover `wlan0mon` from the first card while preparing the second card,
  silently collapsing sniffer and injector onto the same physical adapter (Bug 9)

## [3.0.2] - 2026-10-19 — Dual-Card Interface Bug-Fix Pass

### Bug fixes
- **Dual-card: mass attack sniffed on injector card instead of sniffer (Bug 7)** — `run_scanner_process()` and `run_mass_attack()` were passing `self.interface` to `sniff()` in dual-card mode, which pointed to the primary injector card rather than the dedicated sniffer; moved to `self.sniffer_interface` for packet capture and `self.injector_interface` for `NetworkAttacker` injection
- **Dual-card: WPS attack workflow used wrong interface on all 4 paths (Bug 6)** — `run_pixie_dust_workflow()` used `self.interface` for `WPSPbcSniffer`, `iw set channel`, `reaver -i`, and `PixieDustAttack`; corrected to `sniffer_interface` for sniffing and `injector_interface` for injection/channel control
- **Dual-card: Evil Twin deauth ran on sniffer card (Bug 8)** — `run_eviltwin_workflow()` passed `interface=self.interface` (= wlan0mon, the sniffer) to `EvilTwinAttack`; since `EvilTwinAttack` uses `BaseAttacker` for all deauth injection, deauth frames were silently sent from the wrong card; fixed to `interface=self.injector_interface`
- **Dual-card: handshake capture EAPOL sniffer used wrong interface (Bug 5)** — `run_mass_attack()` sniffed EAPOL handshake frames on `self.interface` (injector) instead of `self.sniffer_interface`; missed handshakes on the dedicated capture card
- **Variable scope crash in handshake sniffer callback (Bug 4)** — `addr1`/`addr2`/`addr3` were defined inside the `if pkt.haslayer(Dot11)` block but referenced in the outer EAPOL check, causing `NameError` on non-Dot11 EAPOL frames (e.g. Ethernet-encapsulated); moved variable definitions outside the block with safe defaults
- **OSError recovery brought up the wrong interface (Bugs 5, 7)** — the `ip link set ... up` recovery line in the scan and mass-attack loops referenced `self.interface` instead of `self.sniffer_interface`, leaving the sniffer interface down after a transient error

## [3.0.1] - 2026-10-18 — Deauth Fix [NOT TESTED]

### Bug fixes
- **Deauth no longer silently fails when mdk4/aireplay-ng are not installed** — previously the tool would abort the entire handshake capture if no external deauth tool was found, even though Scapy-based eviction was available; now it falls back to Scapy-only injection automatically with a warning message
- **External deauth tool check is now non-blocking** — `_start_burst()` in `capture_native.py` now skips the external broadcast step gracefully if no tool is present, instead of crashing the capture flow
- **Deauth/CSA injection errors are now visible to the user** — previously all `sendp()` failures in `eviction.py` were silently swallowed into `logger.debug`; now `PermissionError` (run as root) and `OSError` (interface down / not in monitor mode) print a clear red error message so the user knows exactly what went wrong

---

## [3.0.0] - 2026-10-17 — The Giant Update 🚀

### What's new
- **PMKID Attack (Option 11)** — Clientless WPA2 hash harvesting from EAPOL Association frames without requiring clients or sending deauth. Formatted directly for Hashcat mode 22000 (`.hc22000`).
- **Karma Attack (Option 12)** — Automatically sniffs 802.11 Probe Requests from nearby devices and responds with spoofed Probe Responses to attract clients seamlessly.
- **Beacon Flooding (Option 13)** — Transmits high-frequency 802.11 Beacon storms with common SSIDs, cloned networks, or random SSIDs.
- **WPA-Enterprise Fake RADIUS (Option 14)** — Launches a rogue 802.1X Access Point with an embedded fake UDP RADIUS server to harvest PEAP/TTLS credentials and challenge responses.
- **Smart Wordlists & Auto-Rockyou (Option 15)** — Dynamic candidate generation tailored to the target SSID name/MAC, ISP default patterns for Egypt/MENA (WE, Vodafone, Orange, Etisalat), and automatic rockyou.txt download.
- **Session Export (Main Menu Option 5)** — Exports complete recon and attack datasets to structured JSON, CSV spreadsheets, and clean human-readable reports.
- **Rich TUI Live Dashboard** — Real-time terminal visualization using `rich` with RSSI signal bars, color-coded security badges, client badges, and event logging.
- **Geo-Location BSSID Lookup (Main Menu Option 6)** — Resolves Access Point BSSIDs to physical latitude/longitude and Google Maps links via Wigle.net and OpenWifi APIs.
- **Multi-Vector Eviction (Deauth + CSA + BTM)** — Bypasses 802.11w PMF (Protected Management Frames) by injecting Channel Switch Announcements (Element ID 37) and 802.11v BTM requests.
- **WPA3/SAE Transition Downgrade Attack (Option 10)** — Forces clients connected to WPA3/WPA2 Transition networks to fall back to WPA2-PSK via CSA beacons, capturing crackable M2 4-way handshakes.
- **WPS Push-Button (PBC) Sniffer** — Sniffs physical WPS button presses on the router to extract plaintext WPA-PSK credentials immediately without brute force or PIN cracking.
- **Algorithmic Known-PINs Database** — Built-in offline mathematical generators for ComputePIN, D-Link, and EasyBox algorithms with standardized 8th-digit checksum validation.
- **Multi-Card Aggregation Engine** — Automatically detects and coordinates dual physical adapters: assigns a **Dedicated Sniffer** (zero packet loss on handshake capture) and a **Dedicated Injector** (continuous deauth/CSA injection).
- **Dual-Band Scanning (2.4 GHz + 5 GHz)** — Live scanner now hops across 2.4 GHz (1-13) and 5 GHz channels (36-161) simultaneously.
- **WPA3 & PMF Detection in Live Scanner** — Scanner parses RSN Capabilities to identify WPA3/SAE networks and Protected Management Frames (marked as `WPA3/WPA2+PMF`).

### Bug fixes
- **Monitor mode now uses `airmon-ng` as the primary method** — the old manual `iw` approach caused some wireless adapters to freeze or fail to detect networks; `airmon-ng start` handles adapter quirks automatically and creates a clean monitor-mode interface (e.g. `wlan0mon`)
- **Automatic interface name detection** — the tool now parses `airmon-ng` output to find the exact new interface name instead of assuming it stays the same
- **Smart fallback** — if `airmon-ng` is not installed, falls back to manual `iw` method automatically with a clear warning message

---

## [2.1.2] - 2026-09-29

### What's new
- **Crack passwords directly from the menu** — after capturing a handshake, use the new Option 9 to crack it with any wordlist without leaving the tool

### Bug fixes
- **Fake AP (Evil Twin) now works with a single Wi-Fi card** — previously deauth wouldn't run if you only had one adapter; now it works automatically
- **Captive portal now shows up on modern phones** — fixed an issue where Android 14/15, Samsung One UI 6/7, iPhone, Oppo, Xiaomi, and Vivo devices wouldn't show the login page
- **Password verification was wrong** — the tool sometimes said the password was incorrect even when it was right; this is now fixed
- **Revealed network names are now remembered** — after revealing a hidden network's name, it stays visible in the menu instead of going back to hidden
- **MAC addresses were shown in full in some screens** — they are now always masked for privacy

---

## [2.1.1] - 2026-08-07

### What's new
- MAC addresses are now masked everywhere in the tool (shown as `xx:xx:xx` instead of the full address)
- Saved files are now named after the network name instead of its MAC address

### Improvements
- Handshake capture is faster and more reliable
- Pixie Dust (WPS) attack results are more accurate
- Menus are cleaner

---

## [2.1.0] - 2026-07-19

### What's new
- **Software Evil Twin** — you can now run the Evil Twin attack without an ESP32/ESP8266 device, using just your Wi-Fi adapter (if it supports it)
- **Custom captive portal** — upload your own HTML login page without reflashing the ESP
- **5 built-in portal templates** — choose from TP-Link, Huawei, hotel, corporate, and more

### Improvements
- The tool now shows at startup whether your adapter supports the Software Evil Twin feature
- Better stability and performance across all attack modes

