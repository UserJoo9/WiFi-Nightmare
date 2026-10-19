# CLAUDE.md — WiFi-Nightmare Developer Reference

> Last updated: 2026-10-19  
> This file documents the full architecture, attack workflows, known bugs, and fix history for WiFi-Nightmare.  
> **Read this before starting any analysis or modification session** — it prevents re-analyzing from scratch.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Layout](#2-repository-layout)
3. [Startup Workflow (main.py)](#3-startup-workflow)
4. [Monitor Mode & Card Manager](#4-monitor-mode--card-manager)
5. [Attack Modes — Full Workflow Map](#5-attack-modes)
6. [Core Attack Classes](#6-core-attack-classes)
7. [Eviction Engine (eviction.py)](#7-eviction-engine)
8. [Scanner & Client Monitor](#8-scanner--client-monitor)
9. [Specialized Attacks](#9-specialized-attacks)
10. [Dependency Chain](#10-dependency-chain)
11. [Known Bugs & Fix History](#11-known-bugs--fix-history)
12. [Release & Build System](#12-release--build-system)
13. [External Tool Dependencies](#13-external-tool-dependencies)

---

## 1. Project Overview

WiFi-Nightmare is a Python-based Wi-Fi penetration testing framework with a terminal UI.  
**Entry point:** `wifi_nightmare/__main__.py` → `main.py:WifiGTR`  
**Run as:** `sudo wifi-nightmare` (installed) or `sudo python -m wifi_nightmare` (dev)

**Primary external tools used:**
- `airmon-ng` — monitor mode (primary)
- `airodump-ng` — packet capture for WPA handshake
- `aireplay-ng` / `mdk4` — deauth (optional; Scapy is the fallback)
- `aircrack-ng` — handshake verification
- `hostapd` — Evil Twin / WPA-Enterprise rogue AP
- `scapy` — all packet injection & sniffing (Python layer)

---

## 2. Repository Layout

```
wifi_nightmare/
├── main.py              # Entry point. WifiGTR class. All menus and attack orchestration.
├── config.py            # Config loader (YAML), path constants, colour codes
├── utils.py             # enable_monitor_mode(), restore_managed_mode(), run_command()
├── card_manager.py      # CardManager — dual-adapter role assignment
├── scanner.py           # NetworkScanner (beacon scan) + ClientMonitor
├── deauth.py            # BaseAttacker — deauth loop, calls eviction engine
├── eviction.py          # AdvancedEviction — Deauth + CSA beacon + 802.11v BTM
├── handshake.py         # NetworkAttacker (extends BaseAttacker) — reveal/deauth_only/pmkid/passive
├── capture_native.py    # capture_handshake() — airodump-ng + deauth → .cap file
├── pmkid_attack.py      # PMKIDAttack — clientless WPA2 hash capture (.hc22000)
├── karma_attack.py      # KarmaAttack — Probe Request sniff + spoofed Probe Response
├── beacon_flood.py      # BeaconFlood — fake Beacon frames with random MACs
├── radius_fake.py       # WPAEnterpriseEvil — rogue hostapd + fake RADIUS server
├── evil_twin_software.py# EvilTwin — rogue AP with captive portal
├── eviltwin.py          # Legacy evil twin (hostapd wrapper)
├── wordlist_manager.py  # WordlistManager — smart wordlist selection/download
├── wps_suite.py         # WPS attacks (reaver / pixie dust)
├── pixie_dust.py        # PixieDust WPS attack
├── geo_lookup.py        # GeoLocator — WiGLE API + GPS
├── session_export.py    # SessionExporter — export attack session data
├── database.py          # DatabaseHandler — wifi_db.json
├── esp_driver.py        # ESP32 hardware deauth driver
├── vif_check.py         # Virtual interface compatibility check
├── dep_check.py         # Dependency checker (airmon-ng, airodump-ng, etc.)
├── attacks.py           # AttackSuite — high-level attack orchestration helpers
├── ui.py                # TUI display utilities
├── tui_dashboard.py     # TUIDashboard — real-time stats dashboard
├── vendors.py           # MAC vendor lookup
├── logger.py            # Logging setup
```

---

## 3. Startup Workflow

```
sudo wifi-nightmare
    └── WifiGTR.__init__(interface)
            self.interface = interface          # e.g. "wlan0"
            self.sniffer_interface = interface  # same at init
            self.injector_interface = interface # same at init
            self.card_mgr = CardManager()       # calls refresh_adapters() once at __init__

    └── WifiGTR.start()
            1. self.interface = utils.enable_monitor_mode(self.interface)
               # Returns "wlan0mon" if airmon-ng is used, else "wlan0" (iw fallback)
            2. ip link set <iface> up
            3. roles = card_mgr.auto_assign_roles(preferred_iface=self.interface)
               # FIXED (v3.0.2): deduplicates same-phy interfaces; never mistakes
               # wlan0mon+wlan0 (same card) for dual-card setup
               # Returns {"mode":"single","primary":"wlan0mon"} for 1 card
               # Returns {"mode":"dual","sniffer":"wlan0mon","injector":"wlan1mon"} for 2 cards
            4. if dual:
                   self.sniffer_interface  = roles["sniffer"]
                   self.injector_interface = roles["injector"]
                   utils.enable_monitor_mode(self.injector_interface)
               else:
                   self.sniffer_interface  = self.interface
                   self.injector_interface = self.interface
```

**Critical invariant after `start()`:**
- `self.interface` = the primary monitor-mode interface
- `self.sniffer_interface` = interface used for packet sniffing (= `self.interface` in single-card)
- `self.injector_interface` = interface used for packet injection / deauth (= `self.interface` in single-card)

---

## 4. Monitor Mode & Card Manager

### `utils.enable_monitor_mode(interface)` — `utils.py`

Flow:
1. Kill interfering processes: `airmon-ng check kill`, `pkill wpa_supplicant/dhclient/NetworkManager`
2. **Early return** if any of `[interface, interface+"mon", "wlan0mon"]` is already in monitor mode
3. **Primary:** `airmon-ng start <interface>` — parses stdout with 3 regex patterns to find the new mon iface name
4. **Fallback:** `iw dev <interface> set type monitor`
5. Returns the monitor interface name string (e.g. `wlan0mon`)

### `card_manager.py:CardManager`

**Bug fixed (v3.0.2):** When `airmon-ng` runs on `wlan0`, it creates `wlan0mon` on the **same physical card (phy0)**. Before the fix, `auto_assign_roles()` counted both `wlan0` and `wlan0mon` as 2 adapters, triggering false "dual-card" mode. This caused `self.injector_interface` to be set to `wlan0` (non-monitor) while `self.sniffer_interface` was `wlan0mon`.

**Fix:** Added `_deduplicate_by_phy()` — collapses all interfaces from the same `phy#` into one entry, preferring the `preferred_iface` or the monitor-mode variant.

```python
# auto_assign_roles now works correctly:
# 1 physical card → always returns mode="single"
# 2 physical cards (different phy#) → returns mode="dual"
```

---

## 5. Attack Modes

### Menu Structure (main.py → `scan_workflow()`)

After selecting a network from the scan list:

| Option | Mode string | Handler |
|--------|-------------|---------|
| 1 | `handshake` | `capture_handshake()` via `capture_native.py` |
| 2 | `reveal` | `NetworkAttacker` (handshake.py) |
| 3 | `passive` | `NetworkAttacker` (handshake.py) |
| 4 | Crack | `aircrack-ng` / `hashcat` on existing .cap |
| 5 | `deauth_only` | `NetworkAttacker` (handshake.py) |
| 6 | WPS | `wps_suite.py` |
| 7 | WPA3 Downgrade | CSA injection via `eviction.py` |
| 8 | PMKID | `pmkid_attack.py` |
| 9 | Karma | `karma_attack.py` |
| 10 | Beacon Flood | `beacon_flood.py` |
| 11 | WPA-Enterprise | `radius_fake.py` |
| 12 | Smart Wordlist | `wordlist_manager.py` |
| 13 | Evil Twin | `evil_twin_software.py` |

### Attack Routing in `run_attack(target, mode)`

```
run_attack(mode="handshake")
    └── capture_handshake()        # airodump-ng captures, AdvancedEviction deauths
        └── _verify_handshake()    # aircrack-ng validates .cap file

run_attack(mode ∈ [reveal, passive, deauth_only, pmkid])
    └── NetworkAttacker(interface=self.injector_interface, ...)
        ├── start_deauth_thread()  # if mode in [deauth_only, reveal]
        │   └── _deauth_loop_aggressive() [BaseAttacker, deauth.py]
        │       └── eviction_engine.send_deauth_burst() + send_csa_burst()
        └── sniffer thread → sniff(iface=self.sniffer_interface, prn=attacker.sniffer_callback)
            └── sniffer_callback() [handshake.py]
                ├── Tracks clients from Data frames
                ├── Captures EAPOL-Key frames (WPA handshake)
                ├── Reveals hidden SSID from Probe/Assoc frames
                └── Captures PMKID from EAPOL M1
```

---

## 6. Core Attack Classes

### `BaseAttacker` (deauth.py)

Parent class for all network attackers.

```python
BaseAttacker(interface, target_bssid, target_channel, target_ssid="")
    .eviction_engine = AdvancedEviction(...)
    ._send_deauth_broadcast(count=5)    # calls eviction_engine.send_deauth_burst() + send_csa_burst()
    ._send_deauth_to_client(mac, count) # calls eviction_engine.evict_client()
    ._deauth_loop_aggressive()          # infinite loop: broadcast every 0.5s + per-client
    .stop_deauth = False                # set True to stop the loop
    .deauth_sent = 0                    # counter
```

### `NetworkAttacker` (handshake.py) — extends `BaseAttacker`

```python
NetworkAttacker(interface, target_bssid, target_channel, db_handler, attack_mode, target_ssid)
    # interface here = self.injector_interface (used for deauth injection)
    
    .start_deauth_thread()      # starts _deauth_loop_aggressive() in daemon thread
    .join_threads()             # sets stop_deauth=True, joins thread
    .sniffer_callback(pkt)      # CRITICAL: processes all sniffed packets
        ├── Tracks clients (Data frames)
        ├── deauth_only mode: returns early after client tracking
        ├── EAPOL-Key capture: pkt.haslayer(EAPOL) + type==3
        │   └── Uses Raw (FIXED v3.0.2 — was missing from imports)
        ├── SSID reveal: Dot11Elt parsing
        └── PMKID: EAPOL M1 + KDE parsing
    .save_handshake(suffix)     # wrpcap() to HANDSHAKES_DIR
```

**Scapy imports (handshake.py line 7-10) — MUST include `Raw`:**
```python
from scapy.all import (
    sniff, sendp, wrpcap, RadioTap, Dot11, Dot11Elt, Dot11ProbeReq,
    Dot11Auth, Dot11AssoReq, EAPOL, Raw   # <-- Raw is REQUIRED
)
```

### `capture_handshake()` (capture_native.py)

Used for mode=`handshake` only. This is the airodump-ng path.

```
capture_handshake(interface, bssid, channel, timeout, ssid, injector_interface)
    1. Start airodump-ng → writes .cap + .csv to /tmp/wfnm_cap_XXXX/
    2. Parse .csv every 2s to discover connected clients
    3. Deauth loop using AdvancedEviction (Scapy) or mdk4/aireplay-ng if available
    4. _verify_handshake() every 3s using aircrack-ng
    5. On success: copy .cap to HANDSHAKES_DIR
    Returns: path to .cap file, or None on failure
```

---

## 7. Eviction Engine

### `AdvancedEviction` (eviction.py)

Multi-vector deauth — bypasses 802.11w/PMF.

```python
AdvancedEviction(interface, bssid, channel, ssid)
    .send_deauth_burst(client_mac=None, count=5)
        # Sends Deauth + Disassoc in both directions (AP→STA and STA→AP)
        # Handles PermissionError / OSError gracefully (no crash)
        # client_mac=None → broadcast (ff:ff:ff:ff:ff:ff)
    
    .send_csa_burst(count=3)
        # Sends Channel Switch Announcement beacons (Element ID 37)
        # Works against PMF-protected clients (beacons are not protected by PMF)
        # Spoofs target BSSID + SSID; tells clients to switch to (channel+1)%13+1
    
    .send_btm_burst(client_mac, count=2)
        # 802.11v BSS Transition Management request
        # Works on modern 802.11v-capable smartphones
    
    .evict_client(client_mac, pmf_active=False)
        # Intelligent combination:
        # pmf_active=False → Deauth + Disassoc + CSA
        # pmf_active=True  → CSA only (Deauth would be blocked)
```

**Why CSA works against PMF:**  
Standard Deauth/Disassoc frames are blocked by PMF (802.11w). Channel Switch Announcement is carried inside a Beacon frame — beacons are management frames that are NOT protected by PMF. Clients see the CSA, initiate channel switch, disconnect, and re-associate (triggering 4-way EAPOL handshake).

---

## 8. Scanner & Client Monitor

### `NetworkScanner` (scanner.py)

```python
NetworkScanner(interface, db_handler)
    .channel_hopper()      # daemon thread: cycles 2.4GHz (1-13) + 5GHz (36,40,44,48,149,153,157,161)
    .packet_handler(pkt)   # Beacon parsing:
                           #   - SSID, BSSID, channel, crypto, WPS, WPA3/SAE (AKM 00:0F:AC:08), PMF
                           #   - Client count from Data frames
                           #   - Hidden SSID detection (ssid starts with \x00)
    .networks              # dict: {bssid: {SSID, channel, crypto, rssi, ...}}
```

### `ClientMonitor` (main.py inner class)
- Scans for Probe Requests from nearby devices
- Tracks device MACs and their preferred SSIDs

---

## 9. Specialized Attacks

### `PMKIDAttack` (pmkid_attack.py)
- **Clientless** WPA2 hash capture (no connected clients needed)
- Sends spoofed Auth + Assoc to AP using fake MAC `02:00:00:11:22:33`
- AP responds with EAPOL M1 which contains PMKID KDE
- Saves as `.hc22000` for hashcat mode 22000
- Does not require deauth

### `KarmaAttack` (karma_attack.py)
- Sniffs 802.11 Probe Requests from nearby devices
- Responds with matching Probe Responses (spoofing the requested SSID)
- Completes Auth + Assoc to attract clients
- Backend: `airbase-ng` (native) or pure Scapy

### `BeaconFlood` (beacon_flood.py)
- Sends fake 802.11 Beacon frames at high rate
- Random MACs + common SSIDs (including Egyptian ISP networks: WE, Vodafone, Orange, Etisalat, Zain)
- Floods nearby devices' Wi-Fi lists

### `WPAEnterpriseEvil` (radius_fake.py)
- Rogue `hostapd` configured for WPA-Enterprise (EAP)
- Fake RADIUS server on UDP 1812
- Harvests PEAP/TTLS credentials + NT hashes

### `EvilTwin` (evil_twin_software.py)
- Full rogue AP with captive portal
- `hostapd` + DHCP + DNS + HTTP server
- Portal pages in `portals.py`

### WPS Suite (wps_suite.py + pixie_dust.py)
- `reaver` integration for WPS PIN brute-force
- `pixiedust` — offline WPS PIN attack using E-S1/E-S2 nonces

---

## 10. Dependency Chain

```
wifi-nightmare (CLI)
    ├── REQUIRED: Python 3.8+, scapy, colorama
    ├── REQUIRED: airmon-ng (monitor mode) — fallback: iw
    ├── OPTIONAL: airodump-ng (handshake capture via mode=handshake)
    ├── OPTIONAL: aircrack-ng (handshake verification)
    ├── OPTIONAL: aireplay-ng / mdk4 (deauth assist in capture_native)
    ├── OPTIONAL: hostapd (evil twin / WPA-Enterprise)
    ├── OPTIONAL: reaver (WPS brute force)
    └── OPTIONAL: hashcat (local cracking)
```

All optional tools are checked at runtime with `shutil.which()`. Missing tools gracefully fall back to Scapy-only implementations.

---

## 11. Known Bugs & Fix History

### FIXED — v3.0.2

#### Bug 1: `Raw` not imported in `handshake.py` (CRITICAL)
**File:** `wifi_nightmare/handshake.py` line 7-10  
**Symptom:** Every EAPOL packet received caused `NameError: name 'Raw' is not defined` inside `sniffer_callback()`. The exception was silently swallowed by the bare `except Exception: pass` at the bottom, making deauth and handshake capture appear to "work" (frames were sent) but EAPOL was never recorded.  
**Root cause:** `pkt.haslayer(Raw)` on line 214 uses the Scapy `Raw` class, but `Raw` was never included in the `from scapy.all import (...)` block.  
**Fix:** Added `Raw` to the import on line 9.

```python
# BEFORE (broken):
from scapy.all import (
    sniff, sendp, wrpcap, RadioTap, Dot11, Dot11Elt, Dot11ProbeReq,
    Dot11Auth, Dot11AssoReq, EAPOL
)

# AFTER (fixed):
from scapy.all import (
    sniff, sendp, wrpcap, RadioTap, Dot11, Dot11Elt, Dot11ProbeReq,
    Dot11Auth, Dot11AssoReq, EAPOL, Raw
)
```

---

#### Bug 2: CardManager false dual-mode on single-card with airmon-ng (CRITICAL)
**File:** `wifi_nightmare/card_manager.py` — `auto_assign_roles()` and `has_multi_card()`  
**Symptom:** When `airmon-ng` runs on `wlan0`, it creates `wlan0mon` on the same physical chip. Both interfaces share `phy0` but `iw dev` lists them as two separate `Interface` entries. The old `has_multi_card()` used `len(self.adapters) >= 2`, so it returned `True` for a single card, triggering dual-mode. `self.injector_interface` then got set to `wlan0` (managed mode, not monitor), making all Scapy injection fail silently.  
**Fix:** Added `_deduplicate_by_phy()` method that collapses all interfaces sharing the same `phy#` into one, preferring the `preferred_iface` or the monitor-mode interface. `auto_assign_roles()` now operates on deduplicated adapters. `has_multi_card()` now checks `len(unique_phys) >= 2` (physical cards), not raw interface count.

---

#### Bug 3: Sniffer using `self.interface` instead of `self.sniffer_interface`
**File:** `wifi_nightmare/main.py` line 925 (in `run_attack()`)  
**Symptom:** In dual-card mode, the sniffer thread sniffed on `self.interface` (the primary injector card) instead of `self.sniffer_interface` (the dedicated sniffer card), defeating the purpose of dual-card aggregation.  
**Fix:** Changed `sniff(iface=self.interface, ...)` to `sniff(iface=self.sniffer_interface, ...)`.

---

### FIXED — v3.0.1

#### `capture_native.py` — hard abort when mdk4/aireplay-ng missing
**Fix:** No longer raises exception when external deauth tools are missing; falls back to Scapy-only AdvancedEviction.

#### `eviction.py` — unhandled `PermissionError`/`OSError` from `sendp()`
**Fix:** Added specific `PermissionError`, `OSError`, and generic `Exception` handlers around `sendp()` calls.

#### `debian/changelog` version mismatch
**Fix:** Bumped from `wifi-nightmare (3.0.0)` to `wifi-nightmare (3.0.1)` so `.deb` file gets correct version number from `dpkg-buildpackage`.

---

### OPEN BUGS / PENDING

None currently known. If a new bug is found, add it here with symptom + root cause + fix.

---

## 12. Release & Build System

### GitHub Actions (`.github/workflows/build-deb.yml`)

Triggered on `v*` tags (e.g. `git tag v3.0.2 && git push origin v3.0.2`).

Flow:
1. Builds `.deb` package using `dpkg-buildpackage` — **version comes from `debian/changelog`** (NOT the git tag)
2. Creates GitHub Release with notes parsed from the `## [vX.Y.Z]` section in `CHANGELOG.md`
3. Uploads `.deb` as release asset
4. Updates APT repository on `gh-pages` branch

**IMPORTANT:** Every version bump MUST update `debian/changelog` to match the new version, or the `.deb` will have the wrong version number.

### Commit + Tag + Push Workflow

```bash
# On the Windows dev machine (git credentials required):
git add -A
git commit -m "fix: describe changes"
# Update debian/changelog version first!
git tag v3.0.X
git push origin main
git push origin v3.0.X
```

**Git noreply email:** Use `UserJoo9@users.noreply.github.com` for commits — GitHub email privacy (GH007) blocks commits with real emails.

---

## 13. External Tool Dependencies

| Tool | Used in | Fallback |
|------|---------|---------|
| `airmon-ng` | `utils.enable_monitor_mode()` | `iw dev set type monitor` |
| `airodump-ng` | `capture_native.capture_handshake()` | N/A (mode=handshake won't work) |
| `aireplay-ng` / `mdk4` | `capture_native` deauth assist | Scapy AdvancedEviction |
| `aircrack-ng` | `capture_native._verify_handshake()` | Scapy EAPOL count heuristic |
| `hostapd` | `radius_fake.py`, `evil_twin_software.py` | N/A |
| `reaver` | `wps_suite.py` | N/A |
| `airbase-ng` | `karma_attack.py` | Pure Scapy karma engine |
| `hashcat` | wordlist cracking | `aircrack-ng` |
| `rfkill` | `utils.enable_monitor_mode()` | skipped silently |

All tool checks use `shutil.which()`. Missing optional tools log a warning and skip that code path.
