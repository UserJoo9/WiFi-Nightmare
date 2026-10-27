# CLAUDE.md — WiFi-Nightmare Developer Reference

> Last updated: 2026-10-28 (HARDWARE-TESTED pass 9 — Bug 20: Software Evil Twin crashed entire program on single card; added global per-attack crash safety net)
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

---

### FIXED — v3.0.2 (continued, deep-scan pass 2)

#### Bug 4: `addr1`/`addr2`/`addr3` scope error in `sniffer_callback()` (CRITICAL)
**File:** `wifi_nightmare/handshake.py` — `sniffer_callback()` around line 157  
**Symptom:** Any EAPOL packet that **lacked a Dot11 layer** (e.g. a raw Ethernet-encapsulated EAPOL during replay) caused `NameError: name 'addr1' is not defined`. The error was silently swallowed by `except Exception: pass`, so the EAPOL frame was silently dropped and never recorded in `self.eapol_packets`. Handshake capture could stall indefinitely even with valid frames on the wire.  
**Root cause:** `addr1`, `addr2`, `addr3` were only assigned inside the `if pkt.haslayer(Dot11):` block but were referenced afterwards in the EAPOL section (`if self.target_bssid in [addr1, addr2]:`), which runs regardless.  
**Fix:** Added `addr1 = addr2 = addr3 = ""` initialisation before the `try:` block (line 157).

```python
# BEFORE (broken): addr1/addr2/addr3 defined only inside Dot11 block
try:
    if pkt.haslayer(Dot11):
        addr1 = pkt.addr1.lower() if pkt.addr1 else ""
        ...
    if pkt.haslayer(EAPOL):
        if self.target_bssid in [addr1, addr2]:   # ← NameError if no Dot11 layer

# AFTER (fixed):
addr1 = addr2 = addr3 = ""   # safe default before try block
try:
    if pkt.haslayer(Dot11):
        addr1 = pkt.addr1.lower() if pkt.addr1 else ""
        ...
    if pkt.haslayer(EAPOL):
        if self.target_bssid in [addr1, addr2]:   # ← always defined now
```

---

#### Bug 5: `run_mass_attack()` using `self.interface` for injection and sniffing (CRITICAL)
**File:** `wifi_nightmare/main.py` — `run_mass_attack()` (3 occurrences)  
**Symptom:** In dual-card mode, the mass attack function used `self.interface` for:
- `NetworkAttacker(interface=...)` — injection on wrong interface
- `sniff(iface=...)` — sniffing on injector instead of dedicated sniffer
- `ip link set ... up` — brought up the wrong interface on OSError recovery  
**Fix:** Changed all 3 occurrences: `NetworkAttacker` → `self.injector_interface`, `sniff` and `ip link set` → `self.sniffer_interface`.

---

#### Bug 6: `run_pixie_dust_workflow()` wrong interfaces (4 occurrences)
**File:** `wifi_nightmare/main.py` — `run_pixie_dust_workflow()`  
**Symptom:** All WPS attack paths in the workflow used `self.interface` instead of the correct role-specific interface, breaking dual-card mode for every WPS method.  
**Details:**
1. `WPSPbcSniffer(self.interface, ...)` — PBC sniffer should use `sniffer_interface`
2. `iw dev self.interface set channel` (Known-PINs) — channel set should target `injector_interface`
3. `reaver -i self.interface` (Known-PINs) — reaver injects WPS packets, needs `injector_interface`
4. `PixieDustAttack(interface=self.interface, ...)` — reaver spawned inside uses injector role  
**Fix:** (1) → `sniffer_interface`, (2)(3)(4) → `injector_interface`.

---

#### Bug 7: `run_scanner_process()` sniffing on wrong interface
**File:** `wifi_nightmare/main.py` — `run_scanner_process()`  
**Symptom:** In dual-card mode, the main scan loop sniffed on `self.interface` (the primary injector card in dual mode) instead of `self.sniffer_interface`. This meant beacon/probe/data frames were received on the injector card (which may have been hopping channels or actively transmitting), causing missed networks and unstable scanning. The OSError recovery also brought up the wrong interface.  
**Fix:** Changed `sniff(iface=self.interface, ...)` → `sniffer_interface` and `ip link set self.interface up` → `sniffer_interface`.

---

#### Bug 8: `run_eviltwin_workflow()` passes sniffer card to EvilTwinAttack (FIXED — commit `c7bbd4f`)
**File:** `wifi_nightmare/main.py` line 724 — `run_eviltwin_workflow()`  
**Symptom:** In dual-card mode, `EvilTwinAttack` received `interface=self.interface` (= `wlan0mon`, the sniffer card) instead of `self.injector_interface` (= `wlan1mon`). `EvilTwinAttack` uses its `self.interface` for ALL deauth injection via `BaseAttacker._send_deauth_broadcast()` and `_send_deauth_to_client()`. Result: deauth frames were sent from the sniffer card while the injector card was idle — evil twin deauth silently failed in dual-card mode.  
**Root cause:** `self.interface` is assigned early in `start()` (after `enable_monitor_mode()`) but before dual-card role assignment. It always points to the sniffer card in dual-card mode. The correct interface for injection is `self.injector_interface`.  
**Fix:** Changed `interface=self.interface` → `interface=self.injector_interface`. Safe in single-card mode because `self.injector_interface == self.interface` there.

---

#### Bug 9: Startup adapter check silently accepted the WRONG physical card (FIXED — commit pending)
**File:** `wifi_nightmare/utils.py` — `check_interface_exists()` and `enable_monitor_mode()`  
**Symptom:** Two separate functions used a **hardcoded fallback list** (`"wlan0"`, `"wlan0mon"`, `"mon0"`) instead of checking only the specific adapter the user actually requested:
1. `check_interface_exists(interface)` checked `[interface, interface+"mon", "wlan0mon", "mon0", "wlan0"]`. On a box with more than one wireless adapter, launching with e.g. `wlan1` that is unplugged/missing would still pass this check as long as an unrelated `wlan0` existed — the tool never reported that the requested antenna was missing, it just silently continued with a dead interface.
2. `enable_monitor_mode(interface)`'s "already in monitor mode?" smart-check used `[interface, interface+"mon", "wlan0mon"]`. In dual-card mode, when `start()` calls this on the SECOND adapter (e.g. `wlan1`), a leftover `wlan0mon` from the first card (or a previous run) would falsely match, making the function think `wlan1` was "already in monitor mode" and return `wlan0mon` instead — collapsing the sniffer and injector roles onto the same physical card with no error or warning.
**Root cause:** Both existence/mode checks were scoped to a global, hardcoded adapter name instead of being derived from the `interface` argument that was actually passed in.
**Fix:** Both functions now derive their candidate names only from the requested interface itself (`interface`, and its monitor-mode sibling via `base = interface[:-3] if interface.endswith("mon") else interface` → `base + "mon"`). No more cross-card name guessing. Behavior for the common single-adapter `wlan0` case is unchanged (same two names end up being checked); multi-adapter and dual-card setups now get an honest answer: a genuinely missing/unplugged adapter aborts startup with a clear message instead of silently continuing, and the second card in dual-card mode can no longer be mistaken for the first.

---

#### Bug 10: `capture_handshake()` forgets previously-known clients between deauth bursts
**File:** `wifi_nightmare/capture_native.py` — `capture_handshake()` / `_start_burst()`  
**Symptom:** Every time a new deauth burst cycle started, `known_clients = _start_burst()` REPLACED the accumulated client set with whatever `_extract_clients_from_csv()` returned at that exact instant. If a client wasn't in the CSV snapshot right then (airodump-ng hadn't flushed yet, or the client was briefly idle), it silently dropped out of both the displayed client count AND the next round's targeted unicast deauth list — even though it had been seen (and targeted) earlier in the same capture.  
**Fix:** `known_clients` is now accumulated for the whole capture session; `_start_burst()` merges the fresh CSV read into it (`known_clients | csv_clients`) instead of overwriting it, and targets/returns the merged set.

---

#### Bug 11: ESP-driven `EvilTwinAttack` reverts the SHARED injector card to managed mode when it finishes
**File:** `wifi_nightmare/eviltwin.py` — `EvilTwinAttack.run()`, `finally` block  
**Symptom:** When the ESP32 Evil Twin attack ended (success, Ctrl+C, or any exception), its `finally` block ran `iw dev {self.interface} set type managed` on `self.interface`. In dual-card mode `self.interface` is `self.injector_interface` — the SAME card `main.py` keeps using for every attack for the rest of the session. The interface silently dropped out of monitor mode with no error shown; every later deauth/injection attempt in that run then failed until the whole program was restarted.  
**Root cause:** The class treated the shared session-wide injector interface as if it were owned exclusively by this one attack.  
**Fix:** Removed the forced managed-mode reversion. Interface lifecycle/restoration is `WifiGTR.cleanup()`'s job at full program exit (`utils.restore_managed_mode()`), not an individual attack's.

---

#### Bug 12: `SoftwareEvilTwin` restores the shared radio to managed mode AND restarts NetworkManager on exit
**File:** `wifi_nightmare/evil_twin_software.py` — `SoftwareEvilTwin.run()`, `finally` block  
**Symptom:** Same class of bug as Bug 11, but worse: at the end of every Software Evil Twin run it unconditionally ran `ip link set {original_interface} down` / `iw ... set type managed` / `up`, and then **`systemctl start NetworkManager`** — directly undoing the `service NetworkManager stop` + `pkill NetworkManager` that `enable_monitor_mode()` deliberately did at program startup specifically to keep NetworkManager out of the way for the whole session. After one Software Evil Twin run, the primary radio silently went back under NetworkManager's control and every subsequent scan/attack in `scan_workflow()`'s still-open target menu (the caller is sitting right below this call, not exiting) broke with no explanation.  
**Fix:** Replaced the managed-mode/NetworkManager-restart block with a call to the SAME `utils.enable_monitor_mode()` helper the main app's startup uses, handing the card back in monitor mode (the state the rest of the session actually expects) instead of managed mode.

---

#### Bonus hardening: `WPAEnterpriseEvil` (radius_fake.py) never checked the interface was in managed mode before starting hostapd
**File:** `wifi_nightmare/radius_fake.py`  
**Symptom:** `self.interface` (the ORIGINAL interface name) is written straight into the hostapd config with no check of its actual current mode. On drivers that put the adapter into monitor mode in-place (no separate `<iface>mon` vif), or after a prior run left it in monitor mode, hostapd would just fail to start with no actionable message.  
**Fix:** Added `_ensure_managed_mode()`, called at the top of `run()`: checks the interface's current mode and switches it to managed first if it's in monitor mode. No-op (same behavior as before) when it's already managed.

---

#### Bug 13: `KarmaAttack._run_native_airbase()` reports success even when airbase-ng never started
**File:** `wifi_nightmare/karma_attack.py`  
**Symptom:** `run()` prefers `airbase-ng` when installed, falling back to the pure-Scapy engine only if `_run_native_airbase()` returns `False`. But that method returned `True` unconditionally at the end of the try block — even if the `airbase-ng` process exited almost instantly (bad CLI args, no permission, interface not AP-capable yet) with a non-zero code and zero output. The user saw "Karma Attack finished" after a fraction of a second, and the working Scapy fallback never ran.  
**Fix:** Track whether any output was ever read and how quickly the process died; if it exited near-instantly with a non-zero/invalid exit code and no output, `_run_native_airbase()` now returns `False` so `run()` falls back to the Scapy engine, with a clear message about what happened.

---

#### Bug 14: `BeaconFlood._run_native_mdk()` has the identical "always reports success" bug
**File:** `wifi_nightmare/beacon_flood.py`  
**Symptom:** Same bug as Bug 13, in the mdk4/mdk3 native-tool path. A near-instant crash of `mdk4`/`mdk3` was reported as "Beacon Flood stopped" with no indication the flood never actually transmitted, and `run()` never tried the Scapy fallback.  
**Fix:** Same pattern as Bug 13 — detect a near-instant non-zero exit and return `False` to trigger the Scapy fallback instead of silently claiming success.

---

#### Bug 15: `run_wpa3_downgrade()` sends CSA frames without locking the injector to the target channel
**File:** `wifi_nightmare/main.py` — `run_wpa3_downgrade()`  
**Symptom:** The CSA eviction burst was sent via `AdvancedEviction(self.injector_interface, ...)` with NO prior `iw ... set channel` call at all — the injector stayed on whatever channel it was last left on by a previous attack/target. The CSA frames silently went out on the wrong channel and never reached the target's clients.  
**Fix:** Added the same `ip link set ... up` / `iw ... set channel` pair (for both `self.interface` and, if different, `self.injector_interface`) used by every other eviction workflow, before the CSA burst.

---

#### Bug 16: `run_mass_attack()` never re-tunes the injector card per target
**File:** `wifi_nightmare/main.py` — `run_mass_attack()`  
**Symptom:** The per-target loop only set the channel on `self.interface` (the sniffer card). `NetworkAttacker` is built with `interface=self.injector_interface` and does all its deauth injection there. In dual-card mode, after the first hidden-network target, the injector card stayed parked on the FIRST target's channel for every subsequent target in the batch — deauth silently missed every target after the first.  
**Fix:** Added `iw ... set channel` on `self.injector_interface` (when different from `self.interface`) inside the per-target loop, right alongside the existing sniffer channel-set.

---

#### Bug 17: `run_attack()` never sets the injector's channel for "reveal"/"passive" modes
**File:** `wifi_nightmare/main.py` — `run_attack()`  
**Symptom:** The most heavily-used deauth feature in the whole tool (menu actions "Reveal" and "Passive", i.e. SSID decloaking). `run_attack()` only locked `self.interface` (the sniffer) to the target channel at the top. For `mode == "handshake"` this didn't matter because `capture_handshake()` locks the injector's channel internally -- but for every OTHER mode, `NetworkAttacker(interface=self.injector_interface, ...)` is built and injects deauth directly, with the injector card never tuned to the target's channel at all in dual-card mode. "Reveal" mode's deauth was effectively a no-op against the actual target whenever the injector card happened to be on a different channel (e.g. right after startup, or after any previous attack on another target).  
**Fix:** Added an unconditional `iw ... set channel` on `self.injector_interface` (when different from `self.interface`) right after the existing sniffer channel-set, covering every mode. Harmless no-op duplicate for `mode == "handshake"` since `capture_handshake()` already does its own.

---

#### Bug 18: Beacon Flood always failed — `mdk4 -a` is mutually exclusive with `-n`/`-f` (CONFIRMED on real hardware)
**File:** `wifi_nightmare/beacon_flood.py` — `_run_native_mdk()`  
**Symptom:** Every beacon flood via mdk4 exited immediately with code 1 and silently fell back to the far weaker Scapy engine. Confirmed live on mdk4 4.2: the command `mdk4 wlan0mon b -n <ssid> -c <ch> -a -s 100` aborts with `Only one of -n -a -f or -v may be selected`.  
**Root cause:** In mdk4 4.x, beacon-mode `-a` means "generate SSIDs with non-printable chars / break the 32-byte limit" and is MUTUALLY EXCLUSIVE with the other SSID-source flags `-n` / `-f` / `-v`. The code always passed `-n` (clone) or `-f` (list) **together with** `-a`, so mdk4 rejected the args every single time. (This was almost certainly a leftover assumption from mdk3, where `-a` meant something else.)  
**Fix:** Removed `-a` from the beacon command. Verified live: without `-a`, mdk4 transmits beacons normally (~97 pkt/s).  
**How it was found:** Real hardware testing (Kali, mdk4 4.2) — ran the exact program command manually with and without `-a`.

---

#### Bug 19: mdk4 deauth used the mdk3-era `-b <blacklist file>` instead of direct `-B <BSSID>` targeting
**File:** `wifi_nightmare/capture_native.py` (`capture_handshake` broadcast deauth) and `wifi_nightmare/evil_twin_software.py` (`_deauth_thread`)  
**Symptom:** Deauth via mdk4 was weak/unreliable — handshake capture succeeded on a busy AP (7 clients) but not on a quiet one (2 clients).  
**Root cause:** mdk4 deauth mode `d` with `-b <file>` is the mdk3-era *blacklist* style, which deauths **based on observed data traffic** — on a quiet network with idle clients it sends very few deauths. mdk4 4.x exposes `-B <BSSID>` to actively target a specific AP regardless of traffic (confirmed working live). The code never used it.  
**Fix:** mdk4 deauth now uses `-B <bssid> -c <channel>` (active direct targeting). mdk3 paths keep `-b <file>` since mdk3 has no `-B`. aireplay-ng paths unchanged.  
**How it was found:** Real hardware testing — `mdk4 ... d -B <bssid> -c 6` confirmed to run cleanly (exit via timeout, not error).

---

#### Note: standalone deauth options are Scapy-only (not yet hardware-confirmed)
`run_multivector_eviction()` (menu option 3) and the `deauth_only` path use the pure-Scapy `AdvancedEviction` engine, NOT mdk4/aireplay. Bugs 18-19 do not touch them. If standalone deauth still feels weak on real hardware after these fixes, the next step is to add an mdk4 `-B` / aireplay `-0` injection path alongside the Scapy frames there too. Pending live test feedback.

---

#### Bug 20: Software Evil Twin CRASHED THE ENTIRE PROGRAM (unhandled TimeoutExpired) — CONFIRMED on hardware
**File:** `wifi_nightmare/evil_twin_software.py` (`_create_ap_interface`, `_get_phy_name`) + `wifi_nightmare/main.py` (`scan_workflow`)  
**Symptom (live traceback):** Selecting Software Evil Twin (option 7) on a single card raised `subprocess.TimeoutExpired: Command '['airmon-ng', 'start', 'wlan0']' timed out after 15 seconds`, which propagated all the way up through `scan_workflow` → `main_loop` → `start` → `entry_point` and **killed the whole program** ("Critical Error").  
**Root cause (chain):**
1. Software Evil Twin is given `self.original_interface` = `wlan0`, but by then the app has already turned that card into `wlan0mon` (monitor). `wlan0` no longer exists in sysfs.
2. `_get_phy_name()` only looked up `self.interface` (`wlan0`) → every method failed → returned `None`.
3. With `phy == None`, `_create_ap_interface()` skipped the VIF-creation path entirely and fell through to `airmon-ng start wlan0`.
4. `airmon-ng start wlan0` hung on the non-existent interface → 15s timeout → `TimeoutExpired`, which was **not caught**, so it crashed the entire program.
5. A latent bug too: `_get_phy_name` method 1 returned `"0"` from `"wiphy 0"` instead of `"phy0"`.  
**Fixes:**
- `_get_phy_name()` now resolves the phy against the original name, its `mon` sibling, and any live wireless interface (the phy is the same physical radio regardless of interface name), and correctly returns `phyN`.
- The `airmon-ng start` fallback is wrapped in try/except (TimeoutExpired + generic) so it can never crash the program.
- `_create_ap_interface()` now validates the chosen AP interface actually exists in sysfs before returning success; if a single card in monitor mode can't provide an AP-capable interface, it returns `False` with a clear message ("a second adapter is required, or use the Hardware ESP Evil Twin") instead of letting hostapd fail later.
- **General safety net:** `scan_workflow()`'s entire action-dispatch is now wrapped in try/except. ANY attack that raises is caught, logged, and returns the user to the target menu — a single attack can never again take down the whole tool.  
**How it was found:** Real hardware testing — user ran Software Evil Twin and pasted the full crash traceback.

---

#### Note: standalone "Deauth only" has no dedicated menu entry
The target menu (ui.py `target_items`) has no top-level "Deauth" option. Standalone deauth lives under option **3 (Multi-Vector Eviction) → sub-choice 3 "Standard Deauth Burst Flood"**. The `deauth_only` mode in `run_attack()` exists but is not wired to any menu action. If a dedicated top-level Deauth entry is wanted, it needs adding to `target_items` + a new `scan_workflow` branch. Not a regression from recent changes.

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
