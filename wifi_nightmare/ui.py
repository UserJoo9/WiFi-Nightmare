# ui.py
import os
import re
import shutil
from wifi_nightmare.config import (
    C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET,
    BANNER, VERSION, AUTHOR
)
from wifi_nightmare.utils import mask_bssid

ANSI_REGEX = re.compile(r'\x1b\[[0-9;]*m')
C_DESC = "\033[0;36m"  # Soft teal for crisp, readable descriptions on dark terminals

def clear_screen():
    print("\033[H\033[J", end="")

def strip_ansi(text: str) -> str:
    """Return text with ANSI escape codes removed for accurate width calculation."""
    return ANSI_REGEX.sub('', text)

def pad_visible(text: str, width: int) -> str:
    """Pad string to visible character width, preserving embedded ANSI escape codes."""
    vis_len = len(strip_ansi(text))
    if vis_len < width:
        return text + (' ' * (width - vis_len))
    return text

def get_term_width() -> int:
    try:
        return shutil.get_terminal_size((100, 24)).columns
    except Exception:
        return 100

def get_menu_layout():
    term_w = get_term_width()
    two_col = term_w >= 86
    block_w = min(108, term_w) if two_col else min(56, term_w)
    margin = max(0, (term_w - block_w) // 2)
    return block_w, margin

def get_menu_margin() -> int:
    _, margin = get_menu_layout()
    return margin

def menu_input(prompt: str = "Select Option: ") -> str:
    margin = get_menu_margin()
    return input(f"{' ' * margin}{C_YELLOW}[?]{C_RESET} {prompt}").strip()

def print_banner():
    clear_screen()
    term_w = get_term_width()
    banner_w = 108
    margin = max(0, (term_w - banner_w) // 2)
    sep_w = min(banner_w, term_w)

    lines = BANNER.strip('\n').splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if "Advanced" in stripped:
            pad = max(0, (banner_w - len(stripped)) // 2)
            print(' ' * (margin + pad) + f"{C_GREEN}{stripped}{C_RESET}")
        else:
            print(' ' * margin + f"{C_GREEN}{line}{C_RESET}")

    ver_str = f"v{VERSION} | by {AUTHOR}"
    pad_ver = max(0, (banner_w - len(ver_str)) // 2)
    print(' ' * (margin + pad_ver) + f"{C_CYAN}{ver_str}{C_RESET}")
    print(' ' * margin + "═" * sep_w)

def print_grid_menu(items, col_width=45):
    """
    Renders menu items in a horizontal 2-column grid layout (بالعرض)
    centered horizontally in the terminal, with descriptions placed directly underneath each option.
    
    Each item in items is a tuple:
      (key, title, description, color, disabled_reason)
    """
    block_w, margin = get_menu_layout()
    two_col = block_w >= 86

    if not two_col:
        for key, title, desc, col, disabled in items:
            key_tag = f"[{col}{key}{C_RESET}]"
            dis_tag = f" {C_GREY}({disabled}){C_RESET}" if disabled else ""
            print(' ' * margin + f" {key_tag} {C_WHITE}{title}{C_RESET}{dis_tag}")
            print(' ' * margin + f"     {C_DESC}{desc}{C_RESET}\n")
        return

    # Measure maximum visible width of Column 1 to ensure clean column alignment
    col1_max = 0
    for i in range(0, len(items), 2):
        k, t, d, c, dis = items[i]
        dis_str = f" ({dis})" if dis else ""
        col1_max = max(col1_max, len(f" [{k}] {t}{dis_str}"), len(f"     {d}"))

    col_w = max((block_w - 4) // 2, col1_max)
    gap = 4

    for i in range(0, len(items), 2):
        item1 = items[i]
        item2 = items[i + 1] if i + 1 < len(items) else None

        k1, t1, d1, c1, dis1 = item1
        tag1 = f"[{c1}{k1}{C_RESET}]"
        dis_tag1 = f" {C_GREY}({dis1}){C_RESET}" if dis1 else ""
        title_line1 = f" {tag1} {C_WHITE}{t1}{C_RESET}{dis_tag1}"
        desc_line1 = f"     {C_DESC}{d1}{C_RESET}"

        if item2:
            k2, t2, d2, c2, dis2 = item2
            tag2 = f"[{c2}{k2}{C_RESET}]"
            dis_tag2 = f" {C_GREY}({dis2}){C_RESET}" if dis2 else ""
            title_line2 = f" {tag2} {C_WHITE}{t2}{C_RESET}{dis_tag2}"
            desc_line2 = f"     {C_DESC}{d2}{C_RESET}"

            print(' ' * margin + pad_visible(title_line1, col_w) + (' ' * gap) + title_line2)
            print(' ' * margin + pad_visible(desc_line1, col_w) + (' ' * gap) + desc_line2)
        else:
            print(' ' * margin + title_line1)
            print(' ' * margin + desc_line1)

        print()

def print_main_menu(interface, esp_status="Not Connected", vif_status="Unknown"):
    print_banner()
    block_w, margin = get_menu_layout()
    print(' ' * margin + f" Interface : {C_CYAN}{interface:<12}{C_RESET} │ ESP : {esp_status:<22} │ VIF : {vif_status}")
    print(' ' * margin + "─" * block_w)
    print()

    menu_items = [
        ("1", "Scan & Reconnaissance", "Discover APs, clients, encryption & signals", C_GREEN, ""),
        ("2", "Client Monitor (Live View)", "Live real-time probe & client traffic view", C_GREEN, ""),
        ("3", "Mass Attack (Auto-Pilot)", "Automated decloak of all hidden networks", C_GREEN, ""),
        ("4", "Offline Database & Cracking", "Manage saved captures & verify passphrases", C_GREEN, ""),
        ("5", "Export Session (Data/Report)", "Export audit datasets to JSON, CSV, or Text", C_GREEN, ""),
        ("6", "Geo-Location Lookup (GPS)", "Resolve BSSIDs to physical maps coordinates", C_GREEN, ""),
        ("0", "Exit Application", "Restore managed mode and terminate safely", C_RED, ""),
    ]

    print_grid_menu(menu_items)
    print(' ' * margin + "─" * block_w)

def print_target_menu(ssid, bssid, channel, client_count, crypto="Unknown", vendor="Unknown",
                      has_esp=False, vif_ready=False, has_wps=False):
    clear_screen()
    block_w, margin = get_menu_layout()
    print(' ' * margin + "═" * block_w)
    title = f"{C_CYAN}TARGET AUDIT WORKSPACE{C_RESET}"
    title_pad = max(0, (block_w - len(strip_ansi(title))) // 2)
    print(' ' * (margin + title_pad) + title)
    print(' ' * margin + "═" * block_w)
    
    clean_crypto = crypto.replace("{", "").replace("}", "").replace("'", "")
    clean_vendor = vendor[:24] if vendor else "Unknown"

    print(' ' * margin + f" Target  : {C_GREEN}{ssid:<30}{C_RESET} │ BSSID   : {C_YELLOW}{mask_bssid(bssid):<20}{C_RESET}")
    print(' ' * margin + f" Channel : {C_YELLOW}{str(channel):<30}{C_RESET} │ Clients : {C_YELLOW}{str(client_count) + ' active':<20}{C_RESET}")
    print(' ' * margin + f" Crypto  : {C_WHITE}{clean_crypto:<30}{C_RESET} │ Vendor  : {C_WHITE}{clean_vendor:<20}{C_RESET}")
    print(' ' * margin + "─" * block_w)
    print()

    esp_dis = "" if has_esp else "No ESP connected"
    vif_dis = "" if vif_ready else "VIF not supported"
    wps_dis = "" if has_wps else "No WPS detected"

    target_items = [
        ("1", "Capture Handshake (WPA2/3)", "Record 4-way authentication handshake", C_GREEN, ""),
        ("2", "Reveal Hidden SSID", "Deauth clients to capture association frame", C_GREEN, ""),
        ("3", "Multi-Vector Eviction", "Bypass PMF with CSA (IE 37) & 802.11v BTM", C_GREEN, ""),
        ("4", "Passive Monitor (Stealth)", "Silent zero-transmission packet capture", C_GREEN, ""),
        ("5", "Generate Hashcat (hc22000)", "Convert handshake pcap to hashcat m22000", C_GREEN, ""),
        ("6", "Evil Twin (Hardware ESP)", "Rogue AP with captive phishing portal", C_CYAN if has_esp else C_GREY, esp_dis),
        ("7", "Evil Twin (Software AP)", "Virtual AP (hostapd+dnsmasq) via VIF", C_CYAN if vif_ready else C_GREY, vif_dis),
        ("8", "WPS Attack Suite", "Pixie Dust PRNG + PBC push button + PINs", C_YELLOW if has_wps else C_GREY, wps_dis),
        ("9", "Crack Handshake (aircrack)", "Direct offline dictionary attack with wordlists", C_GREEN, ""),
        ("10", "WPA3 Downgrade Attack", "Force WPA2 fallback via CSA beacons", C_GREEN, ""),
        ("11", "PMKID Attack (Clientless)", "Harvest PMKID from AP (no clients needed)", C_GREEN, ""),
        ("12", "Karma Attack (Auto-Probe)", "Respond to Probe Requests to lure devices", C_GREEN, ""),
        ("13", "Beacon Flood Attack", "High-frequency fake AP beacon storm", C_GREEN, ""),
        ("14", "WPA-Enterprise Evil Twin", "Rogue 802.1X AP + fake RADIUS logger", C_GREEN, ""),
        ("15", "Smart Crack (Smart+rockyou)", "SSID-smart wordlist generator + rockyou", C_GREEN, ""),
        ("16", "Deauth Flood (Standalone)", "Continuously disconnect all clients from the AP", C_RED, ""),
        ("0", "Back to Scan", "Return to live network discovery hopper", C_RED, ""),
    ]

    print_grid_menu(target_items)
    print(' ' * margin + "─" * block_w)

def print_database_menu():
    clear_screen()
    block_w, margin = get_menu_layout()
    print(' ' * margin + "═" * block_w)
    title = f"{C_CYAN}DATABASE & CRACKING WORKSPACE{C_RESET}"
    title_pad = max(0, (block_w - len(strip_ansi(title))) // 2)
    print(' ' * (margin + title_pad) + title)
    print(' ' * margin + "═" * block_w)
    print()

    db_items = [
        ("1", "List Saved Networks", "Inspect captured handshakes, decloaked APs & logs", C_GREEN, ""),
        ("2", "Verify Password", "Test candidate passphrase against captured handshake", C_GREEN, ""),
        ("0", "Back to Main Menu", "Return to main navigation menu", C_RED, ""),
    ]

    print_grid_menu(db_items)
    print(' ' * margin + "─" * block_w)

def print_portal_menu(templates, current_status, has_esp=False):
    clear_screen()
    block_w, margin = get_menu_layout()
    print(' ' * margin + "═" * block_w)
    title = f"{C_CYAN}EVIL TWIN PORTAL CUSTOMIZATION{C_RESET}"
    title_pad = max(0, (block_w - len(strip_ansi(title))) // 2)
    print(' ' * (margin + title_pad) + title)
    print(' ' * margin + "═" * block_w)
    mode_text = "ESP + Software Evil Twin" if has_esp else "Software Evil Twin (No ESP)"
    print(' ' * margin + f" Mode    : {C_YELLOW}{mode_text:<30}{C_RESET} │ Current : {current_status}")
    print(' ' * margin + "─" * block_w)
    print()

    portal_items = []
    for i, name in enumerate(templates, 1):
        portal_items.append((str(i), name, f"Branded portal template: {name}", C_GREEN, ""))
    portal_items.append(("C", "Load from File", "Load custom portal HTML file from disk", C_CYAN, ""))
    portal_items.append(("R", "Reset to Default", "Restore built-in default login portal", C_YELLOW, ""))
    portal_items.append(("0", "Back", "Return without modifying active portal", C_RED, ""))

    print_grid_menu(portal_items)
    print(' ' * margin + "─" * block_w)

def print_scan_table(interface, networks, lock):
    clear_screen()
    print(f"[*] Interface: {C_GREEN}{interface}{C_RESET} | Scanning... ({C_RED}Ctrl+C to Stop{C_RESET})")
    header = f"{'ID':<4} {'BSSID':<18} {'PWR':<5} {'HS':<4} {'WPS':<5} {'CH':<4} {'ENC':<25} {'VENDOR':<16} {'CL':<4} {'SSID'}"
    print("-" * len(header))
    print(header)
    print("-" * len(header))

    display_list = []
    with lock:
        sorted_nets = sorted(networks.items(), key=lambda x: x[1]['RSSI'], reverse=True)
        for i, (bssid, info) in enumerate(sorted_nets):
            display_list.append(bssid)
            rssi = info['RSSI']
            if rssi > -60: pwr_color = C_GREEN
            elif rssi > -80: pwr_color = C_YELLOW
            else: pwr_color = C_RED
            hs_mark = f"{C_GREEN}Yes{C_RESET}" if info['Handshake'] else f"{C_GREY}No {C_RESET}"
            enc = info['Crypto'].replace("{", "").replace("}", "").replace("'", "")
            if enc == "OPN": enc = "OPEN"
            vendor = info.get('Vendor', 'Unknown')
            if len(vendor) > 15: vendor = vendor[:13] + ".."
            client_count = len(info.get('Clients', []))
            cl_str = f"{C_YELLOW}{client_count:<4}{C_RESET}" if client_count > 0 else f"{C_GREY}0   {C_RESET}"
            ssid_raw = info['SSID']
            if info['Known']: ssid_display = f"{C_GREEN}{ssid_raw}{C_RESET}"
            elif info['Hidden']: ssid_display = f"{C_GREY}<HIDDEN>{C_RESET}"
            else: ssid_display = f"{C_WHITE}{ssid_raw}{C_RESET}"
            wps_mark = f"{C_GREEN}Yes{C_RESET}" if info.get('WPS') else f"{C_GREY}No {C_RESET}"
            print(f"{i:<4} {mask_bssid(bssid):<18} {pwr_color}{rssi:<5}{C_RESET} {hs_mark:<13} {wps_mark:<14} {info['Channel']:<4} {enc:<25} {vendor:<16} {cl_str} {ssid_display}")
    return display_list

def print_attack_summary(result):
    if not result: return
    clear_screen()
    print(f"{C_GREEN}=========================================={C_RESET}")
    print(f"{C_GREEN}          ATTACK SUCCESS REPORT           {C_RESET}")
    print(f"{C_GREEN}=========================================={C_RESET}")
    print(f"SSID (Name) : {C_CYAN}{result['SSID']}{C_RESET}")
    print(f"BSSID (MAC) : {C_WHITE}{mask_bssid(result['BSSID'])}{C_RESET}")
    print(f"Channel     : {C_YELLOW}{result['Channel']}{C_RESET}")
    print(f"Clients     : {C_YELLOW}~{result['Clients']} Detected{C_RESET}")
    print("------------------------------------------")
    print(f"{C_GREEN}[+] Network saved to database.{C_RESET}")
    print("==========================================")
    input(f"\n{C_YELLOW}Press Enter to return to main menu...{C_RESET}")

def show_saved_db(db_handler):
    clear_screen()
    print(f"{C_CYAN}--- Saved Networks Database ---{C_RESET}\n")
    if not db_handler.known_networks:
        print("[-] No networks saved yet.")
        return []
    else:
        print(f"{'ID':<4} {'BSSID':<20} {'Handshake':<12} {'Time':<10} {'SSID'}")
        print("-" * 70)
        # NOTE: BSSIDs are displayed masked (first/last octet only) for
        # privacy, but saved_list still carries the FULL BSSID so attacks
        # and password verification can be re-targeted from this list.
        saved_list = []
        i = 0
        for bssid, data in db_handler.known_networks.items():
            saved_list.append(bssid)
            if isinstance(data, dict):
                ssid = data.get('SSID', 'Unknown')
                hs = "YES" if data.get('Handshake') else "NO"
                tm = data.get('HSTime', '')
            else:
                ssid = data
                hs = "NO"
                tm = ""
            hs_col = f"{C_GREEN}{hs}{C_RESET}" if hs == "YES" else f"{C_RED}{hs}{C_RESET}"
            print(f"{i:<4} {mask_bssid(bssid):<20} {hs_col:<20} {tm:<10} {C_GREEN}{ssid}{C_RESET}")
            i += 1
        return saved_list
