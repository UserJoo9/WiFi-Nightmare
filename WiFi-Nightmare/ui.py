
# ui.py
import os
from config import *

def clear_screen():
    print("\033[H\033[J", end="")

def print_banner():
    clear_screen()
    print(f"{C_GREEN}{BANNER}{C_RESET}")
    print(f"{C_CYAN}           v{VERSION} | by {AUTHOR}{C_RESET}")
    print("--------------------------------------------------")

def print_main_menu(interface):
    print_banner()
    print(f"Interface: {C_CYAN}{interface}{C_RESET}")
    print("--------------------------------------------------")
    print(f"[{C_GREEN}1{C_RESET}] 🔍 Scan & Reconnaissance")
    print(f"[{C_GREEN}2{C_RESET}] 📡 Client Monitor (Live View)")
    print(f"[{C_GREEN}3{C_RESET}] 💥 Mass Attack (Auto-Pilot)")
    print(f"[{C_GREEN}4{C_RESET}] 📂 Offline Database & Cracking")
    print(f"[{C_RED}0{C_RESET}] Exit")
    print("--------------------------------------------------")

def print_target_menu(ssid, bssid, channel, client_count):
    clear_screen()
    print(f"{C_CYAN}--- TARGET SELECTED ---{C_RESET}")
    print(f"Target  : {C_GREEN}{ssid}{C_RESET}")
    print(f"BSSID   : {bssid}")
    print(f"Channel : {C_YELLOW}{channel}{C_RESET}")
    print(f"Clients : {C_YELLOW}{client_count}{C_RESET}")
    print("-----------------------")
    print(f"{C_WHITE}[1] 🤝 Capture Handshake (WPA/WPA2){C_RESET}")
    print(f"{C_WHITE}[2] 👁️  Reveal Hidden SSID{C_RESET}")
    print(f"{C_WHITE}[3] 🚫 Deauth Attack (Disconnect){C_RESET}")
    print(f"{C_WHITE}[4] 👂 Passive Monitor (Stealth){C_RESET}")
    print(f"{C_WHITE}[5] 🔓 Generate Hashcat File (hc22000){C_RESET}")
    print(f"{C_WHITE}[0] Back to Scan{C_RESET}")
    print(f"{C_CYAN}-{'-'*22}{C_RESET}")
    
def print_database_menu():
    clear_screen()
    print(f"{C_CYAN}--- DATABASE & CRACKING ---{C_RESET}")
    print(f"[{C_GREEN}1{C_RESET}] List Saved Networks")
    print(f"[{C_GREEN}2{C_RESET}] Verify Password (Crack/Check)")
    print(f"[{C_YELLOW}0{C_RESET}] Back")
    print("---------------------------")

# ... (باقي الدوال: print_scan_table, print_attack_summary, show_saved_db تبقى كما هي في النسخة السابقة) ...
def print_scan_table(interface, networks, lock):
    clear_screen()
    print(f"[*] Interface: {C_GREEN}{interface}{C_RESET} | Scanning... ({C_RED}Ctrl+C to Stop{C_RESET})")
    header = f"{'ID':<4} {'BSSID':<18} {'PWR':<5} {'HS':<4} {'CH':<4} {'ENC':<25} {'VENDOR':<16} {'CL':<4} {'SSID'}"
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
            print(f"{i:<4} {bssid:<18} {pwr_color}{rssi:<5}{C_RESET} {hs_mark:<13} {info['Channel']:<4} {enc:<25} {vendor:<16} {cl_str} {ssid_display}")
    return display_list

def print_attack_summary(result):
    if not result: return
    clear_screen()
    print(f"{C_GREEN}=========================================={C_RESET}")
    print(f"{C_GREEN}          ATTACK SUCCESS REPORT           {C_RESET}")
    print(f"{C_GREEN}=========================================={C_RESET}")
    print(f"SSID (Name) : {C_CYAN}{result['SSID']}{C_RESET}")
    print(f"BSSID (MAC) : {C_WHITE}{result['BSSID']}{C_RESET}")
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
            print(f"{i:<4} {bssid:<20} {hs_col:<20} {tm:<10} {C_GREEN}{ssid}{C_RESET}")
            i += 1
        return saved_list
