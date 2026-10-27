# wordlist_manager.py
"""
Smart Wordlist Manager — Auto-download rockyou, intelligent password ordering.

Features:
  1. Auto-download rockyou.txt if not found
  2. Smart SSID-based wordlist generation (router default patterns)
  3. Vendor-specific default password generation
  4. Priority ordering: SSID-based > vendor defaults > rockyou
"""
import os
import sys
import re
import gzip
import shutil
import urllib.request
from typing import List, Optional

from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET

ROCKYOU_URLS = [
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.gz",
]

DEFAULT_WORDLIST_DIR = os.path.expanduser("~/.wifi-nightmare/wordlists")

VENDOR_PATTERNS = [
    (r'^TE[-_ ]?Data', ['12345678', 'tedata123', '87654321', '11111111']),
    (r'^WE[-_]?\d', ['12345678', 'we12345678', '87654321']),
    (r'^Vodafone[-_]?\d', ['vodafone1', '12345678', 'Vodafone1']),
    (r'^VF-\d', ['12345678', 'vodafone', 'Vodafone1']),
    (r'^Orange[-_]?\d', ['orange123', '12345678', 'Orange1234']),
    (r'^Etisalat', ['etisalat1', '12345678', 'Etisalat1']),
    (r'^TP-Link[-_]', ['12345678', 'tplink123', 'admin1234']),
    (r'^linksys', ['admin123', 'linksys1', 'password', '12345678']),
    (r'^NETGEAR', ['password', 'admin123', '12345678']),
    (r'^D-Link|^dlink', ['admin123', '12345678', 'dlink123']),
    (r'^ASUS|^ASUS_RT', ['admin123', 'asus1234', '12345678']),
    (r'^HuaweiHome|^HUAWEI', ['admin123', 'huawei123', '12345678']),
    (r'^Zain', ['zain1234', '12345678', 'Zain1234']),
    (r'.*', ['12345678', 'password', 'admin123', '123456789', '87654321',
              '11111111', '00000000', 'qwerty123', 'abc12345', '1234abcd']),
]


class WordlistManager:
    """Manages wordlists for WiFi password cracking."""

    def __init__(self, wordlist_dir: str = None):
        self.wordlist_dir = wordlist_dir or DEFAULT_WORDLIST_DIR
        os.makedirs(self.wordlist_dir, exist_ok=True)
        self.rockyou_path = os.path.join(self.wordlist_dir, 'rockyou.txt')

    def generate_ssid_wordlist(self, ssid: str, bssid: str = '') -> List[str]:
        """Generate likely passwords based on SSID name and MAC."""
        candidates = []
        ssid_clean = ssid.strip()
        ssid_lower = ssid_clean.lower()
        ssid_digits = re.sub(r'\D', '', ssid_clean)
        bssid_suffix = bssid.replace(':', '').replace('-', '')[-8:] if bssid else ''

        candidates.extend([
            ssid_clean,
            ssid_lower,
            ssid_clean + '123',
            ssid_clean + '1234',
            ssid_clean + '12345678',
            ssid_lower + '123',
            ssid_lower + '1234',
            ssid_lower + '12345678',
            ssid_clean + '!',
            ssid_clean + '@123',
        ])

        if ssid_digits:
            candidates.extend([
                ssid_digits,
                ssid_digits * 2 if len(ssid_digits) <= 4 else ssid_digits,
                '0' * max(0, 8 - len(ssid_digits)) + ssid_digits,
            ])

        if bssid_suffix:
            candidates.extend([
                bssid_suffix,
                bssid_suffix.upper(),
                bssid_suffix.lower(),
            ])

        seen = set()
        result = []
        for p in candidates:
            if p and p not in seen and 8 <= len(p) <= 63:
                seen.add(p)
                result.append(p)

        return result

    def get_vendor_defaults(self, ssid: str) -> List[str]:
        for pattern, passwords in VENDOR_PATTERNS:
            if re.search(pattern, ssid, re.IGNORECASE):
                return [p for p in passwords if 8 <= len(p) <= 63]
        return []

    def get_smart_wordlist(self, ssid: str, bssid: str = '') -> List[str]:
        smart = self.generate_ssid_wordlist(ssid, bssid)
        vendor = self.get_vendor_defaults(ssid)
        seen = set(smart)
        for p in vendor:
            if p not in seen:
                smart.append(p)
                seen.add(p)
        return smart

    def ensure_rockyou(self, force: bool = False) -> Optional[str]:
        if os.path.exists(self.rockyou_path) and not force:
            size_mb = os.path.getsize(self.rockyou_path) / 1024 / 1024
            print(f"{C_GREEN}[+] rockyou.txt found ({size_mb:.1f} MB): {self.rockyou_path}{C_RESET}")
            return self.rockyou_path

        system_paths = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/rockyou.txt.gz',
            '/opt/wordlists/rockyou.txt',
        ]
        for path in system_paths:
            if os.path.exists(path):
                if path.endswith('.gz'):
                    print(f"{C_CYAN}[*] Found rockyou.gz, decompressing...{C_RESET}")
                    return self._decompress_gz(path, self.rockyou_path)
                print(f"{C_GREEN}[+] Found system rockyou: {path}{C_RESET}")
                return path

        print(f"{C_YELLOW}[*] rockyou.txt not found. Downloading...{C_RESET}")
        return self._download_rockyou()

    def _download_rockyou(self) -> Optional[str]:
        for url in ROCKYOU_URLS:
            print(f"{C_CYAN}[*] Trying: {url}{C_RESET}")
            tmp_path = os.path.join(self.wordlist_dir, '_rockyou_dl_tmp')
            try:
                with urllib.request.urlopen(url, timeout=30) as resp:
                    total = int(resp.headers.get('Content-Length', 0))
                    downloaded = 0
                    with open(tmp_path, 'wb') as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total:
                                pct = downloaded * 100 // total
                                mb = downloaded / 1024 / 1024
                                sys.stdout.write(f"\r{C_YELLOW}[*] Downloading: {mb:.1f} MB ({pct}%){C_RESET}  ")
                                sys.stdout.flush()

                print(f"\n{C_GREEN}[+] Download complete.{C_RESET}")
                if url.endswith('.gz'):
                    return self._decompress_gz(tmp_path, self.rockyou_path)
                else:
                    shutil.move(tmp_path, self.rockyou_path)
                    return self.rockyou_path
            except Exception as e:
                print(f"{C_YELLOW}[!] Download failed ({e}), checking next source...{C_RESET}")
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

        print(f"{C_RED}[!] Could not download rockyou.txt.{C_RESET}")
        return None

    def _decompress_gz(self, gz_path: str, out_path: str) -> str:
        print(f"{C_CYAN}[*] Decompressing {gz_path}...{C_RESET}")
        with gzip.open(gz_path, 'rb') as f_in:
            with open(out_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        size_mb = os.path.getsize(out_path) / 1024 / 1024
        print(f"{C_GREEN}[+] Decompressed: {size_mb:.1f} MB -> {out_path}{C_RESET}")
        return out_path

    def get_combined_wordlist_path(self, ssid: str, bssid: str = '') -> str:
        smart_words = self.get_smart_wordlist(ssid, bssid)
        rockyou = self.ensure_rockyou()

        safe_ssid = re.sub(r'[^\w-]', '_', ssid)[:20] or "target"
        combined_path = os.path.join(self.wordlist_dir, f'smart_{safe_ssid}.txt')

        smart_set = set(smart_words)
        with open(combined_path, 'w', encoding='utf-8', errors='replace') as out:
            for pw in smart_words:
                out.write(pw + '\n')
            if rockyou and os.path.exists(rockyou):
                with open(rockyou, 'r', encoding='utf-8', errors='replace') as ry:
                    for line in ry:
                        pw = line.rstrip('\n\r')
                        if pw and pw not in smart_set:
                            out.write(pw + '\n')

        total = sum(1 for _ in open(combined_path, 'r', errors='replace'))
        print(f"{C_GREEN}[+] Smart wordlist generated: {total:,} passwords -> {combined_path}{C_RESET}")
        return combined_path

    def interactive_select(self, ssid: str, bssid: str = '') -> Optional[str]:
        print(f"\n{C_CYAN}--- SMART WORDLIST SELECTOR ---{C_RESET}")
        print(f"Target SSID: {C_GREEN}{ssid}{C_RESET}")
        smart = self.get_smart_wordlist(ssid, bssid)
        print(f"{C_YELLOW}[*] Generated {len(smart)} smart passwords for this target{C_RESET}")

        print(f"\n{C_WHITE}[1] Smart Wordlist only ({len(smart)} passwords — fast){C_RESET}")
        print(f"{C_WHITE}[2] Smart + rockyou.txt (full power — comprehensive){C_RESET}")
        print(f"{C_WHITE}[3] Custom wordlist (enter path){C_RESET}")
        print(f"{C_WHITE}[4] Show smart passwords{C_RESET}")
        print(f"{C_RED}[0] Cancel{C_RESET}")

        choice = input(f"{C_YELLOW}[?]{C_RESET} Select [1]: ").strip() or '1'

        if choice == '1':
            safe_ssid = re.sub(r'[^\w-]', '_', ssid)[:20] or "target"
            path = os.path.join(self.wordlist_dir, f'smart_{safe_ssid}.txt')
            with open(path, 'w', encoding='utf-8') as f:
                for pw in smart:
                    f.write(pw + '\n')
            print(f"{C_GREEN}[+] Wordlist saved: {path}{C_RESET}")
            return path
        elif choice == '2':
            return self.get_combined_wordlist_path(ssid, bssid)
        elif choice == '3':
            path = input(f"{C_YELLOW}[?] Wordlist path: {C_RESET}").strip()
            path = os.path.expanduser(path)
            if os.path.isfile(path):
                return path
            print(f"{C_RED}[!] File not found.{C_RESET}")
            return None
        elif choice == '4':
            print(f"\n{C_CYAN}Smart passwords for '{ssid}':{C_RESET}")
            for i, pw in enumerate(smart, 1):
                print(f"  {i}. {pw}")
            input(f"\n{C_YELLOW}Press Enter...{C_RESET}")
            return self.interactive_select(ssid, bssid)
        return None
