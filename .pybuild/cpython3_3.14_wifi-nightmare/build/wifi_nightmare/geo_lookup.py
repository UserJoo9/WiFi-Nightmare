# geo_lookup.py
"""
Geo-Location BSSID Lookup — Find approximate physical location of APs.
Providers supported:
  1. Wigle.net API
  2. OpenWifi API / local cache
"""
import os
import json
import time
import base64
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional, Dict, List

from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET
from wifi_nightmare.logger import logger
from wifi_nightmare.utils import mask_bssid

CACHE_FILE = os.path.expanduser('~/.wifi-nightmare/geo_cache.json')
CACHE_TTL = 86400 * 7  # 7 days


@dataclass
class GeoResult:
    bssid: str
    ssid: str = ''
    lat: float = 0.0
    lon: float = 0.0
    accuracy: float = 0.0
    country: str = ''
    city: str = ''
    provider: str = ''
    timestamp: float = field(default_factory=time.time)
    found: bool = False
    google_maps_url: str = ''

    def __post_init__(self):
        if self.found and self.lat and self.lon:
            self.google_maps_url = f"https://www.google.com/maps?q={self.lat},{self.lon}"


class GeoCache:
    """JSON-based local cache for geo results."""

    def __init__(self, cache_file: str = CACHE_FILE):
        self.cache_file = cache_file
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        self._data: Dict = self._load()

    def _load(self) -> Dict:
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save(self):
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            logger.debug(f"Geo cache save error: {e}")

    def get(self, bssid: str) -> Optional[dict]:
        key = bssid.lower().replace(':', '')
        entry = self._data.get(key)
        if entry and time.time() - entry.get('timestamp', 0) < CACHE_TTL:
            return entry
        return None

    def set(self, bssid: str, result: dict):
        key = bssid.lower().replace(':', '')
        result['timestamp'] = time.time()
        self._data[key] = result
        self._save()


class GeoLocator:
    """Multi-provider BSSID geo-location."""

    WIGLE_API_URL = 'https://api.wigle.net/api/v2/network/search'
    OPENWIFI_URL = 'https://openwifi.su/api/v1/lookup'

    def __init__(self, wigle_api_key: str = None, wigle_api_name: str = None):
        self.wigle_key = wigle_api_key
        self.wigle_name = wigle_api_name
        self.cache = GeoCache()

    def lookup(self, bssid: str, ssid: str = '') -> GeoResult:
        bssid_norm = bssid.lower()

        cached = self.cache.get(bssid_norm)
        if cached:
            result = GeoResult(**{k: v for k, v in cached.items()
                                  if k in GeoResult.__dataclass_fields__})
            result.bssid = bssid_norm
            return result

        if self.wigle_key:
            result = self._lookup_wigle(bssid_norm, ssid)
            if result.found:
                self.cache.set(bssid_norm, result.__dict__)
                return result

        result = self._lookup_openwifi(bssid_norm)
        if result.found:
            self.cache.set(bssid_norm, result.__dict__)
            return result

        return GeoResult(bssid=bssid_norm, ssid=ssid, found=False, provider='none')

    def _lookup_wigle(self, bssid: str, ssid: str = '') -> GeoResult:
        try:
            params = urllib.parse.urlencode({
                'netid': bssid,
                'onlymine': 'false',
                'freenet': 'false',
                'paynet': 'false',
                'resultsPerPage': '1',
            })
            url = f"{self.WIGLE_API_URL}?{params}"
            auth = base64.b64encode(
                f"{self.wigle_name}:{self.wigle_key}".encode()
            ).decode() if self.wigle_name else self.wigle_key

            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {auth}')
            req.add_header('Accept', 'application/json')

            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            results = data.get('results', [])
            if not results:
                return GeoResult(bssid=bssid, found=False, provider='wigle')

            r = results[0]
            return GeoResult(
                bssid=bssid,
                ssid=r.get('ssid', ssid),
                lat=float(r.get('trilat', 0)),
                lon=float(r.get('trilong', 0)),
                accuracy=float(r.get('accuracy', 0)),
                country=r.get('country', ''),
                city=r.get('city', ''),
                provider='wigle',
                found=True,
            )
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"{C_RED}[!] Wigle API: Unauthorized (check key/name){C_RESET}")
            elif e.code == 429:
                print(f"{C_YELLOW}[!] Wigle API: Rate limit hit{C_RESET}")
            logger.debug(f"Wigle HTTP error: {e}")
        except Exception as e:
            logger.debug(f"Wigle lookup error: {e}")
        return GeoResult(bssid=bssid, found=False, provider='wigle')

    def _lookup_openwifi(self, bssid: str) -> GeoResult:
        try:
            bssid_clean = bssid.replace(':', '').replace('-', '').lower()
            url = f"{self.OPENWIFI_URL}/{bssid_clean}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'WiFi-Nightmare/3.0')

            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            if data.get('lat') and data.get('lon'):
                return GeoResult(
                    bssid=bssid,
                    lat=float(data['lat']),
                    lon=float(data['lon']),
                    accuracy=float(data.get('accuracy', 100)),
                    country=data.get('country', ''),
                    city=data.get('city', ''),
                    provider='openwifi',
                    found=True,
                )
        except Exception as e:
            logger.debug(f"OpenWifi lookup error: {e}")
        return GeoResult(bssid=bssid, found=False, provider='openwifi')

    @staticmethod
    def print_result(result: GeoResult):
        if result.found:
            print(f"\n{C_GREEN}[+] Location Found for {mask_bssid(result.bssid)}:{C_RESET}")
            if result.ssid:
                print(f"    SSID      : {result.ssid}")
            print(f"    Lat / Lon : {result.lat:.6f}, {result.lon:.6f}")
            print(f"    Accuracy  : ~{result.accuracy:.0f}m")
            if result.city or result.country:
                print(f"    Place     : {result.city}, {result.country}")
            print(f"    Provider  : {result.provider}")
            print(f"    Google Maps: {C_CYAN}{result.google_maps_url}{C_RESET}")
        else:
            print(f"{C_YELLOW}[-] No location found for {mask_bssid(result.bssid)} (provider: {result.provider}){C_RESET}")

    def interactive_lookup(self, networks: Dict) -> None:
        if not networks:
            print(f"{C_YELLOW}[!] No networks to look up. Scan first.{C_RESET}")
            input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")
            return

        print(f"\n{C_CYAN}--- GEO-LOCATION BSSID LOOKUP ---{C_RESET}")

        if not self.wigle_key:
            print(f"{C_YELLOW}[i] Tip: Set WIGLE_API_KEY environment variable for global Wigle.net lookup.{C_RESET}")
            print(f"{C_YELLOW}    Proceeding with OpenWifi public database.{C_RESET}\n")

        nets = list(networks.items())
        for i, (bssid, info) in enumerate(nets):
            ssid = info.get('SSID', '<HIDDEN>')
            print(f"  [{C_GREEN}{i}{C_RESET}] {mask_bssid(bssid):<18} — {ssid}")
        print(f"  [{C_CYAN}A{C_RESET}] Lookup ALL networks")
        print(f"  [{C_RED}0{C_RESET}] Cancel")

        choice = input(f"\n{C_YELLOW}[?]{C_RESET} Select Network ID: ").strip()
        if choice.upper() == 'A':
            for bssid, info in nets:
                res = self.lookup(bssid, info.get('SSID', ''))
                self.print_result(res)
                time.sleep(0.5)
        elif choice.isdigit() and 0 <= int(choice) < len(nets):
            bssid, info = nets[int(choice)]
            res = self.lookup(bssid, info.get('SSID', ''))
            self.print_result(res)
        elif choice == '0':
            return
        else:
            print(f"{C_RED}[!] Invalid choice.{C_RESET}")

        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")
