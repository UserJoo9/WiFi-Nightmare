# session_export.py
"""
Session Export — Export scan results, handshakes, and cracked passwords
to JSON and CSV formats for reporting and external processing.
"""
import os
import csv
import json
import time
import datetime
from typing import Dict, List, Optional, Any

from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET

EXPORT_DIR = os.path.expanduser('~/.wifi-nightmare/exports')


def _now_str() -> str:
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')


class SessionExporter:
    """Exports WiFi-Nightmare session data to JSON, CSV, and text reports."""

    def __init__(self, export_dir: str = None):
        self.export_dir = export_dir or EXPORT_DIR
        os.makedirs(self.export_dir, exist_ok=True)
        self.session_start = time.time()
        self.session_id = _now_str()

    def _build_network_record(self, bssid: str, net_info: dict,
                               db_info: dict = None) -> dict:
        db = db_info or {}
        crypto = net_info.get('Crypto', 'Unknown')
        return {
            'bssid': bssid,
            'ssid': net_info.get('SSID', db.get('SSID', 'Unknown')),
            'channel': net_info.get('Channel', 0),
            'rssi': net_info.get('RSSI', 0),
            'encryption': crypto,
            'wps': bool(net_info.get('WPS', False)),
            'hidden': bool(net_info.get('Hidden', False)),
            'vendor': net_info.get('Vendor', 'Unknown'),
            'clients': list(net_info.get('Clients', [])),
            'client_count': len(net_info.get('Clients', [])),
            'pmf': 'PMF' in crypto,
            'wpa3': 'WPA3' in crypto or 'SAE' in crypto,
            'handshake_captured': bool(db.get('Handshake', False)),
            'handshake_file': db.get('HSFile', ''),
            'handshake_time': db.get('HSTime', ''),
            'wps_pin': db.get('WPS_PIN', ''),
            'password': db.get('Password', ''),
            'first_seen': net_info.get('FirstSeen', ''),
            'last_seen': net_info.get('LastSeen', time.strftime('%Y-%m-%d %H:%M:%S')),
        }

    def _build_session_meta(self, interface: str = '', notes: str = '') -> dict:
        return {
            'session_id': self.session_id,
            'tool': 'WiFi-Nightmare',
            'version': '3.0.2',
            'timestamp': datetime.datetime.now().isoformat(),
            'interface': interface,
            'duration_seconds': int(time.time() - self.session_start),
            'notes': notes,
        }

    def export_json(self, networks: Dict[str, dict],
                    db_handler=None,
                    interface: str = '',
                    notes: str = '',
                    filename: str = None) -> str:
        records = []
        for bssid, net_info in networks.items():
            db_info = db_handler.get_info(bssid) if db_handler else {}
            if isinstance(db_info, str):
                db_info = {'SSID': db_info}
            records.append(self._build_network_record(bssid, net_info, db_info or {}))

        data = {
            'meta': self._build_session_meta(interface, notes),
            'networks': records,
            'summary': {
                'total_networks': len(records),
                'with_handshake': sum(1 for r in records if r['handshake_captured']),
                'wpa3_networks': sum(1 for r in records if r['wpa3']),
                'open_networks': sum(1 for r in records if 'OPN' in r['encryption']),
                'hidden_networks': sum(1 for r in records if r['hidden']),
                'wps_enabled': sum(1 for r in records if r['wps']),
                'total_clients': sum(r['client_count'] for r in records),
            }
        }

        filename = filename or f"session_{self.session_id}.json"
        path = os.path.join(self.export_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"{C_GREEN}[+] JSON exported: {path}{C_RESET}")
        print(f"    Networks: {len(records)} | Handshakes: {data['summary']['with_handshake']}")
        return path

    def export_csv(self, networks: Dict[str, dict],
                   db_handler=None,
                   filename: str = None) -> str:
        records = []
        for bssid, net_info in networks.items():
            db_info = db_handler.get_info(bssid) if db_handler else {}
            if isinstance(db_info, str):
                db_info = {'SSID': db_info}
            records.append(self._build_network_record(bssid, net_info, db_info or {}))

        filename = filename or f"session_{self.session_id}.csv"
        path = os.path.join(self.export_dir, filename)

        fieldnames = [
            'bssid', 'ssid', 'channel', 'rssi', 'encryption', 'wps',
            'hidden', 'vendor', 'client_count', 'pmf', 'wpa3',
            'handshake_captured', 'handshake_file', 'handshake_time',
            'wps_pin', 'password', 'last_seen'
        ]

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(records)

        print(f"{C_GREEN}[+] CSV exported: {path}{C_RESET}")
        print(f"    Rows: {len(records)}")
        return path

    def export_text_report(self, networks: Dict[str, dict],
                           db_handler=None,
                           interface: str = '',
                           filename: str = None) -> str:
        records = []
        for bssid, net_info in networks.items():
            db_info = db_handler.get_info(bssid) if db_handler else {}
            if isinstance(db_info, str):
                db_info = {'SSID': db_info}
            records.append(self._build_network_record(bssid, net_info, db_info or {}))

        lines = [
            "=" * 60,
            "    WiFi-Nightmare v3.0.0 — Session Report",
            "=" * 60,
            f"Session ID : {self.session_id}",
            f"Interface  : {interface}",
            f"Timestamp  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Networks   : {len(records)}",
            "=" * 60,
            "",
        ]

        for i, r in enumerate(records):
            status = []
            if r['handshake_captured']: status.append('HS')
            if r['wpa3']: status.append('WPA3')
            if r['pmf']: status.append('PMF')
            if r['wps']: status.append('WPS')
            if r['password']: status.append(f"PWD:{r['password']}")
            status_str = ' | '.join(status) or 'No captures'

            lines.append(f"[{i+1:3d}] {r['ssid'][:32]:<32} CH:{r['channel']:<3} {r['encryption']:<15} {status_str}")
            lines.append(f"       BSSID: {r['bssid']} | Clients: {r['client_count']} | Vendor: {r['vendor'][:20]}")
            if r['handshake_file']:
                lines.append(f"       HS File: {r['handshake_file']}")
            lines.append("")

        lines.extend(["=" * 60, ""])

        filename = filename or f"report_{self.session_id}.txt"
        path = os.path.join(self.export_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        print(f"{C_GREEN}[+] Report exported: {path}{C_RESET}")
        return path

    def interactive_export(self, networks: Dict[str, dict],
                           db_handler=None,
                           interface: str = '') -> None:
        if not networks:
            print(f"{C_YELLOW}[!] No networks to export (run a scan first).{C_RESET}")
            input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")
            return

        print(f"\n{C_CYAN}--- SESSION EXPORT ---{C_RESET}")
        print(f"Networks to export: {C_GREEN}{len(networks)}{C_RESET}")
        print(f"{C_WHITE}[1] JSON (full structured data){C_RESET}")
        print(f"{C_WHITE}[2] CSV (spreadsheet compatible){C_RESET}")
        print(f"{C_WHITE}[3] Text Report (human-readable){C_RESET}")
        print(f"{C_WHITE}[4] All formats{C_RESET}")
        print(f"{C_RED}[0] Cancel{C_RESET}")

        choice = input(f"{C_YELLOW}[?]{C_RESET} Format [1]: ").strip() or '1'
        notes = input(f"{C_YELLOW}[?]{C_RESET} Notes (optional): ").strip()

        if choice == '1':
            self.export_json(networks, db_handler, interface, notes)
        elif choice == '2':
            self.export_csv(networks, db_handler)
        elif choice == '3':
            self.export_text_report(networks, db_handler, interface)
        elif choice == '4':
            self.export_json(networks, db_handler, interface, notes)
            self.export_csv(networks, db_handler)
            self.export_text_report(networks, db_handler, interface)
            print(f"{C_GREEN}[+] All formats exported to: {self.export_dir}{C_RESET}")
        elif choice == '0':
            return
        else:
            print(f"{C_RED}[!] Invalid option.{C_RESET}")

        input(f"\n{C_YELLOW}Press Enter to return...{C_RESET}")
