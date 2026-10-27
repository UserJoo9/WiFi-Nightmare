# tui_dashboard.py
"""
TUI Dashboard — Terminal UI for WiFi-Nightmare.
Supports Rich if installed, otherwise provides styled ANSI rendering.
"""
import os
import sys
import time
import threading
from typing import Dict, Optional, List

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from wifi_nightmare.logger import logger
from wifi_nightmare.utils import mask_bssid

C_GREEN = "\033[1;32m"
C_RED = "\033[1;31m"
C_YELLOW = "\033[1;33m"
C_CYAN = "\033[1;36m"
C_WHITE = "\033[1;37m"
C_GREY = "\033[1;30m"
C_RESET = "\033[0m"


def _rssi_bar(rssi: int, width: int = 5) -> str:
    if rssi >= -50:
        bars = width
    elif rssi >= -65:
        bars = int(width * 0.8)
    elif rssi >= -75:
        bars = int(width * 0.6)
    elif rssi >= -85:
        bars = int(width * 0.4)
    else:
        bars = max(1, int(width * 0.2))
    return '█' * bars + '░' * (width - bars)


def _enc_short(crypto: str) -> str:
    crypto = crypto.replace("{", "").replace("}", "").replace("'", "").strip()
    if 'WPA3' in crypto and 'WPA2' in crypto:
        return 'WPA3/WPA2'
    if 'WPA3' in crypto or 'SAE' in crypto:
        return 'WPA3'
    if 'WPA2' in crypto:
        return 'WPA2' + (' PMF' if 'PMF' in crypto else '')
    if 'WPA' in crypto:
        return 'WPA'
    if 'WEP' in crypto:
        return 'WEP'
    return 'OPEN'


class TUIDashboard:
    """Live Terminal Dashboard for WiFi-Nightmare."""

    def __init__(self, interface: str = 'wlan0mon',
                 title: str = 'WiFi-Nightmare v3.0.0'):
        self.interface = interface
        self.title = title
        self._networks: Dict = {}
        self._lock = threading.Lock()
        self._attack_log: List[str] = []
        self._display_list: List[str] = []
        self._stats = {'total': 0, 'wpa3': 0, 'open': 0, 'with_hs': 0, 'clients': 0}
        self._console = Console() if HAS_RICH else None

    def update(self, networks: Dict, lock, current_channel: int = 0):
        with lock:
            self._networks = dict(networks)
        self._current_channel = current_channel
        self._recalc_stats()

    def _recalc_stats(self):
        nets = self._networks
        self._stats = {
            'total': len(nets),
            'wpa3': sum(1 for n in nets.values() if 'WPA3' in n.get('Crypto', '')),
            'open': sum(1 for n in nets.values() if 'OPN' in n.get('Crypto', '')),
            'with_hs': sum(1 for n in nets.values() if n.get('Handshake')),
            'clients': sum(len(n.get('Clients', [])) for n in nets.values()),
        }

    def log_event(self, message: str):
        ts = time.strftime('%H:%M:%S')
        with self._lock:
            self._attack_log.append(f"[{ts}] {message}")
            if len(self._attack_log) > 20:
                self._attack_log = self._attack_log[-20:]

    def get_display_list(self) -> List[str]:
        return list(self._display_list)

    def render_rich(self) -> List[str]:
        """Render using Rich table and panels."""
        if not HAS_RICH or not self._console:
            return []

        self._console.clear()
        s = self._stats
        header_text = (
            f"[bold cyan]IFACE:[/] {self.interface} | "
            f"[bold green]NETS:[/] {s['total']} | "
            f"[bold blue]WPA3:[/] {s['wpa3']} | "
            f"[bold red]OPEN:[/] {s['open']} | "
            f"[bold yellow]HS:[/] {s['with_hs']} | "
            f"[bold yellow]CLIENTS:[/] {s['clients']} | "
            f"[dim]Ctrl+C to Stop[/]"
        )
        self._console.print(Panel(header_text, title=f"[bold]{self.title}[/]", border_style="cyan"))

        table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan", expand=True)
        table.add_column('#', style='dim', width=3, justify='right')
        table.add_column('BSSID', width=17)
        table.add_column('Signal', width=10, justify='center')
        table.add_column('CH', width=3, justify='center')
        table.add_column('Encryption', width=12)
        table.add_column('WPS', width=4, justify='center')
        table.add_column('HS', width=4, justify='center')
        table.add_column('CL', width=3, justify='center')
        table.add_column('Vendor', width=14)
        table.add_column('SSID')

        self._display_list = []
        sorted_nets = sorted(
            self._networks.items(),
            key=lambda x: x[1].get('RSSI', -100),
            reverse=True
        )

        for i, (bssid, info) in enumerate(sorted_nets):
            self._display_list.append(bssid)
            rssi = info.get('RSSI', -100)
            sig_color = "bold green" if rssi > -60 else ("bold yellow" if rssi > -80 else "bold red")
            sig_text = Text(f"{_rssi_bar(rssi)} {rssi}", style=sig_color)

            crypto = info.get('Crypto', 'Unknown')
            enc_short = _enc_short(crypto)
            enc_color = "bold blue" if "WPA3" in enc_short else ("bold green" if "WPA2" in enc_short else "bold red")

            hs_text = Text("YES", style="bold green") if info.get('Handshake') else Text("-", style="dim")
            wps_text = Text("YES", style="bold yellow") if info.get('WPS') else Text("-", style="dim")
            clients = info.get('Clients', [])
            cl_text = Text(str(len(clients)), style="bold yellow" if clients else "dim")

            ssid_raw = info.get('SSID', '<HIDDEN>')
            if info.get('Known'):
                ssid_text = Text(ssid_raw, style="bold green")
            elif info.get('Hidden'):
                ssid_text = Text('<HIDDEN>', style="dim")
            else:
                ssid_text = Text(ssid_raw, style="white")

            vendor = info.get('Vendor', 'Unknown')[:14]
            masked = mask_bssid(bssid)

            table.add_row(
                str(i + 1), masked, sig_text, str(info.get('Channel', '?')),
                Text(enc_short, style=enc_color), wps_text, hs_text, cl_text,
                vendor, ssid_text
            )

        self._console.print(table)
        return self._display_list
