# card_manager.py — Multi-Card Aggregation & Coordination Engine (Dual-Card Support)
# Allows 1 dedicated sniffer + 1 dedicated injector, or split 2.4GHz / 5GHz scanning
import subprocess
import shutil
from typing import List, Dict, Optional
from dataclasses import dataclass
from wifi_nightmare.logger import logger
from wifi_nightmare.config import C_GREEN, C_YELLOW, C_CYAN, C_RESET


@dataclass
class WirelessAdapter:
    name: str
    phy: str
    is_monitor: bool = False
    driver: str = ""
    chipset: str = ""


class CardManager:
    """Discovers and coordinates multiple wireless interfaces for synchronized attacks."""
    
    def __init__(self):
        self.adapters: List[WirelessAdapter] = []
        self.primary_iface: Optional[str] = None
        self.secondary_iface: Optional[str] = None
        self.refresh_adapters()

    def refresh_adapters(self) -> List[WirelessAdapter]:
        """Query system for all physical wireless interfaces."""
        self.adapters.clear()
        try:
            iw_out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            current_phy = ""
            for line in iw_out.stdout.splitlines():
                line = line.strip()
                if line.startswith("phy#"):
                    current_phy = line.replace("#", "")
                elif line.startswith("Interface"):
                    iface_name = line.split()[-1]
                    # Check if monitor mode
                    info_out = subprocess.run(["iw", "dev", iface_name, "info"],
                                              capture_output=True, text=True, timeout=3)
                    is_mon = "type monitor" in info_out.stdout.lower()
                    self.adapters.append(WirelessAdapter(
                        name=iface_name,
                        phy=current_phy,
                        is_monitor=is_mon
                    ))
        except Exception as e:
            logger.debug(f"Adapter discovery failed: {e}")
            
        return self.adapters

    def has_multi_card(self) -> bool:
        """True if system has 2 or more DISTINCT physical wireless cards (different phy#)."""
        unique_phys = {a.phy for a in self.adapters if a.phy}
        return len(unique_phys) >= 2

    def _deduplicate_by_phy(self, preferred_iface: Optional[str] = None) -> List['WirelessAdapter']:
        """Return one adapter per physical card.

        When airmon-ng runs on wlan0, it creates wlan0mon on the SAME phy.
        Both interfaces share phy0, so we must pick only one per phy.
        Priority: preferred_iface > monitor-mode interface > first seen.
        """
        seen_phys: Dict[str, 'WirelessAdapter'] = {}
        for adapter in self.adapters:
            phy = adapter.phy
            if phy not in seen_phys:
                seen_phys[phy] = adapter
            else:
                # Prefer the preferred_iface if it matches
                if preferred_iface and adapter.name == preferred_iface:
                    seen_phys[phy] = adapter
                # Otherwise prefer monitor-mode interface (it's the active one)
                elif adapter.is_monitor and not seen_phys[phy].is_monitor:
                    seen_phys[phy] = adapter
        return list(seen_phys.values())

    def auto_assign_roles(self, preferred_iface: Optional[str] = None, refresh: bool = True) -> Dict[str, str]:
        """Automatically assigns roles: 'sniffer' and 'injector' across available adapters.

        Benefits of Dual-Card Aggregation:
        - The sniffer never leaves the target channel -> Zero packet loss on 4-way handshakes.
        - The injector can hop or burst CSA/Deauth continuously without interfering with the capture buffer.

        NOTE: airmon-ng creates wlan0mon from wlan0 on the SAME physical card (same phy#).
        We deduplicate by phy# so we never mistake them for two separate cards.
        """
        if refresh:
            self.refresh_adapters()
        if not self.adapters:
            return {"primary": preferred_iface or "wlan0", "mode": "single"}

        # Deduplicate: one entry per physical card
        unique_adapters = self._deduplicate_by_phy(preferred_iface)

        if len(unique_adapters) == 1:
            # Single physical card — use whichever interface is active (monitor or preferred)
            best = unique_adapters[0]
            if preferred_iface:
                best_name = preferred_iface
            else:
                best_name = best.name
            self.primary_iface = best_name
            self.secondary_iface = None
            return {"primary": best_name, "mode": "single"}

        # Two or more distinct physical cards — assign roles
        names = [a.name for a in unique_adapters]
        if preferred_iface and preferred_iface in names:
            self.primary_iface = preferred_iface
            remaining = [n for n in names if n != preferred_iface]
            self.secondary_iface = remaining[0] if remaining else None
        else:
            self.primary_iface = names[0]
            self.secondary_iface = names[1]

        return {
            "sniffer": self.primary_iface,
            "injector": self.secondary_iface,
            "mode": "dual"
        }
