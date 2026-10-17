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
        """True if system has 2 or more distinct physical wireless interfaces."""
        unique_phys = {a.phy for a in self.adapters if a.phy}
        return len(unique_phys) >= 2 or len(self.adapters) >= 2

    def auto_assign_roles(self, preferred_iface: Optional[str] = None, refresh: bool = True) -> Dict[str, str]:
        """Automatically assigns roles: 'sniffer' and 'injector' across available adapters.
        
        Benefits of Dual-Card Aggregation:
        - The sniffer never leaves the target channel -> Zero packet loss on 4-way handshakes.
        - The injector can hop or burst CSA/Deauth continuously without interfering with the capture buffer.
        """
        if refresh:
            self.refresh_adapters()
        if not self.adapters:
            return {"primary": preferred_iface or "wlan0", "mode": "single"}
            
        if len(self.adapters) == 1:
            self.primary_iface = self.adapters[0].name
            self.secondary_iface = None
            return {"primary": self.adapters[0].name, "mode": "single"}
            
        # If user picked a preferred interface, make it primary
        names = [a.name for a in self.adapters]
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
