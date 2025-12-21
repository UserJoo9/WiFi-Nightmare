# scanner.py
import time
import subprocess
import threading
from scapy.all import *
from config import *
from utils import get_vendor
from logger import logger

class NetworkScanner:
    def __init__(self, interface, db_handler):
        self.interface = interface
        self.db = db_handler
        self.networks = {}
        self.lock = threading.Lock()
        self.stop_sniffing = False

    def channel_hopper(self):
        ch = 1
        while not self.stop_sniffing:
            try:
                # Use iw instead of iwconfig (faster)
                subprocess.run(["iw", "dev", self.interface, "set", "channel", str(ch)], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                ch = ch + 1 if ch < 13 else 1
                time.sleep(0.5)
            except Exception as e:
                logger.debug(f"Channel hopping error: {e}")
                # Don't break loop, retry
                time.sleep(1)

    def packet_handler(self, pkt):
        if not pkt.haslayer(Dot11):
            return

        try:
            # ==========================================
            # 1. Beacons Processing
            # ==========================================
            if pkt.type == 0 and pkt.subtype == 8:
                try:
                    bssid = pkt[Dot11].addr2
                    if not bssid: return
                    bssid = bssid.lower()
                    
                    rssi = -100
                    if pkt.haslayer(RadioTap):
                        rssi = pkt[RadioTap].dBm_AntSignal or -100

                    try:
                        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                    except Exception:
                        ssid = ""

                    stats = pkt[Dot11Beacon].network_stats()
                    channel = stats.get("channel", 0)
                    raw_crypto = stats.get("crypto", {"OPN"})
                    crypto_str = ', '.join(raw_crypto) if isinstance(raw_crypto, set) else str(raw_crypto)

                    is_hidden = not ssid or ssid.startswith("\x00")
                    display_name = ssid
                    is_known = False
                    has_handshake = False
                    
                    vendor_name = get_vendor(bssid)
                    
                    # Database check
                    db_info = self.db.get_info(bssid)
                    if db_info:
                        if isinstance(db_info, dict):
                            saved_name = db_info.get('SSID', '')
                            has_handshake = db_info.get('Handshake', False)
                        else:
                            saved_name = db_info
                        
                        if is_hidden and saved_name:
                            display_name = saved_name
                            is_known = True
                        elif saved_name:
                             is_known = True
                    else:
                        if is_hidden: display_name = "<HIDDEN>"
                    
                    with self.lock:
                        if bssid not in self.networks:
                            self.networks[bssid] = {
                                "SSID": display_name,
                                "Channel": channel,
                                "Crypto": crypto_str,
                                "Hidden": is_hidden,
                                "Known": is_known,
                                "RSSI": rssi,
                                "Handshake": has_handshake,
                                "Vendor": vendor_name,
                                "Clients": set()
                            }
                        else:
                            self.networks[bssid]["RSSI"] = rssi
                            # Update name if decloaked
                            if self.networks[bssid]["SSID"] == "<HIDDEN>" and display_name != "<HIDDEN>":
                                self.networks[bssid]["SSID"] = display_name
                                self.networks[bssid]["Known"] = True
                except Exception as e:
                    logger.debug(f"Beacon processing error: {e}")

            # ==========================================
            # 2. Passive Revealer
            # ==========================================
            elif pkt.type == 0 and pkt.subtype in [0, 2, 5]:
                try:
                    target_bssid = None
                    if pkt.subtype == 5: # Probe Response
                        target_bssid = pkt.addr3.lower()
                    elif pkt.subtype in [0, 2]: # Assoc / Reassoc Request
                        target_bssid = pkt.addr1.lower() 

                    if target_bssid and target_bssid in self.networks:
                        if self.networks[target_bssid]['SSID'] == "<HIDDEN>":
                            if pkt.haslayer(Dot11Elt):
                                try:
                                    elt = pkt.getlayer(Dot11Elt)
                                    while elt:
                                        if elt.ID == 0: 
                                            ssid = elt.info.decode('utf-8', errors='ignore')
                                            if ssid and not ssid.startswith("\x00"):
                                                with self.lock:
                                                    self.networks[target_bssid]['SSID'] = ssid
                                                    self.networks[target_bssid]['Hidden'] = False
                                                    self.networks[target_bssid]['Known'] = True
                                                    self.db.save(target_bssid, ssid)
                                                    return
                                        elt = elt.payload
                                except Exception: pass
                except Exception as e:
                    logger.debug(f"Passive reveal error: {e}")

            # ==========================================
            # 3. Data Frames (Client Counting)
            # ==========================================
            elif pkt.type == 2:
                try:
                    addr1 = pkt.addr1.lower() if pkt.addr1 else None
                    addr2 = pkt.addr2.lower() if pkt.addr2 else None
                    
                    if not addr1 or not addr2: return

                    invalid_prefixes = ("33:33", "01:00:5e", "ff:ff")
                    if addr1.startswith(invalid_prefixes) or addr2.startswith(invalid_prefixes):
                        return

                    with self.lock:
                        if addr2 in self.networks:
                            self.networks[addr2]["Clients"].add(addr1)
                        elif addr1 in self.networks:
                            self.networks[addr1]["Clients"].add(addr2)
                except Exception:
                    pass
        except Exception:
            # global catch to prevent thread death
            pass


class ClientMonitor:
    """Live client monitoring and display"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.stop_monitoring = False
        self.networks_map = {}

    def start(self):
        self.stop_monitoring = False
        
        if not any(t.name == "ChannelHopper" for t in threading.enumerate()):
            t = threading.Thread(target=self.scanner.channel_hopper, name="ChannelHopper", daemon=True)
            t.start()

        print(f"{C_YELLOW}[*] Starting Live Client Monitor... (Press Ctrl+C to Return){C_RESET}")
        time.sleep(1)

        try:
            while not self.stop_monitoring:
                sniff(iface=self.scanner.interface, prn=self.scanner.packet_handler, count=0, timeout=0.1, store=0)
                self.update_and_print()
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop_monitoring = True

    def update_and_print(self):
        # 1. Update data
        with self.scanner.lock:
            for bssid, data in self.scanner.networks.items():
                ssid = data['SSID']
                channel = data['Channel']
                
                if bssid not in self.networks_map:
                    self.networks_map[bssid] = { 'ssid': ssid, 'channel': channel, 'clients': {} }
                
                if self.networks_map[bssid]['ssid'] in ["", "<HIDDEN>"] and ssid not in ["", "<HIDDEN>"]:
                    self.networks_map[bssid]['ssid'] = ssid
                
                self.networks_map[bssid]['channel'] = channel

                # Add all clients
                if data['Clients']:
                    for client_mac in data['Clients']:
                        if client_mac not in self.networks_map[bssid]['clients']:
                            vendor = get_vendor(client_mac)
                            if len(vendor) > 25: vendor = vendor[:23] + ".."
                            self.networks_map[bssid]['clients'][client_mac] = vendor

        # 2. Display
        import os
        os.system("clear")
        print(f"{C_CYAN}======================= LIVE CLIENT MONITOR ======================={C_RESET}")
        
        if not self.networks_map:
            print(f"\n{C_YELLOW}   Scanning for networks and clients...{C_RESET}")
            return

        total_clients = 0
        
        # Sort by name
        sorted_networks = sorted(self.networks_map.items(), key=lambda x: x[1]['ssid'])

        for bssid, net_data in sorted_networks:
            clients = net_data['clients']
            if not clients: continue

            ssid_display = net_data['ssid']
            if ssid_display == "<HIDDEN>" or ssid_display == "":
                ssid_display = f"{C_GREY}<HIDDEN>{C_RESET}"
            else:
                ssid_display = f"{C_WHITE}{ssid_display}{C_RESET}"
            
            ch_display = f"{C_YELLOW}CH:{net_data['channel']}{C_RESET}"

            print(f"{C_GREEN}[+] Network:{C_RESET} {ssid_display}  {C_GREY}({bssid}){C_RESET}  {ch_display}")
            print(f"    {'Client MAC':<20} {'Device Vendor'}")
            print(f"    {'-'*45}")

            for mac, vendor in clients.items():
                print(f"    {mac:<20} {vendor}")
                total_clients += 1
            
            print("")

        print("=" * 60)
        print(f"Total Clients Found: {total_clients}")
