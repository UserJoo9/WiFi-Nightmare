
# client_recon.py
import time
import os
import sys
import threading
from scapy.all import sniff
from config import *
import utils
from vendors import lookup_vendor 

class ClientMonitor:
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
                # استجابة سريعة لـ Ctrl+C (timeout 0.1)
                sniff(iface=self.scanner.interface, prn=self.scanner.packet_handler, count=0, timeout=0.1, store=0)
                self.update_and_print()
                time.sleep(0.5) 
        except KeyboardInterrupt:
            self.stop_monitoring = True

    def update_and_print(self):
        # 1. تحديث البيانات
        with self.scanner.lock:
            for bssid, data in self.scanner.networks.items():
                ssid = data['SSID']
                channel = data['Channel']
                
                if bssid not in self.networks_map:
                    self.networks_map[bssid] = { 'ssid': ssid, 'channel': channel, 'clients': {} }
                
                if self.networks_map[bssid]['ssid'] in ["", "<HIDDEN>"] and ssid not in ["", "<HIDDEN>"]:
                    self.networks_map[bssid]['ssid'] = ssid
                
                self.networks_map[bssid]['channel'] = channel

                # إضافة جميع العملاء
                if data['Clients']:
                    for client_mac in data['Clients']:
                        if client_mac not in self.networks_map[bssid]['clients']:
                            # بحث وتخزين تلقائي
                            vendor = lookup_vendor(client_mac)
                            if len(vendor) > 25: vendor = vendor[:23] + ".."
                            self.networks_map[bssid]['clients'][client_mac] = vendor

        # 2. العرض
        os.system("clear")
        print(f"{C_CYAN}======================= LIVE CLIENT MONITOR ======================={C_RESET}")
        
        if not self.networks_map:
            print(f"\n{C_YELLOW}   Scanning for networks and clients...{C_RESET}")
            return

        total_clients = 0
        
        # ترتيب حسب الاسم
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
