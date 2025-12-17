# cracker.py
import os
import subprocess
import shutil
from config import C_RED, C_GREEN, C_YELLOW, C_RESET, C_CYAN

def verify_password(pcap_file, bssid, ssid, password):
    if not os.path.exists(pcap_file):
        print(f"{C_RED}[!] Error: Pcap file not found.{C_RESET}")
        return False

    # كتابة الباسورد في ملف
    temp_pass_file = "temp_pass.txt"
    with open(temp_pass_file, 'w') as f: f.write(password)

    print(f"{C_CYAN}    [Cracker] Target: {ssid} ({bssid}) | Pass: {password}{C_RESET}")

    result = False
    
    # بناء الأمر بدقة: نحدد الماك والاسم لكي لا يسأل aircrack
    # -l : يكتب المفتاح في ملف (للتأكد) - اختياري
    # -q : الوضع الصامت (يقلل المخرجات غير المهمة)
    cmd = [
        "aircrack-ng",
        "-a", "2",              # WPA2
        "-w", temp_pass_file,   # ملف الباسورد
        "-b", bssid,            # الماك أدرس (ضروري جداً)
        "-e", ssid,             # اسم الشبكة (ضروري جداً)
        pcap_file               # ملف الكابتشر
    ]

    try:
        # تشغيل الأمر
        process = subprocess.run(cmd, capture_output=True, text=True)
        output = process.stdout

        if "KEY FOUND!" in output:
            result = True
        else:
            # تحليل سبب الفشل بدقة
            print(f"{C_RED}    [Debug] Aircrack Failed. Analysis:{C_RESET}")
            
            if "Passphrase not in dictionary" in output:
                # هذا يعني أن الهاند شيك سليم والماك صحيح، لكن الباسورد غلط
                # هذا هو الرد الطبيعي إذا كان الباسورد المدخل خطأ
                print(f"{C_YELLOW}    >>> Result: Wrong Password (Handshake is Valid).{C_RESET}")
            
            elif "No valid WPA handshakes" in output:
                # هذا يعني أن الملف لا يحتوي على هاند شيك لهذا الماك تحديداً
                print(f"{C_RED}    >>> Result: No handshake found for BSSID {bssid}.{C_RESET}")
                print(f"    >>> Full Output:\n{output}") # طباعة الكل للتحليل
            
            else:
                # خطأ آخر (مثل عدم تطابق الاسم)
                print(f"    >>> Unknown Error. Aircrack Output:\n{output}")

    except Exception as e:
        print(f"{C_RED}    [!] Execution Error: {e}{C_RESET}")

    # تنظيف
    if os.path.exists(temp_pass_file): os.remove(temp_pass_file)
    
    return result