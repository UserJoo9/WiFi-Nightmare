import os
import json
import time
import urllib.request
import ssl
from config import VENDOR_FILE, VENDOR_CACHE_FILE

# ==========================================
# 1. INTERNAL DB (Fallback 1)
# ==========================================
INTERNAL_DB = {
    # --- APPLE ---
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
    "00:0D:93": "Apple", "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
    "00:16:CB": "Apple", "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
    "00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple",
    "00:26:08": "Apple", "00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple",
    "DC:A9:04": "Apple", "D8:D1:CB": "Apple", "F0:99:B6": "Apple", "88:63:DF": "Apple",
    "C8:F6:50": "Apple", "E4:CE:8F": "Apple", "98:01:A7": "Apple", "BC:92:6B": "Apple",
    "A8:5B:78": "Apple", "F4:F9:51": "Apple", "48:D7:05": "Apple", "8C:85:90": "Apple",
    "80:E6:50": "Apple", "00:F4:B9": "Apple", "CC:08:8D": "Apple", "40:30:04": "Apple",

    # --- SAMSUNG ---
    "00:00:F0": "Samsung", "00:02:78": "Samsung", "00:07:AB": "Samsung", "00:09:18": "Samsung",
    "00:0D:AE": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung", "00:13:77": "Samsung",
    "00:15:99": "Samsung", "00:15:B9": "Samsung", "00:16:32": "Samsung", "00:16:6C": "Samsung",
    "00:16:DB": "Samsung", "00:17:C9": "Samsung", "00:18:AF": "Samsung", "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung", "00:1C:43": "Samsung", "00:1D:25": "Samsung", "00:1D:98": "Samsung",
    "00:1E:7D": "Samsung", "00:1F:CC": "Samsung", "00:21:19": "Samsung", "00:21:D1": "Samsung",
    "00:21:D2": "Samsung", "00:23:99": "Samsung", "00:23:D7": "Samsung", "00:24:3E": "Samsung",
    "00:24:54": "Samsung", "00:24:90": "Samsung", "00:25:38": "Samsung", "00:26:37": "Samsung",
    "08:37:3D": "Samsung", "34:14:5F": "Samsung", "50:F5:20": "Samsung", "A8:06:00": "Samsung",
    "B8:B9:8A": "Samsung", "D0:17:C2": "Samsung", "FC:C2:DE": "Samsung", "24:F5:A2": "Samsung",

    # --- HUAWEI ---
    "00:0B:46": "Huawei", "00:0F:E2": "Huawei", "00:18:82": "Huawei", "00:19:B5": "Huawei",
    "00:1E:10": "Huawei", "00:22:A1": "Huawei", "00:25:68": "Huawei", "00:46:4B": "Huawei",
    "00:50:5E": "Huawei", "00:66:4B": "Huawei", "00:E0:FC": "Huawei", "04:25:C5": "Huawei",
    "04:C0:6F": "Huawei", "08:19:A6": "Huawei", "0C:37:DC": "Huawei", "0C:96:BF": "Huawei",
    "10:51:72": "Huawei", "10:C6:1F": "Huawei", "20:08:ED": "Huawei", "20:2B:C1": "Huawei",
    "20:AB:37": "Huawei", "20:F4:1B": "Huawei", "24:69:A5": "Huawei", "24:DB:AC": "Huawei",
    "28:3C:93": "Huawei", "28:5F:DB": "Huawei", "28:6E:D4": "Huawei", "30:87:30": "Huawei",
    "30:D1:7E": "Huawei", "34:00:A3": "Huawei", "34:6B:D3": "Huawei", "34:A2:A6": "Huawei",
    "34:CD:BE": "Huawei", "38:F2:3E": "Huawei", "3C:47:11": "Huawei", "3C:F8:08": "Huawei",
    "40:4D:8E": "Huawei", "40:CB:C0": "Huawei", "48:46:FB": "Huawei", "48:62:76": "Huawei",
    "48:7B:6B": "Huawei", "4C:1F:CC": "Huawei", "4C:54:99": "Huawei", "4C:8B:EF": "Huawei",
    "4C:B1:6C": "Huawei", "50:9F:27": "Huawei", "50:A7:2B": "Huawei", "54:39:DF": "Huawei",
    "54:89:98": "Huawei", "54:A5:1B": "Huawei", "58:1F:28": "Huawei", "58:2A:F7": "Huawei",
    "58:60:35": "Huawei", "58:7F:57": "Huawei", "5C:4C:A9": "Huawei", "5C:7D:5E": "Huawei",
    "5C:B4:3E": "Huawei", "60:DE:44": "Huawei", "60:E7:01": "Huawei", "64:16:93": "Huawei",
    "68:A0:3E": "Huawei", "70:54:F5": "Huawei", "70:72:3C": "Huawei", "70:7B:E8": "Huawei",
    "74:88:2A": "Huawei", "78:1D:BA": "Huawei", "78:6A:89": "Huawei", "78:F5:FD": "Huawei",
    "7C:60:97": "Huawei", "80:38:BC": "Huawei", "80:71:7A": "Huawei", "80:B6:86": "Huawei",
    "80:D0:9B": "Huawei", "80:FB:06": "Huawei", "84:A8:E4": "Huawei", "84:DB:AC": "Huawei",
    "88:53:2E": "Huawei", "88:86:03": "Huawei", "88:CE:FA": "Huawei", "8C:34:FD": "Huawei",
    "90:17:AC": "Huawei", "90:4E:91": "Huawei", "94:04:9C": "Huawei", "94:77:2B": "Huawei",
    "98:08:4D": "Huawei", "9C:37:F4": "Huawei", "9C:C1:72": "Huawei", "A4:99:47": "Huawei",
    "A4:CA:A0": "Huawei", "A8:CA:7B": "Huawei", "AC:4E:91": "Huawei", "AC:85:3D": "Huawei",
    "AC:E2:15": "Huawei", "AC:E8:7B": "Huawei", "B0:5B:67": "Huawei", "B4:0F:3B": "Huawei",
    "B4:15:13": "Huawei", "BC:25:E0": "Huawei", "BC:76:70": "Huawei", "C0:70:09": "Huawei",
    "C4:05:45": "Huawei", "C4:07:2F": "Huawei", "C8:D1:5E": "Huawei", "CC:53:B5": "Huawei",
    "CC:96:A0": "Huawei", "CC:CC:81": "Huawei", "D0:2D:B3": "Huawei", "D0:7A:B5": "Huawei",
    "D4:40:F0": "Huawei", "D4:6A:A8": "Huawei", "D4:B1:10": "Huawei", "D8:49:0B": "Huawei",
    "DC:D2:FC": "Huawei", "E0:19:1D": "Huawei", "E0:24:7F": "Huawei", "E0:36:76": "Huawei",
    "E0:97:96": "Huawei", "E4:35:C8": "Huawei", "E4:68:A3": "Huawei", "E8:08:8B": "Huawei",
    "E8:8D:28": "Huawei", "E8:CD:2D": "Huawei", "EC:23:3D": "Huawei", "EC:8C:A2": "Huawei",
    "EC:CB:30": "Huawei", "F0:63:F9": "Huawei", "F4:55:9C": "Huawei", "F4:C7:14": "Huawei",
    "F4:DC:F9": "Huawei", "F8:3D:FF": "Huawei", "F8:4A:BF": "Huawei", "F8:98:B9": "Huawei",
    "FC:48:EF": "Huawei", "FC:E3:3C": "Huawei",

    # --- TP-LINK ---
    "00:03:7F": "TP-Link", "00:0A:EB": "TP-Link", "00:14:78": "TP-Link", "00:19:CB": "TP-Link",
    "00:1D:0F": "TP-Link", "00:21:8C": "TP-Link", "00:23:CD": "TP-Link", "00:25:86": "TP-Link",
    "00:27:19": "TP-Link", "14:CC:20": "TP-Link", "14:CF:92": "TP-Link", "18:A6:F7": "TP-Link",
    "1C:44:19": "TP-Link", "20:DC:E6": "TP-Link", "30:B5:C2": "TP-Link", "3C:46:D8": "TP-Link",
    "40:16:9F": "TP-Link", "44:E9:DD": "TP-Link", "50:3E:AA": "TP-Link", "50:C7:BF": "TP-Link",
    "54:E6:FC": "TP-Link", "60:E3:27": "TP-Link", "64:66:B3": "TP-Link", "64:70:02": "TP-Link",
    "70:4F:57": "TP-Link", "74:EA:3A": "TP-Link", "78:44:76": "TP-Link", "7C:8B:CA": "TP-Link",
    "84:16:F9": "TP-Link", "88:25:93": "TP-Link", "8C:21:0A": "TP-Link", "90:F6:52": "TP-Link",
    "94:0C:6D": "TP-Link", "98:48:27": "TP-Link", "A0:F3:C1": "TP-Link", "A4:2B:B0": "TP-Link",
    "AC:84:C6": "TP-Link", "B0:48:7A": "TP-Link", "B0:BE:76": "TP-Link", "C0:25:E9": "TP-Link",
    "C0:4A:00": "TP-Link", "C0:C1:C0": "TP-Link", "C4:6E:1F": "TP-Link", "C4:E9:84": "TP-Link",
    "CC:32:E5": "TP-Link", "D4:6E:0E": "TP-Link", "D8:0D:17": "TP-Link", "D8:5D:4C": "TP-Link",
    "D8:FEB0": "TP-Link", "E4:D3:32": "TP-Link", "E8:94:F6": "TP-Link", "E8:DE:27": "TP-Link",
    "EC:08:6B": "TP-Link", "EC:17:2F": "TP-Link", "EC:26:CA": "TP-Link", "EC:88:8F": "TP-Link",
    "F4:F2:6D": "TP-Link", "F8:1A:67": "TP-Link", "F8:D1:11": "TP-Link", "FC:D7:33": "TP-Link",

    # --- ZTE ---
    "00:03:C9": "ZTE", "00:05:59": "ZTE", "00:08:2F": "ZTE", "00:08:A3": "ZTE",
    "00:0C:75": "ZTE", "00:0E:64": "ZTE", "00:12:37": "ZTE", "00:14:A4": "ZTE",
    "00:15:EB": "ZTE", "00:17:CC": "ZTE", "00:19:C6": "ZTE", "00:1A:6B": "ZTE",
    "00:1C:8E": "ZTE", "00:1E:73": "ZTE", "00:22:93": "ZTE", "00:24:D9": "ZTE",
    "00:25:12": "ZTE", "00:26:ED": "ZTE", "00:29:C2": "ZTE", "00:2D:02": "ZTE",
    "00:30:11": "ZTE", "00:46:4B": "ZTE", "00:4A:77": "ZTE", "08:18:1A": "ZTE",
    "0C:12:62": "ZTE", "10:1B:54": "ZTE", "14:60:80": "ZTE", "18:44:E6": "ZTE",
    "1C:87:76": "ZTE", "20:89:86": "ZTE", "24:CF:21": "ZTE", "2C:95:7F": "ZTE",
    "30:98:36": "ZTE", "34:E0:CF": "ZTE", "38:46:08": "ZTE", "3C:36:3D": "ZTE",
    "40:2C:F4": "ZTE", "40:B9:91": "ZTE", "44:F4:36": "ZTE", "48:57:02": "ZTE",
    "4C:09:B4": "ZTE", "4C:16:F1": "ZTE", "4C:AC:0A": "ZTE", "50:0D:37": "ZTE",
    "50:93:4F": "ZTE", "54:EC:2F": "ZTE", "58:AC:78": "ZTE", "5C:A4:8A": "ZTE",
    "60:73:BC": "ZTE", "64:13:6C": "ZTE", "68:1A:B2": "ZTE", "6C:8B:2F": "ZTE",
    "70:9F:2D": "ZTE", "74:A0:2F": "ZTE", "74:B5:7E": "ZTE", "78:31:2B": "ZTE",
    "78:48:59": "ZTE", "78:B3:2C": "ZTE", "78:B9:E5": "ZTE", "7C:1C:F1": "ZTE",
    "84:74:2A": "ZTE", "84:A8:14": "ZTE", "84:D3:2A": "ZTE", "84:E0:F6": "ZTE",
    "88:02:59": "ZTE", "8C:E0:81": "ZTE", "90:1D:27": "ZTE", "94:A7:B7": "ZTE",
    "98:00:6A": "ZTE", "98:32:D0": "ZTE", "98:F5:37": "ZTE", "A0:EC:80": "ZTE",
    "A4:50:55": "ZTE", "AC:64:62": "ZTE", "B0:75:D5": "ZTE", "B4:98:42": "ZTE",
    "B4:B3:62": "ZTE", "B8:92:1D": "ZTE", "BC:3A:EA": "ZTE", "C0:92:E6": "ZTE",
    "C8:64:C7": "ZTE", "CC:1A:FA": "ZTE", "D0:5B:A8": "ZTE", "D4:76:EA": "ZTE",
    "D8:55:75": "ZTE", "D8:74:95": "ZTE", "DC:02:8E": "ZTE", "E0:3F:49": "ZTE",
    "E0:C3:F3": "ZTE", "E4:7E:66": "ZTE", "E8:55:32": "ZTE", "EC:8C:9A": "ZTE",
    "F4:6D:E2": "ZTE", "F4:C7:14": "ZTE", "F8:DF:A8": "ZTE", "FC:C8:97": "ZTE",

    # --- D-LINK ---
    "00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:0F:3D": "D-Link", "00:13:46": "D-Link",
    "00:15:E9": "D-Link", "00:17:9A": "D-Link", "00:19:5B": "D-Link", "00:1B:11": "D-Link",
    "00:1C:F0": "D-Link", "00:1E:58": "D-Link", "00:21:91": "D-Link", "00:22:B0": "D-Link",
    "00:24:01": "D-Link", "00:26:5A": "D-Link", "14:D6:4D": "D-Link", "1C:7E:E5": "D-Link",
    "28:10:7B": "D-Link", "34:08:04": "D-Link", "78:54:2E": "D-Link", "84:C9:B2": "D-Link",
    "90:94:E4": "D-Link", "B0:C5:54": "D-Link", "B8:A3:86": "D-Link", "C4:12:F5": "D-Link",
    "C8:D3:A3": "D-Link", "CC:B2:55": "D-Link", "F0:7D:68": "D-Link", "FC:75:16": "D-Link",

    # --- NETGEAR ---
    "00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear", "00:18:4D": "Netgear",
    "00:1B:2F": "Netgear", "00:1E:2A": "Netgear", "00:1F:33": "Netgear", "00:22:3F": "Netgear",
    "00:24:B2": "Netgear", "00:26:F2": "Netgear", "04:A1:51": "Netgear", "10:0D:7F": "Netgear",
    "10:DA:43": "Netgear", "14:59:C0": "Netgear", "20:4E:7F": "Netgear", "20:E5:2A": "Netgear",
    "28:80:23": "Netgear", "2C:30:33": "Netgear", "2C:B0:5D": "Netgear", "30:46:9A": "Netgear",
    "3C:D9:2B": "Netgear", "40:5D:82": "Netgear", "44:94:FC": "Netgear", "48:F8:B3": "Netgear",
    "4C:60:DE": "Netgear", "50:6A:03": "Netgear", "6C:B0:CE": "Netgear", "78:D2:94": "Netgear",
    "80:CC:48": "Netgear", "84:1B:5E": "Netgear", "8A:1B:5E": "Netgear", "9C:3D:CF": "Netgear",
    "9C:D3:6D": "Netgear", "A0:04:60": "Netgear", "A0:21:B7": "Netgear", "A0:63:91": "Netgear",
    "B0:39:56": "Netgear", "B0:7F:B9": "Netgear", "B0:B9:8A": "Netgear", "C0:3F:0E": "Netgear",
    "C4:04:15": "Netgear", "C4:3D:C7": "Netgear", "CC:40:D0": "Netgear", "D8:97:BA": "Netgear",
    "E0:46:9A": "Netgear", "E0:91:F5": "Netgear", "E4:F4:C6": "Netgear", "E8:FC:AF": "Netgear",

    # --- XIAOMI ---
    "00:9E:C8": "Xiaomi", "14:F6:5A": "Xiaomi", "18:59:36": "Xiaomi", "20:34:FB": "Xiaomi",
    "20:47:DA": "Xiaomi", "28:6C:07": "Xiaomi", "28:C2:DD": "Xiaomi", "28:D0:EA": "Xiaomi",
    "34:80:B3": "Xiaomi", "34:CE:00": "Xiaomi", "38:76:CA": "Xiaomi", "40:31:3C": "Xiaomi",
    "50:64:2B": "Xiaomi", "50:8F:4C": "Xiaomi", "50:EC:50": "Xiaomi", "54:48:E6": "Xiaomi",
    "58:44:98": "Xiaomi", "58:B0:D4": "Xiaomi", "5C:C5:D4": "Xiaomi", "60:AB:67": "Xiaomi",
    "64:09:80": "Xiaomi", "64:B4:73": "Xiaomi", "64:CC:2E": "Xiaomi", "74:23:44": "Xiaomi",
    "74:51:BA": "Xiaomi", "78:02:F8": "Xiaomi", "78:11:DC": "Xiaomi", "7C:1D:D9": "Xiaomi",
    "8C:BE:BE": "Xiaomi", "94:87:E0": "Xiaomi", "98:FA:E3": "Xiaomi", "9C:99:A0": "Xiaomi",
    "A0:86:C6": "Xiaomi", "A4:50:46": "Xiaomi", "AC:C1:EE": "Xiaomi", "AC:F7:F3": "Xiaomi",
    "B0:E2:35": "Xiaomi", "C4:0B:CB": "Xiaomi", "C4:6B:B4": "Xiaomi", "D4:36:39": "Xiaomi",
    "D4:97:0B": "Xiaomi", "D8:63:75": "Xiaomi", "DC:B7:2E": "Xiaomi", "E4:46:DA": "Xiaomi",
    "EC:D0:9F": "Xiaomi", "F0:18:98": "Xiaomi", "F0:B4:29": "Xiaomi", "F4:8B:32": "Xiaomi",
    "F8:A4:5F": "Xiaomi", "FC:64:B9": "Xiaomi", "FC:79:2D": "Xiaomi",

    # --- OPPO & VIVO & ONEPLUS ---
    "38:A2:8C": "Oppo", "40:4E:36": "Oppo", "44:7E:5C": "Oppo", "58:00:E3": "Oppo",
    "9C:28:B3": "Oppo", "A0:02:DC": "Oppo", "C4:67:B5": "Oppo", "D0:C5:F3": "Oppo",
    "E4:5F:94": "Oppo", "98:00:3B": "Vivo", "9C:E3:3F": "Vivo", "C0:39:5A": "OnePlus",

    # --- INTEL ---
    "00:1B:21": "Intel", "00:21:6A": "Intel", "00:23:14": "Intel", "00:27:10": "Intel",
    "24:77:03": "Intel", "34:02:86": "Intel", "48:F1:7F": "Intel", "58:94:6B": "Intel",
    "60:57:18": "Intel", "68:05:CA": "Intel", "78:92:9C": "Intel", "80:86:F2": "Intel",
    "90:61:AE": "Intel", "94:65:9C": "Intel", "A0:88:B4": "Intel", "AC:72:89": "Intel",
    "C0:B6:F9": "Intel", "DC:53:60": "Intel", "E0:D5:5E": "Intel", "F8:59:71": "Intel",
    "B4:6D:83": "Intel", "40:25:C2": "Intel", "CC:3D:82": "Intel", "C4:85:08": "Intel",

    # --- REALTEK & MEDIATEK ---
    "00:E0:4C": "Realtek", "00:E0:5C": "Realtek", "52:54:00": "Realtek", "00:0C:43": "Ralink",
    "00:0C:F6": "Sitecom", "00:0E:8E": "SparkLAN", "00:14:D1": "Trendnet",
    
    # --- MIKROTIK ---
    "00:0C:42": "Mikrotik", "18:FD:74": "Mikrotik", "2C:C8:1B": "Mikrotik", "48:8F:5A": "Mikrotik",
    "4C:5E:0C": "Mikrotik", "64:D1:54": "Mikrotik", "6C:3B:6B": "Mikrotik", "74:4D:28": "Mikrotik",
    "B8:69:F4": "Mikrotik", "CC:2D:E0": "Mikrotik", "D4:CA:6D": "Mikrotik", "E4:8D:8C": "Mikrotik",

    # --- UBIQUITI ---
    "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti", "18:E8:29": "Ubiquiti",
    "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti", "60:22:32": "Ubiquiti", "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti", "78:8A:20": "Ubiquiti", "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti", "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",

    # --- CISCO & LINKSYS ---
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:1B:D4": "Cisco", "00:22:6B": "Cisco",
    "00:16:B6": "Linksys", "00:18:39": "Linksys", "00:1C:10": "Linksys", "00:23:69": "Linksys",
    
    # --- GOOGLE ---
    "00:1A:11": "Google", "3C:5A:B4": "Google", "D8:50:E6": "Google", "F4:F5:D8": "Google",
    "F8:8F:CA": "Google", "FC:F1:36": "Google", "70:3E:AC": "Google", "94:EB:CD": "Google",

    # --- TENDA ---
    "00:0A:EB": "Tenda", "00:50:FC": "Tenda", "08:10:76": "Tenda", "50:2B:73": "Tenda",
    "C8:3A:35": "Tenda", "CC:2D:21": "Tenda", "D8:32:14": "Tenda",

    # --- ESPRESSIF ---
    "18:FE:34": "Espressif", "24:0A:C4": "Espressif", "24:6F:28": "Espressif", "24:B2:DE": "Espressif",
    "2C:3A:E8": "Espressif", "30:AE:A4": "Espressif", "3C:71:BF": "Espressif", "4C:11:AE": "Espressif",
    "54:43:B2": "Espressif", "5C:CF:7F": "Espressif", "60:01:94": "Espressif", "68:C6:3A": "Espressif",
    "80:7D:3A": "Espressif", "84:F3:EB": "Espressif", "90:97:D5": "Espressif", "A0:20:A6": "Espressif",
    "A4:7B:9D": "Espressif", "AC:D0:74": "Espressif", "B4:E6:2D": "Espressif", "BC:DD:C2": "Espressif",
    "C4:4F:33": "Espressif", "CC:50:E3": "Espressif", "D8:A0:1D": "Espressif", "DC:4F:22": "Espressif",
    "EC:FA:BC": "Espressif",

    # --- WE / TE DATA (Custom Names) ---
    "00:E0:4C": "Realtek/WE", 
    "B4:0F:3B": "Huawei/WE",  
    "BC:25:E0": "Huawei/WE",
    "F4:C7:14": "ZTE/WE",    
    "F8:DF:A8": "ZTE/WE",
}

# ==========================================
# 2. FILE DB & ONLINE CACHE
# ==========================================
FILE_DB = {}
FILE_LOADED = False
ONLINE_CACHE = {}

def load_file_db():
    global FILE_LOADED
    if not os.path.exists(VENDOR_FILE): return
    try:
        with open(VENDOR_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    FILE_DB[parts[0].upper()] = parts[1].strip()
        FILE_LOADED = True
    except: pass

def load_cache():
    global ONLINE_CACHE
    if os.path.exists(VENDOR_CACHE_FILE):
        try:
            with open(VENDOR_CACHE_FILE, 'r') as f:
                ONLINE_CACHE = json.load(f)
        except: ONLINE_CACHE = {}

def save_cache():
    try:
        with open(VENDOR_CACHE_FILE, 'w') as f:
            json.dump(ONLINE_CACHE, f, indent=4)
    except: pass

# Rate limit: 1 request per second to avoid ban
LAST_REQUEST_TIME = 0

def get_online_vendor(mac_clean):
    global LAST_REQUEST_TIME
    
    current_time = time.time()
    if current_time - LAST_REQUEST_TIME < 1.0:
        time.sleep(1.0 - (current_time - LAST_REQUEST_TIME))
    
    LAST_REQUEST_TIME = time.time()

    try:
        url = f"https://api.macvendors.com/{mac_clean}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        
        # Safe SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
             return response.read().decode('utf-8').strip()
    except urllib.error.HTTPError as e:
        if e.code == 429: # Too Many Requests
            pass # Silent fail on rate limit
        return None
    except Exception: 
        return None

# Initialize Cache
load_cache()

def lookup_vendor(mac):
    if not mac or len(mac) < 8: return "Unknown"
    
    clean_mac = mac.replace(":", "").replace("-", "").upper()
    if len(clean_mac) < 6: return "Unknown"
    
    oui_clean = clean_mac[:6]
    oui_colon = mac.upper()[:8]

    # 1. Online Cache (الأولوية للكاش)
    if oui_clean in ONLINE_CACHE:
        return ONLINE_CACHE[oui_clean]

    # 2. Online API (البحث أونلاين)
    online_res = get_online_vendor(clean_mac)
    if online_res:
        ONLINE_CACHE[oui_clean] = online_res
        save_cache() 
        return online_res

    # 3. Internal DB (القائمة اليدوية)
    if oui_colon in INTERNAL_DB:
        return INTERNAL_DB[oui_colon]

    # 4. File DB (الملف النصي)
    if not FILE_LOADED: load_file_db()
    
    file_res = FILE_DB.get(oui_clean, None)
    if file_res:
        ONLINE_CACHE[oui_clean] = file_res 
        save_cache()
        return file_res

    return "Unknown"

