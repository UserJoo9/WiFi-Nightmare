# database.py
import json
import os
import re
import shutil
try:
    import fcntl
except ImportError:
    fcntl = None # Windows fallback

from config import DB_FILE, C_RED, C_RESET
from logger import logger

class DatabaseHandler:
    def __init__(self):
        self.known_networks = {}
        self.load()

    def load(self):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, 'r') as f:
                    # Shared lock for reading (Unix only)
                    if fcntl:
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    
                    self.known_networks = json.load(f)
                    
                    if fcntl:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except Exception as e:
                logger.error(f"Failed to load database: {e}")
                self.known_networks = {}

    def _validate_bssid(self, bssid):
        """Validate MAC address format"""
        if not bssid: return False
        return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid))

    def save(self, bssid, ssid):
        if not self._validate_bssid(bssid):
            logger.warning(f"Invalid BSSID format ignored: {bssid}")
            return
            
        bssid_key = bssid.lower()
        if bssid_key in self.known_networks:
            if isinstance(self.known_networks[bssid_key], dict):
                self.known_networks[bssid_key]['SSID'] = ssid
            else:
                self.known_networks[bssid_key] = {"SSID": ssid, "Handshake": False, "HSTime": "", "HSFile": ""}
        else:
            self.known_networks[bssid_key] = {"SSID": ssid, "Handshake": False, "HSTime": "", "HSFile": ""}
            
        self._write_to_file()

    def update_handshake(self, bssid, captured=True, time_str="", filename=""):
        if not self._validate_bssid(bssid):
            return
            
        bssid_key = bssid.lower()
        if bssid_key not in self.known_networks:
             # Upsert: Create new record if missing
             self.known_networks[bssid_key] = {"SSID": "<HIDDEN>", "Handshake": False, "HSTime": "", "HSFile": ""}

        if not isinstance(self.known_networks[bssid_key], dict):
            current_ssid = self.known_networks[bssid_key]
            self.known_networks[bssid_key] = {"SSID": current_ssid}
        
        self.known_networks[bssid_key]['Handshake'] = captured
        self.known_networks[bssid_key]['HSTime'] = time_str
        if filename:
            self.known_networks[bssid_key]['HSFile'] = filename
        
        self._write_to_file()

    def _write_to_file(self):
        temp_file = DB_FILE + ".tmp"
        try:
            with open(temp_file, 'w') as f:
                # Exclusive lock for writing (Unix only)
                if fcntl:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                
                json.dump(self.known_networks, f, indent=4)
                
                if fcntl:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Atomic move
            shutil.move(temp_file, DB_FILE)
            
        except Exception as e:
            logger.error(f"DB Save Error: {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
            
    def get_info(self, bssid):
        return self.known_networks.get(bssid.lower(), None)

