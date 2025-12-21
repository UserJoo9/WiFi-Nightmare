# config.py
import os
import sys

# Try to import yaml, if not available use defaults
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    # Only print warning if we are not just checking version/help
    if len(sys.argv) > 1 and not any(x in sys.argv for x in ['-h', '--help', '-v']):
        print("Warning: PyYAML not installed. Using default configuration.", file=sys.stderr)

# --- Paths (الترتيب هنا مهم جداً) ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.yaml")

# --- Load Configuration ---
def load_config():
    defaults = {
        'scanning': {'channel_hop_interval': 0.5, 'timeout': 60},
        'attacks': {'deauth_packets': 50, 'handshake_timeout': 120, 'pmkid_timeout': 30},
        'database': {'path': "wifi_db.json", 'auto_backup': True, 'backup_count': 5},
        'esp32': {'baudrate': 115200, 'timeout': 10},
        'output': {'cracked_passwords': "cracked.txt", 'handshakes_dir': "handshakes", 'log_file': "logs/wifinightmare.log"}
    }
    
    if HAS_YAML and os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    # Deep merge would be better, but simple update for now
                    for section, values in user_config.items():
                        if section in defaults and isinstance(values, dict):
                            defaults[section].update(values)
        except Exception as e:
            print(f"Error loading config.yaml: {e}")
            
    return defaults

config = load_config()

# --- Export Configured Constants ---
DB_FILE = os.path.join(SCRIPT_DIR, config['database']['path'])
HANDSHAKES_DIR = os.path.join(SCRIPT_DIR, config['output']['handshakes_dir'])
VENDOR_FILE = os.path.join(SCRIPT_DIR, "mac-vendor.txt") 
VENDOR_CACHE_FILE = os.path.join(SCRIPT_DIR, "vendors_cache.json") 
LOG_FILE = os.path.join(SCRIPT_DIR, config['output']['log_file'])

CHANNEL_HOP_INTERVAL = config['scanning']['channel_hop_interval']
DEAUTH_PACKETS = config['attacks']['deauth_packets']
BAUDRATE = config['esp32']['baudrate']

# Create dirs
if not os.path.exists(HANDSHAKES_DIR):
    os.makedirs(HANDSHAKES_DIR)
    
log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir)

# --- Colors (ANSI) ---
C_GREEN = "\033[1;32m"
C_RED = "\033[1;31m"
C_YELLOW = "\033[1;33m"
C_CYAN = "\033[1;36m"
C_WHITE = "\033[1;37m"
C_GREY = "\033[1;30m"
C_RESET = "\033[0m"

# --- Project Identity ---
APP_NAME = "Wi-Fi Nightmare"
VERSION = "2.0.2"
AUTHOR = "Youssef Alkhodary"

# --- ASCII Art Banner ---
BANNER = r"""
██╗    ██╗██╗      ███████╗██╗    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███╗   ███╗ █████╗ ██████╗ ███████╗
██║    ██║██║      ██╔════╝██║    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗██╔════╝
██║ █╗ ██║██║█████╗█████╗  ██║    ██╔██╗ ██║██║██║  ███╗███████║   ██║   ██╔████╔██║███████║██████╔╝█████╗  
██║███╗██║██║╚════╝██╔══╝  ██║    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║╚██╔╝██║██╔══██║██╔══██╗██╔══╝  
╚███╔███╔╝██║      ██║     ██║    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗
 ╚══╝╚══╝ ╚═╝      ╚═╝     ╚═╝    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                    Advanced WiFi Security Auditing Framework
"""
