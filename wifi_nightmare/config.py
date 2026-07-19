# config.py
import os
import sys
import importlib.resources as pkg_resources

from wifi_nightmare import __version__, __app_name__, __author__

# --- Detect Installation Mode ---
# Installed via .deb: /usr/share/wifi-nightmare/ exists (created by debian/install)
# Development: no system paths, use ~/.wifi-nightmare/
_INSTALLED = os.path.isdir("/usr/share/wifi-nightmare/")

# --- Runtime Data Directory ---
if _INSTALLED:
    _RUNTIME_DIR = "/var/lib/wifi-nightmare/"
else:
    _RUNTIME_DIR = os.environ.get(
        "WIFI_NIGHTMARE_DATA",
        os.path.join(os.path.expanduser("~"), ".wifi-nightmare")
    )

# --- Firmware Directory ---
if _INSTALLED:
    FIRMWARE_DIR = "/usr/share/wifi-nightmare/esp_firmware/"
else:
    # In dev mode, esp_firmware/ is at the repo root (parent of the package dir)
    _pkg_dir = os.path.dirname(os.path.abspath(__file__))
    FIRMWARE_DIR = os.path.normpath(os.path.join(_pkg_dir, "..", "esp_firmware"))

# --- Load Configuration ---
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    if len(sys.argv) > 1 and not any(x in sys.argv for x in ['-h', '--help', '-v']):
        print("Warning: PyYAML not installed. Using default configuration.", file=sys.stderr)


def load_config():
    defaults = {
        'scanning': {'channel_hop_interval': 0.5, 'timeout': 60},
        'attacks': {'deauth_packets': 50, 'handshake_timeout': 120, 'pmkid_timeout': 30},
        'pixie_dust': {'timeout': 120, 'verbose': True},
        'database': {'path': "wifi_db.json", 'auto_backup': True, 'backup_count': 5},
        'esp32': {'baudrate': 115200, 'timeout': 10},
        'output': {'cracked_passwords': "cracked.txt", 'handshakes_dir': "handshakes",
                    'log_file': "logs/wifinightmare.log"}
    }

    if not HAS_YAML:
        return defaults

    # Try loading from package data (default config shipped with package)
    try:
        _pkg = pkg_resources.files("wifi_nightmare")
        cfg_file = _pkg / "config.yaml"
        if cfg_file.is_file():
            with cfg_file.open('r') as f:
                user_cfg = yaml.safe_load(f)
                if user_cfg:
                    for section, values in user_cfg.items():
                        if section in defaults and isinstance(values, dict):
                            defaults[section].update(values)
    except Exception:
        pass

    # Try loading from /etc/wifi-nightmare/config.yaml (user override, installed mode)
    if _INSTALLED:
        etc_cfg = "/etc/wifi-nightmare/config.yaml"
        if os.path.exists(etc_cfg):
            try:
                with open(etc_cfg, 'r') as f:
                    user_cfg = yaml.safe_load(f)
                    if user_cfg:
                        for section, values in user_cfg.items():
                            if section in defaults and isinstance(values, dict):
                                defaults[section].update(values)
            except Exception as e:
                print(f"Error loading /etc/wifi-nightmare/config.yaml: {e}")

    return defaults


config = load_config()

# --- Export Configured Constants ---
DB_FILE = os.path.join(_RUNTIME_DIR, config['database']['path'])
HANDSHAKES_DIR = os.path.join(_RUNTIME_DIR, config['output']['handshakes_dir'])
VENDOR_CACHE_FILE = os.path.join(_RUNTIME_DIR, "vendors_cache.json")
LOG_FILE = os.path.join(_RUNTIME_DIR, config['output']['log_file'])

# VENDOR_FILE — bundled with the package (read-only)
try:
    _PKG = pkg_resources.files("wifi_nightmare")
    VENDOR_FILE = str(_PKG / "mac-vendor.txt")
except Exception:
    VENDOR_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendor.txt")

CHANNEL_HOP_INTERVAL = config['scanning']['channel_hop_interval']
DEAUTH_PACKETS = config['attacks']['deauth_packets']
BAUDRATE = config['esp32']['baudrate']
PIXIE_DUST_TIMEOUT = config['pixie_dust']['timeout']
ESP_HTML_LIMIT = 4096  # Max bytes for ESP captive portal HTML (also defined in firmware)

# Create runtime directories
os.makedirs(HANDSHAKES_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# --- Colors (ANSI) ---
C_GREEN = "\033[1;32m"
C_RED = "\033[1;31m"
C_YELLOW = "\033[1;33m"
C_CYAN = "\033[1;36m"
C_WHITE = "\033[1;37m"
C_GREY = "\033[1;30m"
C_RESET = "\033[0m"

# --- Project Identity ---
APP_NAME = __app_name__
VERSION = __version__
AUTHOR = __author__

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
