# utils.py
import os
import re
import sys
import subprocess
import time
import shutil
import signal
from datetime import datetime
from wifi_nightmare.config import (
    C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET
)
from wifi_nightmare.logger import logger

# Try to import vendor database
try:
    from wifi_nightmare.vendors import lookup_vendor
except ImportError:
    def lookup_vendor(mac): return "Unknown"

def get_vendor(mac):
    return lookup_vendor(mac)


def mask_bssid(bssid):
    """Mask a BSSID, keeping only the first and last octet.

    '30:99:35:8e:16:6b' -> '30:xx:xx:xx:xx:6b'

    Handles both ':' and '-' separators and any letter case. Returns the
    input unchanged if it doesn't look like a MAC address.
    """
    if not bssid:
        return bssid
    parts = bssid.strip().lower().replace('-', ':').split(':')
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        return bssid
    return f"{parts[0]}:xx:xx:xx:xx:{parts[-1]}"


def mask_bssid_filename(bssid):
    """Masked BSSID safe for file names: '30:xx:xx:xx:xx:6b'."""
    return mask_bssid(bssid).replace(':', '-')


def scrub_bssid(text, bssid):
    """Replace every rendering of the full BSSID in text with the masked form.

    Covers ':'-separated, '-'-separated and separator-free spellings in any
    case (reaver and other tools print MACs in different formats). Returns
    the text unchanged if the BSSID doesn't look like a MAC address.
    """
    if not text or not bssid:
        return text
    masked = mask_bssid(bssid)
    core = bssid.strip().lower().replace(':', '').replace('-', '')
    if len(core) != 12 or not core.isalnum():
        return text
    octets = [core[i:i + 2] for i in range(0, 12, 2)]
    result = text
    for sep in (':', '-', ''):
        pattern = re.compile(re.escape(sep.join(octets)), re.IGNORECASE)
        result = pattern.sub(masked, result)
    return result


def safe_ssid(ssid):
    """Filesystem-safe form of an SSID for exported file names."""
    raw = (ssid or "").strip()
    # Check the RAW value: sanitizing '<HIDDEN>' strips the angle brackets
    # into 'HIDDEN', which would then pass the guard below.
    if not raw or raw in ("Unknown", "<HIDDEN>"):
        return "Unknown_SSID"
    safe = "".join(c for c in raw if c.isalpha() or c.isdigit() or c == ' ').strip()
    if not safe:
        safe = "Unknown_SSID"
    return safe

def get_current_time_12h():
    return datetime.now().strftime("%I:%M %p")

def check_root():
    if os.geteuid() != 0:
        logger.error("This script must be run as root (sudo).")
        sys.exit(1)

def check_interface_exists(interface):
    """Verify the SPECIFIC adapter the user asked for is actually present
    (antenna/dongle plugged in and recognized by the kernel).

    Only checks `interface` itself and its natural monitor-mode sibling
    (e.g. 'wlan0' <-> 'wlan0mon'). It must NOT fall back to unrelated
    hardcoded names like "wlan0" or "wlan0mon" -- on a multi-adapter box
    those belong to a DIFFERENT physical card and would make a missing /
    unplugged adapter look present, hiding the real problem instead of
    reporting it.
    """
    base = interface[:-3] if interface.endswith("mon") else interface
    possible_names = [interface, base, base + "mon"]
    for name in possible_names:
        if os.path.exists(f"/sys/class/net/{name}"):
            return name

    logger.error(f"Interface '{interface}' not found.")
    print(f"{C_RED}[!] Interface '{interface}' not found.{C_RESET}")
    print(f"{C_YELLOW}    Check that the Wi-Fi adapter is plugged in and recognized "
          f"(try 'ip link' or 'iw dev').{C_RESET}")
    sys.exit(1)

def run_command(cmd_list, check=False):
    """Safe wrapper for subprocess.run"""
    try:
        subprocess.run(
            cmd_list, 
            check=check, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.debug(f"Command failed: {cmd_list} - {e}")
        return False
    except Exception as e:
        logger.error(f"Error running command {cmd_list}: {e}")
        return False

def _get_iw_mode(interface):
    """Get current interface mode using 'iw dev info'"""
    try:
        output = subprocess.getoutput(f"iw dev {interface} info")
        if "type monitor" in output:
            return "monitor"
        elif "type managed" in output:
            return "managed"
    except Exception:
        pass
    return None

def enable_monitor_mode(interface):
    print(f"\n{C_YELLOW}[*] Preparing Interface...{C_RESET}")
    logger.info(f"Preparing interface {interface} for monitor mode")

    # 1. Kill interfering processes (airmon-ng check kill handles most of them,
    #    the extra pkill calls are a belt-and-suspenders safety net)
    run_command(["airmon-ng", "check", "kill"])
    for proc in ("wpa_supplicant", "dhclient", "NetworkManager"):
        run_command(["pkill", "-9", proc])
    run_command(["service", "NetworkManager", "stop"])

    # Unblock wifi
    run_command(["rfkill", "unblock", "wifi"])
    run_command(["rfkill", "unblock", "all"])

    time.sleep(0.5)

    # 2. Smart Check: Is it already in Monitor Mode?
    base = interface[:-3] if interface.endswith("mon") else interface
    check_list = [interface, base + "mon"]

    for iface in check_list:
        if os.path.exists(f"/sys/class/net/{iface}"):
            try:
                mode = _get_iw_mode(iface)
                if mode == "monitor":
                    logger.info(f"Interface '{iface}' is already in Monitor Mode.")
                    print(f"{C_GREEN}[+] Interface '{iface}' is ALREADY in Monitor Mode.{C_RESET}")
                    run_command(["ip", "link", "set", iface, "up"])
                    run_command(["iw", "dev", iface, "set", "channel", "1"])
                    return iface
            except Exception as e:
                logger.debug(f"Error checking interface {iface}: {e}")

    print(f"{C_CYAN}[*] Setting Monitor Mode on {interface}...{C_RESET}")
    logger.info(f"Setting Monitor Mode on {interface}")

    # 3. Primary Method: airmon-ng
    #    airmon-ng handles adapter-specific quirks automatically and creates a
    #    dedicated monitor-mode vif (usually <iface>mon or mon0).
    if shutil.which("airmon-ng"):
        print(f"{C_CYAN}[*] Using airmon-ng (primary method)...{C_RESET}")
        try:
            result = subprocess.run(
                ["airmon-ng", "start", interface],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout + result.stderr

            # --- Parse new monitor interface name ---
            # Pattern 1: "(mac80211 monitor mode vif enabled ... on [phy0]wlan0mon)"
            m = re.search(
                r'monitor mode vif enabled(?:\s+for\s+\S+)?\s+on\s+(?:\[\w+\])?(\w+)',
                output, re.IGNORECASE
            )
            if m:
                mon_iface = m.group(1).strip(')')
            else:
                # Pattern 2: "monitor mode enabled on wlan0mon"
                m2 = re.search(r'monitor mode enabled on (\S+)', output, re.IGNORECASE)
                if m2:
                    mon_iface = m2.group(1).rstrip(')')
                else:
                    # Pattern 3: pick first token that looks like a monitor interface
                    m3 = re.search(r'\b(\w+mon\d*|mon\d+)\b', output)
                    mon_iface = m3.group(1) if m3 else interface + "mon"

            time.sleep(1)  # give the kernel time to expose the new interface

            if os.path.exists(f"/sys/class/net/{mon_iface}"):
                print(f"{C_GREEN}[+] Monitor Mode Enabled via airmon-ng: {mon_iface}{C_RESET}")
                logger.info(f"airmon-ng: monitor mode enabled on {mon_iface}")
                run_command(["ip", "link", "set", mon_iface, "up"])
                return mon_iface

            # Name detection missed — probe common names
            for candidate in (base + "mon", "mon0"):
                if os.path.exists(f"/sys/class/net/{candidate}"):
                    print(f"{C_GREEN}[+] Monitor Mode Enabled via airmon-ng: {candidate}{C_RESET}")
                    logger.info(f"airmon-ng: monitor mode enabled on {candidate}")
                    run_command(["ip", "link", "set", candidate, "up"])
                    return candidate

            print(f"{C_YELLOW}[!] airmon-ng ran but new interface not found — trying iw fallback...{C_RESET}")
            logger.warning("airmon-ng ran but new interface not detected; falling back to iw")

        except subprocess.TimeoutExpired:
            print(f"{C_YELLOW}[!] airmon-ng timed out — trying iw fallback...{C_RESET}")
            logger.warning("airmon-ng timed out")
        except Exception as e:
            print(f"{C_YELLOW}[!] airmon-ng error ({e}) — trying iw fallback...{C_RESET}")
            logger.warning(f"airmon-ng exception: {e}")
    else:
        print(f"{C_YELLOW}[!] airmon-ng not found — using manual iw method...{C_RESET}")
        logger.warning("airmon-ng not in PATH; using iw fallback")

    # 4. Fallback: manual iw method
    try:
        run_command(["ip", "link", "set", interface, "down"])
        time.sleep(0.3)
        run_command(["iw", "dev", interface, "set", "type", "monitor"])
        time.sleep(0.3)
        run_command(["ip", "link", "set", interface, "up"])

        if _get_iw_mode(interface) == "monitor":
            print(f"{C_GREEN}[+] Monitor Mode Enabled (iw fallback): {interface}{C_RESET}")
            logger.info(f"iw fallback: monitor mode enabled on {interface}")
            return interface
    except Exception as e:
        logger.warning(f"iw fallback also failed: {e}")

    print(f"{C_RED}[!] Could not enable monitor mode on {interface}{C_RESET}")
    logger.error(f"Failed to enable monitor mode on {interface}")
    return interface

def restore_managed_mode(interface):
    """Restore interface to managed mode and restart NetworkManager"""
    print(f"\n{C_YELLOW}[*] Restoring interface to managed mode...{C_RESET}")
    logger.info(f"Restoring interface {interface} to managed mode")
    
    try:
        # 1. Stop airmon-ng if it was used
        if interface.endswith("mon"):
            original_interface = interface[:-3]
            print(f"{C_CYAN}[*] Stopping airmon-ng on {interface}...{C_RESET}")
            run_command(["airmon-ng", "stop", interface])
            interface = original_interface
            time.sleep(1)
        
        # 2. Bring interface down
        run_command(["ip", "link", "set", interface, "down"])
        time.sleep(0.5)
        
        # 3. Set to managed mode
        run_command(["iw", "dev", interface, "set", "type", "managed"])
        time.sleep(0.5)
        
        # 4. Bring interface up
        run_command(["ip", "link", "set", interface, "up"])
        time.sleep(0.5)
        
        # 5. Restart NetworkManager
        print(f"{C_CYAN}[*] Restarting NetworkManager...{C_RESET}")
        run_command(["service", "NetworkManager", "start"])
        time.sleep(1)
        
        mode = _get_iw_mode(interface)
        if mode == "managed":
            print(f"{C_GREEN}[+] Interface {interface} restored to Managed Mode{C_RESET}")
            print(f"{C_GREEN}[+] NetworkManager restarted{C_RESET}")
            logger.info(f"Interface {interface} successfully restored to managed mode")
        else:
            print(f"{C_YELLOW}[!] Warning: Could not verify managed mode{C_RESET}")
            logger.warning(f"Could not verify managed mode for {interface}")
            
    except Exception as e:
        print(f"{C_RED}[!] Error restoring interface: {e}{C_RESET}")
        logger.error(f"Error restoring interface: {e}")
        print(f"{C_YELLOW}[*] You may need to manually restart NetworkManager:{C_RESET}")
        print(f"    sudo service NetworkManager start")


class SignalManager:
    """Context manager for safe SIGINT handling during attacks."""

    def __init__(self):
        self._original_handler = None
        self._stop_event = None

    def __enter__(self):
        self._original_handler = signal.getsignal(signal.SIGINT)
        self._stop_event = __import__('threading').Event()
        signal.signal(signal.SIGINT, self._handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.signal(signal.SIGINT, self._original_handler)
        return False

    def _handler(self, sig, frame):
        self._stop_event.set()

    @property
    def stopped(self):
        return self._stop_event.is_set() if self._stop_event else False

    def stop(self):
        if self._stop_event:
            self._stop_event.set()


def verify_password(pcap_file, bssid, ssid, password):
    """
    Verify password against captured handshake using aircrack-ng

    Args:
        pcap_file: Path to the PCAP file containing the handshake
        bssid: Target BSSID (MAC address)
        ssid: Target SSID (network name)
        password: Password to verify

    Returns:
        True:  password is correct
        False: password is wrong (handshake was verifiable)
        None:  could not verify (no usable handshake in the capture)
    """
    if not os.path.exists(pcap_file):
        logger.warning(f"PCAP file not found: {pcap_file}")
        print(f"{C_RED}[!] Error: Pcap file not found.{C_RESET}")
        return None

    # Write password to temporary file (trailing newline so aircrack-ng
    # reads it as a complete dictionary line).
    temp_pass_file = "temp_pass.txt"
    try:
        with open(temp_pass_file, 'w') as f:
            f.write(password + "\n")

        print(f"{C_CYAN}    [Cracker] Target: {ssid} ({mask_bssid(bssid)}) | Pass: {password}{C_RESET}")

        # Deliberately NO `-b` / `-e` filters: the capture is already
        # BSSID-filtered by airodump-ng, so it contains only one AP at
        # most. Filtering by ESSID (`-e`) is an exact string match against
        # the EAPOL bytes in the pcap, and ANY discrepancy (case, trailing
        # spaces, non-ASCII, hidden networks with an empty ESSID) makes
        # aircrack-ng report "0 handshake" — we'd then declare the correct
        # password as WRONG. Same reasoning as capture_native._analyze_capture.
        cmd = [
            "aircrack-ng",
            "-a", "2",              # WPA/WPA2
            "-w", temp_pass_file,   # Password file
            pcap_file               # Capture file
        ]

        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL
        )
        output = result.stdout
        out_lower = output.lower()

        if "key found!" in out_lower:
            return True

        # Did aircrack-ng actually see a usable handshake in this capture?
        m = re.search(r'(\d+)\s+handshake', out_lower)
        handshake_count = int(m.group(1)) if m else 0
        if handshake_count >= 1 and "no valid wpa handshakes" not in out_lower:
            # Handshake is valid, but the candidate was checked and failed.
            print(f"{C_YELLOW}    >>> Result: Wrong Password (Handshake is Valid).{C_RESET}")
            return False

        # No usable handshake -> we cannot tell right from wrong.
        print(f"{C_RED}    >>> No usable handshake found in the capture. Cannot verify.{C_RESET}")
        print(f"    >>> Full Output:\n{output}")
        return None

    except subprocess.TimeoutExpired:
        logger.error("aircrack-ng timed out during password verification")
        print(f"{C_RED}    [!] aircrack-ng timed out while verifying.{C_RESET}")
        return None
    except Exception as e:
        logger.error(f"Error verifying password with aircrack: {e}")
        print(f"{C_RED}    [!] Execution Error: {e}{C_RESET}")
        return None
    finally:
        # Cleanup temporary file
        if os.path.exists(temp_pass_file):
            try:
                os.remove(temp_pass_file)
            except OSError:
                pass

def generate_hc22000(pcap_path):
    """
    Generate hc22000 hash file from pcap using hcxpcapngtool.
    Returns: True if successful, False otherwise.
    """
    if not shutil.which("hcxpcapngtool"):
        print(f"{C_RED}[!] hcxpcapngtool not found. Install hcxtools.{C_RESET}")
        logger.error("hcxpcapngtool binary not found")
        return False
    
    if not os.path.exists(pcap_path):
        print(f"{C_RED}[!] PCAP file not found: {pcap_path}{C_RESET}")
        return False
        
    # Generate output filename (same base, different extension)
    # If the input is .pcap or .cap, replace it. Otherwise append.
    if pcap_path.lower().endswith(".pcap"):
        hc22000_path = pcap_path[:-5] + ".hc22000"
    elif pcap_path.lower().endswith(".cap"):
        hc22000_path = pcap_path[:-4] + ".hc22000"
    else:
        hc22000_path = pcap_path + ".hc22000"
        
    cmd = ["hcxpcapngtool", "-o", hc22000_path, pcap_path]
    
    print(f"\n{C_YELLOW}[*] Generating hc22000 file...{C_RESET}")
    print(f"{C_WHITE}    Command: {' '.join(cmd)}{C_RESET}")
    
    # Run command and show output
    try:
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        # hcxpcapngtool often writes important info to stdout/stderr
        # We print it so the user can see "EAPOL pairs", "Information: ...", etc.
        print(f"{C_CYAN}{process.stdout}{C_RESET}")
        
        if os.path.exists(hc22000_path) and os.path.getsize(hc22000_path) > 0:
            print(f"{C_GREEN}[+] Hash file created successfully!{C_RESET}")
            print(f"{C_GREEN}    Path: {hc22000_path}{C_RESET}")
            logger.info(f"Generated hash file: {hc22000_path}")
            return True
        else:
            print(f"{C_RED}[!] Failed to create hash file (or file is empty).{C_RESET}")
            logger.warning(f"Failed to generate hc22000 for {pcap_path}")
            return False
            
    except Exception as e:
        print(f"{C_RED}[!] Error executing hcxpcapngtool: {e}{C_RESET}")
        logger.error(f"hcxpcapngtool execution error: {e}")
        return False
