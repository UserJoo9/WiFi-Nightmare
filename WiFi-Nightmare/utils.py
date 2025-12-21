# utils.py
import os
import sys
import subprocess
import time
import shutil
from datetime import datetime
from config import *
from logger import logger

# Try to import vendor database
try:
    from vendors import lookup_vendor
except ImportError:
    def lookup_vendor(mac): return "Unknown"

def get_vendor(mac):
    return lookup_vendor(mac)

def get_current_time_12h():
    return datetime.now().strftime("%I:%M %p")

def check_root():
    if os.geteuid() != 0:
        logger.error("This script must be run as root (sudo).")
        sys.exit(1)

def check_interface_exists(interface):
    # Check potential names (original or with mon suffix)
    possible_names = [interface, interface + "mon", "wlan0mon", "mon0"]
    for name in possible_names:
        if os.path.exists(f"/sys/class/net/{name}"):
            return name
    
    logger.error(f"Interface '{interface}' not found.")
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

def enable_monitor_mode(interface):
    print(f"\n{C_YELLOW}[*] Preparing Interface...{C_RESET}")
    logger.info(f"Preparing interface {interface} for monitor mode")

    # 1. Kill interfering processes
    commands = [
        ["airmon-ng", "check", "kill"],
        ["pkill", "-9", "wpa_supplicant"],
        ["pkill", "-9", "dhclient"],
        ["pkill", "-9", "NetworkManager"],
        ["service", "NetworkManager", "stop"]
    ]
    
    for cmd in commands:
        run_command(cmd)
    
    # Unblock wifi
    run_command(["rfkill", "unblock", "wifi"])
    run_command(["rfkill", "unblock", "all"])
    
    time.sleep(0.5)

    # 2. Smart Check: Is it already in Monitor Mode?
    check_list = [interface, interface + "mon", "wlan0mon"]
    
    for iface in check_list:
        if os.path.exists(f"/sys/class/net/{iface}"):
            try:
                # Read current mode
                iw_out = subprocess.getoutput(f"iwconfig {iface}")
                if "Mode:Monitor" in iw_out:
                    logger.info(f"Interface '{iface}' is already in Monitor Mode.")
                    print(f"{C_GREEN}[+] Interface '{iface}' is ALREADY in Monitor Mode.{C_RESET}")
                    
                    # Ensure it is up and on a default channel
                    run_command(["ip", "link", "set", iface, "up"])
                    run_command(["iwconfig", iface, "channel", "1"])
                    return iface
            except Exception as e:
                logger.debug(f"Error checking interface {iface}: {e}")

    print(f"{C_CYAN}[*] Setting Monitor Mode on {interface}...{C_RESET}")
    logger.info(f"Setting Monitor Mode on {interface}")

    # 3. Manual Method (Safe)
    try:
        run_command(["ip", "link", "set", interface, "down"])
        time.sleep(0.3)
        run_command(["iwconfig", interface, "mode", "monitor"])
        time.sleep(0.3)
        run_command(["ip", "link", "set", interface, "up"])
        
        # Verify
        if "Mode:Monitor" in subprocess.getoutput(f"iwconfig {interface}"):
            print(f"{C_GREEN}[+] Monitor Mode Enabled on: {interface}{C_RESET}")
            return interface
    except Exception as e:
        logger.warning(f"Manual monitor mode setup failed: {e}")

    # 4. Fallback: airmon-ng
    print(f"{C_YELLOW}[!] Manual method failed, trying airmon-ng...{C_RESET}")
    logger.info("Manual method failed, trying airmon-ng...")
    run_command(["airmon-ng", "start", interface])
    
    # Check for new name
    if os.path.exists(f"/sys/class/net/{interface}mon"):
        print(f"{C_GREEN}[+] Monitor Mode Enabled on: {interface}mon{C_RESET}")
        return interface + "mon"
    
    return interface

def restore_managed_mode(interface):
    """Restore interface to managed mode and restart NetworkManager"""
    print(f"\n{C_YELLOW}[*] Restoring interface to managed mode...{C_RESET}")
    logger.info(f"Restoring interface {interface} to managed mode")
    
    try:
        # 1. Stop airmon-ng if it was used
        if interface.endswith("mon"):
            original_interface = interface[:-3]  # Remove 'mon' suffix
            print(f"{C_CYAN}[*] Stopping airmon-ng on {interface}...{C_RESET}")
            run_command(["airmon-ng", "stop", interface])
            interface = original_interface
            time.sleep(1)
        
        # 2. Bring interface down
        run_command(["ip", "link", "set", interface, "down"])
        time.sleep(0.5)
        
        # 3. Set to managed mode
        run_command(["iwconfig", interface, "mode", "managed"])
        time.sleep(0.5)
        
        # 4. Bring interface up
        run_command(["ip", "link", "set", interface, "up"])
        time.sleep(0.5)
        
        # 5. Restart NetworkManager
        print(f"{C_CYAN}[*] Restarting NetworkManager...{C_RESET}")
        run_command(["service", "NetworkManager", "start"])
        time.sleep(1)
        
        # Verify restoration
        iw_out = subprocess.getoutput(f"iwconfig {interface}")
        if "Mode:Managed" in iw_out:
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


def verify_password(pcap_file, bssid, ssid, password):
    """
    Verify password against captured handshake using aircrack-ng
    
    Args:
        pcap_file: Path to the PCAP file containing the handshake
        bssid: Target BSSID (MAC address)
        ssid: Target SSID (network name)
        password: Password to verify
        
    Returns:
        bool: True if password is correct, False otherwise
    """
    if not os.path.exists(pcap_file):
        logger.warning(f"PCAP file not found: {pcap_file}")
        print(f"{C_RED}[!] Error: Pcap file not found.{C_RESET}")
        return False
    
    # Write password to temporary file
    temp_pass_file = "temp_pass.txt"
    try:
        with open(temp_pass_file, 'w') as f:
            f.write(password)
        
        print(f"{C_CYAN}    [Cracker] Target: {ssid} ({bssid}) | Pass: {password}{C_RESET}")
        
        # Build aircrack-ng command with BSSID and SSID for precise targeting
        cmd = [
            "aircrack-ng",
            "-a", "2",              # WPA2
            "-w", temp_pass_file,   # Password file
            "-b", bssid,            # BSSID (critical)
            "-e", ssid,             # SSID (critical)
            pcap_file               # Capture file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        
        if "KEY FOUND!" in output:
            return True
        else:
            # Detailed failure analysis
            print(f"{C_RED}    [Debug] Aircrack Failed. Analysis:{C_RESET}")
            
            if "Passphrase not in dictionary" in output:
                # Handshake is valid, but password is wrong
                print(f"{C_YELLOW}    >>> Result: Wrong Password (Handshake is Valid).{C_RESET}")
            elif "No valid WPA handshakes" in output:
                # No handshake found for this BSSID
                print(f"{C_RED}    >>> Result: No handshake found for BSSID {bssid}.{C_RESET}")
                print(f"    >>> Full Output:\n{output}")
            else:
                # Other error
                print(f"    >>> Unknown Error. Aircrack Output:\n{output}")
        
        return False
        
    except Exception as e:
        logger.error(f"Error verifying password with aircrack: {e}")
        print(f"{C_RED}    [!] Execution Error: {e}{C_RESET}")
        return False
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