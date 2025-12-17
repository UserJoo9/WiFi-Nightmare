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
    logger.info(f"Interface {interface} left in current state.")
    print(f"\n{C_YELLOW}[*] Info: Interface left in Monitor Mode.{C_RESET}")
    # To restore managed mode manually in future:
    # run_command(["airmon-ng", "stop", interface])
    # run_command(["service", "NetworkManager", "start"])

def verify_password_aircrack(pcap_file, bssid, password):
    if not os.path.exists(pcap_file): 
        logger.warning(f"PCAP file not found: {pcap_file}")
        return False
        
    temp_pass_file = "temp_pass.txt"
    try:
        with open(temp_pass_file, 'w') as f: 
            f.write(password)
            
        cmd = ["aircrack-ng", "-w", temp_pass_file, "-b", bssid, pcap_file]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "KEY FOUND!" in result.stdout:
            return True
    except Exception as e:
        logger.error(f"Error verifying password with aircrack: {e}")
    finally:
        if os.path.exists(temp_pass_file):
            try:
                os.remove(temp_pass_file)
            except OSError:
                pass
                
    return False