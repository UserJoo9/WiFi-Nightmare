# vif_check.py — Virtual Interface (VIF) support detection
import subprocess
import re
from logger import logger


def check_vif_support(interface):
    """
    Detect if the WiFi adapter supports multiple virtual interfaces.
    Returns (supported: bool, info: str)
    """
    # Method 1: Try creating a virtual AP interface
    try:
        subprocess.run(
            ["ip", "link", "add", "vif_test", "type", "dummy"],
            capture_output=True, timeout=3
        )
        subprocess.run(
            ["ip", "link", "delete", "vif_test"],
            capture_output=True, timeout=3
        )
    except Exception:
        pass

    # Method 2: Parse NL80211 interface combinations from `iw list`
    try:
        result = subprocess.run(
            ["iw", "list"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout

        # Find the section for our interface
        current_phy = None
        in_interface_block = False
        combo_text = ""

        for line in output.splitlines():
            # Track which PHY our interface belongs to
            if line.strip().startswith("Wiphy"):
                current_phy = line.strip().split()[-1]
                in_interface_block = False

            if f"Interface {interface}" in line or f"Interface {interface}mon" in line:
                in_interface_block = True
                continue

            if in_interface_block and "interface combinations" in line.lower():
                combo_text = line
                continue

            if in_interface_block and combo_text:
                # We found the combinations section
                combo_text += " " + line
                if "managed" in line.lower() or "#" in line:
                    break

        # Simpler approach: search for max # of interface combos
        # Parse entire output for interface combination blocks
        combos = re.findall(
            r'interface combinations.*?# of interfaces = (\d+)',
            output, re.DOTALL | re.IGNORECASE
        )

        if combos:
            max_ifaces = max(int(c) for c in combos)
            if max_ifaces >= 2:
                return True, f"Max virtual interfaces: {max_ifaces}"
            else:
                return False, f"Max virtual interfaces: {max_ifaces} (need >= 2)"

    except FileNotFoundError:
        return False, "iw not found"
    except Exception as e:
        logger.debug(f"VIF check error: {e}")

    # Method 3: Try creating a second virtual monitor interface
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "interface", "add", "vifmon", "type", "monitor"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            # Clean up
            subprocess.run(
                ["iw", "dev", "vifmon", "del"],
                capture_output=True, timeout=3
            )
            return True, "Successfully created virtual monitor interface"
        else:
            # Also check if it failed because interface already exists
            if "already exists" in result.stderr:
                subprocess.run(
                    ["iw", "dev", "vifmon", "del"],
                    capture_output=True, timeout=3
                )
                return True, "Virtual interface creation supported"
            return False, f"Cannot create virtual interface: {result.stderr.strip()}"
    except Exception as e:
        logger.debug(f"VIF creation test failed: {e}")

    return False, "VIF support could not be determined"


def get_vif_info(interface):
    """Get detailed VIF information for display."""
    supported, info = check_vif_support(interface)

    # Check for hostapd and dnsmasq (needed for software AP)
    import shutil
    has_hostapd = shutil.which("hostapd") is not None
    has_dnsmasq = shutil.which("dnsmasq") is not None

    return {
        "supported": supported,
        "info": info,
        "has_hostapd": has_hostapd,
        "has_dnsmasq": has_dnsmasq,
        "ready": supported and has_hostapd and has_dnsmasq
    }
