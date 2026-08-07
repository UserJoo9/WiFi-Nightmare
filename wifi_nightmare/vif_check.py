# vif_check.py — Virtual Interface (VIF) support detection
import subprocess
import re
from wifi_nightmare.logger import logger


def _split_phys(output):
    """Split `iw list` output into (phy_name, section) per Wiphy block."""
    phys = []
    current_phy = None
    current_lines = []
    for line in output.splitlines():
        m = re.match(r'\s*Wiphy\s+(phy\d+)\s*$', line)
        if m:
            if current_phy:
                phys.append((current_phy, "\n".join(current_lines)))
            current_phy = m.group(1)
            current_lines = [line]
        elif current_phy is not None:
            current_lines.append(line)
    if current_phy:
        phys.append((current_phy, "\n".join(current_lines)))
    return phys


def _parse_combos(section):
    """
    Parse the 'valid interface combinations' block of one PHY section.

    Returns (max_total, has_mixed_combo):
      - max_total: the highest number of concurrent interfaces any single
        combination allows (None when the section has no combination block).
      - has_mixed_combo: True when some combination allows >= 2 interfaces
        that mix an AP-capable mode (AP / mesh / P2P-GO) with a client /
        monitor mode (managed / monitor / IBSS / P2P-client / P2P-device).
    """
    lines = section.splitlines()
    header_idx = None
    header_indent = 0
    for i, line in enumerate(lines):
        if re.search(r'interface\s+combinations', line, re.IGNORECASE):
            if 'not supported' in line.lower():
                return 1, False
            header_idx = i
            header_indent = len(line) - len(line.lstrip())
            break
    if header_idx is None:
        return None, False

    block_lines = []
    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= header_indent:
            break
        block_lines.append(line.strip())
    block = "\n".join(block_lines)

    # Each combination group starts with '* '
    combos = re.split(r'\*', block)
    max_total = 0
    has_mixed = False
    for combo in combos:
        counts = re.findall(r'#\{(.*?)\}\s*<=\s*(\d+)', combo)
        if not counts:
            continue
        modes = [m.strip() for m in ",".join(m for m, _ in counts).split(',')]
        total = sum(int(c) for _, c in counts)
        m_total = re.search(r'total\s*<=\s*(\d+)', combo)
        if m_total:
            total = int(m_total.group(1))
        if total > max_total:
            max_total = total
        has_ap = any(m in ('ap', 'mesh', 'mesh point', 'p2p-go') for m in modes)
        has_client = any(m in ('managed', 'monitor', 'ibss',
                               'p2p-client', 'p2p-device') for m in modes)
        if total >= 2 and has_ap and has_client:
            has_mixed = True
    return max_total, has_mixed


def _test_create_vif(interface):
    """Fallback: try to create a second virtual monitor interface."""
    # Remove any leftover test interface from a previous run first, so a
    # stale 'vifmon' can never make us report support on an incapable card.
    try:
        subprocess.run(["iw", "dev", "vifmon", "del"],
                       capture_output=True, timeout=3)
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "interface", "add", "vifmon", "type", "monitor"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            subprocess.run(["iw", "dev", "vifmon", "del"],
                           capture_output=True, timeout=3)
            return True, "Successfully created virtual monitor interface"
        return False, f"Cannot create virtual interface: {result.stderr.strip()}"
    except Exception as e:
        logger.debug(f"VIF creation test failed: {e}")
        return False, "VIF support could not be determined"


def check_vif_support(interface):
    """
    Detect if the WiFi adapter supports multiple virtual interfaces.
    Returns (supported: bool, info: str)

    The check is scoped to the PHY that actually owns the interface — a
    system-wide scan would wrongly report support whenever ANY adapter on
    the machine advertises multiple interfaces.
    """
    try:
        result = subprocess.run(
            ["iw", "list"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
    except FileNotFoundError:
        return False, "iw not found"
    except Exception as e:
        logger.debug(f"VIF check error: {e}")
        return False, "VIF support could not be determined"

    pattern = re.compile(
        r'^\s*Interface\s+' + re.escape(interface) + r'\s*$',
        re.MULTILINE
    )

    for _phy_name, section in _split_phys(output):
        if pattern.search(section):
            max_total, has_mixed = _parse_combos(section)
            if max_total is not None:
                if max_total >= 2:
                    detail = f"Max concurrent interfaces: {max_total}"
                    if not has_mixed:
                        detail += " (no managed+AP combo)"
                    return True, detail
                return False, f"Max virtual interfaces: {max_total} (need >= 2)"

    # No interface-combinations info (or interface not listed) —
    # fall back to an active creation test.
    return _test_create_vif(interface)


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
