import os
import shutil
import socket
import subprocess
import sys


def _kick_networkmanager():
    """Best-effort reconnect of wifi/ethernet devices before we wait for a link."""
    try:
        subprocess.run(["nmcli", "radio", "wifi", "on"], capture_output=True, timeout=5)
    except Exception:
        pass
    try:
        status = subprocess.run(
            ["nmcli", "-t", "device", "status"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return
    for line in status.splitlines():
        cols = line.split(":")
        if len(cols) > 2 and cols[0] and cols[1] in ("wifi", "ethernet"):
            try:
                subprocess.run(["nmcli", "device", "connect", cols[0]],
                               capture_output=True, timeout=10)
            except Exception:
                pass

REQUIRED_SYSTEM_TOOLS = {
    "aircrack-ng": "Handshake verification (install: apt-get install aircrack-ng)",
    "hcxpcapngtool": "hc22000 hash generation (install: apt-get install hcxtools)",
    "iw": "Wireless interface management (install: apt-get install iw)",
}

OPTIONAL_TOOLS = {
    "hostapd": "Software Evil Twin AP (install: apt-get install hostapd)",
    "dnsmasq": "Software Evil Twin DHCP/DNS (install: apt-get install dnsmasq)",
    "mdk4": "Fast deauth for handshake capture (install: apt-get install mdk4)",
    "airodump-ng": "Fast handshake capture (install: apt-get install aircrack-ng)",
}

CLOUDFLARED_PATHS = ("/usr/local/bin/cloudflared", "/tmp/cloudflared")


def check_cloudflared():
    """Boot-time readiness: verify cloudflared, or download+install it NOW."""
    for p in CLOUDFLARED_PATHS:
        if os.path.exists(p):
            print(f"[+] cloudflared ready: {p}")
            return p
    which = shutil.which("cloudflared")
    if which:
        print(f"[+] cloudflared ready: {which}")
        return which

    print("[*] cloudflared not installed — trying to fetch it now, before "
          "monitor mode disconnects this box's link.")
    try:
        from wifi_nightmare.evil_twin_software import download_cloudflared
    except ImportError:
        try:
            from evil_twin_software import download_cloudflared
        except ImportError:
            print("[!] cloudflared download module not available.")
            return None
    path = download_cloudflared()
    if path:
        print("[+] HTTPS-first captive API ready — will be advertised via DHCP "
              "option 114 on the Software Evil Twin attack.")
    else:
        print(f"[!] No internet reached — HTTPS-first captive API will be OFF "
              f"this run. Once this box has a link, install cloudflared once "
              f"and it persists (no internet needed on later boots):")
        print("    sudo python3 -c 'from wifi_nightmare.evil_twin_software import "
              "download_cloudflared; download_cloudflared()'")
    print()
    return path


def check_dependencies():
    missing = []
    for tool, reason in REQUIRED_SYSTEM_TOOLS.items():
        if not shutil.which(tool):
            missing.append(f"  - {tool}: {reason}")

    if missing:
        print("[!] Missing system dependencies:")
        for m in missing:
            print(m)
        print("[*] Install them with:")
        print("    sudo apt-get install aircrack-ng hcxtools iw")
        print()
        resp = input("[?] Continue anyway? (y/N): ").strip().lower()
        if resp != 'y':
            sys.exit(1)

    missing_optional = []
    for tool, reason in OPTIONAL_TOOLS.items():
        if not shutil.which(tool):
            missing_optional.append(f"  - {tool}: {reason}")

    if missing_optional:
        print("[*] Optional tools missing (needed for Software Evil Twin):")
        for m in missing_optional:
            print(m)
        print()
