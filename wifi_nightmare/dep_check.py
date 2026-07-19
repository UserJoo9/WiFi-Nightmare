import shutil
import sys

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
