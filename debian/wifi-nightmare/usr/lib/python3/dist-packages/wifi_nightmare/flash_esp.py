"""
ESP firmware flashing utility for WiFi-Nightmare.

Uses esptool to flash bundled pre-compiled firmware binaries to ESP32/ESP8266.
Invoked via: sudo wifi-nightmare flash-esp <port> [--board esp32|esp8266]
"""

import sys
import argparse
import os

from wifi_nightmare.config import FIRMWARE_DIR, C_GREEN, C_RED, C_YELLOW, C_RESET

FIRMWARE_MAP = {
    "esp32": {
        "chip": "esp32",
        "files": [
            ("0x1000", "bootloader.bin"),
            ("0x8000", "partitions.bin"),
            ("0x10000", "firmware.bin"),
        ],
        "baud": 921600,
        "flash_mode": "dio",
        "flash_size": "detect",
    },
    "esp8266": {
        "chip": "esp8266",
        "files": [
            ("0x0", "firmware.bin"),
        ],
        "baud": 921600,
        "flash_mode": "dio",
        "flash_size": "detect",
    },
}


def main(args):
    """Parse arguments and flash the ESP board."""
    parser = argparse.ArgumentParser(
        description="Flash ESP firmware for WiFi-Nightmare"
    )
    parser.add_argument("port", help="Serial port (e.g., /dev/ttyUSB0)")
    parser.add_argument(
        "--board",
        choices=["esp32", "esp8266"],
        default="esp32",
        help="Target board type (default: esp32)",
    )
    parsed = parser.parse_args(args)

    board_cfg = FIRMWARE_MAP[parsed.board]
    chip_type = board_cfg["chip"]
    baud = board_cfg["baud"]
    flash_mode = board_cfg["flash_mode"]
    flash_size = board_cfg["flash_size"]

    # Check that all firmware files exist
    file_pairs = []
    for offset, filename in board_cfg["files"]:
        full_path = os.path.join(FIRMWARE_DIR, parsed.board, filename)
        if not os.path.isfile(full_path):
            print(f"{C_RED}[!] Firmware file not found: {full_path}{C_RESET}")
            print(
                f"{C_YELLOW}[*] Make sure firmware binaries are installed. "
                f"Run: pip install wifi-nightmare --upgrade{C_RESET}"
            )
            sys.exit(1)
        file_pairs.append((offset, full_path))

    print(f"{C_GREEN}[*] Flashing {parsed.board} ({chip_type}) on {parsed.port}...{C_RESET}")
    print(f"[*] Baud rate: {baud}")
    for offset, path in file_pairs:
        fname = os.path.basename(path)
        size = os.path.getsize(path)
        print(f"    {offset}: {fname} ({size} bytes)")

    # Build esptool command
    try:
        import esptool
    except ImportError:
        print(f"{C_RED}[!] esptool not installed. Run: pip install esptool{C_RESET}")
        sys.exit(1)

    cmd = [
        "--chip", chip_type,
        "--port", parsed.port,
        "--baud", str(baud),
        "write_flash",
        "--flash_mode", flash_mode,
        "--flash_size", flash_size,
    ]
    for offset, path in file_pairs:
        cmd.append(offset)
        cmd.append(path)

    print(f"{C_YELLOW}[*] Connecting and flashing...{C_RESET}")
    sys.exit(esptool.main(cmd))
