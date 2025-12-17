#pragma once
#include <Arduino.h>

const char WEB_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Sign in to Wi-Fi network</title>
<style>
  body { font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); text-align: center; width: 90%; max-width: 360px; }
  h2 { color: #1a1a1a; margin-top: 0; font-size: 1.5rem; }
  p { color: #65676b; font-size: 0.95rem; margin-bottom: 1.5rem; line-height: 1.5; }
  input { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #dddfe2; border-radius: 6px; box-sizing: border-box; font-size: 16px; outline: none; transition: 0.2s; }
  input:focus { border-color: #1877f2; box-shadow: 0 0 0 2px rgba(24,119,242,0.2); }
  button { width: 100%; padding: 12px; background: #1877f2; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; transition: 0.2s; }
  button:hover { background: #166fe5; }
  .hidden { display: none !important; }
  .error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 0.9rem; text-align: left; display: none; }
  .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #1877f2; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 20px auto; }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  .logo { font-size: 3rem; color: #1877f2; margin-bottom: 10px; }
</style>
</head>
<body>

<div id="login-view" class="card">
  <div class="logo">&#128246;</div>
  <h2>Welcome</h2>
  <p>Authentication is required to access the Wi-Fi network.</p>
  <div id="error-msg" class="error">Access Denied. Incorrect credentials.</div>
  <input type="text" id="username" placeholder="Enter your Name" autocomplete="off" required>
  <button onclick="sendData()">Log In</button>
</div>

<div id="wait-view" class="card hidden">
  <h2>Verifying...</h2>
  <div class="spinner"></div>
  <p>Please wait while the administrator validates your request.</p>
  <p style="color:#999; font-size:0.8rem">Do not close this page.</p>
</div>

<div id="success-view" class="card hidden">
  <div class="logo" style="color:#4caf50">&#10003;</div>
  <h2 style="color:#4caf50">Connected</h2>
  <p>You are now connected to the internet.</p>
</div>

<script>
  let checkInterval;
  function sendData() {
    const name = document.getElementById('username').value.trim();
    if(!name) return;
    document.getElementById('error-msg').style.display = 'none';
    document.getElementById('login-view').classList.add('hidden');
    document.getElementById('wait-view').classList.remove('hidden');

    fetch('/submit', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'name=' + encodeURIComponent(name) })
    .then(() => { if(checkInterval) clearInterval(checkInterval); checkInterval = setInterval(checkStatus, 1000); })
    .catch(() => resetView("Connection Error. Try Again."));
  }

  function checkStatus() {
    fetch('/status').then(r => r.text()).then(status => {
      if (status === 'OK') { clearInterval(checkInterval); document.getElementById('wait-view').classList.add('hidden'); document.getElementById('success-view').classList.remove('hidden'); } 
      else if (status === 'NO') { clearInterval(checkInterval); resetView("Access Denied or Incorrect Name."); }
    }).catch(e => console.log(e));
  }

  function resetView(msg) {
    document.getElementById('wait-view').classList.add('hidden');
    document.getElementById('login-view').classList.remove('hidden');
    const err = document.getElementById('error-msg');
    err.innerText = msg; err.style.display = 'block';
  }
</script>
</body></html>
)rawliteral";