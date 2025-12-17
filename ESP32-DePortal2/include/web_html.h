#pragma once

const char WEB_HTML_START[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESP32 Deauther</title>
    <style>
        :root {
            --bg-color: #2c2f33;
            --card-color: #23272a;
            --primary-color: #7289da;
            --danger-color: #f04747;
            --text-color: #ffffff;
            --text-muted: #99aab5;
            --border-color: #424549;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 15px;
            -webkit-font-smoothing: antialiased;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h1, h2 { color: var(--primary-color); border-bottom: 2px solid var(--primary-color); padding-bottom: 10px; margin-top: 30px; }
        h1 { font-size: 2em; }
        .card { background-color: var(--card-color); border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.2); }
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { background-color: rgba(114, 137, 218, 0.2); font-weight: 600; }
        tr { cursor: pointer; transition: background-color 0.2s ease; }
        tr:hover { background-color: rgba(255, 255, 255, 0.05); }
        tr label { display: flex; align-items: center; width: 100%; }
        input[type="radio"] { margin-right: 15px; transform: scale(1.2); }
        .controls label { display: block; margin-bottom: 8px; color: var(--text-muted); }
        select, .btn { width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 5px; border: 1px solid var(--border-color); background-color: #3a3e42; color: var(--text-color); font-size: 1em; box-sizing: border-box; }
        .btn { background-color: var(--primary-color); border: none; cursor: pointer; font-weight: bold; transition: background-color 0.2s ease; }
        .btn:hover { background-color: #677bc4; }
        .btn.scan { background-color: #43b581; } .btn.scan:hover { background-color: #3aa072; }
        .btn.danger { background-color: var(--danger-color); } .btn.danger:hover { background-color: #d84040; }
        .btn.stop { background-color: #faa61a; } .btn.stop:hover { background-color: #e09618; }
        .status { padding: 12px; background-color: rgba(0,0,0,0.2); border-radius: 5px; color: var(--text-muted); text-align: center; margin-top: 20px; transition: opacity 0.3s ease; }
        @media (max-width: 600px) { body { padding: 10px; } .card { padding: 15px; } th, td { padding: 8px; font-size: 0.9em; } h1 { font-size: 1.5em; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>ESP32 Deauther</h1>
        <div class="card">
            <button class="btn scan" onclick="postAction('/rescan', null, true)">Rescan Networks</button>
        </div>
        <div class="card">
            <h2>Available Networks</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr><th>Select</th><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th><th>Enc.</th></tr>
                    </thead>
                    <tbody>
)rawliteral";

const char WEB_HTML_END[] PROGMEM = R"rawliteral(
                    </tbody>
                </table>
            </div>
        </div>
        <div class="card">
            <h2>Attack Controls</h2>
            <div class="controls">
                <label for="reason_code">Reason Code:</label>
                <select id="reason_code">
                    <option value="1">1: Unspecified reason</option>
                    <option value="2">2: Auth not valid</option>
                    <option value="3">3: STA is leaving</option>
                    <option value="4">4: Inactivity</option>
                    <option value="5">5: AP full</option>
                    <option value="6">6: Class 2 frame</option>
                    <option value="7">7: Class 3 frame</option>
                    <option value="8">8: STA is leaving BSS</option>
                    <option value="9">9: Not authenticated</option>
                    <option value="14">14: MIC failure</option>
                    <option value="15">15: 4-Way Handshake timeout</option>
                </select>
            </div>
            <button class="btn" onclick="launchDeauth()">Launch Deauth on Selected</button>
            <button class="btn danger" onclick="launchDeauthAll()">Launch Deauth on ALL</button>
            <button class="btn stop" onclick="postAction('/stop', null, true)">Stop Attack</button>
        </div>
        <div class="status" id="status">Status: Idle</div>
        <div class="card">
            <p>Eliminated stations: %ELIMINATED_STATIONS%</p>
        </div>
    </div>
    <script>
        const statusDiv = document.getElementById('status');
        const updateStatus = (message, isError = false) => { statusDiv.textContent = `Status: ${message}`; statusDiv.style.color = isError ? 'var(--danger-color)' : 'var(--text-muted)'; };
        const postAction = (url, body = null, reload = false) => {
            fetch(url, { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: body })
            .then(response => { if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`); return response.text(); })
            .then(data => { console.log(data); if (reload) { updateStatus('Reloading page...'); setTimeout(() => window.location.reload(), 1000); } })
            .catch(error => { console.error('Fetch error:', error); updateStatus(error.message, true); });
        };
        function launchDeauth() {
            const selectedNetwork = document.querySelector('input[name="net_num"]:checked');
            if (!selectedNetwork) { updateStatus('Please select a network first!', true); return; }
            const netNum = selectedNetwork.value;
            const reason = document.getElementById('reason_code').value;
            updateStatus(`Launching attack on network ${netNum}...`);
            postAction('/deauth', `net_num=${netNum}&reason=${reason}`);
        }
        function launchDeauthAll() {
            if (confirm('WARNING: This will attack all networks and disable this web interface. You will need to reset the ESP32 to stop it. Are you sure?')) {
                const reason = document.getElementById('reason_code').value;
                updateStatus('Launching attack on ALL networks...');
                postAction('/deauth_all', `reason=${reason}`);
            }
        }
        document.querySelectorAll('tbody tr').forEach(row => { row.addEventListener('click', () => { const radio = row.querySelector('input[type="radio"]'); if (radio) radio.checked = true; }); });
    </script>
</body>
</html>
)rawliteral";