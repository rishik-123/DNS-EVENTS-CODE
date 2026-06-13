import http.server
import socketserver
import os
import json
import sys
import threading
import webbrowser

# Add current folder to path to load config
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

PORT = 8080
LOG_FILE = config.OUTPUT_LOG_FILE

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DeepCytes DNS Agent - SOC Telemetry Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --panel-bg: rgba(17, 24, 39, 0.75);
            --panel-border: rgba(255, 255, 255, 0.06);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            
            --accent-cyan: #06b6d4;
            --accent-emerald: #10b981;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-yellow: #f59e0b;
            --accent-purple: #8b5cf6;
            
            --glow-cyan: rgba(6, 182, 212, 0.15);
            --glow-emerald: rgba(16, 185, 129, 0.15);
            --glow-red: rgba(239, 68, 68, 0.15);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
            background-image: 
                radial-gradient(at 0% 0%, rgba(6, 182, 212, 0.05) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.05) 0px, transparent 50%);
        }

        /* Container & Header */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--panel-border);
            margin-bottom: 24px;
        }

        .header-title h1 {
            font-size: 24px;
            font-weight: 700;
            letter-spacing: -0.5px;
            background: linear-gradient(to right, #22d3ee, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-title p {
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 4px;
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--accent-emerald);
            padding: 6px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--accent-emerald);
            border-radius: 50%;
            animation: pulse-dot 1.5s infinite;
        }

        @keyframes pulse-dot {
            0% { transform: scale(0.9); opacity: 0.6; }
            50% { transform: scale(1.2); opacity: 1; }
            100% { transform: scale(0.9); opacity: 0.6; }
        }

        /* Sound Control Switch */
        .switch-container {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: var(--text-secondary);
        }

        .switch {
            position: relative;
            display: inline-block;
            width: 44px;
            height: 22px;
        }

        .switch input { 
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #374151;
            transition: .3s;
            border-radius: 34px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: var(--accent-cyan);
        }

        input:checked + .slider:before {
            transform: translateX(22px);
        }

        /* KPI Dashboard Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s ease, border-color 0.2s ease;
            position: relative;
            overflow: hidden;
        }

        .card:hover {
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.12);
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
        }

        .card-total::before { background: var(--accent-cyan); }
        .card-alerts::before { background: var(--accent-red); }
        .card-dga::before { background: var(--accent-orange); }
        .card-tunnel::before { background: var(--accent-yellow); }
        .card-intel::before { background: var(--accent-purple); }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .card-header svg {
            width: 18px;
            height: 18px;
            opacity: 0.8;
        }

        .card-total svg { color: var(--accent-cyan); }
        .card-alerts svg { color: var(--accent-red); }
        .card-dga svg { color: var(--accent-orange); }
        .card-tunnel svg { color: var(--accent-yellow); }
        .card-intel svg { color: var(--accent-purple); }

        .card-value {
            font-size: 32px;
            font-weight: 700;
            margin-top: 12px;
            letter-spacing: -1px;
        }

        /* Pulsing animation for active alerts */
        .pulse-red {
            animation: red-flash 1.5s infinite;
        }

        @keyframes red-flash {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
            70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
            100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }

        /* Main Workspace layout */
        .workspace-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
        }

        .panel {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            backdrop-filter: blur(10px);
            padding: 24px;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.25);
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .panel-title {
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .panel-subtitle {
            font-size: 12px;
            color: var(--text-secondary);
        }

        /* Log Table styling */
        .table-container {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }

        th {
            color: var(--text-secondary);
            font-weight: 600;
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }

        td {
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            color: #e5e7eb;
            white-space: nowrap;
        }

        tr.log-row {
            cursor: pointer;
            transition: background-color 0.15s ease;
        }

        tr.log-row:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }

        /* Animations for row additions */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .new-row {
            animation: fadeIn 0.4s ease-out forwards;
        }

        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.2px;
        }

        .badge-benign {
            background-color: rgba(16, 185, 129, 0.1);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.15);
        }

        .badge-dga {
            background-color: rgba(249, 115, 22, 0.15);
            color: var(--accent-orange);
            border: 1px solid rgba(249, 115, 22, 0.2);
            animation: pulse-badge 1.5s infinite;
        }

        .badge-tunneling {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(239, 68, 68, 0.2);
            animation: pulse-badge 1.5s infinite;
        }

        .badge-typosquatting {
            background-color: rgba(245, 158, 11, 0.15);
            color: var(--accent-yellow);
            border: 1px solid rgba(245, 158, 11, 0.2);
        }

        .badge-threat_intel {
            background-color: rgba(139, 92, 246, 0.15);
            color: var(--accent-purple);
            border: 1px solid rgba(139, 92, 246, 0.2);
        }

        @keyframes pulse-badge {
            0% { opacity: 0.8; }
            50% { opacity: 1; }
            100% { opacity: 0.8; }
        }

        /* Details Dropdown Section */
        .details-row {
            background-color: rgba(0, 0, 0, 0.2);
        }

        .details-container {
            padding: 16px 24px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 12px;
            color: #93c5fd;
            border-left: 3px solid var(--accent-cyan);
            overflow-x: auto;
            max-width: 100%;
        }

        .details-container pre {
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>DEEPCYTES DNS AGENT</h1>
                <p>Real-Time Security Operations Center Telemetry Stream</p>
            </div>
            <div class="header-controls">
                <div class="switch-container">
                    <span>Audio Alerts</span>
                    <label class="switch">
                        <input type="checkbox" id="soundToggle" checked>
                        <span class="slider"></span>
                    </label>
                </div>
                <div class="status-badge">
                    <span class="status-dot"></span>
                    <span id="connection-status">ACTIVE POLLING</span>
                </div>
            </div>
        </header>

        <!-- KPI Metrics Grid -->
        <section class="metrics-grid">
            <!-- Total Logs -->
            <div class="card card-total" id="kpi-total-card">
                <div class="card-header">
                    <span>Total Logs</span>
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-.778.099-1.533.284-2.253"></path></svg>
                </div>
                <div class="card-value" id="stat-total">0</div>
            </div>
            
            <!-- Security Alerts -->
            <div class="card card-alerts" id="kpi-alerts-card">
                <div class="card-header">
                    <span>Security Alerts</span>
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                </div>
                <div class="card-value" id="stat-alerts" style="color: var(--accent-red)">0</div>
            </div>

            <!-- DGA Detections -->
            <div class="card card-dga">
                <div class="card-header">
                    <span>DGA Beaconing</span>
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
                <div class="card-value" id="stat-dga" style="color: var(--accent-orange)">0</div>
            </div>

            <!-- DNS Tunneling -->
            <div class="card card-tunnel">
                <div class="card-header">
                    <span>DNS Tunneling</span>
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4V10z"></path></svg>
                </div>
                <div class="card-value" id="stat-tunnel" style="color: var(--accent-yellow)">0</div>
            </div>

            <!-- Threat Intel -->
            <div class="card card-intel">
                <div class="card-header">
                    <span>Intel Matches</span>
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
                <div class="card-value" id="stat-intel" style="color: var(--accent-purple)">0</div>
            </div>
        </section>

        <!-- Logs Stream Workspace -->
        <main class="workspace-grid">
            <div class="panel">
                <div class="panel-header">
                    <div>
                        <div class="panel-title">Live Log Stream</div>
                        <div class="panel-subtitle" id="record-count-label">Displaying latest 0 events</div>
                    </div>
                </div>

                <div class="table-container">
                    <table id="logsTable">
                        <thead>
                            <tr>
                                <th style="width: 140px;">Timestamp</th>
                                <th>Query Domain</th>
                                <th style="width: 80px; text-align: center;">Type</th>
                                <th>Process (PID)</th>
                                <th>Location</th>
                                <th style="width: 160px; text-align: center;">Severity Status</th>
                            </tr>
                        </thead>
                        <tbody id="logsBody">
                            <tr>
                                <td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">
                                    Waiting for telemetry events... Make sure you run 'python main.py' to generate traffic.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>

    <script>
        let lastEventId = null;
        let logsCache = [];
        let totalCount = 0;
        let alertCount = 0;
        let dgaCount = 0;
        let tunnelingCount = 0;
        let intelCount = 0;
        
        const soundToggle = document.getElementById('soundToggle');

        // Play synth alert beep using Web Audio API (zero file dependencies)
        function playAlertSound() {
            if (!soundToggle.checked) return;
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                
                osc.connect(gain);
                gain.connect(ctx.destination);
                
                osc.type = 'sine';
                // Beep details
                osc.frequency.setValueAtTime(800, ctx.currentTime);
                gain.gain.setValueAtTime(0.08, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
                
                osc.start();
                osc.stop(ctx.currentTime + 0.25);
            } catch (e) {
                console.error("Audio trigger failed:", e);
            }
        }

        // Toggle detailed log JSON dropdown
        function toggleDetails(rowId) {
            const detailsRow = document.getElementById('details-' + rowId);
            if (detailsRow.style.display === 'none' || !detailsRow.style.display) {
                detailsRow.style.display = 'table-row';
            } else {
                detailsRow.style.display = 'none';
            }
        }

        // Poll logs from API
        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                if (!response.ok) throw new Error('API down');
                
                const logs = await response.json();
                if (!logs || logs.length === 0) return;
                
                // If there's new data, process stats and table
                const latest = logs[0];
                if (latest.event_id !== lastEventId) {
                    lastEventId = latest.event_id;
                    updateDashboard(logs);
                }
            } catch (err) {
                console.error("Polling error:", err);
                document.getElementById('connection-status').innerText = "DISCONNECTED";
                document.querySelector('.status-badge').style.borderColor = 'rgba(239, 68, 68, 0.2)';
                document.querySelector('.status-badge').style.background = 'rgba(239, 68, 68, 0.1)';
                document.querySelector('.status-dot').style.backgroundColor = 'var(--accent-red)';
            }
        }

        function updateDashboard(logs) {
            // Re-enable polling indicator active
            document.getElementById('connection-status').innerText = "ACTIVE POLLING";
            document.querySelector('.status-badge').style.borderColor = 'rgba(16, 185, 129, 0.2)';
            document.querySelector('.status-badge').style.background = 'rgba(16, 185, 129, 0.1)';
            document.querySelector('.status-dot').style.backgroundColor = 'var(--accent-emerald)';

            // Reset counters to re-accumulate from current fetched logs
            let currentAlerts = 0;
            let currentDga = 0;
            let currentTunnel = 0;
            let currentIntel = 0;

            logs.forEach(log => {
                const innerData = log.data || {};
                const alerts = innerData.alerts || [];
                if (alerts.length > 0) {
                    currentAlerts++;
                    alerts.forEach(a => {
                        if (a.includes('DGA')) currentDga++;
                        if (a.includes('TUNNELING')) currentTunnel++;
                        if (a.includes('THREAT') || a.includes('CORUNA')) currentIntel++;
                    });
                }
            });

            // Update stats DOM
            document.getElementById('stat-total').innerText = logs.length;
            document.getElementById('stat-alerts').innerText = currentAlerts;
            document.getElementById('stat-dga').innerText = currentDga;
            document.getElementById('stat-tunnel').innerText = currentTunnel;
            document.getElementById('stat-intel').innerText = currentIntel;

            // Animate alert KPI card if there are triggers
            const alertCard = document.getElementById('kpi-alerts-card');
            if (currentAlerts > 0) {
                alertCard.classList.add('pulse-red');
            } else {
                alertCard.classList.remove('pulse-red');
            }

            // Play audio notification if the overall alert count increases
            if (currentAlerts > alertCount) {
                playAlertSound();
            }

            alertCount = currentAlerts;

            // Build table rows
            const tbody = document.getElementById('logsBody');
            tbody.innerHTML = '';
            
            document.getElementById('record-count-label').innerText = `Displaying latest ${logs.length} events`;

            logs.forEach((log, index) => {
                const innerData = log.data || {};
                const dns = innerData.dns || {};
                const process = innerData.process || {};
                const locationList = innerData.geolocation || [];
                const alerts = innerData.alerts || [];
                
                // Parse timestamp
                let timeStr = log.timestamp || "";
                if (timeStr.includes("T")) {
                    timeStr = timeStr.split("T")[1].replace("Z", "");
                }

                // Parse Location
                let locStr = "Internal";
                if (locationList.length > 0) {
                    const l = locationList[0];
                    locStr = `${l.country || "Unknown"} (${l.city || "Unknown"})`;
                } else if (dns.response_code === "NXDOMAIN") {
                    locStr = "NXDOMAIN";
                }

                // Render Badge
                let badgeHtml = '<span class="badge badge-benign">Benign</span>';
                if (alerts.length > 0) {
                    badgeHtml = '';
                    alerts.forEach(a => {
                        let cls = 'badge-benign';
                        let label = a;
                        if (a.includes('TUNNELING')) { cls = 'badge-tunneling'; label = 'Tunneling'; }
                        else if (a.includes('DGA')) { cls = 'badge-dga'; label = 'DGA'; }
                        else if (a.includes('TYPOSQUATTING')) { cls = 'badge-typosquatting'; label = 'Typosquat'; }
                        else if (a.includes('THREAT') || a.includes('CORUNA')) { cls = 'badge-threat_intel'; label = 'Threat Intel'; }
                        
                        badgeHtml += `<span class="badge ${cls}" style="margin: 2px;">${label}</span>`;
                    });
                }

                // Main row
                const tr = document.createElement('tr');
                tr.className = 'log-row';
                tr.onclick = () => toggleDetails(index);
                
                tr.innerHTML = `
                    <td style="color: var(--text-secondary); font-family: monospace;">${timeStr}</td>
                    <td style="font-weight: 500; color: #fff;">${dns.query || "-"}</td>
                    <td style="text-align: center; color: var(--accent-cyan); font-family: monospace;">${dns.query_type || "-"}</td>
                    <td>${process.process_name || "System"} <span style="color: var(--text-secondary); font-size: 11px;">(${process.pid || "0"})</span></td>
                    <td style="color: var(--text-secondary);">${locStr}</td>
                    <td style="text-align: center;">${badgeHtml}</td>
                `;

                // Hidden details row containing full formatted JSON context
                const detailsTr = document.createElement('tr');
                detailsTr.id = 'details-' + index;
                detailsTr.className = 'details-row';
                detailsTr.style.display = 'none';
                
                detailsTr.innerHTML = `
                    <td colspan="6">
                        <div class="details-container">
                            <h4 style="margin-bottom: 8px; color: var(--accent-cyan)">Event Details Payload (Full Depth):</h4>
                            <pre>${JSON.stringify(log, null, 2)}</pre>
                        </div>
                    </td>
                `;

                tbody.appendChild(tr);
                tbody.appendChild(detailsTr);
            });
        }

        // Poll every 1 second
        setInterval(fetchLogs, 1000);
        fetchLogs();
    </script>
</body>
</html>
"""

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class DashboardHandler(http.server.BaseHTTPRequestHandler):
    # Suppress console log output of http.server requests to keep console clean
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_CONTENT.encode('utf-8'))
        elif self.path == '/api/logs':
            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            logs = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        # Get last 150 events in reverse chronological order (newest first)
                        for line in reversed(lines[-150:]):
                            line = line.strip()
                            if line:
                                try:
                                    logs.append(json.loads(line))
                                except Exception:
                                    pass
                except Exception as e:
                    print(f"Error reading file: {e}")
            
            self.wfile.write(json.dumps(logs).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

def main():
    print("=================================================================")
    print("      DEEPCYTES DNS AGENT - MINI SOC TELEMETRY DASHBOARD        ")
    print("=================================================================")
    print(f"Reading logs from: {LOG_FILE}")
    print(f"Starting server on: http://localhost:{PORT}")
    
    server = ThreadingHTTPServer(('localhost', PORT), DashboardHandler)
    
    # Auto-open browser in background thread
    def open_browser():
        try:
            webbrowser.open(f"http://localhost:{PORT}")
        except Exception:
            pass
    threading.Thread(target=open_browser, daemon=True).start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Dashboard Server...")
        server.shutdown()
        sys.exit(0)

if __name__ == "__main__":
    main()
