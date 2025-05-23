from flask import Flask, render_template_string
import sqlite3
import subprocess
import re
import datetime

app = Flask(__name__)

DB_PATH = 'scan.db'

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="60">
    <title>Appareils Connectés</title>
    <style>
        body { font-family: Arial; background-color: #f2f2f2; padding: 30px; }
        table { border-collapse: collapse; width: 80%; margin: auto; }
        th, td { border: 1px solid #ccc; padding: 12px; text-align: center; }
        th { background-color: #0074D9; color: white; }
        h1 { text-align: center; color: #333; }
        button {
            background-color: #0074D9;
            color: white;
            border: none;
            padding: 6px 10px;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover {
            background-color: #005fa3;
        }
        .mac-details {
            background-color: #e8f4ff;
            font-style: italic;
        }
    </style>
    <script>
    function toggleDetails(button) {
        const row = button.parentElement.parentElement.nextElementSibling;
        row.style.display = (row.style.display === "none") ? "table-row" : "none";
    }
    </script>
</head>
<body>
    <h1>Appareils connectés au réseau</h1>
    <table>
        <tr>
            <th>Adresse IP</th>
            <th>Première connexion</th>
            <th>Dernière activité</th>
            <th>Détails</th>
        </tr>
        {% for device in devices %}
        <tr>
            <td>{{ device[0] }}</td>
            <td>{{ device[2] }}</td>
            <td>{{ device[3] }}</td>
            <td><button onclick="toggleDetails(this)">+</button></td>
        </tr>
        <tr class="mac-details" style="display:none;">
            <td colspan="4">Adresse MAC : {{ device[1] }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS connexions (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_active_interface():
    result = subprocess.run(["ip", "route"], capture_output=True, text=True)
    match = re.search(r'default via .* dev (\w+)', result.stdout)
    if match:
        return match.group(1)
    return "eth0"

def scan_network():
    interface = get_active_interface()
    print(f"[+] Interface utilisée : {interface}")
    
    result = subprocess.run(['sudo', 'arp-scan', '--interface', interface, '--localnet'],
                            capture_output=True, text=True)
    
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    for line in result.stdout.split('\n'):
        if re.match(r'\d+\.\d+\.\d+\.\d+\s+[0-9a-f:]{17}', line):
            ip, mac = line.split()[:2]
            save_device(ip, mac, now)

def save_device(ip, mac, timestamp):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM connexions WHERE ip = ?', (ip,))
    result = c.fetchone()
    if result:
        c.execute('UPDATE connexions SET last_seen = ? WHERE ip = ?', (timestamp, ip))
    else:
        c.execute('INSERT INTO connexions VALUES (?, ?, ?, ?)', (ip, mac, timestamp, timestamp))
    conn.commit()
    conn.close()

def get_devices():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM connexions ORDER BY last_seen DESC')
    rows = c.fetchall()
    conn.close()
    return rows

@app.route('/')
def index():
    scan_network()
    devices = get_devices()
    return render_template_string(HTML_TEMPLATE, devices=devices)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5015)
