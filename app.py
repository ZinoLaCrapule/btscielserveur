from flask import Flask, render_template_string, request, redirect, session, url_for, jsonify
import sqlite3
import subprocess
import re
import datetime


app = Flask(__name__)
app.secret_key = "supersecretkey"
DB_PATH = 'scan.db'

# === TEMPLATES HTML ===

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Connexion</title>
    <style>
        body { font-family: Arial; background-color: #f2f2f2; text-align: center; padding-top: 50px; }
        form { background: white; padding: 20px; border-radius: 8px; display: inline-block; }
        input { margin: 10px; padding: 8px; }
    </style>
</head>
<body>
    <h1>Connexion</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
        <input type="password" name="password" placeholder="Mot de passe" required><br>
        <button type="submit">Se connecter</button>
    </form>
</body>
</html>
"""

USER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Bienvenue</title>
    <style>
        body { font-family: Arial; background-color: #eef; text-align: center; padding-top: 100px; }
        button { padding: 10px 20px; font-size: 16px; }
        a { display: inline-block; margin-top: 20px; text-decoration: none; color: red; }
    </style>
</head>
<body>
    <h1>Bienvenue, {{ username }}</h1>
    {% if not session_started %}
        <button onclick="startSession()">Démarrer la session</button>
    {% else %}
        <h2>Temps écoulé : <span id="timer">00:00:00</span></h2>
    {% endif %}
    <br>
    <a href="/logout">Se déconnecter</a>

    <script>
        let started = {{ 'true' if session_started else 'false' }};
        let seconds = 0;
        function startSession() {
            started = true;
            window.open("https://www.google.com", '_blank');
            location.href = '/start_timer';
        }
        function updateTimer() {
            if (!started) return;
            seconds++;
            const hrs = String(Math.floor(seconds / 3600)).padStart(2, '0');
            const mins = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
            const secs = String(seconds % 60).padStart(2, '0');
            document.getElementById("timer").textContent = `${hrs}:${mins}:${secs}`;
        }
        setInterval(updateTimer, 1000);
    </script>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin</title>
    <style>
        body { font-family: Arial; background-color: #f2f2f2; padding: 30px; }
        table { border-collapse: collapse; width: 90%; margin: auto; }
        th, td { border: 1px solid #ccc; padding: 12px; text-align: center; }
        th { background-color: #0074D9; color: white; }
        h1, h2 { text-align: center; }
        form { margin: 20px auto; width: 300px; background: white; padding: 20px; border-radius: 8px; }
        input { margin: 10px; padding: 8px; width: 90%; }
        .logout { text-align: center; margin-bottom: 20px; }
    </style>
    <script>
        function updateDevices() {
            fetch('/api/connexions')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('device-table-body');
                    tbody.innerHTML = '';
                    data.devices.forEach(device => {
                        const row = `<tr>
                            <td>${device.username}</td>
                            <td>${device.first_seen}</td>
                            <td>${device.last_seen}</td>
                            <td>
                                <details>
                                    <summary>+</summary>
                                    <p>IP: ${device.ip}</p>
                                    <p>MAC: ${device.mac}</p>
                                </details>
                            </td>
                        </tr>`;
                        tbody.innerHTML += row;
                    });
                });
        }
        setInterval(updateDevices, 10000);
        window.onload = updateDevices;
    </script>
</head>
<body>
    <div class="logout"><a href="/logout">Se déconnecter</a></div>
    <h1>Admin - Connexions utilisateurs</h1>
    <table>
        <thead>
            <tr>
                <th>Nom d'utilisateur</th>
                <th>Première connexion</th>
                <th>Dernière activité</th>
                <th>Détails</th>
            </tr>
        </thead>
        <tbody id="device-table-body"></tbody>
    </table>
    <h2>Créer un nouveau compte</h2>
    <form method="POST" action="/create">
        <input type="text" name="username" placeholder="Nom d'utilisateur" required>
        <input type="password" name="password" placeholder="Mot de passe" required>
        <button type="submit">Créer</button>
    </form>
</body>
</html>
"""

# === BASE DE DONNÉES ===

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS connexions (
                    username TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    ip TEXT,
                    mac TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT
                )''')
    if not c.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone():
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'zino'))
    conn.commit()
    conn.close()

# === ROUTES ===

@app.before_request
def restrict():
    if request.endpoint not in ('login', 'static', 'start_timer', 'api_connexions') and 'username' not in session:
        return redirect(url_for('login'))

@app.route('/')
def index():
    username = session['username']
    if username == 'admin':
        return render_template_string(ADMIN_TEMPLATE)
    else:
        return render_template_string(USER_TEMPLATE, username=username, session_started=session.get('session_started', False))

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        conn = sqlite3.connect(DB_PATH)
        if conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (u, p)).fetchone():
            session['username'] = u
            return redirect(url_for('index'))
        return "<h1>Identifiants invalides</h1>"
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/create', methods=['POST'])
def create():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    u, p = request.form['username'], request.form['password']
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (u, p))
        conn.commit()
    except sqlite3.IntegrityError:
        return "<h2>Ce nom d'utilisateur existe déjà</h2>"
    return redirect(url_for('index'))

@app.route('/start_timer')
def start_timer():
    session['session_started'] = True
    username = session['username']
    ip = request.remote_addr
    mac = get_mac(ip)
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if not c.execute('SELECT * FROM connexions WHERE username = ?', (username,)).fetchone():
        c.execute('INSERT INTO connexions VALUES (?, ?, ?, ?, ?)', (username, now, now, ip, mac))
    else:
        c.execute('UPDATE connexions SET last_seen = ?, ip = ?, mac = ? WHERE username = ?', (now, ip, mac, username))
    conn.commit()
    return redirect(url_for('index'))

@app.route('/api/connexions')
def api_connexions():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, first_seen, last_seen, ip, mac FROM connexions ORDER BY last_seen DESC')
    rows = c.fetchall()
    devices = [dict(username=r[0], first_seen=r[1], last_seen=r[2], ip=r[3], mac=r[4]) for r in rows]
    return jsonify({'devices': devices})

# === OUTILS ===

def get_mac(ip):
    try:
        result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
        match = re.search(r'(([0-9a-f]{2}:){5}[0-9a-f]{2})', result.stdout, re.IGNORECASE)
        return match.group(1) if match else "inconnu"
    except:
        return "inconnu"

# === MAIN ===

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
