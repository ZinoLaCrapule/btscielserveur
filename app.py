from flask import Flask, render_template_string, request, redirect, session, url_for, jsonify
import sqlite3
import subprocess
import re
import datetime
import hashlib

app = Flask(__name__)
app.secret_key = "supersecretkey"
DB_PATH = 'scan.db'

# === TEMPLATES HTML ===

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial; background: linear-gradient(120deg, #89f7fe, #66a6ff); height: 100vh; display: flex; align-items: center; justify-content: center; }
        form { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 0 15px rgba(0,0,0,0.2); width: 300px; }
        h1 { text-align: center; margin-bottom: 20px; }
        input, button { width: 100%; padding: 10px; margin: 10px 0; border-radius: 6px; border: 1px solid #ccc; }
        button { background: #0074D9; color: white; border: none; cursor: pointer; }
        button:hover { background: #005fa3; }
    </style>
</head>
<body>
    <form method="POST">
        <h1>Connexion</h1>
        <input type="text" name="username" placeholder="Nom d'utilisateur" required>
        <input type="password" name="password" placeholder="Mot de passe" required>
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
        body { font-family: Arial; background-color: #f2f2f2; text-align: center; padding: 100px; }
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #0074D9; color: white; text-decoration: none; border-radius: 6px; }
    </style>
</head>
<body>
    <h1>Bienvenue, {{ username }} !</h1>
    {% if not session_started %}
        <a href="/start_timer">Commencer la session</a>
    {% else %}
        <a href="/logout">Se déconnecter</a>
    {% endif %}
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin</title>
    <style>
        body { font-family: Arial; background-color: #f8f9fa; padding: 30px; }
        table { border-collapse: collapse; width: 90%; margin: auto; }
        th, td { border: 1px solid #dee2e6; padding: 12px; text-align: center; }
        th { background-color: #0074D9; color: white; }
        h1, h2 { text-align: center; }
        form { margin: 20px auto; width: 300px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        input, button { width: 100%; padding: 10px; margin: 10px 0; border-radius: 6px; border: 1px solid #ccc; }
        button { background: #28a745; color: white; border: none; cursor: pointer; }
        button:hover { background: #218838; }
        .logout { text-align: center; margin-bottom: 20px; }
        .details { text-align: left; }
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
                            <td>${device.status}</td>
                            <td>${device.total_time}</td>
                            <td class="details">
                                <p><strong>IP:</strong> ${device.ip}</p>
                                <p><strong>MAC:</strong> ${device.mac}</p>
                            </td>
                        </tr>`;
                        tbody.innerHTML += row;
                    });
                });
        }
        setInterval(updateDevices, 5000);
        window.onload = updateDevices;
    </script>
</head>
<body>
    <div class="logout"><a href="/logout">Se déconnecter</a></div>
    <h1>Admin - Supervision des utilisateurs</h1>
    <table>
        <thead>
            <tr>
                <th>Nom d'utilisateur</th>
                <th>Première connexion</th>
                <th>Dernière activité</th>
                <th>Statut</th>
                <th>Temps total</th>
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

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS connexions (
                    username TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    ip TEXT,
                    mac TEXT,
                    status TEXT,
                    total_time INTEGER
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT
                )''')
    if not c.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone():
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', hash_password('zino')))
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
        u, p = request.form['username'], hash_password(request.form['password'])
        conn = sqlite3.connect(DB_PATH)
        if conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (u, p)).fetchone():
            session['username'] = u
            return redirect(url_for('index'))
        return "<h1>Identifiants invalides</h1>"
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    username = session.get('username')
    if username and username != 'admin':
        now = datetime.datetime.now()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT first_seen, total_time FROM connexions WHERE username = ?', (username,))
        result = c.fetchone()
        if result:
            first_seen_str, previous_total = result
            first_seen = datetime.datetime.strptime(first_seen_str, "%d/%m/%Y %H:%M")
            session_time = int((now - first_seen).total_seconds())
            total_time = (previous_total or 0) + session_time
            c.execute('UPDATE connexions SET last_seen = ?, total_time = ?, status = ? WHERE username = ?',
                      (now.strftime("%d/%m/%Y %H:%M"), total_time, 'Succès', username))
            conn.commit()
        conn.close()
    session.clear()
    return redirect(url_for('login'))

@app.route('/create', methods=['POST'])
def create():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    u, p = request.form['username'], hash_password(request.form['password'])
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
        c.execute('INSERT INTO connexions VALUES (?, ?, ?, ?, ?, ?, ?)', (username, now, now, ip, mac, 'En cours', 0))
    else:
        c.execute('UPDATE connexions SET last_seen = ?, ip = ?, mac = ?, status = ? WHERE username = ?', (now, ip, mac, 'En cours', username))
    conn.commit()
    return redirect(url_for('index'))

@app.route('/api/connexions')
def api_connexions():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, first_seen, last_seen, status, total_time, ip, mac FROM connexions ORDER BY last_seen DESC')
    rows = c.fetchall()
    devices = []
    for r in rows:
        total_time = r[4]
        total_time_str = str(datetime.timedelta(seconds=total_time)) if total_time else "En cours"
        devices.append(dict(username=r[0], first_seen=r[1], last_seen=r[2], status=r[3], total_time=total_time_str, ip=r[5], mac=r[6]))
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
