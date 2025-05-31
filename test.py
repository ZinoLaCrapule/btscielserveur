from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'

DB_FILE = 'scan.db'

# --- Initialisation de la BDD ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS connexions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        ip TEXT,
                        mac TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        status TEXT
                    )''')
        conn.commit()

        # Créer un utilisateur admin par défaut si pas déjà présent
        c.execute("SELECT * FROM users WHERE username = ?", ('admin',))
        if not c.fetchone():
            hashed = generate_password_hash('admin123')
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', hashed))
            conn.commit()

init_db()

# --- Routes ---
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if result and check_password_hash(result[0], password):
                session['username'] = username
                return redirect(url_for('admin'))
            else:
                error = 'Identifiants invalides.'
    return render_template_string('''
        <h2>Connexion</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
            <input type="password" name="password" placeholder="Mot de passe" required><br>
            <button type="submit">Se connecter</button>
        </form>
        {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
    ''', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template_string('''
        <h2>Page Admin - Connexions Réseau</h2>
        <a href="{{ url_for('logout') }}">Se déconnecter</a>
        <table border="1" id="table">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>Status</th>
                    <th>Durée de connexion</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
        <script>
            async function refresh() {
                const res = await fetch("/data");
                const data = await res.json();
                const tbody = document.querySelector("#table tbody");
                tbody.innerHTML = "";
                data.forEach(row => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${row.username || "-"}</td>
                        <td>${row.ip || "-"}</td>
                        <td>${row.mac || "-"}</td>
                        <td>${row.status}</td>
                        <td>${row.duree_connexion}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
            setInterval(refresh, 3000);
            refresh();
        </script>
    ''')

@app.route('/data')
def data():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT username, ip, mac, first_seen, last_seen, status FROM connexions")
        rows = c.fetchall()
    result = []
    for row in rows:
        username, ip, mac, first, last, status = row
        if first and last:
            try:
                dt_first = datetime.strptime(first, "%Y-%m-%d %H:%M:%S")
                dt_last = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
                delta = dt_last - dt_first
                duree_connexion = str(delta)
            except:
                duree_connexion = "-"
        else:
            duree_connexion = "-"
        result.append({
            "username": username,
            "ip": ip,
            "mac": mac,
            "status": status,
            "duree_connexion": duree_connexion
        })
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
