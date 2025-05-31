import subprocess
import sqlite3
import re
import datetime
import time

DB_PATH = 'scan.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS connexions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            mac TEXT,
            first_seen TEXT,
            last_seen TEXT,
            success TEXT,
            duration TEXT
        )
    ''')
    conn.commit()
    conn.close()

def scan_network():
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    ip_mac_list = []

    for line in result.stdout.splitlines():
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+.*?\s+([0-9a-fA-F:-]{17})', line)
        if match:
            ip = match.group(1)
            mac = match.group(2).lower()
            ip_mac_list.append((ip, mac))
    return ip_mac_list

def update_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scanned_devices = scan_network()

    # Mettre à jour ou insérer les connexions
    for ip, mac in scanned_devices:
        c.execute("SELECT * FROM connexions WHERE mac = ?", (mac,))
        row = c.fetchone()
        if row:
            # Mettre à jour la dernière connexion et succès
            c.execute("UPDATE connexions SET last_seen = ?, success = ? WHERE mac = ?", (current_time, "Yes", mac))
        else:
            # Nouvelle connexion
            c.execute("INSERT INTO connexions (ip, mac, first_seen, last_seen, success, duration) VALUES (?, ?, ?, ?, ?, ?)",
                      (ip, mac, current_time, current_time, "Yes", "0"))
    # Mettre à jour les échecs
    c.execute("SELECT mac, last_seen FROM connexions WHERE success = 'Yes'")
    rows = c.fetchall()
    for mac, last_seen in rows:
        # Vérifier si la machine est encore présente dans le scan actuel
        if mac not in [mac_addr for _, mac_addr in scanned_devices]:
            # Calculer la durée de session
            last_seen_time = datetime.datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            now = datetime.datetime.now()
            duration = now - last_seen_time
            duration_str = str(duration).split(".")[0]  # Sans les microsecondes

            # Marquer comme échec et mettre la durée
            c.execute("UPDATE connexions SET success = ?, duration = ? WHERE mac = ?", ("No", duration_str, mac))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    while True:
        update_db()
        time.sleep(10)

