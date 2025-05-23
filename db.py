import sqlite3
import time

def init_db():
    conn = sqlite3.connect("scan.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS connexions (
        ip TEXT PRIMARY KEY,
        mac TEXT,
        first_seen REAL,
        last_seen REAL
    )""")
    conn.commit()
    conn.close()

def save_device(ip, mac):
    now = time.time()
    conn = sqlite3.connect("scan.db")
    c = conn.cursor()
    c.execute("SELECT * FROM connexions WHERE ip=?", (ip,))
    row = c.fetchone()
    if row:
        c.execute("UPDATE connexions SET last_seen=? WHERE ip=?", (now, ip))
    else:
        c.execute("INSERT INTO connexions VALUES (?, ?, ?, ?)", (ip, mac, now, now))
    conn.commit()
    conn.close()

def get_devices():
    conn = sqlite3.connect("scan.db")
    c = conn.cursor()
    c.execute("SELECT * FROM connexions")
    rows = c.fetchall()
    conn.close()
    return rows
