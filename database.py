import sqlite3
from datetime import datetime

DB_NAME = "sniffing.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            mac_address TEXT,
            attack_type TEXT NOT NULL,
            details TEXT,
            recommendation TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_alert(ip_address, mac_address, attack_type, details, recommendation):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, ip_address, mac_address, attack_type, details, recommendation)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip_address,
        mac_address,
        attack_type,
        details,
        recommendation
    ))
    conn.commit()
    conn.close()

def get_all_alerts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_alerts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()