import os
import re
import sqlite3
import requests
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, render_template

app = Flask(__name__)

DB_FILE = 'cyberguard.db'
LOG_FILE = 'dummy_logs.txt'

# Nginx standart log formati uchun regex (Combined Log Format)
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
    r'-\s+-\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)'
)

SQLI_PATTERNS = [
    re.compile(r'(?i)union.*select'),
    re.compile(r'(?i)select.*from'),
    re.compile(r'(?i)or\s+1=1'),
    re.compile(r'(?i)or\s+\'1\'=\'1'),
    re.compile(r'(?i)--\s'),
    re.compile(r'(?i)/\*.*\*/'),
    re.compile(r'(?i)drop\s+table'),
    re.compile(r'(?i)information_schema'),
    re.compile(r'(?i)sleep\(')
]

LOGIN_ENDPOINTS = ['/login', '/api/login', '/auth', '/api/auth', '/signin']
CRED_STUFFING_THRESHOLD = 20
EXFILTRATION_THRESHOLD_BYTES = 5 * 1024 * 1024
DOS_THRESHOLD = 50 # 50 ta so'rov qisqa vaqt ichida

# Telegram Sozlamalari (O'zingizning bot tokeningizni kiriting)
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        requests.post(url, json=payload, timeout=2)
    except Exception as e:
        print("Telegram alert failed:", e)

IP_CACHE = {}

def get_geoip(ip):
    # Local IPlar uchun aniqlab o'tirmaymiz
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
        return {"country": "Local Network", "countryCode": "LOCAL"}
    
    if ip in IP_CACHE:
        return IP_CACHE[ip]
        
    try:
        # Rate limitga tushmaslik uchun oddiy GET so'rov
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res.get("status") == "success":
            data = {"country": res.get("country"), "countryCode": res.get("countryCode")}
            IP_CACHE[ip] = data
            return data
    except:
        pass
        
    return {"country": "Unknown", "countryCode": "UN"}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            attack_type TEXT,
            requests INTEGER,
            bytes_exfiltrated INTEGER,
            start_time TEXT,
            end_time TEXT,
            duration REAL,
            UNIQUE(ip, attack_type, start_time)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            banned_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

class AttackTracker:
    def __init__(self):
        self.requests = 0
        self.bytes_exfiltrated = 0
        self.start_time = None
        self.end_time = None

    def update(self, time_obj, bytes_sent):
        self.requests += 1
        self.bytes_exfiltrated += bytes_sent
        if self.start_time is None or time_obj < self.start_time:
            self.start_time = time_obj
        if self.end_time is None or time_obj > self.end_time:
            self.end_time = time_obj

    def get_duration(self):
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0

    def to_dict(self, ip):
        geo = get_geoip(ip)
        return {
            "ip": ip,
            "requests": self.requests,
            "bytes_exfiltrated": self.bytes_exfiltrated,
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S") if self.start_time else None,
            "end_time": self.end_time.strftime("%Y-%m-%d %H:%M:%S") if self.end_time else None,
            "duration": self.get_duration(),
            "country": geo.get("country", "Unknown"),
            "countryCode": geo.get("countryCode", "UN")
        }

def parse_time(time_str):
    return datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')

def save_to_db(data_list, attack_type):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for item in data_list:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO attacks 
                (ip, attack_type, requests, bytes_exfiltrated, start_time, end_time, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (item['ip'], attack_type, item['requests'], item['bytes_exfiltrated'], 
                  item['start_time'], item['end_time'], item['duration']))
            
            # Agar chindan ham yangi hujum yozilgan bo'lsa (rowcount 1 bo'lsa), xabar beramiz
            if cursor.rowcount > 0:
                msg = f"🚨 <b>YANGI HUJUM:</b> {attack_type}\n" \
                      f"🌐 <b>IP:</b> {item['ip']}\n" \
                      f"📈 <b>So'rovlar:</b> {item['requests']}\n" \
                      f"📦 <b>Hajmi:</b> {item['bytes_exfiltrated']} bayt"
                send_telegram_alert(msg)
                
        except sqlite3.Error as e:
            print("DB Error:", e)
    conn.commit()
    conn.close()

def get_analysis_data(log_file):
    sqli_attackers = defaultdict(AttackTracker)
    cred_stuffing_attackers = defaultdict(AttackTracker)
    exfiltration_attackers = defaultdict(AttackTracker)
    dos_attackers = defaultdict(AttackTracker) # YANAGI: DoS trackers

    if not os.path.exists(log_file):
        return {"error": "Log file not found"}

    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                match = LOG_PATTERN.search(line)
                if not match:
                    continue
                
                data = match.groupdict()
                ip = data['ip']
                
                try:
                    time_obj = parse_time(data['time'])
                except ValueError:
                    continue
                    
                url = data['url']
                bytes_sent = int(data['bytes']) if data['bytes'] != '-' else 0
                method = data['method']
                status = data['status']

                # DoS / DDoS (Barcha so'rovlar yig'indisi)
                dos_attackers[ip].update(time_obj, bytes_sent)

                # SQL Injection
                if any(p.search(url) for p in SQLI_PATTERNS):
                    sqli_attackers[ip].update(time_obj, bytes_sent)

                # Credential Stuffing
                if method == 'POST' and any(endpoint in url for endpoint in LOGIN_ENDPOINTS):
                    if status in ['401', '403', '200', '429']: 
                        cred_stuffing_attackers[ip].update(time_obj, bytes_sent)

                # Data Exfiltration
                if status == '200':
                    exfiltration_attackers[ip].update(time_obj, bytes_sent)
    except Exception as e:
        return {"error": str(e)}

    results = {
        "sqli": [tracker.to_dict(ip) for ip, tracker in sqli_attackers.items() if tracker.requests > 0],
        "cred_stuffing": [tracker.to_dict(ip) for ip, tracker in cred_stuffing_attackers.items() if tracker.requests >= CRED_STUFFING_THRESHOLD],
        "exfiltration": [tracker.to_dict(ip) for ip, tracker in exfiltration_attackers.items() if tracker.bytes_exfiltrated >= EXFILTRATION_THRESHOLD_BYTES],
        "dos": [tracker.to_dict(ip) for ip, tracker in dos_attackers.items() if tracker.requests >= DOS_THRESHOLD]
    }
    
    # Bazaga saqlash
    save_to_db(results["sqli"], "SQL Injection")
    save_to_db(results["cred_stuffing"], "Credential Stuffing")
    save_to_db(results["exfiltration"], "Data Exfiltration")
    save_to_db(results["dos"], "DoS Attack")
    
    # Block qilingan IPlarni qo'shish
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM banned_ips')
    banned = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    results["banned_ips"] = banned
    
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    data = get_analysis_data(LOG_FILE)
    return jsonify(data)

@app.route('/api/chart_data')
def chart_data():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT attack_type, COUNT(*) 
        FROM attacks 
        GROUP BY attack_type
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    labels = [row[0] for row in rows]
    data = [row[1] for row in rows]
    
    return jsonify({"labels": labels, "data": data})

from flask import request, Response
import csv
import io

@app.route('/api/export')
def export_csv():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT ip, attack_type, requests, bytes_exfiltrated, start_time, duration FROM attacks')
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP Address', 'Attack Type', 'Requests', 'Bytes Exfiltrated', 'Start Time', 'Duration (s)'])
    for row in rows:
        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=cyberguard_report.csv"}
    )

@app.route('/api/block', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address required"}), 400
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT OR IGNORE INTO banned_ips (ip, banned_at) VALUES (?, ?)', 
                       (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500
    conn.close()
    
    return jsonify({"success": True, "ip": ip})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
