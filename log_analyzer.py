import re
import sys
from datetime import datetime
from collections import defaultdict

# Nginx standart log formati uchun regex (Combined Log Format)
# Misol: 192.168.1.1 - - [25/Apr/2026:17:06:48 +0500] "GET /api/users HTTP/1.1" 200 1024
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
    r'-\s+-\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)'
)

# SQL Injection ni aniqlash uchun regex patternlar (payloadlar)
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

# Credential Stuffing bo'lishi mumkin bo'lgan endpointlar
LOGIN_ENDPOINTS = ['/login', '/api/login', '/auth', '/api/auth', '/signin']

# Credential Stuffing uchun limit (bitta IP dan 20 tadan ko'p urinish bo'lsa shubhali)
CRED_STUFFING_THRESHOLD = 20

# Data Exfiltration uchun limit (masalan, 5 MB dan ko'p ma'lumot ko'chirilsa)
EXFILTRATION_THRESHOLD_BYTES = 5 * 1024 * 1024

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

def parse_time(time_str):
    # Log vaqt formatini parse qilish: '25/Apr/2026:17:06:48 +0500'
    return datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')

def analyze_logs(log_file):
    sqli_attackers = defaultdict(AttackTracker)
    cred_stuffing_attackers = defaultdict(AttackTracker)
    exfiltration_attackers = defaultdict(AttackTracker)

    print(f"Log fayli tahlil qilinmoqda: {log_file}...\n")

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
                    continue # Vaqt formati mos kelmasa o'tkazib yuborish
                    
                url = data['url']
                bytes_sent = int(data['bytes']) if data['bytes'] != '-' else 0
                method = data['method']
                status = data['status']

                # 1. SQL Injection tahlili
                is_sqli = any(p.search(url) for p in SQLI_PATTERNS)
                if is_sqli:
                    sqli_attackers[ip].update(time_obj, bytes_sent)

                # 2. Credential Stuffing tahlili (Login endpointlariga ko'p POST so'rovlari)
                if method == 'POST' and any(endpoint in url for endpoint in LOGIN_ENDPOINTS):
                    # Odatda xato avtorizatsiyalar 401 status qaytaradi
                    if status in ['401', '403', '200']: 
                        cred_stuffing_attackers[ip].update(time_obj, bytes_sent)

                # 3. Data Exfiltration tahlili (Barcha so'rovlardagi hajm yig'indisi)
                # Odatda muvaffaqiyatli qilingan va katta hajmda qaytgan javoblar (masalan API orqali)
                if status == '200':
                    exfiltration_attackers[ip].update(time_obj, bytes_sent)

    except FileNotFoundError:
        print(f"Xatolik: '{log_file}' fayli topilmadi.")
        return

    # Natijalarni chop etish
    print("="*40)
    print("TAHLIL NATIJALARI (Hujum Vektorlari)")
    print("="*40)

    print("\n[1] SQL INJECTION HUJUMLARI")
    found_sqli = False
    for ip, tracker in sqli_attackers.items():
        if tracker.requests > 0:
            found_sqli = True
            print(f" IP-manzil: {ip}")
            print(f"  - Boshlanish vaqti: {tracker.start_time}")
            print(f"  - Tugash vaqti:     {tracker.end_time}")
            print(f"  - Davomiyligi:      {tracker.get_duration()} soniya")
            print(f"  - So'rovlar soni:   {tracker.requests}")
            print(f"  - Eksfiltratsiya:   {tracker.bytes_exfiltrated} bayt\n")
    if not found_sqli:
         print("  SQL Injection aniqlanmadi.\n")

    print("[2] CREDENTIAL STUFFING HUJUMLARI")
    found_cred = False
    for ip, tracker in cred_stuffing_attackers.items():
        if tracker.requests >= CRED_STUFFING_THRESHOLD:
            found_cred = True
            print(f" IP-manzil: {ip}")
            print(f"  - Boshlanish vaqti: {tracker.start_time}")
            print(f"  - Tugash vaqti:     {tracker.end_time}")
            print(f"  - Davomiyligi:      {tracker.get_duration()} soniya")
            print(f"  - So'rovlar soni:   {tracker.requests}")
            print(f"  - Eksfiltratsiya:   {tracker.bytes_exfiltrated} bayt\n")
    if not found_cred:
         print("  Credential Stuffing aniqlanmadi.\n")

    print("[3] DATA EXFILTRATION (Ommaviy yuklab olish)")
    found_exfil = False
    for ip, tracker in exfiltration_attackers.items():
        # SQLi qatoriga kirmaydigan katta hajm ko'chirganlarni ajratish
        if tracker.bytes_exfiltrated >= EXFILTRATION_THRESHOLD_BYTES:
            found_exfil = True
            print(f" IP-manzil: {ip}")
            print(f"  - Boshlanish vaqti: {tracker.start_time}")
            print(f"  - Tugash vaqti:     {tracker.end_time}")
            print(f"  - Davomiyligi:      {tracker.get_duration()} soniya")
            print(f"  - So'rovlar soni:   {tracker.requests}")
            print(f"  - Eksfiltratsiya:   {tracker.bytes_exfiltrated} bayt\n")
    if not found_exfil:
         print("  Data Exfiltration aniqlanmadi.\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Foydalanish: python log_analyzer.py <log_fayl_nomi>")
        sys.exit(1)
    
    log_file_path = sys.argv[1]
    analyze_logs(log_file_path)
