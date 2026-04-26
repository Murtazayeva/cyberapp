import time
import random
import datetime

LOG_FILE = "dummy_logs.txt"

def generate_public_ip():
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.') or ip.startswith('127.'):
            continue
        return ip

SQLI_PAYLOADS = [
    "/index.php?id=1+UNION+SELECT+username,password+FROM+users",
    "/login.php?user=admin'--",
    "/api/data?q=1;DROP+TABLE+users",
    "/search?q=1'+OR+'1'='1"
]

def get_time():
    return datetime.datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')

def write_log(ip, method, url, status, bytes_sent):
    log_line = f'{ip} - - [{get_time()}] "{method} {url} HTTP/1.1" {status} {bytes_sent}\n'
    with open(LOG_FILE, "a") as f:
        f.write(log_line)
    print(f"[*] Generated: {log_line.strip()}")

def simulate_sqli():
    ip = generate_public_ip()
    payload = random.choice(SQLI_PAYLOADS)
    write_log(ip, "GET", payload, "403", random.randint(200, 500))

def simulate_dos():
    ip = generate_public_ip()
    print(f"[!] Initiating DoS burst from {ip}")
    # DoS requires >50 requests
    for _ in range(55): 
        write_log(ip, "GET", "/", "200", random.randint(100, 300))
        time.sleep(0.01)

def simulate_cred_stuffing():
    ip = generate_public_ip()
    print(f"[!] Initiating Credential Stuffing from {ip}")
    # Needs > 20 requests
    for _ in range(25):
        write_log(ip, "POST", "/api/login", "401", random.randint(150, 250))
        time.sleep(0.02)

def simulate_exfiltration():
    ip = generate_public_ip()
    # Needs > 5MB
    large_bytes = random.randint(6 * 1024 * 1024, 15 * 1024 * 1024)
    write_log(ip, "GET", "/db_backup.sql", "200", large_bytes)

def main():
    print("========================================")
    print("[*] CYBERGUARD ATTACK SIMULATOR STARTED [*]")
    print("========================================")
    print("Press Ctrl+C to stop.")
    
    attacks = [simulate_sqli, simulate_dos, simulate_cred_stuffing, simulate_exfiltration]
    
    try:
        while True:
            # Randomly pick an attack
            attack = random.choice(attacks)
            attack()
            
            # Sleep for a random interval between 0.5 to 2 seconds to make it look real
            time.sleep(random.uniform(0.5, 2.0))
            
    except KeyboardInterrupt:
        print("\n[!] Attack Simulator Stopped.")

if __name__ == "__main__":
    main()
