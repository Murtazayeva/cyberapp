#!/usr/bin/env python3
"""
SQB Mobile Internet-Banking Kiberhujum Analizatori
===================================================
Aniqlash turlari:
  1. Credential Stuffing  - avtomatlashtirilgan login urinishlari
  2. SQL Injection         - zararli SQL so'rovlari
  3. Data Exfiltration     - ruxsatsiz ommaviy ma'lumot yuklab olish
"""

import re
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# ─────────────────────────── KONFIGURATSIYA ────────────────────────────────
CONFIG = {
    # Credential Stuffing
    "cs_login_endpoints": ["/api/auth/login", "/api/login", "/login", "/auth"],
    "cs_fail_codes":      [401, 403],
    "cs_success_codes":   [200],
    "cs_threshold":       5,           # N ta muvaffaqiyatsiz urinish
    "cs_window_sec":      60,          # vaqt oynasi (soniya)
    "cs_min_requests":    5,           # jami minimal so'rovlar

    # SQL Injection
    "sqli_patterns": [
        r"(?i)(UNION\s+SELECT)",
        r"(?i)(OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(?i)(DROP\s+TABLE)",
        r"(?i)(INSERT\s+INTO)",
        r"(?i)(DELETE\s+FROM)",
        r"(?i)(SLEEP\s*\()",
        r"(?i)(BENCHMARK\s*\()",
        r"(?i)(information_schema)",
        r"(?i)(--\s*$|--\s+)",
        r"(?i)(;\s*SELECT|;\s*DROP|;\s*INSERT)",
        r"['\"]\s*(OR|AND)\s+['\"]?\d",
        r"(?i)(xp_cmdshell|exec\s*\(|execute\s*\()",
    ],
    "sqli_error_codes": [400, 500, 503],

    # Data Exfiltration
    "exfil_endpoints": [
        "/export", "/bulk", "/download", "/all", "/list", "/dump"
    ],
    "exfil_min_bytes":    100_000,     # minimal javob hajmi (bayt)
    "exfil_min_requests": 3,           # minimal so'rovlar soni
    "exfil_window_sec":   300,         # 5 daqiqa
}

# ─────────────────────────── LOG PARSERI ───────────────────────────────────
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>[^\s"]+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_log_line(line: str) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), TIME_FORMAT)
    except ValueError:
        return None
    return {
        "ip":     m.group("ip"),
        "time":   ts,
        "method": m.group("method"),
        "path":   m.group("path"),
        "status": int(m.group("status")),
        "bytes":  int(m.group("bytes")),
        "ua":     m.group("ua") or "",
    }


def load_logs(file_paths: list[str]) -> list[dict]:
    entries = []
    for fp in file_paths:
        path = Path(fp)
        if not path.exists():
            print(f"[OGOHLANTIRISH] Fayl topilmadi: {fp}")
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                entry = parse_log_line(line)
                if entry:
                    entries.append(entry)
    entries.sort(key=lambda x: x["time"])
    return entries


# ─────────────────────────── 1. CREDENTIAL STUFFING ───────────────────────
def detect_credential_stuffing(logs: list[dict]) -> list[dict]:
    login_eps = CONFIG["cs_login_endpoints"]
    threshold  = CONFIG["cs_threshold"]
    window     = timedelta(seconds=CONFIG["cs_window_sec"])
    min_req    = CONFIG["cs_min_requests"]

    by_ip = defaultdict(list)
    for e in logs:
        if any(e["path"].startswith(ep) for ep in login_eps):
            by_ip[e["ip"]].append(e)

    incidents = []
    for ip, reqs in by_ip.items():
        if len(reqs) < min_req:
            continue
        fails    = [r for r in reqs if r["status"] in CONFIG["cs_fail_codes"]]
        successes= [r for r in reqs if r["status"] in CONFIG["cs_success_codes"]]

        # Sliding window
        burst_detected = False
        for i, req in enumerate(fails):
            window_reqs = [r for r in fails if req["time"] <= r["time"] <= req["time"] + window]
            if len(window_reqs) >= threshold:
                burst_detected = True
                break

        if burst_detected:
            t_start = reqs[0]["time"]
            t_end   = reqs[-1]["time"]
            duration = (t_end - t_start).total_seconds()
            incidents.append({
                "attack_type":       "Credential Stuffing",
                "ip":                ip,
                "start_time":        t_start.isoformat(),
                "end_time":          t_end.isoformat(),
                "duration_sec":      round(duration, 1),
                "total_requests":    len(reqs),
                "failed_attempts":   len(fails),
                "successful_logins": len(successes),
                "bytes_exfiltrated": 0,
                "user_agents":       list({r["ua"] for r in reqs if r["ua"]}),
                "severity":          "CRITICAL" if successes else "HIGH",
            })

    return incidents


# ─────────────────────────── 2. SQL INJECTION ─────────────────────────────
def detect_sql_injection(logs: list[dict]) -> list[dict]:
    compiled = [re.compile(p) for p in CONFIG["sqli_patterns"]]

    by_ip = defaultdict(list)
    for e in logs:
        path_decoded = e["path"].replace("%20", " ").replace("+", " ")
        hits = [p.pattern for p in compiled if p.search(path_decoded)]
        if hits:
            e["sqli_patterns_hit"] = hits
            by_ip[e["ip"]].append(e)

    incidents = []
    for ip, reqs in by_ip.items():
        t_start = reqs[0]["time"]
        t_end   = reqs[-1]["time"]
        duration = (t_end - t_start).total_seconds()
        error_cnt = sum(1 for r in reqs if r["status"] in CONFIG["sqli_error_codes"])
        all_patterns = []
        for r in reqs:
            all_patterns.extend(r.get("sqli_patterns_hit", []))

        incidents.append({
            "attack_type":       "SQL Injection",
            "ip":                ip,
            "start_time":        t_start.isoformat(),
            "end_time":          t_end.isoformat(),
            "duration_sec":      round(duration, 1),
            "total_requests":    len(reqs),
            "error_responses":   error_cnt,
            "bytes_exfiltrated": 0,
            "matched_patterns":  list(set(all_patterns)),
            "sample_payloads":   [r["path"][:120] for r in reqs[:3]],
            "user_agents":       list({r["ua"] for r in reqs if r["ua"]}),
            "severity":          "CRITICAL",
        })

    return incidents


# ─────────────────────────── 3. DATA EXFILTRATION ─────────────────────────
def detect_data_exfiltration(logs: list[dict]) -> list[dict]:
    exfil_eps  = CONFIG["exfil_endpoints"]
    min_bytes  = CONFIG["exfil_min_bytes"]
    min_req    = CONFIG["exfil_min_requests"]
    window     = timedelta(seconds=CONFIG["exfil_window_sec"])

    by_ip = defaultdict(list)
    for e in logs:
        if (e["status"] == 200
                and e["bytes"] >= min_bytes
                and any(ep in e["path"] for ep in exfil_eps)):
            by_ip[e["ip"]].append(e)

    incidents = []
    for ip, reqs in by_ip.items():
        if len(reqs) < min_req:
            continue

        t_start    = reqs[0]["time"]
        t_end      = reqs[-1]["time"]
        duration   = (t_end - t_start).total_seconds()
        total_bytes= sum(r["bytes"] for r in reqs)

        # Rate: bayt / soniya
        rate = total_bytes / max(duration, 1)

        incidents.append({
            "attack_type":         "Data Exfiltration",
            "ip":                  ip,
            "start_time":          t_start.isoformat(),
            "end_time":            t_end.isoformat(),
            "duration_sec":        round(duration, 1),
            "total_requests":      len(reqs),
            "bytes_exfiltrated":   total_bytes,
            "bytes_exfil_human":   human_bytes(total_bytes),
            "avg_response_bytes":  round(total_bytes / len(reqs)),
            "transfer_rate_bps":   round(rate),
            "endpoints_accessed":  list({r["path"].split("?")[0] for r in reqs}),
            "user_agents":         list({r["ua"] for r in reqs if r["ua"]}),
            "severity":            "CRITICAL" if total_bytes > 5_000_000 else "HIGH",
        })

    return incidents


# ─────────────────────────── YORDAMCHI FUNKSIYALAR ────────────────────────
def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def print_report(incidents: list[dict]):
    if not incidents:
        print("\n[✓] Hech qanday hujum aniqlanmadi.")
        return

    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  SQB KIBERHUJUM TAHLILI HISOBOTI")
    print(f"  Sana: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Jami aniqlangan hodisalar: {len(incidents)}")
    print(sep)

    by_type = defaultdict(list)
    for inc in incidents:
        by_type[inc["attack_type"]].append(inc)

    icons = {
        "Credential Stuffing": "🔐",
        "SQL Injection":        "💉",
        "Data Exfiltration":    "📤",
    }

    for attack_type, items in by_type.items():
        print(f"\n{icons.get(attack_type,'⚠')}  {attack_type.upper()} ({len(items)} ta hodisa)")
        print("-" * 70)
        for i, inc in enumerate(items, 1):
            print(f"\n  [{i}] IP manzil   : {inc['ip']}  [{inc.get('severity','?')}]")
            print(f"      Boshlanish  : {inc['start_time']}")
            print(f"      Tugash      : {inc['end_time']}")
            print(f"      Davomiyligi : {inc['duration_sec']} soniya")
            print(f"      So'rovlar   : {inc['total_requests']} ta")
            if inc.get("failed_attempts"):
                print(f"      Xato login  : {inc['failed_attempts']} ta")
            if inc.get("successful_logins"):
                print(f"      Muvaffaqiyat: {inc['successful_logins']} ta (!))")
            if inc.get("error_responses") is not None and attack_type == "SQL Injection":
                print(f"      Xato javoblar: {inc['error_responses']} ta")
            if inc.get("bytes_exfiltrated"):
                print(f"      Eksfiltratsiya: {inc['bytes_exfil_human']} ({inc['bytes_exfiltrated']:,} bayt)")
                print(f"      Tezlik        : {inc['transfer_rate_bps']:,} bayt/soniya")
            if inc.get("sample_payloads"):
                print(f"      Namuna payload-lar:")
                for p in inc["sample_payloads"]:
                    print(f"        → {p}")
            if inc.get("endpoints_accessed"):
                print(f"      Ulangan endpoint-lar:")
                for ep in inc["endpoints_accessed"]:
                    print(f"        → {ep}")
    print(f"\n{sep}\n")


def save_json(incidents: list[dict], path: str):
    out = {
        "generated_at":    datetime.now().isoformat(),
        "total_incidents": len(incidents),
        "incidents":       incidents,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[✓] JSON hisobot saqlandi: {path}")


# ─────────────────────────── ASOSIY FUNKSIYA ──────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SQB Kiberhujum Log Analizatori"
    )
    parser.add_argument(
        "logs", nargs="+",
        help="Nginx / backend log fayllari yo'li"
    )
    parser.add_argument(
        "--json", metavar="OUT.json",
        help="JSON formatida hisobotni saqlash"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Faqat JSON chiqarish, matn hisobotini o'chirish"
    )
    args = parser.parse_args()

    print(f"[*] Loglar yuklanmoqda: {args.logs}")
    logs = load_logs(args.logs)
    print(f"[*] Jami {len(logs)} ta log yozuvi yuklandi")

    print("[*] Credential Stuffing tahlili...")
    cs = detect_credential_stuffing(logs)

    print("[*] SQL Injection tahlili...")
    sqli = detect_sql_injection(logs)

    print("[*] Data Exfiltration tahlili...")
    exfil = detect_data_exfiltration(logs)

    all_incidents = cs + sqli + exfil

    if not args.quiet:
        print_report(all_incidents)

    if args.json:
        save_json(all_incidents, args.json)
    else:
        # Har doim hisobot faylini saqlash
        default_out = "sqb_report.json"
        save_json(all_incidents, default_out)

    print(f"\n[✓] Tahlil tugadi. Jami: {len(cs)} Credential Stuffing, "
          f"{len(sqli)} SQL Injection, {len(exfil)} Data Exfiltration hodisasi.")
    return all_incidents


if __name__ == "__main__":
    main()
