#!/usr/bin/env python3
"""
Red Team Mindset Hunter
Думаем как хакер — ищем как защитник
Все источники публичные и легальные
"""
import requests, time, json, re, hashlib, os
from datetime import datetime

SERVER = "http://localhost:8080/observer_feed"
SENT_FILE = "data/sent_redteam.json"
os.makedirs("data", exist_ok=True)

try:
    sent = set(json.load(open(SENT_FILE)))
except:
    sent = set()

def save():
    json.dump(list(sent), open(SENT_FILE,"w"))

def send(source, hostname, summary, severity="YELLOW"):
    key = hashlib.md5((source+hostname+summary[:50]).encode()).hexdigest()
    if key in sent:
        return False
    try:
        requests.post(SERVER, json={
            "source": source,
            "hostname": hostname,
            "summary": summary,
            "severity": severity
        }, timeout=5)
        sent.add(key)
        save()
        print(f"  [{source}] {summary[:80]}")
        return True
    except:
        return False

# ============================================================
# ШАГ 1: РАЗВЕДКА (Reconnaissance)
# Хакер думает: "Что я могу узнать не касаясь цели?"
# ============================================================

def recon_passive():
    """
    Пассивная разведка — хакер собирает данные из открытых источников
    Цель: понять инфраструктуру, найти забытые активы
    """
    print("\n[RECON] Пассивная разведка...")

    # 1.1 Сертификаты — хакер знает что crt.sh раскрывает все субдомены
    # "Компании регистрируют сертификаты для внутренних сервисов"
    domains_to_check = []
    try:
        with open("targets.txt") as f:
            domains_to_check = [l.strip() for l in f if l.strip()]
    except:
        domains_to_check = []

    for domain in domains_to_check[:3]:
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=45
            )
            if r.status_code == 200:
                subs = set()
                for cert in r.json()[:50]:
                    name = cert.get("name_value","")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if domain in sub and sub not in subs:
                            subs.add(sub)
                            send("recon_crt", sub,
                                f"RECON: субдомен {sub} (из SSL сертификата)",
                                "YELLOW")
        except Exception as e:
            print(f"  [-] crt.sh: {e}")

    # 1.2 DNS брутфорс по публичным данным
    # "Хакер ищет dev/staging/admin субдомены"
    interesting_prefixes = [
        "dev","staging","test","api","admin","vpn",
        "mail","ftp","ssh","git","jenkins","jira",
        "confluence","kibana","grafana","internal"
    ]
    for domain in domains_to_check[:2]:
        for prefix in interesting_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                import socket
                ip = socket.gethostbyname(subdomain)
                send("recon_dns", subdomain,
                    f"RECON: {subdomain} → {ip} (интересный субдомен)",
                    "YELLOW")
            except:
                pass

# ============================================================
# ШАГ 2: СКАНИРОВАНИЕ (Scanning)
# Хакер думает: "Что запущено? Какие версии? Где слабые места?"
# ============================================================

def scan_exposure():
    """
    Хакер использует Shodan чтобы найти:
    - Устаревшие версии ПО
    - Открытые панели управления
    - Неправильно настроенные сервисы
    """
    print("\n[SCAN] Поиск экспонированных сервисов...")

    # Хакер знает: "Разработчики часто оставляют debug endpoints открытыми"
    exposed_services = [
        ("kibana port:5601",     "Kibana без auth",      "RED"),
        ("grafana port:3000",    "Grafana dashboard",    "YELLOW"),
        ("elasticsearch port:9200 -auth", "ElasticSearch открытый", "RED"),
        ("mongodb port:27017",   "MongoDB без пароля",   "RED"),
        ("redis port:6379",      "Redis без пароля",     "RED"),
        ("jenkins port:8080",    "Jenkins CI/CD",        "YELLOW"),
        ("docker port:2375",     "Docker API открытый",  "RED"),
        ("kubernetes port:8443", "K8s API server",       "RED"),
        ("jupyter port:8888",    "Jupyter Notebook",     "YELLOW"),
    ]

    SHODAN_KEY = "fhTJwwj0k5H7RMRkhUed1u8wHwJrmGl1"
    for query, desc, severity in exposed_services:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/count?key={SHODAN_KEY}&query={query}",
                timeout=10
            )
            if r.status_code == 200:
                count = r.json().get("total", 0)
                if count > 0:
                    send("scan_exposure", query,
                        f"SCAN: {desc} — {count} открытых в интернете",
                        severity)
        except Exception as e:
            print(f"  [-] Scan: {e}")

# ============================================================
# ШАГ 3: АНАЛИЗ УЯЗВИМОСТЕЙ
# Хакер думает: "Что из найденного можно эксплуатировать?"
# ============================================================

def analyze_vulns():
    """
    AI помогает хакеру: приоритизирует находки
    Хакер + AI = эффективный поиск уязвимостей
    """
    print("\n[ANALYZE] Анализ уязвимостей через AI...")

    API_KEY = "YOUR_OPENROUTER_API_KEY"

    # Получаем находки с сервера
    try:
        r = requests.get(f"{SERVER.replace('/observer_feed','/findings')}", timeout=10)
        findings = r.json()[-10:]  # последние 10
    except:
        return

    for f in findings:
        summary = f.get("summary","")
        if not summary:
            continue

        prompt = f"""You are a red team AI assistant analyzing security findings.
Finding: {summary[:200]}

Answer in JSON only:
{{
  "attack_vector": "how attacker would exploit this",
  "impact": "what attacker gains",
  "likelihood": "high/medium/low",
  "defender_action": "how to detect/prevent",
  "priority": "critical/high/medium/low"
}}"""

        try:
            resp = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "openai/gpt-oss-120b:free",
                    "max_tokens": 400,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=30
            )
            text = resp.json()["choices"][0]["message"]["content"]
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                analysis = json.loads(m.group())
                priority = analysis.get("priority","medium")
                vector = analysis.get("attack_vector","?")
                action = analysis.get("defender_action","?")

                if priority in ("critical","high"):
                    send("ai_redteam",
                        f.get("hostname","unknown"),
                        f"AI RedTeam [{priority.upper()}]: {vector[:60]} | Защита: {action[:60]}",
                        "RED" if priority=="critical" else "YELLOW"
                    )
        except Exception as e:
            print(f"  [-] AI analyze: {e}")
        time.sleep(2)

# ============================================================
# ШАГ 4: ПОИСК СЛЕДОВ АТАК
# Хакер думает: "Кто ещё атакует эти цели?"
# ============================================================

def find_attack_traces():
    """
    Ищем следы реальных атак в открытых источниках
    Honeypots, SIEM алерты, IDS сигнатуры
    """
    print("\n[TRACES] Поиск следов атак...")

    # AbuseIPDB - IP адреса которые атакуют прямо сейчас
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist?limit=20&confidenceMinimum=90",
            headers={"Key": "YOUR_ABUSEIPDB_KEY", "Accept": "application/json"},
            timeout=45
        )
        if r.status_code == 200:
            for entry in r.json().get("data",[])[:10]:
                ip = entry.get("ipAddress","")
                score = entry.get("abuseConfidenceScore",0)
                country = entry.get("countryCode","?")
                send("attack_trace", ip,
                    f"Активная атака с {ip} ({country}) conf:{score}%",
                    "RED")
    except:
        pass

    # GreyNoise - интернет-шум и сканеры
    try:
        r = requests.get(
            "https://api.greynoise.io/v3/community/8.8.8.8",
            headers={"key": "YOUR_GREYNOISE_KEY"},
            timeout=10
        )
        # GreyNoise показывает кто сканирует интернет
    except:
        pass

    # Публичные honeypot логи (через RSS)
    try:
        r = requests.get("https://feeds.threatfeeds.io/", timeout=10)
        if r.status_code == 200:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(r.content)
            for item in root.findall(".//item")[:5]:
                title_el = item.find("title")
                if title_el is not None:
                    send("honeypot", "threat_feed",
                        f"Threat: {title_el.text[:100]}", "YELLOW")
    except:
        pass

# ============================================================
# ШАГ 5: МЫШЛЕНИЕ ХАКЕРА — АВТОМАТИЧЕСКАЯ РАССТАНОВКА ПРИОРИТЕТОВ
# AI + хакерское мышление = умная приоритизация
# ============================================================

def hacker_ai_prioritize():
    """
    Хакер с AI думает: "Что принесёт максимальный результат
    за минимальное время?"
    """
    print("\n[AI PRIORITY] Расстановка приоритетов по хакерской логике...")

    API_KEY = "YOUR_OPENROUTER_API_KEY"

    try:
        r = requests.get(
            f"{SERVER.replace('/observer_feed','/findings')}",
            timeout=10
        )
        all_findings = r.json()
        if not all_findings:
            return

        # Формируем список для AI
        findings_text = "\n".join([
            f"{i+1}. [{f.get('source','')}] {f.get('summary','')[:100]}"
            for i, f in enumerate(all_findings[-20:])
        ])

        prompt = f"""You are a red team AI. Analyze these security findings and think like an attacker.
Which finding would you exploit FIRST and WHY?

Findings:
{findings_text}

Answer in JSON:
{{
  "top_target": "finding number",
  "reason": "why attacker picks this first",
  "attack_chain": "step1 -> step2 -> step3",
  "estimated_time": "time to exploit",
  "defender_blind_spot": "what defenders miss"
}}"""

        resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "openai/gpt-oss-120b:free",
                "max_tokens": 500,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=30
        )
        text = resp.json()["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            priority = json.loads(m.group())
            print(f"\n  🎯 AI Red Team приоритет:")
            print(f"     Цель #{priority.get('top_target','?')}: {priority.get('reason','?')}")
            print(f"     Цепочка: {priority.get('attack_chain','?')}")
            print(f"     Слепое пятно защиты: {priority.get('defender_blind_spot','?')}")

            # Сохраняем в файл
            with open(f"data/redteam_priority_{int(time.time())}.json","w") as f:
                json.dump(priority, f, indent=2, ensure_ascii=False)

    except Exception as e:
        print(f"  [-] AI priority: {e}")

# ============================================================
# ГЛАВНЫЙ ЦИКЛ — РОТАЦИЯ ЭТАПОВ
# ============================================================

STAGES = [
    ("ThreatFox+Phishing", 900,  lambda: __import__("subprocess").run(
        ["python3","observers/hacker_tools_watcher.py"], capture_output=True)),
    ("Passive Recon",      1800, recon_passive),
    ("Exposure Scan",      3600, scan_exposure),
    ("AI Analysis",        1200, analyze_vulns),
    ("Attack Traces",      2700, find_attack_traces),
    ("AI Prioritize",      1800, hacker_ai_prioritize),
]

timers = {name: 0 for name,_,_ in STAGES}

print("[*] Red Team Mindset Hunter v1.0")
print("[*] Этапы: Recon → Scan → Analyze → Trace → Prioritize")
print("[*] Все источники легальны и публичны")
print()

# Запускаем сразу первые этапы
recon_passive()
scan_exposure()
analyze_vulns()
hacker_ai_prioritize()

while True:
    now = time.time()
    for name, interval, func in STAGES:
        if now - timers[name] >= interval:
            try:
                func()
            except Exception as e:
                print(f"[-] {name}: {e}")
            timers[name] = now
    time.sleep(60)
