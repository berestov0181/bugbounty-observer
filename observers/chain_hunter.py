import requests, time, json, hashlib, os
from datetime import datetime

SERVER = "http://localhost:8080/observer_feed"
SENT_FILE = "data/sent_chains.json"
os.makedirs("data", exist_ok=True)

try:
    sent = set(json.load(open(SENT_FILE)))
except:
    sent = set()

def save():
    json.dump(list(sent), open(SENT_FILE,"w"))

def send(source, hostname, summary, severity="YELLOW"):
    key = hashlib.md5((source+hostname+summary[:50]).encode()).hexdigest()
    if key in sent: return False
    try:
        requests.post(SERVER, json={"source":source,"hostname":hostname,
            "summary":summary,"severity":severity}, timeout=5)
        sent.add(key); save()
        print(f"  [{source}] {summary[:80]}")
        return True
    except: return False

SHODAN = "fhTJwwj0k5H7RMRkhUed1u8wHwJrmGl1"

# === ЦЕПОЧКА 1: Jenkins → RCE ===
# AI выбирал Jenkins 5 раз — ищем уязвимые инстансы
def chain_jenkins():
    print("[CHAIN-1] Jenkins RCE цепочка...")
    queries = [
        ("jenkins port:8080 -auth", "Jenkins без auth"),
        ("jenkins script console", "Jenkins Script Console"),
        ("X-Jenkins port:8080", "Jenkins открытый"),
        ("jenkins version:2.3", "Jenkins старая версия"),
    ]
    for q, desc in queries:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/count?key={SHODAN}&query={q}",
                timeout=10)
            if r.status_code == 200:
                count = r.json().get("total",0)
                if count > 0:
                    send("chain_jenkins", q,
                        f"CHAIN-1 Jenkins: {desc} — {count} хостов | "
                        f"Вектор: Groovy Script -> RCE -> pivot", "RED")
        except Exception as e: print(f"  [-] {e}")
    # CVE для Jenkins
    jenkins_cves = ["CVE-2024-23897","CVE-2023-27898","CVE-2022-0847"]
    for cve in jenkins_cves:
        try:
            r = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
                timeout=10)
            if r.status_code == 200:
                vulns = r.json().get("vulnerabilities",[])
                if vulns:
                    desc = vulns[0]["cve"].get("descriptions",[{}])[0].get("value","")[:100]
                    send("chain_jenkins_cve", cve,
                        f"CHAIN-1 Jenkins CVE: {cve} — {desc}", "RED")
        except Exception as e: print(f"  [-] NVD: {e}")

# === ЦЕПОЧКА 2: Docker → Escape → Host ===
# Docker API выбирался как цель #1 чаще всего
def chain_docker():
    print("[CHAIN-2] Docker Escape цепочка...")
    queries = [
        ("port:2375 Docker", "Docker API открытый"),
        ("port:2376 Docker", "Docker TLS API"),
        ("docker-compose port:2375", "Docker Compose exposed"),
    ]
    for q, desc in queries:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/search?key={SHODAN}&query={q}",
                timeout=45)
            if r.status_code == 200:
                matches = r.json().get("matches",[])[:5]
                for m in matches:
                    ip = m.get("ip_str","")
                    country = m.get("location",{}).get("country_name","?")
                    send("chain_docker", ip,
                        f"CHAIN-2 Docker: {ip} ({country}) | "
                        f"Вектор: API->privileged container->host mount->root", "RED")
        except Exception as e: print(f"  [-] {e}")

# === ЦЕПОЧКА 3: MongoDB/Redis → Data Exfil ===
# MongoDB 86k хостов, Redis 66k — ищем реальные открытые инстансы
def chain_databases():
    print("[CHAIN-3] Database Exfil цепочка...")
    db_queries = [
        ("mongodb port:27017 -auth", "MongoDB", "mongo_dump->data_exfil"),
        ("redis port:6379 -auth",    "Redis",   "redis-cli SLAVEOF->RCE"),
        ("elasticsearch port:9200",  "ElasticSearch", "index dump->PII leak"),
        ("cassandra port:9042",      "Cassandra", "cqlsh->data access"),
        ("memcached port:11211",     "Memcached", "session hijack->pivot"),
    ]
    for q, db, vector in db_queries:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/count?key={SHODAN}&query={q}",
                timeout=10)
            if r.status_code == 200:
                count = r.json().get("total",0)
                if count > 0:
                    send("chain_db", q,
                        f"CHAIN-3 {db}: {count} открытых | Вектор: {vector}",
                        "RED" if count > 1000 else "YELLOW")
        except Exception as e: print(f"  [-] {e}")

# === ЦЕПОЧКА 4: Phishing → Cobalt Strike ===
# AI строил эту цепочку 2 раза
def chain_phishing_c2():
    print("[CHAIN-4] Phishing->C2 цепочка...")
    # Ищем свежие фишинговые домены
    try:
        r = requests.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            headers={"Content-Type":"application/json"}, timeout=45)
        if r.status_code == 200:
            for entry in r.json().get("urls",[])[:10]:
                url = entry.get("url","")
                threat = entry.get("threat","")
                if "cobalt" in threat.lower() or "beacon" in threat.lower():
                    send("chain_phish_c2", url,
                        f"CHAIN-4 Phishing->C2: {threat} | {url[:80]}", "RED")
    except Exception as e: print(f"  [-] URLhaus: {e}")

    # Cobalt Strike по Shodan
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/search?key={SHODAN}&query=port:50050",
            timeout=45)
        if r.status_code == 200:
            for m in r.json().get("matches",[])[:5]:
                ip = m.get("ip_str","")
                country = m.get("location",{}).get("country_name","?")
                send("chain_c2", ip,
                    f"CHAIN-4 Cobalt Strike TeamServer: {ip} ({country}) | "
                    f"Вектор: phish->beacon->lateral", "RED")
    except Exception as e: print(f"  [-] Shodan C2: {e}")

# === ЦЕПОЧКА 5: Supply Chain — GitHub Actions / CI/CD ===
# Новая цепочка на основе статистики Jenkins
def chain_supply_chain():
    print("[CHAIN-5] Supply Chain цепочка...")
    queries = [
        "github+actions+secrets+leaked",
        "ci+cd+pipeline+credentials",
        "npm+token+leaked",
        "aws+key+github+actions",
    ]
    for q in queries:
        try:
            r = requests.get(
                f"https://api.github.com/search/code?q={q}&per_page=3",
                headers={"User-Agent":"BugBountyObserver/3.0"}, timeout=10)
            if r.status_code == 200:
                for item in r.json().get("items",[]):
                    repo = item.get("repository",{}).get("full_name","")
                    name = item.get("name","")
                    send("chain_supply", repo,
                        f"CHAIN-5 Supply Chain: {name} в {repo} | "
                        f"Вектор: leaked creds->CI/CD->deploy->RCE", "RED")
        except Exception as e: print(f"  [-] GitHub: {e}")

# === ЦЕПОЧКА 6: CVE-2026 свежие эксплойты ===
# CVE-2026-31431 нашли ночью
def chain_fresh_cves():
    print("[CHAIN-6] Свежие CVE 2026...")
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&startIndex=0",
            timeout=45)
        if r.status_code == 200:
            for v in r.json().get("vulnerabilities",[]):
                cve = v["cve"]
                cve_id = cve["id"]
                if "2026" not in cve_id: continue
                desc = cve.get("descriptions",[{}])[0].get("value","")[:100]
                metrics = cve.get("metrics",{})
                score = 0
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                if score >= 8.0:
                    send("chain_cve_2026", cve_id,
                        f"CHAIN-6 CVE-2026 [{score}]: {desc}", "RED")
    except Exception as e: print(f"  [-] NVD 2026: {e}")

# === ЦЕПОЧКА 7: Lateral Movement паттерны ===
# На основе attack_chain из redteam отчётов
def chain_lateral():
    print("[CHAIN-7] Lateral Movement цепочка...")
    # SMB/WMI для lateral movement
    lateral_queries = [
        ("port:445 os:Windows", "SMB Windows", "pass-the-hash->lateral"),
        ("port:5985 WinRM",     "WinRM open",  "evil-winrm->RCE"),
        ("port:3389 rdp",       "RDP open",    "RDP bruteforce->session"),
        ("port:22 openssh-5",   "SSH старый",  "CVE exploit->root"),
    ]
    for q, desc, vector in lateral_queries:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/count?key={SHODAN}&query={q}",
                timeout=10)
            if r.status_code == 200:
                count = r.json().get("total",0)
                if count > 0:
                    send("chain_lateral", q,
                        f"CHAIN-7 Lateral: {desc} ({count} хостов) | {vector}",
                        "YELLOW")
        except Exception as e: print(f"  [-] {e}")

# === РОТАЦИЯ ЦЕПОЧЕК ===
CHAINS = [
    ("Jenkins RCE",      1800, chain_jenkins),
    ("Docker Escape",    2700, chain_docker),
    ("DB Exfil",         1800, chain_databases),
    ("Phishing->C2",     2700, chain_phishing_c2),
    ("Supply Chain",     3600, chain_supply_chain),
    ("CVE-2026",         1200, chain_fresh_cves),
    ("Lateral Move",     3600, chain_lateral),
]

timers = {n:0 for n,_,_ in CHAINS}
print("[*] Chain Hunter v1.0 — 7 новых цепочек атак")
print("[*] Jenkins|Docker|DB|Phishing|SupplyChain|CVE2026|Lateral")

while True:
    now = time.time()
    for name, interval, func in CHAINS:
        if now - timers[name] >= interval:
            try: func()
            except Exception as e: print(f"[-] {name}: {e}")
            timers[name] = now
    time.sleep(30)
