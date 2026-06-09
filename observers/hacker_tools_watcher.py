import requests, time, json, hashlib, os, re
from datetime import datetime

SERVER = "http://localhost:8080/observer_feed"
SENT_FILE = "data/sent_tools.json"
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
        requests.post(SERVER, json={"source":source,"hostname":hostname,
            "summary":summary,"severity":severity}, timeout=5)
        sent.add(key)
        save()
        print(f"  [{source}] {summary[:80]}")
        return True
    except:
        return False

# --- СЛЕД 1: Shodan - открытые порты хакерских инструментов ---
def find_hacker_ports():
    """Характерные порты и баннеры хакерских инструментов в интернете"""
    print("[*] След 1: Порты хакерских инструментов (Shodan InternetDB)...")
    
    # Характерные IP диапазоны и порты
    suspicious_ports = [
        ("4444",  "Metasploit default listener"),
        ("4445",  "Metasploit reverse handler"),
        ("1234",  "Common RAT port"),
        ("31337", "Elite hacker port (Back Orifice)"),
        ("12345", "NetBus RAT"),
        ("6666",  "Common C2 port"),
        ("8888",  "Common RAT/C2 port"),
        ("9999",  "Common backdoor port"),
    ]
    
    for port, desc in suspicious_ports:
        try:
            r = requests.get(
                f"https://internetdb.shodan.io/",
                timeout=10
            )
            # InternetDB не требует ключа для базовых запросов
            # Используем поиск по тегам
            r2 = requests.get(
                f"https://api.shodan.io/shodan/host/count?key=fhTJwwj0k5H7RMRkhUed1u8wHwJrmGl1&query=port:{port}",
                timeout=10
            )
            if r2.status_code == 200:
                count = r2.json().get("total", 0)
                if count > 0:
                    send("shodan_tools", f"port:{port}",
                        f"Подозрительный порт {port} ({desc}): {count} хостов в сети",
                        "YELLOW")
        except Exception as e:
            print(f"  [-] Shodan ports: {e}")

# --- СЛЕД 2: Сканеры в Shodan (Masscan, Nmap следы) ---
def find_scanners():
    """Ищем активные сканеры в сети по характерным UA и заголовкам"""
    print("[*] След 2: Активные сканеры (Shodan)...")
    
    scanner_queries = [
        ("masscan", "Masscan сканер"),
        ("zgrab",   "ZGrab сканер"),
        ("nmap",    "Nmap сканер"),
        ("dirbuster", "DirBuster"),
        ("sqlmap",  "SQLMap следы"),
        ("nuclei",  "Nuclei сканер"),
    ]
    
    for tool, desc in scanner_queries:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/search?key=fhTJwwj0k5H7RMRkhUed1u8wHwJrmGl1&query={tool}&facets=country",
                timeout=45
            )
            if r.status_code == 200:
                data = r.json()
                total = data.get("total", 0)
                matches = data.get("matches", [])[:3]
                for m in matches:
                    ip = m.get("ip_str","")
                    country = m.get("location",{}).get("country_name","?")
                    send("scanner_detected", ip,
                        f"Сканер {desc}: {ip} ({country})", "YELLOW")
        except Exception as e:
            print(f"  [-] Scanner search: {e}")

# --- СЛЕД 3: Pastebin/GitHub - утечки инструментов и конфигов ---
def find_leaked_tools():
    """Ищем утёкшие конфиги и инструменты на GitHub"""
    print("[*] След 3: Утёкшие конфиги хакеров (GitHub)...")
    
    queries = [
        "cobalt+strike+profile+extension:c2",
        "metasploit+config+filename:.rc",
        "empire+config+filename:.json",
        "burpsuite+license",
        "nmap+scan+results+filename:.xml",
        "masscan+results+filename:.json",
    ]
    
    headers = {"User-Agent": "BugBountyObserver/3.0"}
    
    for q in queries:
        try:
            r = requests.get(
                f"https://api.github.com/search/code?q={q}&per_page=5",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    repo = item.get("repository",{}).get("full_name","")
                    name = item.get("name","")
                    url = item.get("html_url","")
                    send("github_tools", repo,
                        f"Утёкший конфиг: {name} в {repo}", "RED")
        except Exception as e:
            print(f"  [-] GitHub tools: {e}")

# --- СЛЕД 4: Shodan - C2 фреймворки по сертификатам ---
def find_c2_frameworks():
    """Cobalt Strike, Covenant, Brute Ratel по SSL сертификатам"""
    print("[*] След 4: C2 фреймворки по сертификатам...")
    
    # Характерные CN в сертификатах C2 фреймворков
    c2_signatures = [
        ("ssl:Cobalt Strike", "Cobalt Strike"),
        ("ssl:Major Cobalt Strike", "Cobalt Strike"),
        ("http.html:Covenant",  "Covenant C2"),
        ("http.title:Havoc",   "Havoc C2"),
        ("port:50050",         "Cobalt Strike Team Server"),
        ("port:2222 ssl",      "Brute Ratel C4"),
    ]
    
    for query, framework in c2_signatures:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/search?key=fhTJwwj0k5H7RMRkhUed1u8wHwJrmGl1&query={query}&facets=country",
                timeout=45
            )
            if r.status_code == 200:
                matches = r.json().get("matches", [])[:5]
                for m in matches:
                    ip = m.get("ip_str","")
                    country = m.get("location",{}).get("country_name","?")
                    send("c2_framework", ip,
                        f"{framework} обнаружен: {ip} ({country})", "RED")
        except Exception as e:
            print(f"  [-] C2 search: {e}")

# --- СЛЕД 5: Abuse.ch - активное вредоносное ПО ---
def find_active_malware():
    """ThreatFox - свежие IOC с высокой уверенностью"""
    print("[*] След 5: Активное вредоносное ПО (ThreatFox)...")
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=45
        )
        if r.status_code == 200:
            for ioc in r.json().get("data", [])[:20]:
                value = ioc.get("ioc_value","")
                ioc_type = ioc.get("ioc_type","")
                malware = ioc.get("malware","?")
                confidence = ioc.get("confidence_level", 0)
                tags = ", ".join(ioc.get("tags") or [])
                
                if confidence >= 75:
                    send("threatfox", value,
                        f"IOC [{ioc_type}] {malware} (conf:{confidence}%) {tags}",
                        "RED" if confidence >= 90 else "YELLOW")
    except Exception as e:
        print(f"  [-] ThreatFox: {e}")

# --- СЛЕД 6: Cert.pl - свежие фишинговые домены ---
def find_phishing_domains():
    """Недавно зарегистрированные подозрительные домены"""
    print("[*] След 6: Фишинговые домены (OpenPhish + URLhaus)...")
    
    # OpenPhish
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=45)
        if r.status_code == 200:
            for url in r.text.strip().split("\n")[:10]:
                if url:
                    domain = re.sub(r"https?://([^/]+).*", r"\1", url)
                    send("phishing", domain,
                        f"Активный фишинг: {url[:100]}", "RED")
    except Exception as e:
        print(f"  [-] OpenPhish: {e}")
    
    # URLhaus - malware hosting
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            headers={"Content-Type": "application/json"},
            timeout=45
        )
        if r.status_code == 200:
            for entry in r.json().get("urls", [])[:10]:
                url = entry.get("url","")
                threat = entry.get("threat","?")
                tags = ", ".join(entry.get("tags") or [])
                send("urlhaus", url,
                    f"Malware hosting [{threat}] {tags}: {url[:80]}", "RED")
    except Exception as e:
        print(f"  [-] URLhaus: {e}")

# --- СЛЕД 7: CISA KEV - новые эксплуатируемые уязвимости ---
def find_new_kev():
    """Свежие записи в CISA Known Exploited Vulnerabilities"""
    print("[*] След 7: Новые KEV (CISA)...")
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=45
        )
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            # Берём последние 5
            for v in vulns[-5:]:
                cve = v.get("cveID","")
                name = v.get("vulnerabilityName","")
                vendor = v.get("vendorProject","")
                due = v.get("dueDate","")
                send("cisa_kev_new", cve,
                    f"CISA KEV: {vendor} - {name} (deadline: {due})", "RED")
    except Exception as e:
        print(f"  [-] CISA KEV: {e}")

# --- РОТАЦИЯ 7 СРЕД ---
ENVIRONMENTS = [
    ("ThreatFox IOC",    900,   find_active_malware),
    ("Phishing/URLhaus", 1200,  find_phishing_domains),
    ("C2 Frameworks",   3600,  find_c2_frameworks),
    ("Leaked Configs",  1800,  find_leaked_tools),
    ("CISA KEV",        1800,  find_new_kev),
    ("Scanner Detect",  3600,  find_scanners),
    ("Hacker Ports",    7200,  find_hacker_ports),
]

timers = {name: 0 for name,_,_ in ENVIRONMENTS}

print("[*] Hacker Tools Watcher v1.0")
print("[*] 7 сред: ThreatFox | Phishing | C2 | GitHub | CISA | Scanners | Ports")
print("[*] Только публичные источники — легально")

cycle = 0
while True:
    now = time.time()
    fired = False
    for name, interval, func in ENVIRONMENTS:
        if now - timers[name] >= interval:
            func()
            timers[name] = now
            fired = True
    if fired:
        print(f"\n[{datetime.now().strftime(chr(37)+chr(72)+chr(58)+chr(37)+chr(77))}] Уникальных находок: {len(sent)}")
    time.sleep(30)
# Добавить в начало файла после импортов:
_LAST_PORT_COUNTS = {}

def should_report_port(port, count):
    global _LAST_PORT_COUNTS
    prev = _LAST_PORT_COUNTS.get(port, 0)
    # Репортить только если изменение > 1%
    if abs(count - prev) / max(prev, 1) > 0.01:
        _LAST_PORT_COUNTS[port] = count
        return True
    return False
