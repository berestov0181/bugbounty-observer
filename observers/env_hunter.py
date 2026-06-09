import requests, time, re, json, hashlib, os
from datetime import datetime

SERVER = "http://localhost:8080/observer_feed"
SENT_FILE = "data/sent_env.json"
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
        print(f"  [{source}] {summary[:70]}")
        return True
    except:
        return False

# --- СРЕДА 1: C2 серверы через Shodan (бесплатный API) ---
def hunt_c2_shodan():
    print("[*] Среда 1: C2 серверы (Shodan)...")
    # Cobalt Strike характерные порты и сертификаты
    queries = [
        "ssl.cert.subject.cn:*.stage.123456",
        "product:Cobalt Strike Beacon",
        "port:50050",  # Cobalt Strike Team Server
        "port:4444 product:Metasploit",
    ]
    for q in queries:
        try:
            r = requests.get(f"https://internetdb.shodan.io/{q}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                for host in data.get("matches", [])[:5]:
                    ip = host.get("ip_str","")
                    send("c2_shodan", ip, f"C2 сервер: {ip} | {q}", "RED")
        except Exception as e:
            print(f"  [-] Shodan: {e}")

# --- СРЕДА 2: Feodo Tracker (C&C ботнетов) ---
def hunt_botnets():
    print("[*] Среда 2: Botnet C&C (Feodo Tracker)...")
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=45)
        if r.status_code == 200:
            for entry in r.json().get("blocklist",[])[:20]:
                ip = entry.get("ip_address","")
                malware = entry.get("malware","?")
                country = entry.get("country","?")
                send("botnet_c2", ip,
                    f"Botnet C&C: {malware} | {ip} ({country})", "RED")
    except Exception as e:
        print(f"  [-] Feodo: {e}")

# --- СРЕДА 3: URLhaus (вредоносные URL) ---
def hunt_malware_urls():
    print("[*] Среда 3: Вредоносные URL (URLhaus)...")
    try:
        r = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", 
            timeout=45, headers={"Content-Type":"application/json"})
        if r.status_code == 200:
            for url_entry in r.json().get("urls",[])[:15]:
                url = url_entry.get("url","")
                threat = url_entry.get("threat","?")
                tags = ",".join(url_entry.get("tags",[]) or [])
                send("urlhaus", url,
                    f"Malware URL: {threat} | {tags} | {url[:80]}", "RED")
    except Exception as e:
        print(f"  [-] URLhaus: {e}")

# --- СРЕДА 4: ThreatFox (IOC база) ---
def hunt_ioc():
    print("[*] Среда 4: IOC (ThreatFox)...")
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
            json={"query":"get_iocs","days":1}, timeout=45)
        if r.status_code == 200:
            for ioc in r.json().get("data",[])[:15]:
                value = ioc.get("ioc_value","")
                ioc_type = ioc.get("ioc_type","")
                malware = ioc.get("malware","?")
                confidence = ioc.get("confidence_level",0)
                if confidence >= 70:
                    send("threatfox", value,
                        f"IOC [{ioc_type}]: {malware} | {value}", "RED")
    except Exception as e:
        print(f"  [-] ThreatFox: {e}")

# --- СРЕДА 5: PhishTank (фишинг) ---
def hunt_phishing():
    print("[*] Среда 5: Фишинг (OpenPhish)...")
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=45)
        if r.status_code == 200:
            for url in r.text.strip().split("\n")[:15]:
                if url:
                    send("phishing", url,
                        f"Phishing URL: {url[:100]}", "YELLOW")
    except Exception as e:
        print(f"  [-] OpenPhish: {e}")

# --- СРЕДА 6: Reddit security (без API) ---
def hunt_reddit():
    print("[*] Среда 6: Reddit (netsec/malware)...")
    for sub in ["netsec","malware","cybersecurity"]:
        try:
            r = requests.get(f"https://www.reddit.com/r/{sub}/new.json?limit=5",
                headers={"User-Agent":"BugBountyObserver/3.0"}, timeout=10)
            if r.status_code == 200:
                for post in r.json()["data"]["children"]:
                    d = post["data"]
                    title = d.get("title","")
                    link = f"reddit.com{d.get(chr(112)+chr(101)+chr(114)+chr(109)+chr(97)+chr(108)+chr(105)+chr(110)+chr(107),'')}"
                    send("reddit", link, f"Reddit r/{sub}: {title}", "YELLOW")
        except Exception as e:
            print(f"  [-] Reddit: {e}")

# --- СРЕДА 7: RSS безопасность (Bleeping, HackerNews, CISA) ---
def hunt_rss():
    print("[*] Среда 7: RSS (новости безопасности)...")
    feeds = [
        ("https://feeds.feedburner.com/TheHackersNews", "hackernews"),
        ("https://www.bleepingcomputer.com/feed/", "bleeping"),
        ("https://www.cisa.gov/cybersecurity-advisories/feed", "cisa_rss"),
    ]
    for feed_url, source in feeds:
        try:
            r = requests.get(feed_url, timeout=10)
            if r.status_code == 200:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(r.content)
                for item in root.findall(".//item")[:5]:
                    title_el = item.find("title")
                    link_el = item.find("link")
                    if title_el is not None:
                        title = title_el.text or ""
                        link = link_el.text if link_el is not None else ""
                        send(source, link, title[:150], "YELLOW")
        except Exception as e:
            print(f"  [-] RSS {source}: {e}")

# --- РОТАЦИЯ СРЕД (не топчемся на месте) ---
ENVIRONMENTS = [
    ("Botnet C&C",    600,   hunt_botnets),
    ("URLhaus",       900,   hunt_malware_urls),
    ("ThreatFox IOC", 1800,  hunt_ioc),
    ("Phishing",      1200,  hunt_phishing),
    ("Reddit",        600,   hunt_reddit),
    ("RSS News",      900,   hunt_rss),
    ("C2 Shodan",     3600,  hunt_c2_shodan),
]

timers = {name: 0 for name,_,_ in ENVIRONMENTS}

print("[*] Environment Hunter запущен — 7 сред поиска")
print("[*] Источники: Feodo, URLhaus, ThreatFox, OpenPhish, Reddit, RSS, Shodan")

cycle = 0
while True:
    now = time.time()
    for name, interval, func in ENVIRONMENTS:
        if now - timers[name] >= interval:
            func()
            timers[name] = now
    cycle += 1
    if cycle % 10 == 0:
        print(f"\n[*] Цикл {cycle} | {datetime.now().strftime(chr(37)+chr(72)+chr(58)+chr(37)+chr(77))} | Уникальных находок: {len(sent)}")
    time.sleep(30)
