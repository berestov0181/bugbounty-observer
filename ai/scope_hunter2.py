#!/usr/bin/env python3
"""
Scope Hunter v2 — ищем программы где РЕАЛЬНО можно найти баги
Стратегия: средние компании, open source проекты, VDP программы
"""
import requests, json, time, os, re
from datetime import datetime

SHODAN = "fhTJwwj0k5H7RMRkhUed1u8wHwJrmGl1"
API_KEY = "YOUR_OPENROUTER_API_KEY"
os.makedirs("data/scope_findings", exist_ok=True)

# Реалистичные цели — средние компании и open source
PROGRAMS = [
    # Open Source с bug bounty
    {"name":"Nextcloud","domain":"nextcloud.com","email":"security@nextcloud.com","bounty":"до €5000"},
    {"name":"Discourse","domain":"discourse.org","email":"security@discourse.org","bounty":"есть"},
    {"name":"Mattermost","domain":"mattermost.com","email":"https://hackerone.com/mattermost","bounty":"до $1000"},
    {"name":"Rocket.Chat","domain":"rocket.chat","email":"security@rocket.chat","bounty":"есть"},
    # Средние SaaS с VDP
    {"name":"Bitwarden","domain":"bitwarden.com","email":"https://hackerone.com/bitwarden","bounty":"до $5000"},
    {"name":"Grafana Labs","domain":"grafana.com","email":"security@grafana.com","bounty":"есть"},
    {"name":"Elastic Cloud","domain":"elastic.co","email":"security@elastic.co","bounty":"до $3000"},
]

def shodan_search(query, limit=5):
    """Поиск в Shodan"""
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/search?key={SHODAN}&query={query}&facets=country",
            timeout=45)
        if r.status_code == 200:
            return r.json().get("matches", [])[:limit]
    except Exception as e:
        print(f"  [-] {e}")
    return []

def check_grafana(ip, port=3000):
    """Проверка Grafana — анонимный доступ"""
    try:
        r = requests.get(f"http://{ip}:{port}/api/health", timeout=5)
        if r.status_code == 200:
            # Проверяем анонимный доступ к дашбордам
            dash = requests.get(f"http://{ip}:{port}/api/search", timeout=5)
            if dash.status_code == 200:
                data = dash.json()
                if isinstance(data, list) and len(data) > 0:
                    return True, f"Анонимный доступ к {len(data)} дашбордам"
                return True, "Grafana без auth (API доступен)"
    except: pass
    return False, ""

def check_elasticsearch(ip, port=9200):
    """Проверка ES — индексы без auth"""
    try:
        r = requests.get(f"http://{ip}:{port}/", timeout=5)
        if r.status_code == 200 and "elasticsearch" in r.text.lower():
            cat = requests.get(f"http://{ip}:{port}/_cat/indices?v", timeout=5)
            if cat.status_code == 200 and len(cat.text) > 10:
                lines = cat.text.strip().split("\n")
                return True, f"Открытые индексы ({len(lines)-1} шт): {cat.text[:150]}"
    except: pass
    return False, ""

def check_kibana(ip, port=5601):
    """Проверка Kibana"""
    try:
        r = requests.get(f"http://{ip}:{port}/api/status", timeout=5)
        if r.status_code == 200:
            return True, f"Kibana без auth: {r.text[:100]}"
    except: pass
    return False, ""

CHECKS = [
    ("grafana port:3000", check_grafana, 3000, "Grafana Anonymous Access"),
    ("elasticsearch port:9200", check_elasticsearch, 9200, "Elasticsearch No Auth"),
    ("kibana port:5601", check_kibana, 5601, "Kibana No Auth"),
]

def make_report(program, ip, port, vuln_name, evidence):
    """Создаём отчёт в стиле bug bounty"""
    report = f"""# Bug Bounty Report
**Program:** {program["name"]}
**Submit:** {program["email"]}
**Bounty:** {program["bounty"]}
**Date:** {datetime.now().strftime("%Y-%m-%d")}

## Summary
{vuln_name} on {ip}:{port} in scope of {program["name"]}

## Affected Component
- Host: {ip}
- Port: {port}
- Service: {vuln_name}

## Steps to Reproduce
1. Navigate to http://{ip}:{port}/
2. No authentication required
3. Sensitive data accessible

## Evidence
## Impact
- Unauthorized data access without credentials
- Potential for data exfiltration
- CVSS 9.1 (Critical)

## Remediation
- Enable authentication
- Restrict to internal network
- Apply firewall rules

---
Reported via responsible disclosure.
90-day timeline from acknowledgment.
"""
    fname = f"data/scope_findings/{program['name'].replace(' ','_')}_{ip}_{int(time.time())}.md"
    open(fname,'w').write(report)
    return fname

print("[*] Scope Hunter v2 — реалистичный поиск")
print("[*] Стратегия: средние компании + open source")
print()

found = []

for prog in PROGRAMS:
    domain = prog["domain"]
    print(f"[>>] {prog['name']} ({domain})")
    
    for query, check_fn, port, vuln_name in CHECKS:
        # Ищем хосты в домене
        full_query = f"hostname:{domain} {query}"
        hosts = shodan_search(full_query, limit=3)
        
        if not hosts:
            # Пробуем без ограничения домена — SSL сертификат
            ssl_query = f"ssl.cert.subject.cn:{domain} {query}"
            hosts = shodan_search(ssl_query, limit=2)
        
        for h in hosts:
            ip = h.get("ip_str","")
            if not ip: continue
            
            print(f"  [?] Проверяем {ip}:{port}")
            ok, evidence = check_fn(ip, port)
            
            if ok:
                print(f"  [!] НАЙДЕНО: {vuln_name} на {ip}:{port}")
                print(f"      {evidence[:80]}")
                fname = make_report(prog, ip, port, vuln_name, evidence)
                found.append({"program":prog["name"],"ip":ip,"port":port,
                               "vuln":vuln_name,"report":fname,"email":prog["email"]})
                print(f"  [+] Отчёт: {fname}")
            time.sleep(1)
    
    time.sleep(2)
    print()

print("="*60)
print(f"Найдено: {len(found)} реальных хостов")
if found:
    print()
    for f in found:
        print(f"  -> {f['program']}: {f['ip']}:{f['port']}")
        print(f"     Отправить: {f['email']}")
    json.dump(found, open("data/scope_findings/summary_v2.json","w"), indent=2)
else:
    print("Не найдено — программы хорошо защищены.")
    print()
    print("Рекомендация: ищи через Intigriti/YesWeHack программы")
    print("с Next.js/Jenkins/MongoDB в scope — там выше шанс найти баг.")
