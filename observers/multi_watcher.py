#!/usr/bin/env python3
"""
Multi-source watcher: NVD, CISA KEV, Exploit-DB, PacketStorm, OSV.dev
"""
import os, sys, json, time, requests
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from observer_core import post_finding, load_state, save_state

OBSERVER_FEED = os.getenv("OBSERVER_FEED", "http://localhost:8080/observer_feed")
STATE_FILE = "state_multi_watcher"

# === NVD ===
def check_nvd():
    findings = []
    try:
        pub_start = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={pub_start}&pubEndDate={pub_end}&resultsPerPage=20"
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "unknown")
                desc = cve.get("descriptions", [{}])[0].get("value", "No description")
                severity = "MEDIUM"
                score = 5.0
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                if metrics:
                    score = metrics.get("cvssData", {}).get("baseScore", 5.0)
                    severity = "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
                
                findings.append({
                    "source": "nvd",
                    "title": f"CVE: {cve_id}",
                    "description": desc[:500],
                    "severity": severity,
                    "factors": ["cve_fresh", f"cve_score_{score}"],
                    "meta": {"cve_id": cve_id, "score": score, "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
                })
    except Exception as e:
        print(f"[-] NVD error: {e}")
    return findings

# === CISA KEV ===
def check_cisa_kev():
    findings = []
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("vulnerabilities", [])[:10]:
                cve_id = item.get("cveID", "")
                product = item.get("product", "Unknown")
                desc = item.get("shortDescription", "No description")
                findings.append({
                    "source": "cisa_kev",
                    "title": f"CISA KEV: {cve_id} ({product})",
                    "description": desc[:500],
                    "severity": "HIGH",
                    "factors": ["cisa_kev", "known_exploited"],
                    "meta": {"cve_id": cve_id, "product": product, "vendor": item.get("vendorProject", "")}
                })
    except Exception as e:
        print(f"[-] CISA KEV error: {e}")
    return findings

# === Exploit-DB ===
def check_exploitdb():
    findings = []
    try:
        url = "https://www.exploit-db.com/rss.xml"
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(r.text)
            for item in root.findall(".//item")[:10]:
                title = item.find("title").text if item.find("title") is not None else "Unknown"
                link = item.find("link").text if item.find("link") is not None else ""
                desc = item.find("description").text if item.find("description") is not None else ""
                findings.append({
                    "source": "exploitdb",
                    "title": f"Exploit-DB: {title[:80]}",
                    "description": desc[:500],
                    "severity": "HIGH",
                    "factors": ["public_exploit", "exploitdb_fresh"],
                    "meta": {"title": title, "url": link}
                })
    except Exception as e:
        print(f"[-] Exploit-DB error: {e}")
    return findings

# === Vulners + Seclists (замена PacketStorm) ===
def check_packetstorm():
    findings = []
    import xml.etree.ElementTree as ET
    sources = [
        ("vulners", "https://vulners.com/rss.xml"),
        ("seclists", "https://seclists.org/rss/fulldisclosure.rss"),
    ]
    for src_name, url in sources:
        try:
            r = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and r.text.strip().startswith("<"):
                root = ET.fromstring(r.text)
                for item in root.findall(".//item")[:5]:
                    title_el = item.find("title")
                    link_el = item.find("link")
                    title = (title_el.text or "Unknown") if title_el is not None else "Unknown"
                    link = (link_el.text or "") if link_el is not None else ""
                    findings.append({
                        "source": src_name,
                        "title": f"{src_name.title()}: {title[:80]}",
                        "description": f"New advisory: {link}",
                        "severity": "MEDIUM",
                        "factors": [src_name, "public_advisory"],
                        "meta": {"title": title, "url": link}
                    })
        except Exception as e:
            print(f"[-] {src_name} error: {e}")
    return findings

# === OSV.dev (Google) ===
def check_osv():
    findings = []
    # Популярные пакеты для мониторинга — можно расширить
    packages = [
        {"name": "lodash", "ecosystem": "npm"},
        {"name": "django", "ecosystem": "PyPI"},
        {"name": "requests", "ecosystem": "PyPI"},
        {"name": "express", "ecosystem": "npm"},
        {"name": "spring-boot", "ecosystem": "Maven"},
        {"name": "golang.org/x/net", "ecosystem": "Go"},
        {"name": "serde", "ecosystem": "crates.io"},
        {"name": "newtonsoft.json", "ecosystem": "NuGet"},
        {"name": "react", "ecosystem": "npm"},
        {"name": "vue", "ecosystem": "npm"},
        {"name": "axios", "ecosystem": "npm"},
        {"name": "flask", "ecosystem": "PyPI"},
        {"name": "fastapi", "ecosystem": "PyPI"},
        {"name": "tensorflow", "ecosystem": "PyPI"},
        {"name": "torch", "ecosystem": "PyPI"},
    ]
    
    for pkg in packages:
        try:
            r = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": pkg, "limit": 3},
                timeout=15,
                headers={"Content-Type": "application/json"}
            )
            if r.status_code != 200:
                continue
            
            data = r.json()
            for vuln in data.get("vulns", []):
                vuln_id = vuln.get("id", "unknown")
                summary = vuln.get("summary", "No summary")
                
                # Severity из CVSS_V3
                severity = "MEDIUM"
                cvss_score = 5.0
                for s in vuln.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        score_str = s.get("score", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
                        # Парсим base score из CVSS строки
                        try:
                            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → ищем последнюю часть
                            parts = score_str.split("/")
                            for part in parts:
                                if part.startswith("C:"):
                                    c = part.split(":")[1]
                                    confidentiality = {"N": 0, "L": 0.22, "H": 0.56}.get(c, 0)
                                if part.startswith("I:"):
                                    i = part.split(":")[1]
                                    integrity = {"N": 0, "L": 0.22, "H": 0.56}.get(i, 0)
                                if part.startswith("A:"):
                                    a = part.split(":")[1]
                                    availability = {"N": 0, "L": 0.22, "H": 0.56}.get(a, 0)
                            # Упрощённая оценка
                            if "C:H" in score_str or "I:H" in score_str or "A:H" in score_str:
                                severity = "HIGH" if "C:H" in score_str or "I:H" in score_str else "MEDIUM"
                            if "C:H" in score_str and "I:H" in score_str and "A:H" in score_str:
                                severity = "CRITICAL"
                        except:
                            pass
                
                # Проверяем свежесть (последние 90 дней для OSV — они реже обновляются)
                published = vuln.get("published", "")
                is_fresh = False
                try:
                    pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    if (datetime.now(pub_date.tzinfo) - pub_date).days <= 90:
                        is_fresh = True
                except:
                    is_fresh = True  # Если не парсится — считаем свежим
                
                # Берём только свежие или критические
                if not is_fresh and severity not in ["HIGH", "CRITICAL"]:
                    continue
                
                # Aliases (CVE IDs)
                aliases = vuln.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")]
                
                findings.append({
                    "source": "osv_dev",
                    "title": f"OSV: {vuln_id} in {pkg['name']} ({pkg['ecosystem']})",
                    "description": summary[:500],
                    "severity": severity,
                    "factors": ["osv_dev", f"ecosystem_{pkg['ecosystem']}", "package_vulnerability"] + ([f"cve_{cve_ids[0]}"] if cve_ids else []),
                    "meta": {
                        "vuln_id": vuln_id,
                        "package": pkg["name"],
                        "ecosystem": pkg["ecosystem"],
                        "published": published,
                        "modified": vuln.get("modified", ""),
                        "aliases": aliases,
                        "cve_ids": cve_ids,
                        "source_url": f"https://osv.dev/vulnerability/{vuln_id}",
                        "affected_versions": str(vuln.get("affected", []))[:200]
                    }
                })
                time.sleep(0.1)
        except Exception as e:
            print(f"[-] OSV error for {pkg['name']}: {e}")
    
    return findings

# === Main loop ===
def main():
    state = load_state(STATE_FILE)
    print("[*] Multi-source watcher запущен")
    print("[*] Источники: NVD, CISA KEV, Exploit-DB, PacketStorm, OSV.dev")
    
    while True:
        all_findings = []
        
        print("\n[*] NVD проверка...")
        all_findings.extend(check_nvd())
        
        print("[*] CISA KEV проверка...")
        all_findings.extend(check_cisa_kev())
        
        print("[*] Exploit-DB проверка...")
        all_findings.extend(check_exploitdb())
        
        print("[*] PacketStorm проверка...")
        all_findings.extend(check_packetstorm())
        
        print("[*] OSV.dev проверка...")
        osv_findings = check_osv()
        all_findings.extend(osv_findings)
        print(f"    OSV.dev: {len(osv_findings)} находок")
        
        # Дедупликация и отправка
        sent = 0
        for f in all_findings:
            key = f"{f['source']}:{f.get('meta', {}).get('cve_id', f.get('meta', {}).get('vuln_id', f.get('title', '')))}"
            if key in state.get("seen", {}):
                continue
            
            if post_finding(f):
                state.setdefault("seen", {})[key] = time.time()
                sent += 1
        
        save_state(STATE_FILE, state)
        print(f"\n[*] Отправлено {sent} новых находок")
        
        print("[*] Sleeping 5min...")
        time.sleep(300)

if __name__ == "__main__":
    main()
