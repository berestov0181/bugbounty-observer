#!/usr/bin/env python3
"""
OSV.dev watcher — standalone, без observer_core
"""
import os, json, time, requests
from datetime import datetime

OBSERVER_URL = "http://localhost:8080/observer_feed"
STATE_FILE = "data/state_osv_watcher.json"

PACKAGES = [
    {"name": "lodash", "ecosystem": "npm"},
    {"name": "react", "ecosystem": "npm"},
    {"name": "express", "ecosystem": "npm"},
    {"name": "axios", "ecosystem": "npm"},
    {"name": "django", "ecosystem": "PyPI"},
    {"name": "flask", "ecosystem": "PyPI"},
    {"name": "requests", "ecosystem": "PyPI"},
    {"name": "fastapi", "ecosystem": "PyPI"},
    {"name": "tensorflow", "ecosystem": "PyPI"},
    {"name": "spring-boot", "ecosystem": "Maven"},
    {"name": "golang.org/x/net", "ecosystem": "Go"},
    {"name": "serde", "ecosystem": "crates.io"},
]

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"seen": {}}

def save_state(state):
    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def parse_cvss(score_str):
    if not score_str:
        return "MEDIUM", 5.0
    if "C:H" in score_str and "I:H" in score_str and "A:H" in score_str:
        return "CRITICAL", 9.0
    if "C:H" in score_str or "I:H" in score_str:
        return "HIGH", 7.5
    if "A:H" in score_str:
        return "HIGH", 7.0
    return "MEDIUM", 5.0

def check_osv():
    findings = []
    for pkg in PACKAGES:
        try:
            r = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": pkg, "limit": 3},
                timeout=15,
                headers={"Content-Type": "application/json"}
            )
            if r.status_code != 200:
                continue
            for vuln in r.json().get("vulns", []):
                vuln_id = vuln.get("id", "unknown")
                summary = vuln.get("summary", "")
                published = vuln.get("published", "")
                
                severity, _ = "MEDIUM", 5.0
                for s in vuln.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        severity, _ = parse_cvss(s.get("score", ""))
                
                # Фильтр: только свежие (< 90 дней) или HIGH+
                is_fresh = True
                try:
                    pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    is_fresh = (datetime.now(pub_date.tzinfo) - pub_date).days <= 90
                except:
                    pass
                
                if not is_fresh and severity not in ["HIGH", "CRITICAL"]:
                    continue
                
                cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
                
                findings.append({
                    "source": "osv_dev",
                    "title": f"OSV: {vuln_id} in {pkg['name']}",
                    "description": f"{summary}\nPublished: {published}\nCVEs: {', '.join(cve_ids) if cve_ids else 'None'}",
                    "severity": severity,
                    "factors": ["osv_dev", f"ecosystem_{pkg['ecosystem']}", "package_vulnerability"],
                    "meta": {
                        "vuln_id": vuln_id,
                        "package": pkg["name"],
                        "ecosystem": pkg["ecosystem"],
                        "published": published,
                        "cve_ids": cve_ids,
                        "source_url": f"https://osv.dev/vulnerability/{vuln_id}"
                    }
                })
        except Exception as e:
            print(f"[-] {pkg['name']}: {e}")
        time.sleep(0.5)
    return findings

def send(finding):
    try:
        r = requests.post(OBSERVER_URL, json=finding, timeout=10)
        print(f"  [{'+' if r.status_code==200 else '-'}] {r.status_code} | {finding['title'][:50]}")
        return r.status_code == 200
    except Exception as e:
        print(f"  [-] {e}")
        return False

def main():
    state = load_state()
    print("[*] OSV.dev watcher")
    
    while True:
        findings = check_osv()
        sent = 0
        for f in findings:
            key = f"osv:{f['meta']['vuln_id']}:{f['meta']['package']}"
            if key in state.get("seen", {}):
                continue
            if send(f):
                state.setdefault("seen", {})[key] = time.time()
                sent += 1
        save_state(state)
        print(f"[*] Отправлено {sent} находок. Sleep 10m...")
        time.sleep(600)

if __name__ == "__main__":
    main()
