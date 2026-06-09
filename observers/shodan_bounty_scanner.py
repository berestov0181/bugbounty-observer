import os, shodan, requests
from datetime import datetime
from observer_core import post_finding, load_state, save_state

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
api = shodan.Shodan(SHODAN_KEY) if SHODAN_KEY else None

def load_bounty_companies():
    url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/programs.json"
    try:
        resp = requests.get(url, timeout=30)
        return {p.get("organization_name","").lower(): {
            "domains": [d.lower() for d in p.get("targets",{}).get("domains",[]) if d],
            "url": p.get("url"), "max_payout": p.get("max_payout"),
            "offers_bounties": p.get("offers_bounties", False)
        } for p in resp.json()}
    except: 
        return {}

def search_shodan(domains, limit=50):
    if not api: 
        return []
    results = []
    for domain in domains[:10]:
        try:
            for host in api.search(f'hostname:"{domain}"', limit=limit).get("matches", []):
                results.append({
                    "ip": host.get("ip_str"), 
                    "port": host.get("port"),
                    "domain": domain, 
                    "tech": host.get("http",{}).get("components",{}),
                    "org": host.get("org"), 
                    "timestamp": host.get("timestamp")
                })
        except: 
            pass
    return results

def fetch_cve(tech_name):
    try:
        resp = requests.post("https://api.osv.dev/v1/query", 
            json={"package": {"name": tech_name, "ecosystem": "PyPI"}}, timeout=10)
        if resp.status_code == 200:
            return [{"id": v.get("id"), "summary": v.get("summary"),
                "severity": v.get("severity",[{}])[0].get("score"),
                "url": f"https://osv.dev/vulnerability/{v.get('id')}"}
                for v in resp.json().get("vulns", [])[:5]]
    except: 
        pass
    return []

def run_scan():
    if not api:
        print("[-] Shodan API key not set")
        return
    companies = load_bounty_companies()
    state = load_state("shodan_bounty")
    for company, info in companies.items():
        if not info["offers_bounties"] or not info["domains"]: 
            continue
        for asset in search_shodan(info["domains"]):
            for tech_name in asset.get("tech", {}).keys():
                for cve in fetch_cve(tech_name):
                    key = f"{company}:{asset['ip']}:{cve['id']}"
                    if key not in state.get("seen", {}):
                        post_finding({
                            "source": "shodan_osv", 
                            "company": company,
                            "target": f"{asset['ip']}:{asset['port']}",
                            "domain": asset["domain"], 
                            "tech": tech_name,
                            "cve": cve["id"], 
                            "cvss": cve["severity"],
                            "description": cve["summary"], 
                            "bounty_url": info["url"],
                            "max_payout": info["max_payout"],
                            "priority": "high" if cve["severity"] and cve["severity"]>7 else "medium",
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        state.setdefault("seen",{})[key]=True
                        save_state("shodan_bounty", state)
                        print(f"[+] {company} | {cve['id']} | {asset['ip']}")
