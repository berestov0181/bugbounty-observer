import json, os, re, socket, time, requests, sys
from datetime import datetime

BASE_DIR = os.path.expanduser("~/bugbounty-observer")
COMPANIES_FILE = os.path.join(BASE_DIR, "data/global_companies/all_companies.json")
BB_FILE = os.path.join(BASE_DIR, "data/bounty_targets/bb_programs.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "data/global_companies/company_hits.json")

CDN = ("104.","172.6","162.159","141.101","108.162","190.93","188.114","2.19.","151.101","199.232","13.32","13.35","52.84")

def guess(name):
    n = name.lower()
    for s in [" inc"," corp"," ltd"," llc"," plc"," ag"," group"," holdings"," technologies"," technology"," systems"," global","'",'\"',"("," pao"," oao"," pac"]:
        n = n.replace(s, "")
    n = n.strip()
    c = re.sub(r"[^a-z0-9]", "", n)
    c2 = re.sub(r"[^a-z0-9]", "-", n).strip("-")
    r = []
    if c and len(c) > 2:
        r += [c + ".com", c + ".io"]
    if c2 != c and len(c2) > 2:
        r.append(c2 + ".com")
    return r[:3]

def idb_check(ip):
    try:
        r = requests.get("https://internetdb.shodan.io/" + ip, timeout=8)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def get_contact(domain):
    for url in ["https://" + domain + "/.well-known/security.txt", "https://" + domain + "/security.txt"]:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and "contact" in r.text.lower():
                for line in r.text.splitlines():
                    if line.lower().startswith("contact:"):
                        return line.split(":", 1)[1].strip()
        except:
            pass
    return "security@" + domain

def scan(max_c=50, country=None):
    companies = json.load(open(COMPANIES_FILE))
    bb = json.load(open(BB_FILE))
    bbd = {}
    for p in bb:
        for a in p.get("assets", []):
            d = a.get("domain", "").lstrip("*.")
            if d:
                bbd[d] = p["name"]
    if country:
        companies = [c for c in companies if c.get("country") == country]
    print("[*] Scanning", min(max_c, len(companies)), "of", len(companies), "companies | country=" + str(country))
    hits = []
    checked = skipped = 0
    for comp in companies[:max_c]:
        name = comp.get("name", "")
        ticker = comp.get("ticker", "")
        cntry = comp.get("country", "")
        for dom in guess(name):
            try:
                ip = socket.gethostbyname(dom)
                if any(ip.startswith(p) for p in CDN):
                    skipped += 1
                    continue
                d = idb_check(ip)
                vulns = list(d.get("vulns", []))
                ports = d.get("ports", [])
                checked += 1
                in_bb = bbd.get(dom)
                ctc = get_contact(dom)
                hits.append({"company": name, "ticker": ticker, "country": cntry, "domain": dom, "ip": ip, "ports": ports[:8], "vulns": vulns, "in_bb": in_bb, "contact": ctc})
                if vulns:
                    print("  VULN |", name, "|", dom, "|", ip, "|", vulns[:2])
                elif not in_bb:
                    print("  NOBB |", name, "|", dom, "|", ctc)
                time.sleep(0.25)
                break
            except socket.gaierror:
                pass
            except:
                pass
    print("[+] checked=" + str(checked) + " cdn_skip=" + str(skipped) + " hits=" + str(len(hits)))
    vh = [h for h in hits if h["vulns"]]
    print("[+] WITH VULNS:", len(vh))
    for h in vh:
        print(" ", h["country"], "|", h["company"], "|", h["domain"], "|", h["vulns"][:2])
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    out_file = os.path.join(BASE_DIR, "data/global_companies/hits_" + (country or "all") + ".json"); json.dump(hits, open(out_file, "w"), indent=2, ensure_ascii=False)
    lines = ["DISCLOSURE REPORT " + datetime.utcnow().strftime("%Y-%m-%d"), "=" * 50, ""]
    for h in vh:
        lines += ["Company: " + h["company"] + " (" + h["ticker"] + ")", "Domain: " + h["domain"] + " IP:" + h["ip"], "Contact: " + h["contact"], "CVEs: " + str(h["vulns"]), "", "To: " + h["contact"], "Subject: Security Notice - " + h["domain"], "", "Hello " + h["company"] + " Security Team,", "", "During open-source security research we found:", ""] + ["  - " + v for v in h["vulns"]] + ["", "Please review and apply patches.", "-" * 40, ""]
    rf = os.path.join(BASE_DIR, "data/global_companies/disclosure_report.txt")
    open(rf, "w").write("\n".join(lines))
    print("[*] Saved:", out_file)
    print("[*] Report:", rf)

country = sys.argv[1] if len(sys.argv) > 1 else None
max_c = int(sys.argv[2]) if len(sys.argv) > 2 else 50
scan(max_c, country)
