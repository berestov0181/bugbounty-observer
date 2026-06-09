import requests, time, json, os, re
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scoring_engine import score_finding, is_telemetry

SERVER = "http://localhost:8080"
ANALYZED_FILE = "data/analyzed_ids.json"
ARCHIVE_DIR = "data/archive"
os.makedirs(ARCHIVE_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)

try:
    analyzed = set(json.load(open(ANALYZED_FILE)))
except:
    analyzed = set()

_cve_cache = {}
_port_counts = {}

def save_analyzed():
    json.dump(list(analyzed), open(ANALYZED_FILE, "w"))

def is_cve_patched(cve_id):
    if cve_id in _cve_cache:
        return _cve_cache[cve_id]
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=10)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                patched = vulns[0]["cve"].get("vulnStatus","") == "Analyzed"
                _cve_cache[cve_id] = patched
                return patched
    except:
        pass
    _cve_cache[cve_id] = False
    return False

def should_skip(finding):
    source = finding.get("source","")
    summary = finding.get("summary","")
    if source in ("shodan_tools","hacker_port"):
        key = summary[:50]
        m = re.search(r"(\d+)\s+хост", summary)
        if m:
            count = int(m.group(1))
            prev = _port_counts.get(key, 0)
            if prev > 0 and abs(count-prev)/prev <= 0.01:
                return True, "port_duplicate"
            _port_counts[key] = count
    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", summary, re.IGNORECASE):
        try:
            if int(cve.split("-")[1]) < 2024 and is_cve_patched(cve):
                return True, f"patched:{cve}"
        except:
            pass
    return False, ""

def fetch_new():
    try:
        r = requests.get(f"{SERVER}/findings", timeout=10)
        if r.status_code == 200:
            new = []
            for f in r.json():
                fid = str(f.get("id","")) or f.get("hostname","") + f.get("summary","")[:20]
                if fid not in analyzed:
                    new.append((fid, f))
            return new
    except Exception as e:
        print(f"[-] Server: {e}")
    return []

def analyze(finding):
    API_KEY = "YOUR_OPENROUTER_API_KEY"
    src = finding.get("source","")
    smr = finding.get("summary","")[:200]
    prompt = f"Finding: {src} | {smr}. JSON only: type, severity, bounty_potential, next_steps"
    try:
        resp = requests.post("https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
            json={"model": "openai/gpt-oss-120b:free", "max_tokens": 300,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        text = resp.json()["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group())
    except:
        pass
    return {"type":"unknown","severity":"medium","bounty_potential":"?","next_steps":"manual check"}

cycle = 0
skipped_total = 0
print("[*] Analyzer Loop v2 — CVE filter + port dedup")

while True:
    cycle += 1
    new = fetch_new()
    if not new:
        print(f"[{datetime.now().strftime('%H:%M')}] No new. Wait 10m...")
        time.sleep(600)
        continue
    results = []
    skipped = 0
    for fid, f in new:
        analyzed.add(fid)
        skip, reason = should_skip(f)
        if skip:
            skipped += 1
            skipped_total += 1
            continue
        scored = score_finding(f)
        if scored["severity"] == "INFO":
            skipped += 1
            skipped_total += 1
            continue
        sev = scored["severity"]
        score_val = scored["score"]
        factors = ",".join(scored["factors"][:3])
        icon = "🔴" if sev=="CRITICAL" else "🟠" if sev=="HIGH" else "🟡" if sev=="MEDIUM" else "🔵"
        print(f"{icon} {sev}({score_val}) | {f.get('summary','')[:65]}")
        print(f"   factors: {factors}")
        # AI анализ только для CRITICAL и HIGH чтобы не зависать
        next_steps = ""
        if sev in ("CRITICAL", "HIGH"):
            r = analyze(f)
            next_steps = str(r.get('next_steps',''))[:90]
        if next_steps:
            print(f"   {next_steps}")
        results.append({"finding": f, "analysis": {"severity": sev, "score": score_val, "factors": scored["factors"], "next_steps": next_steps}})
    save_analyzed()
    print(f"[Cycle #{cycle}] New:{len(results)} Skipped:{skipped} Total_skipped:{skipped_total}")
    if results:
        fname = f"{ARCHIVE_DIR}/cycle_{cycle}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        json.dump(results, open(fname,"w"), indent=2, ensure_ascii=False)
        print(f"[*] Archive: {fname}")
    time.sleep(600)
