import requests, time, re, json, os

OBSERVER_URL = "http://localhost:8080/observer_feed"
INTERVAL = 300
SENT_FILE = "data/sent_repos.json"

NOISE = ["demo","lab","test","tutorial","course","patrowl","akto-api",
         "corridorkey","swiftioc","nullai","ghostlm","guardvibe","binsmasher",
         "vulnerability-lookup","cves_data","xclussive","sitey-vm","code-audit",
         "rce-oast","ssrf_vulnerable","cvehunt","leachazalon","int3rceptor",
         "recon-x","burp-idor","paramx","rcet-main","rcepc","vietshield"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

os.makedirs("data", exist_ok=True)
try:
    sent = set(json.load(open(SENT_FILE)))
except:
    sent = set()

def save_sent():
    json.dump(list(sent), open(SENT_FILE,"w"))

def fetch():
    print("[*] Checking GitHub...")
    try:
        r = requests.get("https://api.github.com/search/repositories?q=CVE+exploit&sort=updated&per_page=30", timeout=10)
        for repo in r.json().get("items", []):
            name = repo.get("full_name","")
            desc = repo.get("description","") or ""
            text = (name + " " + desc).lower()
            if name in sent: continue
            if any(n in text for n in NOISE): continue
            cves = CVE_RE.findall(name + " " + desc)
            if not cves: continue
            sev = "RED"
            finding = {"source":"github","hostname":name,"summary":name+" - "+desc[:100],"severity":sev}
            try:
                requests.post(OBSERVER_URL, json=finding, timeout=5)
                sent.add(name)
                save_sent()
                print(f"  [+] {name} | CVEs: {cves}")
            except: pass
    except Exception as e:
        print(f"  [-] {e}")

print("[*] GitHub watcher started (dedup+filter)")
while True:
    fetch()
    print(f"[*] Sleeping {INTERVAL//60}min...")
    time.sleep(INTERVAL)
