import json, os, requests, glob
from datetime import datetime

SVETOFOR = "http://localhost:8003"
ARCHIVE_DIR = "data/archive"
SENT_FILE = "data/sent_to_svetofor.json"

try:
    sent = set(json.load(open(SENT_FILE)))
except:
    sent = set()

def send_to_svetofor(finding, analysis):
    # создаём отчёт
    r = requests.post(f"{SVETOFOR}/report", timeout=5)
    rid = r.json().get("id")
    if not rid:
        return

    # заполняем
    steps = analysis.get("next_steps", "")
    if isinstance(steps, list):
        steps = "\n".join(f"{i+1}. {s}" for i,s in enumerate(steps))

    data = {
        "title": finding.get("hostname",""),
        "description": finding.get("summary",""),
        "severity": analysis.get("severity","medium").lower(),
        "steps": steps,
        "impact": f"Bounty: {analysis.get('bounty_potential','?')} | Type: {analysis.get('type','?')}"
    }
    requests.post(f"{SVETOFOR}/report/{rid}",
        json=data, headers={"Content-Type":"application/json"}, timeout=5)
    print(f"  [+] Svetofor ID {rid}: {finding.get(chr(104)+chr(111)+chr(115)+chr(116)+chr(110)+chr(97)+chr(109)+chr(101),'')}")
    return rid

# читаем все архивные файлы
files = sorted(glob.glob(f"{ARCHIVE_DIR}/cycle_*.json"))
new_reports = 0

for fpath in files:
    fname = os.path.basename(fpath)
    if fname in sent:
        continue
    try:
        items = json.load(open(fpath))
        for item in items:
            send_to_svetofor(item["finding"], item["analysis"])
            new_reports += 1
        sent.add(fname)
    except Exception as e:
        print(f"[-] {fpath}: {e}")

json.dump(list(sent), open(SENT_FILE,"w"))
print(f"\n[*] Отправлено в Svetofor: {new_reports} отчётов")
