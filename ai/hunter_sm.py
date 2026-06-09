import requests, time, re
from datetime import datetime
from enum import Enum

SERVER = "http://localhost:8080"

class State(Enum):
    NORMAL = 0
    RECON = 1
    PREPARATION = 2
    ACTIVE_THREAT = 3

TRANSITIONS = {
    State.NORMAL: {"subdomain_found": State.RECON},
    State.RECON: {"service_detected": State.PREPARATION, "poc_found": State.ACTIVE_THREAT},
    State.PREPARATION: {"poc_matched": State.ACTIVE_THREAT},
}

CRITICAL_CVES = ["CVE-2025-55182","CVE-2025-54424","CVE-2025-49844","CVE-2026-24061"]

class TargetAutomaton:
    def __init__(self, domain):
        self.domain = domain
        self.state = State.NORMAL
        self.subdomains = set()
        self.services = []
        self.pocs = []

    def process(self, finding):
        source = finding.get("source", "")
        hostname = finding.get("hostname", "") or ""
        summary = finding.get("summary", "") or ""

        if False:
            return

        old = self.state

        if source == "crtsh":
            if hostname not in self.subdomains:
                self.subdomains.add(hostname)
                self._transit("subdomain_found", f"поддомен {hostname}")

        elif source == "shodan":
            tech = ["next.js","react","nginx","apache","spring"]
            if any(t in summary.lower() for t in tech):
                self.services.append(hostname)
                self._transit("service_detected", f"сервис на {hostname}")

        elif source == "github":
            m = re.search(r"CVE-\d{4}-\d{4,}", summary)
            if m:
                cve = m.group(0)
                if cve not in self.pocs:
                    self.pocs.append(cve)
                # любой PoC сразу -> ACTIVE_THREAT
                if self.state == State.PREPARATION:
                    self._transit("poc_matched", f"PoC {cve}")
                elif self.state in (State.NORMAL, State.RECON):
                    self.state = State.ACTIVE_THREAT
                    print(f"  -> poc_found: {cve}")

        if self.state != old:
            print(f"[{self.domain}] {old.name} -> {self.state.name}")
            if self.state == State.ACTIVE_THREAT:
                print(f"   АКТИВНАЯ УГРОЗА! CVEs: {self.pocs}")
                self._save_report()

    def _transit(self, event, detail=""):
        if self.state in TRANSITIONS and event in TRANSITIONS[self.state]:
            self.state = TRANSITIONS[self.state][event]
            print(f"  -> {event}: {detail}")

    def _save_report(self):
        with open(f"threat_{self.domain}_{int(time.time())}.txt","w") as f:
            f.write(f"DOMAIN: {self.domain}\n")
            f.write(f"STATE: {self.state.name}\n")
            f.write(f"SUBDOMAINS: {list(self.subdomains)}\n")
            f.write(f"POCS: {self.pocs}\n")
            f.write(f"DATE: {datetime.now()}\n")
        print(f"   Отчёт сохранён: threat_{self.domain}_*.txt")
        # LFI проверка локального стенда
        lfi = check_lfi("http://localhost:3001")
        if lfi:
            with open(fname.replace(".txt","_lfi.txt"),"w") as f:
                import json
                f.write(json.dumps(lfi, indent=2))
            print(f"   LFI отчёт сохранён")
        # LFI проверка локального стенда
        lfi = check_lfi("http://localhost:3001")
        if lfi:
            lfi_fname = f"threat_{self.domain}_{int(__import__("time").time())}_lfi.txt"
            with open(lfi_fname,"w") as f:
                import json
                f.write(json.dumps(lfi, indent=2))
            print(f"   LFI отчёт сохранён")

def fetch():
    try:
        r = requests.get(f"{SERVER}/findings", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[-] Сервер недоступен: {e}")
    return []


def check_lfi(target_url):
    """LFI проверка только на разрешённых целях (локальный стенд)"""
    ALLOWED = ["localhost", "127.0.0.1"]
    from urllib.parse import urlparse
    host = urlparse(target_url).hostname or target_url
    if not any(a in host for a in ALLOWED):
        print(f"  [SKIP] {host} не в списке разрешённых целей")
        return None

    payloads = [
        "/etc/passwd",
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
    ]
    import requests as req
    results = []
    for p in payloads:
        try:
            r = req.get(target_url + p, timeout=5)
            if "root:x:0:0" in r.text:
                results.append({"payload": p, "status": r.status_code, "result": "LFI CONFIRMED"})
                print(f"  [LFI] НАЙДЕНО: {target_url+p}")
            else:
                results.append({"payload": p, "status": r.status_code, "result": "clean"})
        except Exception as e:
            results.append({"payload": p, "result": f"error: {e}"})
    return results


def check_lfi(target_url):
    """LFI проверка только на разрешённых целях (локальный стенд)"""
    ALLOWED = ["localhost", "127.0.0.1"]
    from urllib.parse import urlparse
    host = urlparse(target_url).hostname or target_url
    if not any(a in host for a in ALLOWED):
        print(f"  [SKIP] {host} не в списке разрешённых целей")
        return None

    payloads = [
        "/etc/passwd",
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
    ]
    import requests as req
    results = []
    for p in payloads:
        try:
            r = req.get(target_url + p, timeout=5)
            if "root:x:0:0" in r.text:
                results.append({"payload": p, "status": r.status_code, "result": "LFI CONFIRMED"})
                print(f"  [LFI] НАЙДЕНО: {target_url+p}")
            else:
                results.append({"payload": p, "status": r.status_code, "result": "clean"})
        except Exception as e:
            results.append({"payload": p, "result": f"error: {e}"})
    return results

def main():
    try:
        with open("targets.txt") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        targets = ["selectel.ru"]
        print("[!] targets.txt не найден, используем selectel.ru")

    autos = {d: TargetAutomaton(d) for d in targets}
    print(f"[*] State Machine Hunter запущен. Цели: {targets}")
    print("[*] Только анализ данных от локального сервера (легально)")

    while True:
        findings = fetch()
        for f in findings:
            for auto in autos.values():
                auto.process(f)

        print("\n" + "="*50)
        for auto in autos.values():
            icon = "УГРОЗА" if auto.state == State.ACTIVE_THREAT else "OK"
            print(f" [{icon}] {auto.domain:20} | {auto.state.name:15} | PoC: {auto.pocs}")
        print("="*50)
        time.sleep(60)

if __name__ == "__main__":
    main()
