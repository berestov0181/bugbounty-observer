import json, os, time, requests, re
from datetime import datetime, timezone

HISTORY_FILE = "data/shodan_spike_history.json"
SIGNALS_FILE = "data/shodan_spike_signals.json"
os.makedirs("data", exist_ok=True)

TRACKED_SERVICES = {
    "redis":      ["redis без пароля", "redis open", "redis", "6379", "порт 6379"],
    "mongodb":    ["mongodb без пароля", "mongodb open", "mongodb", "порт 27017"],
    "elasticsearch": ["elasticsearch открытый", "elasticsearch open"],
    "kibana":     ["kibana без auth", "kibana open"],
    "docker":     ["docker api открытый", "docker api open", "docker", "порт 2375"],
    "k8s":        ["k8s api", "kubernetes api"],
    "jenkins":    ["jenkins ci/cd", "jenkins open"],
    "grafana":    ["grafana dashboard", "grafana open"],
}

def extract_count(summary):
    m = re.search(r'(\d[\d,]+)\s+(?:открытых|open|exposed|хостов)', summary, re.IGNORECASE)
    return int(m.group(1).replace(",", "")) if m else None

def get_current_counts():
    try:
        r = requests.get("http://localhost:8080/findings", timeout=10)
        findings = r.json()
    except:
        return {}
    counts = {}
    for f in findings:
        if f.get("source") not in ("scan_exposure", "shodan_tools", "hacker_tools"):
            continue
        summary = f.get("summary", "").lower()
        for service, keywords in TRACKED_SERVICES.items():
            if any(kw in summary for kw in keywords):
                count = extract_count(f.get("summary", ""))
                if count:
                    counts[service] = count
                break
    return counts

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            return json.load(open(HISTORY_FILE))
        except:
            pass
    return {}

def save_history(h):
    json.dump(h, open(HISTORY_FILE, "w"), indent=2)

def detect_spikes(current, history):
    signals = []
    now = datetime.now(timezone.utc).isoformat()
    for service, count in current.items():
        if service not in history:
            history[service] = {"counts": []}
        hist = history[service]["counts"]
        if hist:
            prev_count = hist[-1]["count"]
            delta = count - prev_count
            pct = (delta / prev_count * 100) if prev_count > 0 else 0
            if pct >= 5 or delta >= 5000:
                level = "CRITICAL" if pct >= 20 or delta >= 20000 else "HIGH" if pct >= 10 else "MEDIUM"
                emoji = "🔴" if level == "CRITICAL" else "🟠" if level == "HIGH" else "🟡"
                signals.append({
                    "service": service, "level": level, "emoji": emoji,
                    "prev_count": prev_count, "curr_count": count,
                    "delta": delta, "delta_pct": round(pct, 1),
                    "message": f"{service.upper()}: {prev_count:,} -> {count:,} (+{delta:,}, +{pct:.1f}%) SPIKE!",
                    "timestamp": now,
                })
                print(f"  {emoji} SPIKE: {service}: {prev_count:,} -> {count:,} (+{pct:.1f}%)")
        hist.append({"count": count, "ts": now})
        history[service]["counts"] = hist[-48:]
    return signals, history

def run():
    print("[*] Shodan Spike Detector v1.0")
    history = load_history()
    current = get_current_counts()
    if not current:
        print("[-] No scan/shodan findings yet")
        return []
    print(f"[*] Current: {current}")
    signals, history = detect_spikes(current, history)
    save_history(history)
    if signals:
        print(f"\n=== SPIKE ALERTS {datetime.now().strftime('%H:%M')} ===")
        for s in signals:
            print(f"{s['emoji']} [{s['level']}] {s['message']}")
        json.dump(signals, open(SIGNALS_FILE, "w"), indent=2, ensure_ascii=False)
    else:
        print("[*] No spikes — counts stable")
        for svc, cnt in current.items():
            hist = history.get(svc, {}).get("counts", [])
            trend = f" (delta: {hist[-1]['count']-hist[-2]['count']:+,})" if len(hist) >= 2 else ""
            print(f"  {svc}: {cnt:,}{trend}")
    return signals

def loop():
    print("[*] Spike loop — каждые 15 мин")
    while True:
        try:
            run()
        except Exception as e:
            print(f"[-] Error: {e}")
        time.sleep(15 * 60)

if __name__ == "__main__":
    import sys
    if "--loop" in sys.argv:
        loop()
    else:
        run()