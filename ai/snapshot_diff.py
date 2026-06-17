#!/usr/bin/env python3
import json, os, requests
from datetime import datetime, timezone, timedelta
from collections import Counter

SNAPSHOT_DIR = "data/snapshots"
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

def get_findings():
    try:
        r = requests.get("http://localhost:8080/findings", timeout=10)
        return r.json()
    except Exception as e:
        print(f"[-] Server error: {e}")
        return []

def save_snapshot(findings):
    ts = datetime.now(timezone.utc)
    snap = {"timestamp": ts.isoformat(), "total": len(findings), "findings": findings}
    path = f"{SNAPSHOT_DIR}/snapshot_{ts.strftime('%Y%m%d_%H%M')}.json"
    json.dump(snap, open(path, "w"), indent=2, ensure_ascii=False)
    return path

def find_closest_snapshot(hours_ago=24):
    import glob
    files = sorted(glob.glob(f"{SNAPSHOT_DIR}/snapshot_*.json"))
    if not files:
        return None
    target = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    best = None
    best_diff = None
    for f in files:
        try:
            data = json.load(open(f))
            ts = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
            diff = abs((ts - target).total_seconds())
            if best_diff is None or diff < best_diff:
                best_diff = diff
                best = data
        except Exception:
            continue
    return best

def diff_findings(old_findings, new_findings):
    def key(f):
        return f"{f.get('source','')}:{f.get('summary','')}"
    old_keys = set(key(f) for f in old_findings)
    new_items = [f for f in new_findings if key(f) not in old_keys]
    by_source = Counter(f.get("source", "?") for f in new_items)
    by_severity = Counter(f.get("severity", "?") for f in new_items)
    critical_new = [f for f in new_items if f.get("severity") in ("CRITICAL", "RED")]
    return {"new_count": len(new_items), "by_source": dict(by_source.most_common()),
            "by_severity": dict(by_severity), "new_items": new_items, "critical_new": critical_new}

def get_forecast_changes():
    import glob
    files = sorted(glob.glob("data/forecasts/forecast_*.json"))
    if len(files) < 2:
        return None
    try:
        old = json.load(open(files[-2]))
        new = json.load(open(files[-1]))
        old_cves = {f["cve"]: f["forecast_score"] for f in old}
        risen = []
        for cve_item in new:
            cve = cve_item["cve"]
            score = cve_item["forecast_score"]
            old_score = old_cves.get(cve, 0)
            if score > old_score + 10:
                risen.append({"cve": cve, "old": old_score, "new": score})
        new_critical = [f for f in new if f["cve"] not in old_cves and f["forecast_score"] >= 60]
        return {"risen": risen, "new_critical": new_critical}
    except Exception:
        return None

def run():
    print("[*] Daily Snapshot Diff v1.0")
    current = get_findings()
    if not current:
        print("[-] No findings to snapshot")
        return None
    path = save_snapshot(current)
    print(f"[*] Snapshot saved: {path}")
    old_snap = find_closest_snapshot(hours_ago=24)
    if not old_snap:
        print("[*] No 24h-old snapshot yet - first run")
        print(f"[*] Current total: {len(current)} findings")
        return {"first_run": True, "total": len(current)}
    old_time = datetime.fromisoformat(old_snap["timestamp"].replace("Z", "+00:00"))
    hours_diff = (datetime.now(timezone.utc) - old_time).total_seconds() / 3600
    diff = diff_findings(old_snap["findings"], current)
    forecast_changes = get_forecast_changes()
    print(f"\n{'='*60}")
    print(f"  CHANGES OVER {hours_diff:.1f}h (since {old_time.strftime('%Y-%m-%d %H:%M')})")
    print(f"{'='*60}")
    print(f"\nTotal findings: {old_snap['total']} -> {len(current)} (+{diff['new_count']})")
    print("\nBy source:")
    for src, cnt in diff["by_source"].items():
        print(f"  +{cnt:3} {src}")
    if diff["critical_new"]:
        print(f"\nNew critical: {len(diff['critical_new'])}")
        for f in diff["critical_new"][:5]:
            print(f"   {f.get('summary','')[:80]}")
    if forecast_changes and forecast_changes["risen"]:
        print("\nForecast score risen:")
        for r in forecast_changes["risen"][:5]:
            print(f"   {r['cve']}: {r['old']} -> {r['new']}")
    if forecast_changes and forecast_changes["new_critical"]:
        print("\nNew high forecasts:")
        for f in forecast_changes["new_critical"][:5]:
            print(f"   {f['cve']} - score {f['forecast_score']}")
    print(f"{'='*60}")
    result = {"hours": round(hours_diff, 1), "old_total": old_snap["total"],
               "new_total": len(current), "new_count": diff["new_count"],
               "by_source": diff["by_source"], "critical_new": diff["critical_new"][:10],
               "forecast_risen": forecast_changes["risen"] if forecast_changes else []}
    json.dump(result, open(f"{SNAPSHOT_DIR}/latest_diff.json", "w"), indent=2, ensure_ascii=False)
    return result

if __name__ == "__main__":
    import sys
    if "--loop" in sys.argv:
        loop()
    else:
        run()


def loop():
    import time
    print("[*] Snapshot loop - every 60 min")
    while True:
        try:
            run()
        except Exception as e:
            print(f"[-] Error: {e}")
        time.sleep(60 * 60)
