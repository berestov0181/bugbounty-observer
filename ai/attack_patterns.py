#!/usr/bin/env python3
"""
Attack Patterns DB v1.0
Историческая память: сколько раз видели паттерн, какая доля была критичной.
Чистая статистика по собственным наблюдениям системы, без внешних API.
"""
import json, os
from datetime import datetime, timezone

PATTERNS_FILE = "data/attack_patterns.json"
os.makedirs("data", exist_ok=True)

PATTERN_RULES = {
    "exposed_redis":        ["redis"],
    "exposed_mongodb":       ["mongodb"],
    "exposed_elasticsearch": ["elasticsearch"],
    "exposed_kibana":        ["kibana"],
    "exposed_docker":        ["docker"],
    "exposed_k8s":           ["k8s api", "kubernetes"],
    "exposed_jenkins":       ["jenkins"],
    "exposed_grafana":       ["grafana"],
    "github_poc_rce":        ["rce", "remote code"],
    "active_phishing":       ["phishing", "фишинг"],
    "wordpress_plugin_vuln": ["wp ", "wordpress", "plugin"],
    "rat_c2_port":           ["rat port", "c2 port"],
}

def load_patterns():
    if os.path.exists(PATTERNS_FILE):
        try:
            return json.load(open(PATTERNS_FILE))
        except Exception:
            pass
    return {}

def save_patterns(patterns):
    json.dump(patterns, open(PATTERNS_FILE, "w"), indent=2, ensure_ascii=False)

def match_patterns(summary):
    s = summary.lower()
    matched = []
    for pattern, keywords in PATTERN_RULES.items():
        if any(kw in s for kw in keywords):
            matched.append(pattern)
    return matched

def update_patterns(findings):
    patterns = load_patterns()
    now = datetime.now(timezone.utc).isoformat()
    for f in findings:
        summary = f.get("summary", "")
        matched = match_patterns(summary)
        severity = f.get("severity", "")
        is_critical = severity in ("RED", "CRITICAL")
        for p in matched:
            if p not in patterns:
                patterns[p] = {
                    "pattern": p, "times_seen": 0, "critical_count": 0,
                    "first_seen": now, "last_seen": now, "examples": [],
                }
            entry = patterns[p]
            entry["times_seen"] += 1
            entry["last_seen"] = now
            if is_critical:
                entry["critical_count"] += 1
            if len(entry["examples"]) < 3:
                entry["examples"].append(summary[:100])
    save_patterns(patterns)
    return patterns

def get_pattern_insight(pattern_name):
    patterns = load_patterns()
    entry = patterns.get(pattern_name)
    if not entry or entry["times_seen"] < 2:
        return None
    crit_rate = entry["critical_count"] / entry["times_seen"] if entry["times_seen"] else 0
    return {
        "pattern": pattern_name, "times_seen": entry["times_seen"],
        "critical_rate": round(crit_rate * 100, 1),
        "first_seen": entry["first_seen"], "last_seen": entry["last_seen"],
    }

def get_top_patterns(limit=10):
    patterns = load_patterns()
    items = sorted(patterns.values(), key=lambda x: -x["times_seen"])
    return items[:limit]

def run():
    import requests
    print("[*] Attack Patterns DB v1.0")
    try:
        r = requests.get("http://localhost:8080/findings", timeout=10)
        findings = r.json()
    except Exception as e:
        print(f"[-] Server error: {e}")
        return
    if not findings:
        print("[-] No findings")
        return
    patterns = update_patterns(findings)
    print(f"[*] Processed {len(findings)} findings")
    print(f"[*] Known patterns: {len(patterns)}")
    top = get_top_patterns(10)
    print("\n=== TOP PATTERNS ===")
    for p in top:
        crit_rate = (p["critical_count"] / p["times_seen"] * 100) if p["times_seen"] else 0
        print(f"  {p['pattern']}: seen {p['times_seen']}x, critical {crit_rate:.0f}%")

if __name__ == "__main__":
    run()
