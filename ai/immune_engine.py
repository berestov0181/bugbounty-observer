import json, os, requests
from datetime import datetime, timezone

IMMUNE_FILE = "data/immune_recommendations.json"
os.makedirs("data", exist_ok=True)

RULES = {
    "scan_exposure": {
        "redis":         ["Close port 6379", "Enable requirepass in redis.conf", "bind 127.0.0.1"],
        "mongodb":       ["Close port 27017", "Enable auth in mongod.conf", "Restrict bindIp"],
        "elasticsearch": ["Close port 9200/9300", "Enable xpack.security"],
        "kibana":        ["Close port 5601", "Enable auth in kibana.yml", "Use nginx reverse proxy"],
        "jenkins":       ["Close port 8080", "Enable auth matrix", "Restrict by IP"],
        "grafana":       ["Close port 3000", "Change admin password", "Enable OAuth"],
        "docker":        ["Close port 2375/2376", "Enable TLS for Docker API"],
        "k8s":           ["Close port 6443", "Enable RBAC", "Configure Network Policies"],
    },
    "phishing": {
        "default": ["Block domain at DNS level", "Add to proxy blacklist", "Notify users"],
    },
    "github": {
        "rce":     ["Apply vendor patch immediately", "Enable WAF rules", "Check logs for exploitation"],
        "default": ["Check if component is in infrastructure", "Apply patch", "Update to latest version"],
    },
    "default": {
        "default": ["Review finding manually", "Assess impact", "Create ticket"],
    },
}

def get_recommendations(finding):
    source = finding.get("source", "default")
    summary = finding.get("summary", "").lower()
    severity = finding.get("severity", "")
    rule_set = RULES.get(source, RULES["default"])
    recs = None
    for keyword, actions in rule_set.items():
        if keyword != "default" and keyword in summary:
            recs = actions
            break
    if recs is None:
        recs = rule_set.get("default", RULES["default"]["default"])
    if severity in ("RED", "CRITICAL"):
        priority = "CRITICAL"
    elif severity in ("ORANGE", "HIGH"):
        priority = "HIGH"
    else:
        priority = "MEDIUM"
    return {"priority": priority, "actions": recs}

def run():
    print("[*] Immune Engine v1.0")
    try:
        r = requests.get("http://localhost:8080/findings", timeout=10)
        findings = r.json()
    except Exception as e:
        print("[-] Server error:", e)
        return
    critical = [f for f in findings if f.get("severity") in ("RED", "CRITICAL")]
    print("[*] Total:", len(findings), "critical:", len(critical))
    results = []
    seen = set()
    for f in sorted(findings, key=lambda x: x.get("severity", "") == "RED", reverse=True):
        s = f.get("summary", "")[:80]
        if s in seen:
            continue
        seen.add(s)
        recs = get_recommendations(f)
        if recs["priority"] in ("CRITICAL", "HIGH"):
            results.append({
                "priority": recs["priority"],
                "source": f.get("source", ""),
                "summary": s,
                "actions": recs["actions"],
            })
    print("\n=== IMMUNE RECOMMENDATIONS", len(results), "===")
    for item in results[:10]:
        print("\n[" + item["priority"] + "] " + item["source"] + " | " + item["summary"])
        for a in item["actions"]:
            print("   ->", a)
    json.dump(results, open(IMMUNE_FILE, "w"), indent=2, ensure_ascii=False)
    print("[*] Saved:", IMMUNE_FILE)
    return results

if __name__ == "__main__":
    run()
