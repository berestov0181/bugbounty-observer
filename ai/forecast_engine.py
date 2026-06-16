import requests, json, re, os, time
from datetime import datetime, timezone
from collections import defaultdict

SERVER = "http://localhost:8080"
FORECAST_DIR = "data/forecasts"
os.makedirs(FORECAST_DIR, exist_ok=True)

SIGNAL_WEIGHTS = {
    "github_poc":        20,
    "exploitdb":         15,
    "cisa_kev":          35,
    "threatfox":         35,
    "nvd_high":          20,
    "nvd_critical":      30,
    "multi_source":      25,
    "company_hit":       40,
    "rce_keyword":       25,
    "active_exploit":    30,
    "fresh_cve":         15,
    "public_poc_github": 20,
}

def score_to_forecast(score):
    if score >= 80:
        return {"level": "CRITICAL", "emoji": "🔴", "days": "3-7",  "confidence": 0.85}
    elif score >= 60:
        return {"level": "HIGH",     "emoji": "🟠", "days": "7-14", "confidence": 0.70}
    elif score >= 40:
        return {"level": "MEDIUM",   "emoji": "🟡", "days": "14-30","confidence": 0.55}
    elif score >= 20:
        return {"level": "LOW",      "emoji": "🟢", "days": "30+",  "confidence": 0.35}
    else:
        return {"level": "NOISE",    "emoji": "⚪", "days": "N/A",  "confidence": 0.10}

def extract_cves(text):
    return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))

def compute_signals(findings_for_cve):
    signals = {}
    sources = set(f.get("source", "") for f in findings_for_cve)
    summaries = " ".join(f.get("summary", "") for f in findings_for_cve).lower()
    if "github" in sources:
        signals["github_poc"] = True
    if "exploitdb" in sources or "exploit_db" in sources:
        signals["exploitdb"] = True
    if "cisa_kev" in sources or "kev" in summaries:
        signals["cisa_kev"] = True
    if "threatfox" in sources or "threat" in summaries:
        signals["threatfox"] = True
    if "company_scanner" in sources:
        signals["company_hit"] = True
    if len(sources) >= 2:
        signals["multi_source"] = True
    if any(w in summaries for w in ["rce", "remote code", "unauthenticated"]):
        signals["rce_keyword"] = True
    if any(w in summaries for w in ["actively exploited", "in the wild", "ransomware"]):
        signals["active_exploit"] = True
    if any(w in summaries for w in ["poc", "proof-of-concept", "exploit"]) and "github" in sources:
        signals["public_poc_github"] = True
    cve_years = re.findall(r'CVE-(\d{4})-', summaries)
    if any(int(y) >= 2025 for y in cve_years):
        signals["fresh_cve"] = True
    for f in findings_for_cve:
        score_val = f.get("score", 0)
        if isinstance(score_val, (int, float)):
            if score_val >= 9.0:
                signals["nvd_critical"] = True
            elif score_val >= 8.5:
                signals["nvd_high"] = True
    return signals

def build_forecasts(findings):
    cve_groups = defaultdict(list)
    for f in findings:
        cves = extract_cves(f.get("summary", ""))
        for cve in cves:
            cve_groups[cve.upper()].append(f)
    forecasts = []
    for cve_id, cve_findings in cve_groups.items():
        signals = compute_signals(cve_findings)
        score = min(sum(SIGNAL_WEIGHTS.get(s, 0) for s in signals), 100)
        forecast = score_to_forecast(score)
        sources = list(set(f.get("source", "") for f in cve_findings))
        forecasts.append({
            "cve": cve_id,
            "forecast_score": score,
            "level": forecast["level"],
            "emoji": forecast["emoji"],
            "expected_wave_days": forecast["days"],
            "confidence": forecast["confidence"],
            "signals": list(signals.keys()),
            "sources": sources,
            "finding_count": len(cve_findings),
            "key_summary": next((f.get("summary","")[:120] for f in cve_findings), ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    forecasts.sort(key=lambda x: -x["forecast_score"])
    return forecasts

def run():
    print("[*] Incident Forecast Engine v1.0")
    try:
        r = requests.get(f"{SERVER}/findings", timeout=10)
        findings = r.json()
        if not findings:
            print("[-] No findings yet")
            return []
    except Exception as e:
        print(f"[-] Server error: {e}")
        return []
    print(f"[*] Findings: {len(findings)}, строим прогнозы...")
    forecasts = build_forecasts(findings)
    if not forecasts:
        print("[-] No CVE-based forecasts")
        return []
    print(f"\n{'='*60}")
    print(f"  INCIDENT FORECAST — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}")
    top = [f for f in forecasts if f["forecast_score"] >= 20][:10]
    for fc in top:
        print(f"\n{fc['emoji']} [{fc['level']}] {fc['cve']} — Score: {fc['forecast_score']}/100")
        print(f"   Волна: через {fc['expected_wave_days']} дней | Уверенность: {int(fc['confidence']*100)}%")
        print(f"   Сигналы: {', '.join(fc['signals'])}")
        print(f"   Источники: {', '.join(fc['sources'])}")
    print(f"\n{'='*60}")
    ts = int(time.time())
    os.makedirs(FORECAST_DIR, exist_ok=True)
    json.dump(forecasts[:50], open(f"{FORECAST_DIR}/forecast_{ts}.json","w"), indent=2, ensure_ascii=False)
    critical = [f for f in forecasts if f["level"] in ("CRITICAL","HIGH")]
    if critical:
        json.dump(critical, open(f"{FORECAST_DIR}/forecast_critical_latest.json","w"), indent=2, ensure_ascii=False)
        print(f"[!] Критичных: {len(critical)}")
    return forecasts

def loop():
    print("[*] Forecast loop — каждые 90 мин")
    while True:
        try:
            run()
        except Exception as e:
            print(f"[-] Forecast error: {e}")
        time.sleep(90 * 60)

if __name__ == "__main__":
    import sys
    if "--loop" in sys.argv:
        loop()
    else:
        run()