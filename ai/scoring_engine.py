import re

TELEMETRY_SOURCES = {"shodan_tools", "hacker_port", "scan_exposure"}

TELEMETRY_KEYWORDS = [
    "common rat port", "netbus", "подозрительный порт",
    "хостов в сети", "открытых в интернете",
    "kibana без auth", "grafana dashboard",
    "mongodb без пароля", "redis без пароля",
    "elasticsearch открытый", "jenkins ci/cd",
    "docker api открытый", "k8s api server",
]

def is_telemetry(finding):
    source = finding.get("source", "").lower()
    summary = finding.get("summary", "").lower()
    if source in TELEMETRY_SOURCES:
        for kw in TELEMETRY_KEYWORDS:
            if kw in summary:
                return True
    return False

def score_finding(finding):
    summary = finding.get("summary", "").lower()
    source  = finding.get("source", "").lower()
    score   = 0
    factors = []

    if is_telemetry(finding):
        return {"score": 5, "severity": "INFO", "factors": ["telemetry/aggregate"]}

    if source == "phishing" or "фишинг" in summary:
        score += 40
        factors.append("active_phishing")
        for brand in ["apple","google","meta","facebook","coinbase",
                      "steam","roblox","netflix","bank","easybank","dkb"]:
            if brand in summary:
                score += 15
                factors.append(f"brand:{brand}")
                break

    cves = re.findall(r"cve-(\d{4})-\d+", summary)
    for year_str in cves:
        year = int(year_str)
        if year >= 2025:
            score += 35
            factors.append("cve_fresh_2025+")
        elif year == 2024:
            score += 25
            factors.append("cve_2024")
        else:
            score += 5
            factors.append("cve_old")

    if any(w in summary for w in ["rce","remote code execution","unauthenticated"]):
        score += 20
        factors.append("rce_unauthenticated")

    if any(w in summary for w in ["lpe","privilege escalation","local privilege"]):
        score += 15
        factors.append("privilege_escalation")

    if source == "github" and any(w in summary for w in ["poc","exploit","proof-of-concept"]):
        score += 20
        factors.append("public_poc")

    if source in ("cisa_kev","multi_watcher") and "kev" in summary:
        score += 30
        factors.append("cisa_kev")

    if any(w in summary for w in ["ransomware","actively exploited","in the wild"]):
        score += 25
        factors.append("active_exploitation")

    if source == "scan_exposure":
        if any(w in summary for w in ["docker api","k8s api"]):
            score += 30
            factors.append("exposed_critical_api")
        elif any(w in summary for w in ["jenkins","grafana"]):
            score += 20
            factors.append("exposed_ci_cd")
        else:
            score += 8
            factors.append("exposed_service_aggregate")

    if source == "ai_redteam":
        score += 10
        factors.append("ai_redteam_analysis")

    m = re.search(r"(\d[\d,]+)\s+(?:хост|open|exposed)", summary)
    if m:
        count = int(m.group(1).replace(",",""))
        if count > 10000:
            score += 5
            factors.append("internet_scale_10k+")

    score = min(score, 100)

    if score >= 75:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    elif score >= 10:
        severity = "LOW"
    else:
        severity = "INFO"

    return {"score": score, "severity": severity, "factors": factors}
