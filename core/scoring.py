def score_finding(text: str):
    t = text.lower()
    score = 0

    # CVE signal
    if "cve" in t:
        score += 25

    # exploit signals
    if "rce" in t:
        score += 30
    if "auth bypass" in t:
        score += 25
    if "ssrf" in t:
        score += 20
    if "0day" in t:
        score += 40
    if "unauth" in t:
        score += 15

    # exploit existence
    if "exploit" in t or "poc" in t:
        score += 25

    # infra relevance
    if any(x in t for x in ["linux", "kernel", "cloud", "api", "docker"]):
        score += 10

    # noise penalty
    if any(x in t for x in ["awesome", "course", "tutorial", "collection"]):
        score -= 100

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity
