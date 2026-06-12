import requests, json, re, os
from datetime import datetime
from collections import defaultdict

SERVER = "http://localhost:8080"
CHAINS_DIR = "data/attack_chains"
os.makedirs(CHAINS_DIR, exist_ok=True)

CHAIN_TEMPLATES = {
    "initial_access_rce": {
        "name": "Remote Code Execution → Full Compromise",
        "steps": ["Initial Access (RCE)", "Establish Persistence", "Credential Dump", "Lateral Movement", "Data Exfiltration"],
        "triggers": ["rce", "remote code execution", "unauthenticated"],
        "sources": ["github", "multi_watcher"],
    },
    "phishing_ato": {
        "name": "Phishing → Account Takeover → Pivot",
        "steps": ["Phishing Email Delivery", "Credential Harvest", "Account Takeover", "Internal Pivot", "Ransomware/Exfil"],
        "triggers": ["фишинг", "phishing", "credential"],
        "sources": ["phishing"],
    },
    "exposed_db_breach": {
        "name": "Exposed Database → Data Breach → Credential Reuse",
        "steps": ["Discover Open DB (Shodan)", "Unauthenticated Access", "Dump Credentials/PII", "Credential Stuffing", "Account Takeover"],
        "triggers": ["mongodb", "elasticsearch", "redis", "без пароля", "открытый"],
        "sources": ["scan_exposure", "ai_redteam"],
    },
    "ci_cd_compromise": {
        "name": "CI/CD Compromise → Supply Chain Attack",
        "steps": ["Discover Jenkins/GitHub Actions", "RCE via Pipeline", "Inject Malicious Code", "Poison Artifacts", "Supply Chain Breach"],
        "triggers": ["jenkins", "ci/cd", "pipeline", "supply chain"],
        "sources": ["scan_exposure", "github"],
    },
    "kernel_lpe": {
        "name": "Linux LPE → Root → Persistence",
        "steps": ["Initial Low-Priv Access", "Exploit Kernel LPE", "Root Access", "Install Rootkit", "Maintain Persistence"],
        "triggers": ["lpe", "privilege escalation", "kernel", "linux"],
        "sources": ["github", "multi_watcher"],
    },
    "container_escape": {
        "name": "Docker Escape → Host Compromise",
        "steps": ["Access Container", "Exploit Docker API", "Escape to Host", "Compromise Host", "Lateral to K8s Cluster"],
        "triggers": ["docker", "container", "escape", "k8s", "kubernetes"],
        "sources": ["scan_exposure", "github"],
    },
}

def fetch_all():
    try:
        r = requests.get(f"{SERVER}/findings", timeout=10)
        return r.json() if r.status_code == 200 else []
    except:
        return []

def score_chain(finding_count, sources_count, has_cve, has_kev, year):
    # Требуем минимум 2 разных источника для HIGH+
    # Один источник = максимум MEDIUM
    if sources_count < 2:
        base = 20
    else:
        base = 30
    score = base
    score += min(finding_count * 3, 15)   # было *5 — снижаем вес количества
    score += min(sources_count * 15, 30)  # diversity важнее количества
    # CVE старше 2024 не должны поднимать score
    if has_cve and year and year >= 2025:
        score += 15
    elif has_cve and (not year or year < 2025):
        score += 3  # старая CVE — минимальный буст
    score += 20 if has_kev else 0
    if year and year >= 2025:
        score += 15
    elif year and year == 2024:
        score += 8
    return min(score, 100)

def build_chains(findings):
    chains = []
    import re as _re

    for chain_id, template in CHAIN_TEMPLATES.items():
        matched = []
        for f in findings:
            summary = f.get("summary", "").lower()
            trigger_match = any(t in summary for t in template["triggers"])
            if trigger_match:
                matched.append(f)

        if not matched:
            continue

        # ANTI-SPECULATION: требуем реальную связь между находками
        # Находки должны разделять общий индикатор: CVE, домен, IP, технологию
        def has_shared_indicator(findings_list):
            # Извлекаем CVE из каждой находки
            cve_sets = []
            for f in findings_list:
                cves = set(_re.findall(r"CVE-\d{4}-\d{4,7}", f.get("summary",""), _re.IGNORECASE))
                if cves:
                    cve_sets.append(cves)
            # Если есть CVE в нескольких находках — нужно пересечение
            if len(cve_sets) >= 2:
                for i in range(len(cve_sets)):
                    for j in range(i+1, len(cve_sets)):
                        if cve_sets[i] & cve_sets[j]:
                            return True, "shared_cve"
            # Разные типы источников — уже показатель связи
            source_types = set()
            for f in findings_list:
                src = f.get("source","")
                if src in ("github", "multi_watcher"): source_types.add("code")
                elif src in ("scan_exposure", "shodan_tools"): source_types.add("scan")
                elif src in ("phishing", "threatfox", "urlhaus"): source_types.add("threat")
                elif src in ("cisa_kev", "nvd"): source_types.add("vuln_db")
            if len(source_types) >= 2:
                return True, "multi_source_" + "_".join(sorted(source_types))
            # Только один источник — speculative
            return False, "single_source_speculative"

        # Фильтруем: нужна реальная связь
        if len(matched) < 2:
            continue

        related, relation_type = has_shared_indicator(matched)
        if not related:
            # Один тип источника без общих CVE = speculative, пропускаем CRITICAL/HIGH
            # Разрешаем только MEDIUM и ниже
            chain_score_cap = 44
        else:
            chain_score_cap = 100

        if not matched:
            continue

        cves = []
        for f in matched:
            cves += re.findall(r"CVE-\d{4}-\d{4,7}", f.get("summary",""), re.IGNORECASE)
        cves = list(set(cves))

        years = []
        for cve in cves:
            try:
                years.append(int(cve.split("-")[1]))
            except:
                pass
        max_year = max(years) if years else None

        # ai_redteam не считается независимым источником — это комментарий к данным
        INDEPENDENT_SOURCES = {"github", "multi_watcher", "phishing", "scan_exposure",
                               "shodan_tools", "cisa_kev"}
        sources_used = list(set(
            f.get("source","") for f in matched
            if f.get("source","") in INDEPENDENT_SOURCES
        ))
        if not sources_used:
            sources_used = list(set(f.get("source","") for f in matched))
        has_kev = any("kev" in f.get("source","").lower() for f in matched)

        score = score_chain(
            finding_count=len(matched),
            sources_count=len(sources_used),
            has_cve=bool(cves),
            has_kev=has_kev,
            year=max_year
        )

        # Применяем cap если нет реальной связи
        score = min(score, chain_score_cap)

        if score >= 75:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        chain = {
            "id": chain_id,
            "name": template["name"],
            "score": score,
            "severity": severity,
            "speculative": not related,
            "relation_type": relation_type,
            "steps": template["steps"],
            "evidence": {
                "finding_count": len(matched),
                "sources": sources_used,
                "cves": cves[:5],
                "key_findings": [f.get("summary","")[:100] for f in matched[:3]],
            },
            "timestamp": datetime.now().isoformat(),
        }
        chains.append(chain)

    return sorted(chains, key=lambda x: -x["score"])

def run():
    print("[*] Attack Chain Builder v1.0")
    findings = fetch_all()
    if not findings:
        print("[-] No findings")
        return

    chains = build_chains(findings)
    if not chains:
        print("[*] No chains built")
        return

    print(f"\n[+] Built {len(chains)} attack chains:\n")
    for c in chains:
        icon = "🔴" if c["severity"]=="CRITICAL" else "🟠" if c["severity"]=="HIGH" else "🟡"
        print(f"{icon} [{c['severity']}({c['score']})] {c['name']}")
        print(f"   Steps: {' → '.join(c['steps'])}")
        ev = c["evidence"]
        print(f"   Evidence: {ev['finding_count']} findings, sources: {ev['sources']}")
        if ev["cves"]:
            print(f"   CVEs: {', '.join(ev['cves'][:3])}")
        if ev["key_findings"]:
            print(f"   Key: {ev['key_findings'][0]}")
        print()

    fname = f"{CHAINS_DIR}/chains_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    json.dump(chains, open(fname,"w"), indent=2, ensure_ascii=False)
    print(f"[*] Saved: {fname}")

if __name__ == "__main__":
    import time, sys
    if "--loop" in sys.argv:
        print("[*] Attack chains loop — каждые 30 мин")
        while True:
            run()
            time.sleep(1800)
    else:
        run()
