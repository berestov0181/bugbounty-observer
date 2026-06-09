import requests, json, re, os
from datetime import datetime, timezone
from collections import defaultdict

SERVER = "http://localhost:8080"
CORR_DIR = "data/correlations"
os.makedirs(CORR_DIR, exist_ok=True)

CONFIDENCE_THRESHOLD = 0.5   # минимальный confidence для корреляции
TEMPORAL_WINDOW_HOURS = 72   # находки старше 72ч не участвуют в цепочках

def fetch_all():
    try:
        r = requests.get(f"{SERVER}/findings", timeout=10)
        return r.json() if r.status_code == 200 else []
    except:
        return []

def parse_time(finding):
    """Извлекает timestamp из finding. Возвращает datetime или None."""
    ts = finding.get("created_at") or finding.get("timestamp") or finding.get("time")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except:
        return None

def is_recent(finding, hours=TEMPORAL_WINDOW_HOURS):
    """True если finding создан не позже чем hours назад."""
    t = parse_time(finding)
    if t is None:
        return True  # нет timestamp — не фильтруем
    now = datetime.now(timezone.utc)
    try:
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (now - t).total_seconds() < hours * 3600
    except:
        return True

def extract_cves(text):
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))

def extract_tech(text):
    text = text.lower()
    return [t for t in [
        "grafana","kibana","elasticsearch","mongodb","redis","jenkins",
        "docker","kubernetes","k8s","nginx","apache","wordpress",
        "hikvision","evince","laravel","chamilo","typebot","xwiki",
        "magento","gitlab","bitbucket","confluence","jira"
    ] if t in text]

def edge_confidence(f1, f2):
    """
    Вычисляет confidence связи между двумя findings.
    Возвращает (confidence: float, reasons: list[str])
    """
    s1 = f1.get("summary","").lower()
    s2 = f2.get("summary","").lower()
    src1 = f1.get("source","")
    src2 = f2.get("source","")
    confidence = 0.0
    reasons = []

    # Совпадение CVE ID — сильный сигнал
    cves1 = set(c.upper() for c in extract_cves(s1))
    cves2 = set(c.upper() for c in extract_cves(s2))
    shared_cves = cves1 & cves2
    if shared_cves:
        confidence += 0.5
        reasons.append(f"shared_cve:{','.join(shared_cves)}")

    # Совпадение технологии из разных источников
    techs1 = set(extract_tech(s1))
    techs2 = set(extract_tech(s2))
    shared_techs = techs1 & techs2
    if shared_techs and src1 != src2:
        confidence += 0.25
        reasons.append(f"tech_cross_source:{','.join(shared_techs)}")
    elif shared_techs and src1 == src2:
        confidence += 0.1  # слабый сигнал — один источник
        reasons.append(f"tech_same_source:{','.join(shared_techs)}")

    # Совпадение домена или IP в summary
    domains1 = set(re.findall(r'[\w.-]+\.\w{2,6}', s1))
    domains2 = set(re.findall(r'[\w.-]+\.\w{2,6}', s2))
    shared_domains = domains1 & domains2 - {"com","org","net","io","gov"}
    if shared_domains:
        confidence += 0.4
        reasons.append(f"shared_domain:{','.join(list(shared_domains)[:2])}")

    # Временная близость (оба свежие < 24ч) — небольшой буст
    t1 = parse_time(f1)
    t2 = parse_time(f2)
    if t1 and t2:
        try:
            if t1.tzinfo is None: t1 = t1.replace(tzinfo=timezone.utc)
            if t2.tzinfo is None: t2 = t2.replace(tzinfo=timezone.utc)
            delta_h = abs((t1 - t2).total_seconds()) / 3600
            if delta_h < 24:
                confidence += 0.1
                reasons.append("temporal_24h")
        except:
            pass

    # Источник github + scan_exposure с одинаковой tech — надёжно
    if src1 in ("github","multi_watcher") and src2 == "scan_exposure" and shared_techs:
        confidence += 0.15
        reasons.append("poc_plus_exposure")
    if src2 in ("github","multi_watcher") and src1 == "scan_exposure" and shared_techs:
        confidence += 0.15
        reasons.append("poc_plus_exposure")

    return min(confidence, 1.0), reasons

def build_evidence_graph(findings):
    """
    Строит граф: nodes = findings, edges = (confidence, reasons).
    Возвращает только рёбра с confidence >= CONFIDENCE_THRESHOLD.
    """
    edges = []
    n = len(findings)
    for i in range(n):
        for j in range(i+1, n):
            conf, reasons = edge_confidence(findings[i], findings[j])
            if conf >= CONFIDENCE_THRESHOLD:
                edges.append({
                    "a": i,
                    "b": j,
                    "confidence": round(conf, 2),
                    "reasons": reasons,
                })
    return edges

def cluster_by_confidence(findings, edges):
    """Простой union-find для группировки связанных findings."""
    parent = list(range(len(findings)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    for e in edges:
        union(e["a"], e["b"])

    clusters = defaultdict(list)
    for i in range(len(findings)):
        clusters[find(i)].append(i)

    return [v for v in clusters.values() if len(v) >= 2]

def describe_cluster(findings, cluster_indices, edges):
    """Формирует описание кластера с confidence и reasons."""
    cluster_findings = [findings[i] for i in cluster_indices]
    cluster_edges = [e for e in edges if e["a"] in cluster_indices and e["b"] in cluster_indices]

    avg_conf = round(sum(e["confidence"] for e in cluster_edges) / max(len(cluster_edges),1), 2)

    all_cves = []
    all_techs = []
    sources = set()
    for f in cluster_findings:
        s = f.get("summary","")
        all_cves += extract_cves(s)
        all_techs += extract_tech(s.lower())
        sources.add(f.get("source",""))

    all_reasons = []
    for e in cluster_edges:
        all_reasons += e["reasons"]
    reason_counts = {}
    for r in all_reasons:
        reason_counts[r] = reason_counts.get(r,0) + 1
    top_reasons = sorted(reason_counts, key=lambda x: -reason_counts[x])[:4]

    score = int(avg_conf * 100)
    if avg_conf >= 0.8:
        severity = "CRITICAL"
    elif avg_conf >= 0.6:
        severity = "HIGH"
    elif avg_conf >= 0.5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "cluster_size": len(cluster_findings),
        "avg_confidence": avg_conf,
        "score": score,
        "severity": severity,
        "sources": list(sources),
        "cves": list(set(c.upper() for c in all_cves))[:5],
        "technologies": list(set(all_techs))[:5],
        "top_reasons": top_reasons,
        "key_findings": [f.get("summary","")[:100] for f in cluster_findings[:3]],
        "edges": cluster_edges,
    }

def run():
    print("[*] Correlator v2.0 — evidence graph + confidence + temporal filter")
    all_findings = fetch_all()
    if not all_findings:
        print("[-] No findings")
        return

    # Temporal filter
    findings = [f for f in all_findings if is_recent(f)]
    filtered_out = len(all_findings) - len(findings)
    print(f"[*] Findings: {len(all_findings)} total, {len(findings)} recent (<{TEMPORAL_WINDOW_HOURS}h), {filtered_out} filtered")

    if len(findings) < 2:
        print("[*] Not enough recent findings")
        return

    edges = build_evidence_graph(findings)
    print(f"[*] Evidence edges (confidence>={CONFIDENCE_THRESHOLD}): {len(edges)}")

    if not edges:
        print("[*] No confident correlations found")
        print("    (speculative correlations suppressed — need shared CVE/domain/tech+source)")
        return

    clusters = cluster_by_confidence(findings, edges)
    print(f"[+] Correlated clusters: {len(clusters)}\n")

    results = []
    for cluster in sorted(clusters, key=lambda c: -len(c)):
        desc = describe_cluster(findings, cluster, edges)
        icon = "🔴" if desc["severity"]=="CRITICAL" else "🟠" if desc["severity"]=="HIGH" else "🟡"
        print(f"{icon} [{desc['severity']}] confidence={desc['avg_confidence']} cluster={desc['cluster_size']} findings")
        print(f"   Evidence: {', '.join(desc['top_reasons'][:3])}")
        if desc["cves"]:
            print(f"   CVEs: {', '.join(desc['cves'][:3])}")
        if desc["technologies"]:
            print(f"   Tech: {', '.join(desc['technologies'][:3])}")
        print(f"   Sources: {desc['sources']}")
        print(f"   Key: {desc['key_findings'][0][:90]}")
        print()
        results.append(desc)

    fname = f"{CORR_DIR}/corr_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    json.dump(results, open(fname,"w"), indent=2, ensure_ascii=False)
    print(f"[*] Saved: {fname}")

if __name__ == "__main__":
    import time, sys
    if "--loop" in sys.argv:
        print("[*] Correlator loop — каждые 60 мин")
        while True:
            run()
            time.sleep(3600)
    else:
        run()
