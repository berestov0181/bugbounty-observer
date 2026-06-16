#!/usr/bin/env python3
"""
Temporal Correlation Engine v1.0
Детектирует паттерн: PoC появился → через 24-48ч ThreatFox видит попытки
Это самый ценный сигнал для предсказания волны атак.
"""
import json, os, re, time
from datetime import datetime, timezone, timedelta
from collections import defaultdict

FINDINGS_HISTORY = "data/temporal_history.json"
SIGNALS_OUT = "data/temporal_signals.json"
os.makedirs("data", exist_ok=True)

def load_history():
    if os.path.exists(FINDINGS_HISTORY):
        try:
            return json.load(open(FINDINGS_HISTORY))
        except:
            pass
    return {}

def save_history(h):
    json.dump(h, open(FINDINGS_HISTORY, "w"), indent=2, ensure_ascii=False)

def extract_cves(text):
    return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))

def get_findings_from_server():
    try:
        import requests
        r = requests.get("http://localhost:8080/findings", timeout=10)
        return r.json()
    except:
        return []

def update_history(findings, history):
    """Обновляем историю — для каждого CVE фиксируем когда какой источник его увидел."""
    now = datetime.now(timezone.utc).isoformat()
    for f in findings:
        summary = f.get("summary", "")
        source = f.get("source", "")
        ts = f.get("timestamp", now)
        cves = extract_cves(summary)
        for cve in cves:
            cve = cve.upper()
            if cve not in history:
                history[cve] = {}
            if source not in history[cve]:
                history[cve][source] = ts
                print(f"  [NEW] {cve} seen in {source} at {ts[:16]}")
    return history

# Источники по типам
SOURCE_TYPES = {
    "poc":     ["github", "exploitdb", "multi_watcher"],
    "vuln_db": ["nvd", "cisa_kev", "osv_dev"],
    "threat":  ["threatfox", "phishing", "urlhaus", "hacker_tools"],
    "scan":    ["scan_exposure", "shodan_tools"],
    "company": ["company_scanner"],
}

def classify_source(source):
    for stype, sources in SOURCE_TYPES.items():
        if any(s in source for s in sources):
            return stype
    return "other"

def detect_temporal_signals(history):
    """Ищем паттерны: poc → threat за 48ч, poc → scan за 72ч и т.д."""
    signals = []
    now = datetime.now(timezone.utc)

    for cve, source_times in history.items():
        if len(source_times) < 2:
            continue

        # Группируем по типу источника
        by_type = defaultdict(list)
        for src, ts_str in source_times.items():
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                stype = classify_source(src)
                by_type[stype].append((ts, src))
            except:
                continue

        # Сортируем по времени
        for stype in by_type:
            by_type[stype].sort(key=lambda x: x[0])

        # Паттерн 1: PoC → Threat за 72 часа (ВЫСОКИЙ РИСК)
        if "poc" in by_type and "threat" in by_type:
            poc_time = by_type["poc"][0][0]
            threat_time = by_type["threat"][0][0]
            delta = threat_time - poc_time
            if timedelta(0) <= delta <= timedelta(hours=72):
                signals.append({
                    "cve": cve,
                    "pattern": "POC_TO_THREAT",
                    "signal_level": "CRITICAL",
                    "emoji": "🔴",
                    "delta_hours": round(delta.total_seconds() / 3600, 1),
                    "poc_source": by_type["poc"][0][1],
                    "threat_source": by_type["threat"][0][1],
                    "message": f"{cve}: PoC появился, через {round(delta.total_seconds()/3600,1)}ч ThreatFox видит попытки эксплуатации",
                    "expected_wave_days": "1-7",
                    "confidence": 0.90,
                })

        # Паттерн 2: PoC → Scan за 48 часа (СРЕДНИЙ РИСК)
        if "poc" in by_type and "scan" in by_type:
            poc_time = by_type["poc"][0][0]
            scan_time = by_type["scan"][0][0]
            delta = scan_time - poc_time
            if timedelta(0) <= delta <= timedelta(hours=48):
                signals.append({
                    "cve": cve,
                    "pattern": "POC_TO_SCAN",
                    "signal_level": "HIGH",
                    "emoji": "🟠",
                    "delta_hours": round(delta.total_seconds() / 3600, 1),
                    "poc_source": by_type["poc"][0][1],
                    "scan_source": by_type["scan"][0][1],
                    "message": f"{cve}: PoC → массовое сканирование за {round(delta.total_seconds()/3600,1)}ч",
                    "expected_wave_days": "3-14",
                    "confidence": 0.75,
                })

        # Паттерн 3: VulnDB → PoC за 24 часа (РАННИЙ СИГНАЛ)
        if "vuln_db" in by_type and "poc" in by_type:
            vuln_time = by_type["vuln_db"][0][0]
            poc_time = by_type["poc"][0][0]
            delta = poc_time - vuln_time
            if timedelta(0) <= delta <= timedelta(hours=24):
                signals.append({
                    "cve": cve,
                    "pattern": "VULN_TO_POC_FAST",
                    "signal_level": "HIGH",
                    "emoji": "🟠",
                    "delta_hours": round(delta.total_seconds() / 3600, 1),
                    "message": f"{cve}: CVE опубликована, PoC появился через {round(delta.total_seconds()/3600,1)}ч — очень быстро!",
                    "expected_wave_days": "7-14",
                    "confidence": 0.70,
                })

        # Паттерн 4: Multi-source за 24ч (любые 3+ источника)
        all_times = []
        for stype, items in by_type.items():
            all_times.extend(items)
        if len(all_times) >= 3:
            all_times.sort(key=lambda x: x[0])
            first, last = all_times[0][0], all_times[-1][0]
            delta = last - first
            if delta <= timedelta(hours=24):
                sources_list = [x[1] for x in all_times]
                signals.append({
                    "cve": cve,
                    "pattern": "MULTI_SOURCE_24H",
                    "signal_level": "HIGH",
                    "emoji": "🟠",
                    "delta_hours": round(delta.total_seconds() / 3600, 1),
                    "sources": sources_list,
                    "message": f"{cve}: {len(all_times)} источников за {round(delta.total_seconds()/3600,1)}ч — синхронная активность!",
                    "expected_wave_days": "5-14",
                    "confidence": 0.80,
                })

    signals.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["signal_level"], 3))
    return signals

def run():
    print("[*] Temporal Correlation Engine v1.0")
    print("[*] Детектирует: PoC→Threat, PoC→Scan, VulnDB→PoC, Multi-source")

    history = load_history()
    findings = get_findings_from_server()

    if not findings:
        print("[-] No findings from server")
    else:
        print(f"[*] Processing {len(findings)} findings...")
        history = update_history(findings, history)
        save_history(history)

    signals = detect_temporal_signals(history)

    if signals:
        print(f"\n{'='*60}")
        print(f"  TEMPORAL SIGNALS — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"{'='*60}")
        for s in signals[:10]:
            print(f"\n{s['emoji']} [{s['signal_level']}] {s['pattern']}")
            print(f"   {s['message']}")
            print(f"   Волна: через {s['expected_wave_days']} дней | Уверенность: {int(s['confidence']*100)}%")
        print(f"{'='*60}")
        json.dump(signals, open(SIGNALS_OUT, "w"), indent=2, ensure_ascii=False)
        print(f"[*] Сохранено: {SIGNALS_OUT}")
    else:
        print("[*] Нет временных паттернов (нужно больше данных из разных источников)")
        print(f"[*] CVE в истории: {len(history)}")

    return signals

def loop():
    print("[*] Temporal loop — каждые 30 мин")
    while True:
        try:
            run()
        except Exception as e:
            print(f"[-] Error: {e}")
        time.sleep(30 * 60)

if __name__ == "__main__":
    import sys
    if "--loop" in sys.argv:
        loop()
    else:
        run()
