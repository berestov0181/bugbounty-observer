#!/usr/bin/env python3
import requests, json, os, sys
from datetime import datetime

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")
SERVER = "http://localhost:8080"

def get_findings(limit=20, source=None):
    try:
        r = requests.get(f"{SERVER}/findings", timeout=10)
        findings = r.json()
        if source:
            findings = [f for f in findings if f.get("source","") == source]
        return findings[-limit:]
    except Exception as e:
        return {"error": str(e)}

def get_forecast():
    try:
        import glob
        files = sorted(glob.glob("data/forecasts/forecast_*.json"))
        if files:
            return json.load(open(files[-1]))[:10]
        return {"error": "No forecasts yet"}
    except Exception as e:
        return {"error": str(e)}

def get_attack_chains():
    try:
        import glob
        files = sorted(glob.glob("data/attack_chains/*.json"))
        if files:
            return json.load(open(files[-1]))[:5]
        return {"error": "No chains yet"}
    except Exception as e:
        return {"error": str(e)}

def get_review_queue():
    try:
        path = "data/review_queue.json"
        if os.path.exists(path):
            return json.load(open(path))[-10:]
        return []
    except Exception as e:
        return {"error": str(e)}

def get_stats():
    try:
        r = requests.get(f"{SERVER}/findings", timeout=10)
        findings = r.json()
        from collections import Counter
        by_source = Counter(f.get("source","?") for f in findings)
        by_severity = Counter(f.get("severity","?") for f in findings)
        return {
            "total_findings": len(findings),
            "by_source": dict(by_source.most_common(10)),
            "by_severity": dict(by_severity),
        }
    except Exception as e:
        return {"error": str(e)}

def get_snapshot_diff():
    try:
        path = "data/snapshots/latest_diff.json"
        if os.path.exists(path):
            return json.load(open(path))
        return {"error": "No diff yet"}
    except Exception as e:
        return {"error": str(e)}

TOOLS = [
    {"name": "get_findings", "description": "Получить последние security findings. Фильтр по source: github/nvd/phishing/scan_exposure/cisa_kev/company_scanner", "input_schema": {"type": "object", "properties": {"limit": {"type": "integer"}, "source": {"type": "string"}}}},
    {"name": "get_forecast", "description": "Прогноз волн атак — какие CVE будут эксплуатироваться в ближайшие дни.", "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_attack_chains", "description": "Attack chains — цепочки атак из связанных находок.", "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_review_queue", "description": "CRITICAL находки ожидающие ручной проверки.", "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_stats", "description": "Статистика: количество находок по источникам и severity.", "input_schema": {"type": "object", "properties": {}}},
]

TOOL_MAP = {"get_findings": get_findings, "get_forecast": get_forecast, "get_attack_chains": get_attack_chains, "get_review_queue": get_review_queue, "get_stats": get_stats}

def run_agent(user_query):
    print(f"\n🤖 Agent: {user_query}")
    print("="*60)
    system = "You are a cybersecurity AI agent. Use tools to get live data. Respond in Russian. Be concise and actionable."
    messages = [{"role": "user", "content": user_query}]

    # Собираем все данные сразу
    print("  🔧 get_stats()")
    stats = get_stats()
    print("  🔧 get_findings(limit=15)")
    findings = get_findings(limit=15)
    print("  🔧 get_forecast()")
    forecast = get_forecast()
    print("  🔧 get_attack_chains()")
    chains = get_attack_chains()
    print("  🔧 get_review_queue()")
    queue = get_review_queue()
    print("  🔧 get_snapshot_diff()")
    snapshot = get_snapshot_diff()

    # Формируем контекст для LLM
    context = f"""
SECURITY SYSTEM DATA:

STATS: {json.dumps(stats, ensure_ascii=False)}

RECENT FINDINGS (last 15):
{json.dumps(findings, ensure_ascii=False)[:2000]}

FORECAST (attack wave predictions):
{json.dumps(forecast, ensure_ascii=False)[:1000]}

ATTACK CHAINS:
{json.dumps(chains, ensure_ascii=False)[:800]}

REVIEW QUEUE (critical):
{json.dumps(queue, ensure_ascii=False)[:500]}

24H CHANGES:
{json.dumps(snapshot, ensure_ascii=False)[:600]}

USER QUESTION: {user_query}

You are a senior threat intelligence analyst, not a CVE list reader.
Answer in Russian. Structure your answer as:
1. WHAT happened (brief facts)
2. WHY it matters (risk context, exposure, exploit availability)
3. WHAT LIKELY happens next (forecast-based prediction with timeframe)
4. RECOMMENDED ACTION (specific, prioritized)

Bad style: "13 new CVEs detected."
Good style: "13 new CVEs detected. 2 are likely to be weaponized within days due to public PoC plus exposure spike pattern."

Be concise but insightful. Always end with a forward-looking statement, not just a list.
"""

    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"},
        json={"model": "nvidia/nemotron-3-super-120b-a12b:free", "max_tokens": 800,
              "messages": [{"role": "user", "content": context}]},
        timeout=60
    )
    data = resp.json()
    answer = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    if answer and answer.strip():
        print("\n🤖 Ответ агента:")
        print(answer.strip())
    else:
        print("\n📊 Прямые данные:")
        print(f"Всего находок: {stats.get('total_findings', 0)}")
        print(f"По источникам: {stats.get('by_source', {})}")
        if forecast and not isinstance(forecast, dict):
            print(f"Топ прогноз: {forecast[0].get('cve')} — {forecast[0].get('level')} score={forecast[0].get('forecast_score')}")

def interactive():
    print("\n🤖 BugBounty Observer Agent v1.0")
    print("Примеры: 'Какие критичные угрозы?' / 'Прогноз атак' / 'Статистика'")
    print("exit — выход\n")
    while True:
        try:
            query = input("You: ").strip()
            if query.lower() in ("exit","quit","q"): break
            if not query: continue
            run_agent(query)
            print()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_agent(" ".join(sys.argv[1:]))
    else:
        interactive()
