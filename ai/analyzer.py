import json, requests, time, os

OBSERVER_URL = "http://localhost:8080/findings"
OPENROUTER_API_KEY = "YOUR_OPENROUTER_API_KEY"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "openai/gpt-oss-120b:free"

SYSTEM_PROMPT = """Ты эксперт по Bug Bounty (статья Selectel "Что такое багбаунти").
Анализируй находку максимально практично:
- Exposed admin panels, Ceph, Jenkins, Grafana и т.п. — почти всегда CRITICAL/HIGH.
- Pre-auth RCE, IDOR, Broken Access Control, SSRF — высокий bounty potential.
- Новые staging/dev поддомены — проверяй на наличие админок, утечек данных, слабую авторизацию (часто MEDIUM или HIGH).
Отвечай ТОЛЬКО валидным JSON:

{
  "verdict": "CRITICAL|HIGH|MEDIUM|LOW|NOISE",
  "real_threat": true/false,
  "bounty_potential": "HIGH|MEDIUM|LOW|NONE",
  "confidence": 0-100,
  "analysis": "1-2 предложения на русском с указанием типа уязвимости (Broken Access Control, RCE и т.д.)",
  "next_steps": ["конкретный шаг 1", "конкретный шаг 2"],
  "report_template": "Краткий шаблон отчёта"
}
"""

def get_findings():
    try:
        r = requests.get(OBSERVER_URL, timeout=10)
        return r.json() or []
    except Exception as e:
        print(f"[-] Ошибка: {e}")
        return []

def analyze_with_openrouter(finding):
    msg = f"Источник: {finding.get('source')}\nХост: {finding.get('ip') or finding.get('hostname', '?')}\nОписание: {finding.get('summary')}\nSeverity: {finding.get('severity')}"

    try:
        r = requests.post(OPENROUTER_URL, 
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "http://localhost",
                "Content-Type": "application/json"
            },
            json={
                "model": OPENROUTER_MODEL,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": msg}],
                "max_tokens": 600,
                "temperature": 0.1
            }, timeout=40)
        data = r.json()
        text = data["choices"][0]["message"]["content"]
        s, e = text.find("{"), text.rfind("}") + 1
        if s >= 0 and e > s:
            return json.loads(text[s:e])
    except Exception as e:
        print(f"[-] AI error: {e}")
    return None

def analyze_finding(finding):
    result = analyze_with_openrouter(finding)
    if not result:
        summary = finding.get("summary", "").lower()
        if any(x in summary for x in ["ceph", "admin panel", "no authentication", "rce", "pre-auth"]):
            result = {"verdict":"CRITICAL", "bounty_potential":"HIGH", "confidence":85, "analysis":"Критическая находка — открытый админский интерфейс или RCE", "next_steps":["Проверить доступ", "Сделать PoC"], "report_template":"..."}
        elif "staging" in summary or "dev." in summary:
            result = {"verdict":"MEDIUM", "bounty_potential":"MEDIUM", "confidence":65, "analysis":"Staging поддомен может содержать незащищённые функции или данные", "next_steps":["Исследовать поддомен", "Проверить авторизацию"], "report_template":"..."}
        else:
            result = {"verdict":"MEDIUM", "bounty_potential":"MEDIUM", "confidence":50, "analysis":"Rule-based оценка", "next_steps":["Проверить вручную"], "report_template":"..."}
    return result

def main():
    print("="*75)
    print("  🐛 BugBounty AI Analyzer v2.1 — оптимизировано под Selectel")
    print("="*75)
    findings = get_findings()
    if not findings:
        print("[-] Находок нет")
        return

    print(f"\n[*] Находок: {len(findings)}. Анализируем...\n")
    stats = {}
    for i, f in enumerate(findings):
        a = analyze_finding(f)
        v = a.get("verdict", "LOW")
        stats[v] = stats.get(v, 0) + 1
        em = {"CRITICAL":"🔴", "HIGH":"🟠", "MEDIUM":"🟡", "LOW":"🟢"}.get(v, "⚪")
        print(f"\n{em} [{v}] {f.get('source')} | {f.get('summary','?')[:75]}")
        print(f"   Анализ: {a.get('analysis','?')}")
        print(f"   Bounty: {a.get('bounty_potential','?')} | Уверенность: {a.get('confidence','?')}%")
        print(f"   Шаги: {' → '.join(a.get('next_steps', ['Проверить вручную'])[:2])}")
        time.sleep(1.2)

    print(f"\n{'='*75}")
    for v in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if v in stats:
            print(f"  {v}: {stats[v]}")
    print("="*75)



if __name__ == "__main__":
    import time as _time
    while True:
        try:
            main()
        except Exception as e:
            print(f"[-] Ошибка: {e}")
        print("[*] Следующий анализ через 10 минут...")
        _time.sleep(600)
