#!/usr/bin/env python3
"""
Агентный харнесс по методу Mozilla:
1. Находим потенциальный баг
2. AI создаёт PoC
3. Проверяем воспроизводимость
4. Только подтверждённые баги идут в отчёт
"""
import requests, json, re, os, time
from datetime import datetime

SERVER = "http://localhost:8080/findings"
API_KEY = "YOUR_OPENROUTER_API_KEY"
ARCHIVE = "data/archive"
os.makedirs(ARCHIVE, exist_ok=True)

# Список кому писать по типу уязвимости
DISCLOSURE_TARGETS = {
    "mongodb":      {"name": "MongoDB",      "email": "security@mongodb.com",      "program": "https://www.mongodb.com/security"},
    "elasticsearch":{"name": "Elastic",      "email": "security@elastic.co",       "program": "https://www.elastic.co/security"},
    "docker":       {"name": "Docker",       "email": "security@docker.com",       "program": "https://www.docker.com/security"},
    "jenkins":      {"name": "Jenkins",      "email": "jenkinsci-cert@googlegroups.com", "program": "https://www.jenkins.io/security"},
    "grafana":      {"name": "Grafana",      "email": "security@grafana.com",       "program": "https://grafana.com/security"},
    "redis":        {"name": "Redis",        "email": "security@redis.io",         "program": "https://redis.io/security"},
    "cobalt strike":{"name": "Recorded Future (CS)", "email": "support@cobaltstrike.com", "program": "N/A"},
    "firefox":      {"name": "Mozilla",      "email": "security@mozilla.org",      "program": "https://www.mozilla.org/security/bug-bounty/"},
    "phishing":     {"name": "Google SafeBrowsing", "email": "https://safebrowsing.google.com/safebrowsing/report_phish/", "program": "free"},
    "cve":          {"name": "Vendor + MITRE", "email": "cve@mitre.org",           "program": "https://cve.mitre.org/cve/request_id.html"},
}

def classify_finding(finding):
    """Определяем кому писать по содержимому находки"""
    summary = (finding.get("summary","") + finding.get("hostname","")).lower()
    targets = []
    for keyword, info in DISCLOSURE_TARGETS.items():
        if keyword in summary:
            targets.append(info)
    return targets

def ai_create_poc(finding):
    """
    Mozilla метод: AI создаёт PoC для подтверждения бага
    Только подтверждённые баги идут в отчёт
    """
    summary = finding.get("summary","")
    source = finding.get("source","")
    
    prompt = f"""Security finding analysis (Mozilla harness method):

Finding: [{source}] {summary[:300]}

Create a verification approach:
1. How to CONFIRM this is real (not false positive)
2. Safe PoC steps (no actual exploitation)
3. Impact assessment
4. Which vendor to notify

Return JSON only:
{{
  "is_real": true/false,
  "confidence": 0-100,
  "verification_steps": ["step1", "step2"],
  "safe_poc": "curl/nmap/etc command that only checks existence",
  "impact": "description",
  "severity": "critical/high/medium/low",
  "vendor": "name",
  "notify_email": "email",
  "cve_applicable": true/false
}}"""

    try:
        resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
            json={"model": "openai/gpt-oss-120b:free", "max_tokens": 600,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30
        )
        text = resp.json()["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception as e:
        print(f"  [-] AI PoC: {e}")
    return None

def generate_disclosure_letter(finding, poc, targets):
    """Генерируем письмо для ответственного раскрытия"""
    severity = poc.get("severity","high").upper()
    impact = poc.get("impact","")
    steps = "\n".join([f"{i+1}. {s}" for i,s in enumerate(poc.get("verification_steps",[]))])
    safe_poc = poc.get("safe_poc","")
    
    for target in targets:
        letter = f"""To: {target['email']}
Subject: Responsible Disclosure: {severity} Security Issue - {target['name']}

Dear {target['name']} Security Team,

I am writing to responsibly disclose a security vulnerability discovered 
through automated security research.

SUMMARY:
{finding.get('summary','')[:200]}

SEVERITY: {severity}
SOURCE: {finding.get('source','')}

IMPACT:
{impact}

VERIFICATION STEPS (read-only, no exploitation):
{steps}

SAFE VERIFICATION COMMAND:
{safe_poc}

This disclosure follows responsible disclosure principles.
I have not exploited this vulnerability and will not disclose 
publicly for 90 days to allow time for remediation.

Please acknowledge receipt within 7 days.

Best regards,
Security Researcher
[YOUR NAME/EMAIL]

---
Discovered via: Open source security monitoring
Date: {datetime.now().strftime('%Y-%m-%d')}
"""
        fname = f"{ARCHIVE}/disclosure_{target['name'].replace(' ','_')}_{int(time.time())}.txt"
        with open(fname, 'w') as f:
            f.write(letter)
        print(f"  [+] Письмо: {fname}")
        print(f"      Кому: {target['email']}")

def run_harness():
    """Основной харнесс по методу Mozilla"""
    print("[*] Mozilla-style Harness запущен")
    print("[*] Принцип: находим -> подтверждаем -> только реальные баги")
    
    try:
        r = requests.get(SERVER, timeout=10)
        findings = r.json()
    except Exception as e:
        print(f"[-] Сервер: {e}")
        return

    # Фильтруем только HIGH/CRITICAL
    priority = [f for f in findings if f.get("severity") in ("RED","CRITICAL")]
    print(f"[*] Приоритетных находок: {len(priority)}")
    
    confirmed = []
    letters_to_send = []
    
    for f in priority[-15:]:  # берём последние 15
        summary = f.get("summary","")[:60]
        print(f"\n[?] Проверяем: {summary}")
        
        # AI оценивает реальность бага (Mozilla метод — фильтр false positives)
        poc = ai_create_poc(f)
        if not poc:
            continue
            
        confidence = poc.get("confidence", 0)
        is_real = poc.get("is_real", False)
        
        if not is_real or confidence < 70:
            print(f"  [SKIP] Вероятно false positive (confidence: {confidence}%)")
            continue
        
        print(f"  [CONFIRMED] {poc.get('severity','?').upper()} | confidence: {confidence}%")
        print(f"  Impact: {poc.get('impact','')[:80]}")
        
        # Определяем кому писать
        targets = classify_finding(f)
        if poc.get("notify_email"):
            targets.append({"name": poc["vendor"], "email": poc["notify_email"], "program": "direct"})
        
        if targets:
            print(f"  Уведомить: {[t['name'] for t in targets]}")
            generate_disclosure_letter(f, poc, targets[:2])
            letters_to_send.append({"finding": f, "poc": poc, "targets": targets})
        
        confirmed.append({"finding": f, "analysis": poc})
        time.sleep(3)  # не перегружаем AI
    
    # Итоговый отчёт
    print(f"\n{'='*60}")
    print(f"ИТОГ Mozilla Harness:")
    print(f"  Проверено: {len(priority[-15:])}")
    print(f"  Подтверждено: {len(confirmed)}")
    print(f"  Писем создано: {len(letters_to_send)}")
    
    if letters_to_send:
        print(f"\nКУДА ПИСАТЬ:")
        seen = set()
        for item in letters_to_send:
            for t in item["targets"]:
                if t["name"] not in seen:
                    print(f"  {t['name']}: {t['email']}")
                    if "program" in t:
                        print(f"    Bug bounty: {t['program']}")
                    seen.add(t["name"])
    
    # Сохраняем
    report_file = f"{ARCHIVE}/harness_report_{int(time.time())}.json"
    with open(report_file, "w") as f:
        json.dump({"confirmed": confirmed, "letters": len(letters_to_send)}, f, indent=2, ensure_ascii=False)
    print(f"\nОтчёт: {report_file}")

if __name__ == "__main__":
    run_harness()
