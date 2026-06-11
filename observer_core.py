import json, os, requests
from datetime import datetime, timezone

# Базовая директория для state-файлов
STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "state")
os.makedirs(STATE_DIR, exist_ok=True)

OBSERVER_FEED = "http://localhost:8080/observer_feed"

def post_finding(endpoint=None, finding=None):
    """Отправляет находку на сервер (поддержка 1 или 2 аргументов)"""
    if finding is None and isinstance(endpoint, dict):
        finding = endpoint
        endpoint = OBSERVER_FEED
    elif endpoint is None:
        return False

    # Прогоняем через scoring_engine если нет score
    if isinstance(finding, dict) and "score" not in finding:
        try:
            import sys as _sys
            _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from ai.scoring_engine import score_finding
            result = score_finding(finding)
            finding["score"] = result["score"]
            finding["severity"] = result["severity"]
            if "factors" not in finding:
                finding["factors"] = result["factors"]
            # Светофор
            s = result["score"]
            if s >= 75:
                finding["_light"] = "CRITICAL"
            elif s >= 50:
                finding["_light"] = "HIGH"
            elif s >= 25:
                finding["_light"] = "MEDIUM"
            elif s >= 10:
                finding["_light"] = "LOW"
            else:
                finding["_light"] = "INFO"
        except Exception as _e:
            pass

    url = endpoint if endpoint else OBSERVER_FEED
    try:
        resp = requests.post(url, json=finding, timeout=5)
        return resp.status_code == 200
    except Exception as e:
        print(f"[-] post_finding error: {e}")
        return False

def load_state(name):
    """Загружает состояние. name может быть 'multi_watcher' или 'multi_watcher.json'"""
    # Убираем .json если есть, добавляем один раз
    base_name = name.replace(".json", "")
    path = os.path.join(STATE_DIR, f"{base_name}.json")
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_state(name, data):
    """Сохраняет состояние. name может быть 'multi_watcher' или 'multi_watcher.json'"""
    base_name = name.replace(".json", "")
    path = os.path.join(STATE_DIR, f"{base_name}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"[-] save_state error: {e}")
        return False
