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
