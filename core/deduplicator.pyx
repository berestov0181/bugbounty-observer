import os

DB_FILE = "logs/seen.txt"

# загружаем уже известные элементы
def load_seen():
    if not os.path.exists(DB_FILE):
        return set()

    with open(DB_FILE, "r") as f:
        return set(line.strip() for line in f)


seen = load_seen()


def is_new(item_id):
    if item_id in seen:
        return False

    seen.add(item_id)

    # сохраняем сразу (устойчивость к падению)
    with open(DB_FILE, "a") as f:
        f.write(item_id + "\n")

    return True



