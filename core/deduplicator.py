seen = set()

def is_new(item_id):
    if item_id in seen:
        return False
    seen.add(item_id)
    return True
