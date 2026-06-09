def log(msg, file="logs/system.log"):
    with open(file, "a") as f:
        f.write(msg + "\n")
