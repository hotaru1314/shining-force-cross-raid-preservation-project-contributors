"""core.log -- one timeline for every service.

All four children write their stdout into a single file, each line prefixed
with the service name, so a client's round trip (ALL.Net -> RD2 -> SIF) can be
read top-to-bottom instead of correlating four separate logs.
"""
import datetime
import os
import threading

_lock = threading.Lock()


def stamp():
    now = datetime.datetime.now()
    return now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"


def line(cfg, tag, message):
    text = f"[{stamp()}] [{tag:6}] {message}"
    with _lock:
        path = os.path.join(cfg["log_dir"], "server.log")
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass
    return text


def tail(cfg, n=20):
    path = os.path.join(cfg["log_dir"], "server.log")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.readlines()[-n:]
