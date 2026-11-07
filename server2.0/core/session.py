"""core.session -- who is actually connected right now.

This is the piece we were missing during the two-machine test: every service
knew about *its own* sockets and nothing knew "how many cabinets are online".
Adapters (and, for now, the supervisor's port probe) register peers here; the
registry is a small JSON file so several processes can share it.

    touch(cfg, peer, service)   -> record/refresh a peer
    list_alive(cfg, ttl=90)     -> [{peer, services, last_seen}]
    expire(cfg, ttl=90)         -> drop stale entries
"""
import datetime
import json
import os
import threading

_lock = threading.Lock()
FILENAME = "sessions.json"


def _path(cfg):
    return os.path.join(cfg["log_dir"], FILENAME)


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _load(cfg):
    path = _path(cfg)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(cfg, data):
    path = _path(cfg)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def touch(cfg, peer, service="?", extra=None):
    with _lock:
        data = _load(cfg)
        entry = data.setdefault(peer, {"services": [], "first_seen": _now()})
        if service not in entry["services"]:
            entry["services"].append(service)
        entry["last_seen"] = _now()
        if extra:
            entry.update(extra)
        _save(cfg, data)
        return entry


def list_alive(cfg, ttl=90):
    cutoff = datetime.datetime.now() - datetime.timedelta(seconds=ttl)
    out = []
    with _lock:
        data = _load(cfg)
    for peer, entry in data.items():
        try:
            seen = datetime.datetime.fromisoformat(entry.get("last_seen", ""))
        except ValueError:
            continue
        if seen >= cutoff:
            out.append({"peer": peer, **entry})
    return sorted(out, key=lambda e: e.get("first_seen", ""))


def expire(cfg, ttl=90):
    cutoff = datetime.datetime.now() - datetime.timedelta(seconds=ttl)
    removed = []
    with _lock:
        data = _load(cfg)
        for peer in list(data):
            try:
                seen = datetime.datetime.fromisoformat(data[peer].get("last_seen", ""))
            except ValueError:
                seen = cutoff - datetime.timedelta(seconds=1)
            if seen < cutoff:
                removed.append(peer)
                del data[peer]
        if removed:
            _save(cfg, data)
    return removed
