"""core.config -- the single source of truth for the fake arcade server.

Everything that used to be scattered across data\\*.on files and hard-coded IPs
now comes from config.json (plus optional CLI overrides).  The four protocol
scripts stay untouched; this module pushes the config *into* their data dir:

    sync_flags()        -> create/remove data\\*.on markers
    patch_resp_file()   -> rewrite uri=/host= inside data\\allnet_resp.txt
    port_of(name)       -> the port a service should listen on

Keeping the translation in one place is the whole point: when the topology
changes (local -> 10.0.0.7, etc.) only config.json is edited.
"""
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FLAG_FILES = {
    "echo_start_fixed": "echo_start_fixed.on",
    "fill_start_u32": "fill_start_u32.on",
    "fill_userinfo": "fill_userinfo.on",
    "rd2_plain": "rd2_plain.on",
    "rd2_manual": "rd2_manual.on",
    "echo_save": "echo_save.on",
    "end_status1": "end_status1.on",
    "echo_oldbug": "echo_oldbug.on",
}

DEFAULT_SERVICES = {
    "allnet": {"enabled": True, "script": "allnet_server.py", "port": 80, "args": []},
    "sif": {"enabled": True, "script": "match_server.py", "port": 52000, "args": []},
    "pcp": {"enabled": True, "script": "pcp_server.py", "ports": [], "args": []},
    "udp": {"enabled": True, "script": "udp_echo.py", "port": 52002, "args": []},
}


def load(path=None):
    path = path or os.path.join(BASE, "config.json")
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    cfg = {
        "path": path,
        "server_ip": raw.get("server_ip", "10.0.0.10"),
        "bind": raw.get("bind", "0.0.0.0"),
        "data_dir": raw.get("data_dir", "data"),
        "log_dir": raw.get("log_dir", "logs"),
        "flags": dict(raw.get("flags", {})),
        "sif": dict(raw.get("sif", {})),
        "poweron": dict(raw.get("poweron", {})),
        "fake_time": raw.get("fake_time"),
        "services": {},
    }
    for name, default in DEFAULT_SERVICES.items():
        svc = dict(default)
        svc.update(raw.get("services", {}).get(name, {}))
        cfg["services"][name] = svc
    # 2026-11-01: 配置里额外定义的服务（如 udp3953）也要加载，
    # 否则 supervisor 不认识、永远不会 spawn。
    for name, svc in raw.get("services", {}).items():
        if name not in cfg["services"] and isinstance(svc, dict):
            cfg["services"][name] = dict(svc)

    cfg["data"] = os.path.join(BASE, cfg["data_dir"])
    cfg["logs"] = os.path.join(BASE, cfg["log_dir"])
    cfg["data_dir"] = cfg["data"]
    cfg["log_dir"] = cfg["logs"]
    return cfg


def ensure_dirs(cfg):
    for d in (cfg["data"], cfg["logs"]):
        os.makedirs(d, exist_ok=True)


# ---------------------------------------------------------------- flags

def sync_flags(cfg):
    """Materialise the flag dict as data\\*.on markers.  Returns [(file, on)]."""
    changed = []
    for key, filename in FLAG_FILES.items():
        want = bool(cfg["flags"].get(key, False))
        path = os.path.join(cfg["data"], filename)
        have = os.path.exists(path)
        if want and not have:
            with open(path, "w", encoding="ascii") as f:
                f.write("1")
            changed.append((filename, True))
        elif not want and have:
            os.remove(path)
            changed.append((filename, False))

    # set_start_status.on carries a value, not just presence
    status = cfg["flags"].get("start_status", 0)
    path = os.path.join(cfg["data"], "set_start_status.on")
    if status:
        value = f"{int(status):#010x}"
        old = None
        if os.path.exists(path):
            try:
                old = open(path, encoding="ascii").read().strip()
            except OSError:
                old = None
        if old != value:
            with open(path, "w", encoding="ascii") as f:
                f.write(value)
            changed.append(("set_start_status.on", value))
    elif os.path.exists(path):
        os.remove(path)
        changed.append(("set_start_status.on", False))

    # s1_mode.txt for the :52000 responder
    mode = str(cfg["sif"].get("s1_mode", "empty")).strip() or "empty"
    path = os.path.join(cfg["data"], "s1_mode.txt")
    if not os.path.exists(path) or open(path, encoding="ascii").read().strip() != mode:
        with open(path, "w", encoding="ascii") as f:
            f.write(mode)
        changed.append(("s1_mode.txt", mode))

    return changed


# ------------------------------------------------------------ resp file

RESP_FILE = "allnet_resp.txt"


def upsert(text, key, value):
    """Set key=value in a flat a=b&c=d string, appending when absent."""
    pattern = rf"(?:^|&){re.escape(key)}=[^&]*"
    if re.search(pattern, text):
        return re.sub(pattern, f"&{key}={value}", text, count=1)
    sep = "" if text.endswith("&") or not text else "&"
    return f"{text}{sep}{key}={value}"


def patch_resp_file(cfg):
    """Point uri=/host= at server_ip and force the v2 constants.

    Returns (path, before, after) for the IP fields, or None when the file is
    missing.  The three constants come from config["poweron"] so the PowerOn
    response is defined in exactly one place.
    """
    path = os.path.join(cfg["data"], RESP_FILE)
    if not os.path.exists(path):
        return None
    text = open(path, encoding="utf-8-sig").read().strip()
    before = re.findall(r"(?:uri|host)=([^&]*)", text)

    ip = cfg["server_ip"]
    text = re.sub(r"uri=[^&]*", f"uri=http://{ip}/", text)
    text = re.sub(r"host=[^&]*", f"host={ip}", text)

    for key, value in cfg.get("poweron", {}).items():
        if value is None:
            continue
        text = upsert(text, key, value)

    after = re.findall(r"(?:uri|host)=([^&]*)", text)
    if open(path, encoding="utf-8-sig").read().strip() != text:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return path, before, after


def resp_flags(cfg):
    """What the response file currently says about setting/timezone/res_class."""
    path = os.path.join(cfg["data"], RESP_FILE)
    if not os.path.exists(path):
        return {}
    text = open(path, encoding="utf-8-sig").read()
    out = {}
    for key in ("stat", "uri", "host", "setting", "timezone", "res_class"):
        m = re.search(rf"(?:^|&){key}=([^&]*)", text)
        out[key] = m.group(1).strip() if m else None
    return out


# ---------------------------------------------------------------- ports

def ports_of(cfg, name):
    svc = cfg["services"].get(name, {})
    if svc.get("ports"):
        return list(svc["ports"])
    return [svc["port"]] if svc.get("port") else []


def all_ports(cfg):
    seen = []
    for name in cfg["services"]:
        for p in ports_of(cfg, name):
            if p not in seen:
                seen.append(p)
    return seen
