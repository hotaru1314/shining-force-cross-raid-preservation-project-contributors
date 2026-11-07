"""run_server.py -- one entry point for the whole fake cabinet.

    python run_server.py            start every enabled service (Ctrl+C stops all)
    python run_server.py --status   show config / flags / ports / peers and exit
    python run_server.py --stop     stop a running instance via its pid file
    python run_server.py --check    validate config and exit (no sockets opened)

The four protocol scripts are untouched: this supervisor pushes config into
their data dir (flags, resp file IPs) and runs them as children with the right
arguments.  That keeps the wire behaviour we already verified while removing
the "five places to edit an IP" problem.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import config as core_config
from core import log as core_log
from core import session as core_session

BASE = core_config.BASE
PIDFILE = os.path.join(BASE, "logs", "server.pid.json")
STOP = threading.Event()
SHUTTING = threading.Event()
CHILDREN = {}


# ------------------------------------------------------------------ utils

def port_open(port, host="127.0.0.1", timeout=0.35):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def udp_bound(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", port))
        return False          # bind succeeded -> nothing else is listening
    except OSError:
        return True
    finally:
        s.close()


def svc_args(cfg, name):
    svc = cfg["services"][name]
    args = [sys.executable, "-u", os.path.join(BASE, svc["script"])]
    args += [str(a) for a in svc.get("args", [])]
    return args


# -------------------------------------------------------------- lifecycle

def prepare(cfg):
    core_config.ensure_dirs(cfg)
    for filename, state in core_config.sync_flags(cfg):
        core_log.line(cfg, "config", f"flag {filename} -> {state}")
    patched = core_config.patch_resp_file(cfg)
    if patched:
        path, before, after = patched
        if before != after:
            core_log.line(cfg, "config", f"resp ip {before} -> {after}")
    return cfg


def spawn(cfg):
    for name, svc in cfg["services"].items():
        if not svc.get("enabled", True):
            core_log.line(cfg, "config", f"{name}: disabled")
            continue
        spawn_one(cfg, name)
    return CHILDREN


def spawn_one(cfg, name):
    args = svc_args(cfg, name)
    core_log.line(cfg, name, "spawn " + " ".join(args[1:]))
    env = dict(os.environ)
    if cfg.get("fake_time"):
        env["SRV_FAKE_TIME"] = str(cfg["fake_time"])
    env["PYTHONIOENCODING"] = "utf-8:replace"
    env["PYTHONUTF8"] = "1"
    proc = subprocess.Popen(
        args,
        cwd=BASE,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        encoding="utf-8",
        errors="replace",
    )
    CHILDREN[name] = proc
    threading.Thread(target=pump, args=(cfg, name, proc), daemon=True).start()
    save_pids(cfg, CHILDREN)
    return proc


def pump(cfg, name, proc):
    for line in proc.stdout:
        core_log.line(cfg, name, line.rstrip())
    code = proc.wait()
    if SHUTTING.is_set():
        core_log.line(cfg, name, f"exited with {code}")
        return
    core_log.line(cfg, name, f"exited with {code} -- restarting in 1s")
    time.sleep(1.0)
    if not SHUTTING.is_set():
        try:
            spawn_one(cfg, name)
        except OSError as exc:
            core_log.line(cfg, name, f"restart failed: {exc}")


def save_pids(cfg, children):
    data = {name: p.pid for name, p in children.items()}
    with open(PIDFILE, "w", encoding="utf-8") as f:
        json.dump({"pids": data, "started": core_log.stamp()}, f, indent=1)


def stop_children(children):
    for name, proc in children.items():
        if proc.poll() is None:
            proc.terminate()
    for name, proc in children.items():
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ------------------------------------------------------------------ modes

def do_status(cfg):
    print(f"config      : {cfg['path']}")
    print(f"server_ip   : {cfg['server_ip']}   bind: {cfg['bind']}")
    print()
    print("services")
    for name, svc in cfg["services"].items():
        ports = core_config.ports_of(cfg, name)
        mark = "on " if svc.get("enabled", True) else "off"
        states = []
        for p in ports:
            up = udp_bound(p) if name == "udp" else port_open(p)
            states.append(f"{p}:{'UP' if up else '--'}")
        print(f"  {name:6} [{mark}] {svc.get('script',''):20} {' '.join(states)}")
    print()
    print("flags")
    for key, filename in core_config.FLAG_FILES.items():
        path = os.path.join(cfg["data"], filename)
        print(f"  {filename:24} {'SET' if os.path.exists(path) else '-'}")
    status_file = os.path.join(cfg["data"], "set_start_status.on")
    value = open(status_file, encoding="ascii").read().strip() if os.path.exists(status_file) else "-"
    print(f"  {'set_start_status.on':24} {value}")
    print()
    print("PowerOn response (data/allnet_resp.txt)")
    for key, value in core_config.resp_flags(cfg).items():
        print(f"  {key:12} {value}")
    print()
    peers = core_session.list_alive(cfg)
    print(f"peers       : {len(peers)}")
    for entry in peers:
        print(f"  {entry['peer']:16} {','.join(entry.get('services', [])):24} {entry.get('last_seen')}")
    if os.path.exists(PIDFILE):
        print()
        print("running     :", open(PIDFILE, encoding="utf-8").read().replace("\n", " "))
    return 0


def do_stop(cfg):
    if not os.path.exists(PIDFILE):
        print("no pid file:", PIDFILE)
        return 1
    data = json.load(open(PIDFILE, encoding="utf-8"))
    for name, pid in data.get("pids", {}).items():
        try:
            os.kill(pid, 15)
            print(f"stopped {name} pid={pid}")
        except OSError as exc:
            print(f"{name} pid={pid}: {exc}")
    os.remove(PIDFILE)
    return 0


def do_check(cfg):
    problems = []
    for name, svc in cfg["services"].items():
        script = os.path.join(BASE, svc.get("script", ""))
        if svc.get("enabled", True) and not os.path.exists(script):
            problems.append(f"{name}: missing {script}")
    for port in core_config.all_ports(cfg):
        if port < 1024 and os.name == "nt":
            pass  # cannot test privileges cheaply; warned below
    if cfg["server_ip"] in ("0.0.0.0", "", None):
        problems.append("server_ip is 0.0.0.0 -- clients cannot reach that")
    print("config OK" if not problems else "config problems:")
    for p in problems:
        print("  -", p)
    low = [p for p in core_config.all_ports(cfg) if p < 1024]
    if low:
        print(f"note: ports {low} need an elevated shell on Windows")
    return 0 if not problems else 2


def do_run(cfg):
    prepare(cfg)
    print(f"config {cfg['path']}")
    print(f"server_ip={cfg['server_ip']} bind={cfg['bind']}")
    children = spawn(cfg)
    save_pids(cfg, children)
    print(f"started {len(children)} services; logs -> {os.path.join(cfg['log_dir'], 'server.log')}")
    print("Ctrl+C to stop.")
    try:
        while not STOP.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        SHUTTING.set()
        core_log.line(cfg, "config", "shutting down")
        stop_children(CHILDREN)
        if os.path.exists(PIDFILE):
            os.remove(PIDFILE)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    cfg = core_config.load(args.config)
    if args.status:
        return do_status(cfg)
    if args.stop:
        return do_stop(cfg)
    if args.check:
        return do_check(cfg)
    return do_run(cfg)


if __name__ == "__main__":
    sys.exit(main())
