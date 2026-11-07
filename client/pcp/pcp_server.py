"""PCP (libpcp) server -- minimal implementation + sniffer for RingEdge ports.

Protocol (https://sega.bsnk.me/ringedge/software/pcp/):

    server   -- ">" ------------------------->  consumer   # ready
    server   <-- "k1=v1&k2=v2\\r\\n" ----------  consumer   # request
    server   -- "k1=v1&k2=v2\\r\\n" ---------->  consumer   # response
    server   -- ">" ------------------------->  consumer   # next round

Binary transfer (server -> consumer):

    consumer -> keychip.billing.cacertification=?
    server   -> keychip.billing.cacertification=0&port=40107&size=817
    consumer -> connect :40107, read 817 bytes, close
    consumer -> single "$" byte on the control connection (ack)

Unknown command / bad packet -> single "?".
A payload (incl. CRLF) must not exceed 256 bytes, and 64 key/value pairs.

Usage:
    python pcp_server.py
    python pcp_server.py --ports 40100,40106,40102,40113
    python pcp_server.py --systemflag 00
    python pcp_server.py --pki-dir D:\\...\\minime\\pki
    python pcp_server.py --no-reply
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
BASE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_LOG = os.path.join(BASE, "data", "pcp.log")
DEFAULT_PORTS = [40100, 40106]
READY = b">"
ERROR = b"?"
MAX_PACKET = 256          # including CRLF
RECV_TIMEOUT = 30.0

_print_lock = threading.Lock()


def now() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


WSA_TEXT = {
    10014: "WSAEFAULT (bad address)",
    10022: "WSAEINVAL (invalid argument)",
    10024: "WSAEMFILE (too many open sockets)",
    10035: "WSAEWOULDBLOCK (would block)",
    10048: "WSAEADDRINUSE (address already in use)",
    10049: "WSAEADDRNOTAVAIL (address not available)",
    10053: "WSAECONNABORTED (software caused connection abort)",
    10054: "WSAECONNRESET (connection reset by peer)",
    10055: "WSAENOBUFS (no buffer space)",
    10056: "WSAEISCONN (already connected)",
    10057: "WSAENOTCONN (not connected)",
    10058: "WSAESHUTDOWN (cannot send after shutdown)",
    10060: "WSAETIMEDOUT (connection timed out)",
    10061: "WSAECONNREFUSED (connection refused)",
    10064: "WSAEHOSTDOWN (host down)",
    10065: "WSAEHOSTUNREACH (host unreachable)",
}


def err_text(exc: BaseException) -> str:
    """Readable, correctly-decoded text for an OS error.

    Windows returns its socket error strings in the ANSI code page (GBK here),
    so ``str(OSError)`` can contain bytes that turn into mojibake once written
    to a UTF-8 log.  Winsock codes are not POSIX errnos either, so map the common
    ones explicitly and only then fall back to os.strerror().
    """
    errno = getattr(exc, "errno", None)
    if errno in WSA_TEXT:
        return f"[{errno}] {WSA_TEXT[errno]}"
    if errno is not None:
        try:
            return f"[{errno}] {os.strerror(errno)}"
        except (ValueError, OverflowError):
            pass
    return repr(exc)


class Logger:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.lock = threading.Lock()
        open(path, "a", encoding="utf-8").close()   # append: keep previous runs

    def __call__(self, msg: str) -> None:
        line = f"[{now()}] {msg}"
        with self.lock:
            with _print_lock:
                try:
                    print(line, flush=True)
                except Exception:
                    pass
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


LOG: Logger

CFG = {
    "gameid": "SBVB",
    "platformid": "AAL",
    "modeltype": "01",
    "region": "01",
    "systemflag": "05",       # bit0=dev | bit2=ALL.Net (no billing)
    "formattype": "01",
    "networkaddr": "127.0.0.1",
    "dvdflag": "00",
    # billing fields: playcount/playlimit/nearfull are %08X strings
    # Keychip serial.  sub_E3FBD0 validates it strictly:
#   pos 4 = "-", pos 0-3 and 5-7 = digit or uppercase (no I/O), pos 8-15 = digit
#   => exactly 16 chars:  XXXX-YYYNNNNNNNN
# The old "A72E-0000000" (12 chars) failed the check, so the whole ALL.Net
# task never started and the game could never connect to anything.
"keyid": "A72E-00000000000",
    "mainid": "AALG-000000",
    "playcount": "00000000",
    "playlimit": "000186A0",
    "nearfull": "0000FFFF",
}

def hexdump(data: bytes, limit: int = 256) -> str:
    data = data[:limit]
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"    {i:04X}  {hx:<47}  {asc}")
    return "\n".join(out)


def parse_packet(raw: bytes) -> list[tuple[str, str]]:
    text = raw.decode("latin-1").strip("\r\n")
    if not text:
        return []
    pairs: list[tuple[str, str]] = []
    for part in text.split("&"):
        if not part:
            continue
        if "=" not in part:
            return []
        k, _, v = part.partition("=")
        k, v = k.strip(" \t"), v.strip(" \t")
        if not k:
            return []
        pairs.append((k, v))
    return pairs


def build_packet(pairs: list[tuple[str, str]]) -> bytes:
    return ("&".join(f"{k}={v}" for k, v in pairs) + "\r\n").encode("latin-1")


# ---------------------------------------------------------------- handlers

def _echo(cmd: str, args: dict[str, str]) -> list[tuple[str, str]]:
    return [(cmd, args.get(cmd, "?"))]


# 40100 = mxmaster
def h_mxm_getcount(cmd, args):
    return [(cmd, args.get(cmd, "?")), ("count", "0")]


def h_mxm_current(cmd, args):
    return [(cmd, "2")]


def h_mxm_next(cmd, args):
    v = args.get(cmd, "?")
    return [(cmd, "0" if v == "?" else v)]


def h_mxm_active(cmd, args):
    v = args.get(cmd, "?")
    return [(cmd, v if v in ("0", "1") else "1")]


def h_mxm_fault(cmd, args):
    return [(cmd, "0")]


def h_mxm_develop(cmd, args):
    return [(cmd, "0")]


HANDLERS_40100 = {
    "mxmaster.foreground.getcount": h_mxm_getcount,
    "mxmaster.foreground.current": h_mxm_current,
    "mxmaster.foreground.next": h_mxm_next,
    "mxmaster.foreground.active": h_mxm_active,
    "mxmaster.foreground.fault": h_mxm_fault,
    "mxmaster.develop": h_mxm_develop,
    "mxmaster.reconnect.usb.device": lambda c, a: [(c, "0")],
}


# 40106 = mxkeychip
def h_kc_version(cmd, args):
    return [(cmd, "0104")]


def h_kc_status(cmd, args):
    return [(cmd, "available")]


def _kcf(field: str):
    def h(cmd, args):
        return [(cmd, CFG[field])]
    return h


HANDLERS_40106 = {
    "keychip.version": h_kc_version,
    "keychip.status": h_kc_status,
    "keychip.appboot.gameid": _kcf("gameid"),
    "keychip.appboot.platformid": _kcf("platformid"),
    "keychip.appboot.modeltype": _kcf("modeltype"),
    "keychip.appboot.region": _kcf("region"),
    "keychip.appboot.systemflag": _kcf("systemflag"),
    "keychip.appboot.formattype": _kcf("formattype"),
    "keychip.appboot.networkaddr": _kcf("networkaddr"),
    "keychip.appboot.dvdflag": _kcf("dvdflag"),
    "keychip.billing.keyid": _kcf("keyid"),
    "keychip.billing.mainid": _kcf("mainid"),
    "keychip.billing.playcount": _kcf("playcount"),
    "keychip.billing.playlimit": _kcf("playlimit"),
    "keychip.billing.nearfull": _kcf("nearfull"),
}


# ---- binary fields (PCP port/size transfer) ----------------------------
#
#   consumer -> keychip.billing.cacertification=?
#   server   -> keychip.billing.cacertification=0&port=40107&size=817
#   consumer -> connects :40107, reads 817 bytes, closes
#   consumer -> sends a single "$" on the control connection
#
PKI_DIR = r"C:\SegaTools\minime\pki"
BINARY_FIELDS = {
    "keychip.billing.signaturepubkey": "billing.pub",
    "keychip.billing.cacertification": "ca.crt",
}

_binary_cache: dict[str, bytes] = {}
_binary_lock = threading.Lock()


def load_binary_field(cmd: str) -> bytes:
    with _binary_lock:
        if cmd in _binary_cache:
            return _binary_cache[cmd]
        path = os.path.join(PKI_DIR, BINARY_FIELDS[cmd])
        with open(path, "rb") as f:
            data = f.read()
        _binary_cache[cmd] = data
        LOG(f"loaded {path} ({len(data)}B) for {cmd}")
        return data


def serve_binary_once(data: bytes, tag: str) -> int:
    """Open a one-shot data port, wait for the consumer, send data. Returns port.

    Real mxkeychip uses a fixed data port 40107; we prefer it and fall back to
    an ephemeral port if it is already in use.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = 40107
    try:
        srv.bind(("127.0.0.1", port))
    except OSError:
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
    srv.listen(1)

    def worker():
        srv.settimeout(30.0)
        try:
            conn, peer = srv.accept()
            conn.sendall(data)
            LOG(f"binary {tag}: sent {len(data)}B to {peer[0]}:{peer[1]} on port {port}")
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            conn.close()
        except Exception as exc:
            LOG(f"binary {tag} on port {port}: {exc!r}")
        finally:
            try:
                srv.close()
            except OSError:
                pass

    threading.Thread(target=worker, daemon=True).start()
    return port


def h_binary(cmd, args):
    data = load_binary_field(cmd)
    port = serve_binary_once(data, cmd)
    LOG(f"{cmd}: serving {len(data)}B on data port {port}")
    return [(cmd, "0"), ("port", str(port)), ("size", str(len(data)))]


for _cmd in BINARY_FIELDS:
    HANDLERS_40106[_cmd] = h_binary


# ---- DS28CN01 challenge/response (dev keychip) -------------------------
#
# In development mode amDongle does not use the real secret; it uses a fixed
# 7-byte challenge (2CFECBC71CF1E4) and a hard-coded 20-byte MAC per EEPROM
# page.  Those MACs live in the game exe at VA 0x164A988 (file 0x1249388),
# 20 bytes per page, 4 pages.
#
DS_DEV_CHALLENGE = "2CFECBC71CF1E4"
DS_DEV_MACS = bytes.fromhex(
    "CA6ED736401682DD4411A27D2440AC4B478BAD8B"
    "4AC606302CE5EF51ABB3DF2DC46C863B3C06AA2C"
    "2AAF35B2ABA4C6840BDB7BD40ECBCE2CCA934795"
    "2F6D713DABDE3C43DF818491AB9467BA8BA0FED4"
)


_ds_counter = 0
_DS_MODES = ["hex"]


def h_ds_compute(cmd, args):
    global _ds_counter
    try:
        page = int(args.get("page", "0"))
    except ValueError:
        page = 0
    page &= 3
    mac = DS_DEV_MACS[page * 20:(page + 1) * 20]
    challenge = args.get(cmd, "?")
    _ds_counter += 1
    value = mac.hex()
    LOG(f"ds.compute #{_ds_counter}: challenge={challenge} page={page} -> {value}")
    return [(cmd, value)]


# ---- SSD proof: challenge/response table shipped with the game ----------
#
# <gameid>_Table.dat layout (1,190,000 bytes), as recovered from the parsers
# sub_E433B0 (DS) and sub_E43590 (SSD) in the game:
#
#     0 .. 869999   DS region   10,000 records x 87 bytes
#                              = 7-byte challenge + 4 x 20-byte MAC
#     870000 ..     SSD region  10,000 records x 32 bytes
#                              = 16-byte challenge + 16-byte response
#
# Both parsers pick a random record and *unscramble* it with a fixed byte
# permutation before storing it as the expected value:
#
#     expected[i] = record_bytes[PERM[i]]
#
# so the keychip has to answer with the unscrambled form, NOT the file bytes.
# (Sending the raw 16 bytes + 4 extra bytes used to overflow the 16-byte reply
#  buffer and also clobber the expected value -> "Verify SSD NG!!!".)
#
DS_TABLE_FILE = (r"C:\Games\Shining Force - Cross Raid"
                 r"\Shining Force - Cross Raid\SBVB_Table.dat")
SSD_REGION = 870000
SSD_RECORD = 32
PERM16 = (6, 8, 4, 12, 7, 13, 1, 10, 2, 3, 11, 14, 15, 0, 5, 9)
_table_cache: bytes | None = None


def load_ds_table() -> bytes:
    global _table_cache
    if _table_cache is None:
        with open(DS_TABLE_FILE, "rb") as f:
            _table_cache = f.read()
        LOG(f"loaded {DS_TABLE_FILE} ({len(_table_cache)}B)")
    return _table_cache


def unscramble(buf: bytes, perm) -> bytes:
    """Inverse of the game's table scramble: expected[i] = buf[perm[i]]."""
    return bytes(buf[p] for p in perm)


def find_ssd_record(table: bytes, challenge: bytes) -> int:
    i = table.find(challenge, SSD_REGION)
    while i >= 0:
        if (i - SSD_REGION) % SSD_RECORD == 0:
            return i
        i = table.find(challenge, i + 1)
    return -1


def h_ssd_proof(cmd, args):
    challenge = args.get(cmd, "?")
    try:
        raw = bytes.fromhex(challenge)
    except ValueError:
        raw = b""
    if len(raw) != 16:
        LOG(f"ssd.proof: bad challenge {challenge!r} -> ?")
        return None
    table = load_ds_table()
    idx = find_ssd_record(table, raw)
    if idx < 0:
        LOG(f"ssd.proof: challenge {challenge} NOT FOUND in table -> ?")
        return None
    stored = table[idx + 16: idx + SSD_RECORD]
    resp = unscramble(stored, PERM16)
    LOG(f"ssd.proof: challenge={challenge} @0x{idx:X} (rec#{(idx - SSD_REGION)//SSD_RECORD}) "
        f"file={stored.hex()} -> {resp.hex()}")
    return [(cmd, resp.hex())]


HANDLERS_40106["keychip.ds.compute"] = h_ds_compute
HANDLERS_40106["keychip.ssd.proof"] = h_ssd_proof
HANDLERS_40106["keychip.ssd.hostproof"] = h_ssd_proof


# 40104 = mxnetwork / amNetwork
#
# The game's amNetworkResponseCheck parses:
#   result=0            (atoi; any non-numeric also reads as 0)
#   response=<request>  must echo the request name
#   query_dhcp_status  -> dhcp_status=<0..4>
#   query_mac_address  -> mac_address=xx-xx-xx-xx-xx-xx
# Anything else leaves the caller at -6 ("No Response"/keyword missing).
NET_MAC = "00-11-22-33-44-55"
# SEGA's own LAN convention (see segatools [netenv]):
#   <subnet>.1  = router / gateway / DNS
#   <subnet>.11 = normal cabinet
#   <subnet>.12 = cabinet for in-store battle
# The reported NIC address therefore follows --networkaddr instead of being
# hard-coded, so the whole environment can be switched in one place.
NET_ADDR = "10.0.0.11"
NET_GW = "10.0.0.1"
NET_MASK = "255.255.255.0"
# amNetwork's DHCP state machine (sub_D7C3E0) maps dhcp_status as:
#   0/4 = start DHCP, 1 = "could not get DHCP" (FAILURE), 2 = in progress,
#   3   = acquired -> the game then requests the network properties
#     (route_ip / auth_ip / play_billing_ip / bbrouter_ip).
# Returning 1 made the game report "could not get DHCP" for ever.
NET_DHCP_STATUS = "3"        # 3 = address acquired


def h_amnetwork(cmd, args):
    global NET_DHCP_STATUS
    req = args.get("request", "?")
    if req == "update_dhcp_status":
        # The game does update_dhcp_status(status=N) then polls
        # query_dhcp_status until it reads back N -- echo it.
        NET_DHCP_STATUS = args.get("status", NET_DHCP_STATUS)
        LOG(f"port 40104: dhcp_status -> {NET_DHCP_STATUS}")
    # sub_E3CF30: "result" must be a STRING ("success" is the accepted value)
    # and "code" is the numeric status (0 = ok).  Sending both keeps both
    # branches of that check happy.
    resp = [("result", "success"), ("code", "0"), ("response", req)]
    if req == "query_dhcp_status":
        resp.append(("dhcp_status", NET_DHCP_STATUS))
    elif req == "query_mac_address":
        resp.append(("mac_address", NET_MAC))
    # amNetwork walks a configuration chain (sub_E40850).  For query_nic_status:
    # if status != "0" the game takes the whole address block from THIS packet
    # (ip_address / subnetmask / gateway / primary_dns / secondary_dns); only
    # when status == "0" does it walk the separate
    # query_ip_address -> query_subnetmask -> query_gateway chain.
    elif req == "query_nic_status":
        resp.append(("status", "1"))
        resp.append(("ip_address", NET_ADDR))
        resp.append(("subnetmask", NET_MASK))
        resp.append(("gateway", NET_GW))
        resp.append(("primary_dns", NET_GW))
        resp.append(("secondary_dns", NET_GW))
    elif req == "query_ip_address":
        resp.append(("ip_address", NET_ADDR))
    elif req == "query_subnetmask":
        resp.append(("subnetmask", NET_MASK))
    elif req == "query_gateway":
        resp.append(("gateway", NET_GW))
    elif req == "query_dns":
        resp.append(("primary_dns", NET_GW))
        resp.append(("secondary_dns", NET_GW))
    return resp


HANDLERS_NETWORK = {"request": h_amnetwork}


# 40102 / 40103 / 40113 / 40104: request=xxx
def h_request(cmd, args):
    req = args.get("request", "?")
    return [("result", "success"), ("response", req)]


# --- 40102 = mxappdata ------------------------------------------------------
# The packet is  request=<subcommand>, so dispatch on the VALUE, not the key.
# sub_E4F770 (query_appdata_status reply parser) needs a "status" key, one of
# available / restored / unknown / error / needed / checking / formatting.
# Without it the installer returns -6 and the app treats the service as broken.
def h_appdata_request(cmd, args):
    req = args.get("request", "?")
    resp = [("response", req), ("result", "success")]
    if req == "query_appdata_status":
        resp.append(("status", "available"))
    return resp


HANDLERS_40102 = {"request": h_appdata_request}


HANDLERS_REQUEST = {"request": h_request}


# 40114 = mxstorage
STORAGE_RESP_FILE = os.path.join(BASE, "data", "resp_40114.json")


# mxstorage answers.  The game's storage state machine walks
#   query_storage_status(id=0..7) -> query_storage_count -> query_storage_info
#   -> check -> format -> get_volume -> mount/umount -> query_drive
# and gives up (leaving amSysData empty, hence MAIN ID = INVALID_SERIALNO)
# if the status never looks good.  Keys are intentionally duplicated: the
# parser only reads the ones it knows and ignores the rest.
STORAGE_N = 2          # two storage devices claimed


def _storage_defaults(req, args):
    if req == "query_storage_count":
        return {"count": STORAGE_N, "storage_count": STORAGE_N}
    if req == "query_storage_status":
        try:
            sid = int(args.get("id", "0"))
        except ValueError:
            sid = 0
        # A real cabinet exposes 1-2 storages.  Answering "success" for every
        # probed id made the game see eight phantom devices and give up
        # (amSysData then had no record -> MAIN ID = INVALID_SERIALNO).
        if sid < STORAGE_N:
            return {"status": 1, "storage_status": 1}
        # code=1 is what sub_E3CF30 maps to an error; do NOT add a second
        # "result" key (the parser takes the first one and would still see
        # the base result=success).
        return {"code": "1", "status": 0}
    if req == "query_storage_info":
        return {"storage_size": 0x100000, "size": 0x100000,
                "status": 1, "type": 1}
    if req == "get_volume":
        return {"volume": 100, "status": 1, "result_code": 0}
    if req in ("check", "format", "mount", "umount", "set_volume"):
        return {"status": 1, "result_code": 0, "letter": "D"}
    return {}


def h_storage(cmd, args):
    req = args.get("request", "?")
    # sub_E3D8E0 parses "result" as a NUMBER (v4 = sub_E3CF30(); ok when >= 0).
    # The old "success" string made strtoul fail, so every storage reply was
    # treated as an error and the state machine restarted forever.
    # sub_E3CF30: "result" must be a STRING ("success" is the accepted value)
    # and "code" is the numeric status (0 = ok).  Sending both keeps both
    # branches of that check happy.
    resp = [("result", "success"), ("code", "0"), ("response", req)]
    fields = dict(_storage_defaults(req, args))
    try:
        # utf-8-sig: the file is edited by hand on Windows and often carries a
        # BOM, which made json.load fail and silently dropped every override.
        with open(STORAGE_RESP_FILE, "r", encoding="utf-8-sig") as f:
            extra = json.load(f)
        fields.update(extra.get(req, {}))
    except FileNotFoundError:
        pass
    except Exception as exc:
        LOG(f"port 40114: resp file error: {exc!r}")
    for k, v in fields.items():
        resp.append((k, str(v)))
    return resp


HANDLERS_STORAGE = {"request": h_storage}

HANDLERS: dict[int, dict] = {
    40100: HANDLERS_40100,
    40106: HANDLERS_40106,
    40102: HANDLERS_40102,
    40103: HANDLERS_REQUEST,
    40104: HANDLERS_NETWORK,
    40113: HANDLERS_REQUEST,
    40114: HANDLERS_STORAGE,
}


class Table:
    """Optional JSON override table: { "40100": { "cmd": {"k": "v"} } }"""

    def __init__(self, raw: dict | None):
        self.raw = raw or {}

    @classmethod
    def load(cls, path: str | None) -> "Table":
        if not path:
            return cls(None)
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def lookup(self, port: int, cmd: str):
        return self.raw.get(str(port), {}).get(cmd)


# ---------------------------------------------------------------- catcher
# The game asks the "catcher router" (port 40110) to start the updater and then
# polls isupdate.  On a real cabinet that router launches mfetcher.exe, so we do
# the same -- otherwise the game never gets a final answer.
GAME_DIR = r"C:\Games\Shining Force - Cross Raid\Shining Force - Cross Raid"
_catcher_lock = threading.Lock()
_catcher_proc = None


def start_catcher() -> None:
    global _catcher_proc
    with _catcher_lock:
        if _catcher_proc is not None and _catcher_proc.poll() is None:
            return
        exe = os.path.join(GAME_DIR, "mfetcher.exe")
        if not os.path.isfile(exe):
            LOG(f"catcher: {exe} not found")
            return
        try:
            # mfetcher refuses to run without "-r <base dir>"; the path contains
            # spaces so it must be quoted, and -b selects the broadband profile.
            # With these it binds STATUS_PORT (32007) and COMMAND_PORT (32108).
            _catcher_proc = subprocess.Popen(
                [exe, "-r", GAME_DIR, "-b"], cwd=GAME_DIR,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            LOG(f"catcher: started mfetcher.exe pid={_catcher_proc.pid}")
        except Exception as exc:
            LOG(f"catcher: spawn failed: {exc!r}")


def handle_connection(conn: socket.socket, peer, port: int, table: Table, no_reply: bool) -> None:
    peer_s = f"{peer[0]}:{peer[1]}"
    LOG(f"port {port}: ACCEPT {peer_s}")
    conn.settimeout(RECV_TIMEOUT)
    buf = b""
    try:
        conn.sendall(READY)
        LOG(f"port {port}: SENT '>'")

        while True:
            # a single "$" acknowledges a completed binary transfer (no CRLF)
            if buf.startswith(b"$"):
                buf = buf[1:]
                LOG(f"port {port}: ACK '$'")
                continue

            while b"\r\n" not in buf:
                if buf.startswith(b"$"):
                    break
                chunk = conn.recv(4096)
                if not chunk:
                    LOG(f"port {port}: {peer_s} closed (buf={len(buf)}B)")
                    return
                buf += chunk

            if buf.startswith(b"$"):
                continue

            raw, _, buf = buf.partition(b"\r\n")
            raw += b"\r\n"
            LOG(f"port {port}: RECV {len(raw)}B\n{hexdump(raw)}")

            pairs = parse_packet(raw)
            if not pairs:
                LOG(f"port {port}: unparsable ({raw!r}) -> '?'")
                conn.sendall(ERROR)
                conn.sendall(READY)
                continue

            cmd = pairs[0][0]
            args = dict(pairs)
            LOG(f"port {port}: command={cmd!r} args={args}")

            # priority: builtin handler > JSON table > '?'
            resp = None
            fn = HANDLERS.get(port, {}).get(cmd)
            if fn:
                try:
                    resp = fn(cmd, args)
                except Exception as exc:
                    LOG(f"port {port}: handler error: {exc!r}")
                    resp = None
            if resp is None:
                resp = table.lookup(port, cmd)
            if resp is None and port == 40110:
                # 40110 is the local "catcher" router.  Requests seen:
                #   startcatcher / stopcatcher / isupdate / reloadinfo
                #
                # startcatcher (sub_E53900): response=<name> + result=success
                # isupdate     (sub_E53A50): the above plus
                #     incompatible=<int> server=<ip>
                #     originalf/originalb/patchf/patchb =
                #         notavailable|available|needed|instant|erasable
                # Anything missing/invalid -> -150 -> "server communication
                # failed" in game.
                req = args.get("request", "")
                resp = [("response", req), ("result", "success")]
                if req == "startcatcher":
                    start_catcher()
                if req == "isupdate":
                    resp += [
                        ("incompatible", "0"),
                        ("server", "127.0.0.1"),
                        ("originalf", "notavailable"),
                        ("originalb", "notavailable"),
                        ("patchf", "notavailable"),
                        ("patchb", "notavailable"),
                    ]
            if resp is None:
                LOG(f"port {port}: NO HANDLER for {cmd!r} -> '?'")
                payload = ERROR
            else:
                items = list(resp.items()) if isinstance(resp, dict) else list(resp)
                payload = build_packet(items)
                if len(payload) > MAX_PACKET:
                    LOG(f"port {port}: !! {len(payload)}B > {MAX_PACKET}B, sending '?'")
                    payload = ERROR

            if not no_reply:
                conn.sendall(payload)
                LOG(f"port {port}: SENT {len(payload)}B\n{hexdump(payload)}")
                conn.sendall(READY)
                LOG(f"port {port}: SENT '>'")

    except socket.timeout:
        LOG(f"port {port}: {peer_s} timeout")
    except OSError as exc:
        LOG(f"port {port}: {peer_s} error: {err_text(exc)}")
    except Exception as exc:
        LOG(f"port {port}: {peer_s} UNEXPECTED {exc!r}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        LOG(f"port {port}: CLOSE {peer_s}")


def serve_port(port: int, table: Table, no_reply: bool) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
    except OSError as exc:
        LOG(f"port {port}: BIND FAILED: {err_text(exc)}")
        return
    srv.listen(8)
    LOG(f"port {port}: listening on 127.0.0.1")

    while True:
        try:
            conn, peer = srv.accept()
        except OSError as exc:
            LOG(f"port {port}: accept failed: {err_text(exc)}")
            return
        threading.Thread(target=handle_connection,
                         args=(conn, peer, port, table, no_reply),
                         daemon=True).start()


def main() -> int:
    global PKI_DIR, LOG, NET_ADDR, DS_TABLE_FILE
    ap = argparse.ArgumentParser(description="PCP (libpcp) server / sniffer")
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)))
    ap.add_argument("--table", default=None, help="JSON override table")
    ap.add_argument("--log", default=DEFAULT_LOG)
    ap.add_argument("--no-reply", action="store_true")
    ap.add_argument("--gameid", default=CFG["gameid"])
    ap.add_argument("--platformid", default=CFG["platformid"])
    ap.add_argument("--modeltype", default=CFG["modeltype"])
    ap.add_argument("--region", default=CFG["region"])
    ap.add_argument("--systemflag", default=CFG["systemflag"])
    ap.add_argument("--networkaddr", default="10.0.0.4",
                    help="keychip.appboot.networkaddr (cabinet LAN address)")
    ap.add_argument("--keyid", default=None, help="override keychip.billing.keyid")
    ap.add_argument("--mainid", default=None, help="override keychip.billing.mainid")
    ap.add_argument("--pki-dir", default=PKI_DIR,
                    help="directory with billing.pub / ca.crt")
    ap.add_argument("--ds-table", default=DS_TABLE_FILE,
                    help="SBVB_Table.dat used by keychip.ssd.proof (default: dev path)")
    args = ap.parse_args()
    if args.keyid:
        CFG["keyid"] = args.keyid
    if args.mainid:
        CFG["mainid"] = args.mainid

    PKI_DIR = args.pki_dir
    DS_TABLE_FILE = args.ds_table
    CFG.update({
        "gameid": args.gameid,
        "platformid": args.platformid,
        "modeltype": args.modeltype,
        "region": args.region,
        "systemflag": args.systemflag,
        "networkaddr": args.networkaddr,
    })
    NET_ADDR = args.networkaddr

    LOG = Logger(args.log)

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    table = Table.load(args.table)

    LOG("=" * 64)
    LOG(f"PCP server | ports={ports} | no_reply={args.no_reply} | pki={PKI_DIR}")
    LOG(f"cfg={CFG}")
    LOG("=" * 64)

    for p in ports:
        threading.Thread(target=serve_port, args=(p, table, args.no_reply), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        LOG("stopped by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())

