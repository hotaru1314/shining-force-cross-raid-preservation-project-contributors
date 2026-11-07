"""spSif / match channel :52000 responder -- baton 9 (2026-10-23).

---------------------------------------------------------------------------
WHY THE OLD VARIANTS A..G COULD NEVER WORK  (found by static RE this baton)
---------------------------------------------------------------------------
The 84-byte "ESCTP INIT" the client sends is *not* an ESCTP chunk packet.
It is a match-layer request framed by spSif.  Two headers are stacked:

    wire frame = [ outer 4B ][ inner 12B ][ payload ]
        outer: type:1  flags:1  len:2 BE        len = 12 + len(payload)
        inner: cmd:1   flags:1  len:2 BE        len = len(payload)
               f4:4 BE        f8:4 BE
        payload

Proof / addresses (project.exe, base 0x400000):
  * sub_E7CAB0  builds the outer 4B header:  byte0 = type & 0x7F,
                byte1 = flags nibbles, word2 = htons(total_of_sbuf).  The
                sbuf already contains the 12B inner header, so
                outer_len = 12 + payload_len, and the frame is 4 + outer_len.
  * sub_E7CC20  (spSif rx cb) strips the outer 4B, ignores type except
                4/12 (heartbeat), then calls the match layer via
                dword_324EF98 == sub_E7C150.
  * sub_E7C150  (match rx) reads the inner 12B:
                    +0 cmd, +1 flags, +2 len, +4 f4, +8 f8
                then advances the buffer by 12 and works on the payload.

The client's request is therefore:
    cmd = 0x22, len = 68, f4 = 0, f8 = 0, payload = 68B
    (payload has a GetTickCount-ish dword @+0x14, keychip "A72E0000000"
     @+0x25 and two u32s @+0x30/0x34 that differ between sessions)

WHAT THE CLIENT EXPECTS BACK
  sub_E7C0A0 (connect cb) stores the *first byte of the queued request*
  (= the inner cmd 0x22) into conn+22 and later sub_E7C150 state 1 does
        if (cmd == (*(u16*)(conn+22) | 0x80))  -> advance to state 5
  so the reply command must be 0x22 | 0x80 = 0xA2.  The old variants echoed
  cmd 0x22, which the client silently ignored (then 6 retries / ~7 s apart).

  The outer type byte is *not* inspected for data frames (only 4 and 12 are
  special-cased as heartbeat), so several type values are equally plausible;
  we cycle a short list of them, one per heartbeat that arrives, so one
  connection tests several candidates.

  The client's rx state machine only consumes 16 bytes per frame
  (sub_E83FD0: header 4B + 12B, alloc len-12) -- i.e. server->client frames
  are expected to be exactly 4 + 12 + payload bytes with payload 0..len-12.
  Our 16-byte reply (payload 0) matches that path exactly.

Usage:
    python match_server.py [--bind 10.0.0.10] [--port 52000] [--hold 25]
    python match_server.py --list          # print the candidate table
Log:
    <install>\\data\\match_server.log
---------------------------------------------------------------------------
"""
import os

import socket

import struct

import sys

import threading

import time
BASE = os.path.dirname(os.path.abspath(__file__))


BIND_IP = "10.0.0.10"
PORT = 52000
HOLD = 25.0
LOG = os.path.join(BASE, "data", "match_server.log")

counter = [0]
lock = threading.Lock()
conn_seq = [0]

# one entry per connection, cycled outside-in; inside a connection the
# candidates are sent one per incoming heartbeat so a single 5-heartbeat
# connection covers the first five.
CAND_FILE = os.path.join(BASE, "data", "variant_start.txt")
# 2026-10-23: how many replies of the S1..S7 ladder to send per connection.
# "1" = only the login ack (cmd=A2), then keep the session open -- this is what
# a real match server does; sending S4 (cmd=0x84) makes the client end the
# session immediately (sub_E7C150 state 4 -> 5 -> close), which is what the
# "communication error" after picking an Online mode looked like.
LADDER_FILE = os.path.join(BASE, "data", "match_ladder.txt")
# 2026-10-23 baton 10: payload shape of the first reply (login ack).
# empty | echo | zeros | raw -- see build_s1().
S1_MODE_FILE = os.path.join(BASE, "data", "s1_mode.txt")
CC_PLAYER0_FILE = os.path.join(BASE, "data", "cc_player0.txt")

# ---------------------------------------------------------------- baton 10
# A/B result (13:42, 2026-10-23): with S1 only (16B, cmd=A2, no payload) the
# client keeps the session for ~22 s and sends one heartbeat per second
# (outer type=0x04, len field 0x8008 -> mask 0x7FFF, body
# "30 00 01 00 00 00 00 00"); we ack with type=0x0C and it is accepted.
# The 84B "echo" reply (S2, cmd=A2 + the 68B request payload echoed back)
# kills the connection in ~1 ms.  So S2 -- specifically the payload -- is the
# poison, not the missing ladder.  Hence: keep the session alive with S1 and
# probe, one variable at a time, what the app layer wants inside cmd=0xA2.
PROBE_MODE = True
QUIET = False          # --quiet: send S1 once, then only answer heartbeats (clean baseline)
STATE_PROBE = False    # --state-probe: reply by login-state byte (off40), rotate S1 variants
CC_PROBE = False       # --cc-probe: A2 + CC matching-result frame in one send (search state)
A2_PROBE = False       # --a2-probe: A2 carrying the matching-response struct (see build_a2_probe)
A2_FILE = os.path.join(os.path.dirname(S1_MODE_FILE), "a2_probe.txt")
CC_FILE = os.path.join(os.path.dirname(S1_MODE_FILE), "cc_fields.txt")
SILENT_PROBE = False   # --silent-probe: accept + log the request, never reply
CC_FIRST_PROBE = False # --cc-first-probe: send CC then A2 in one write (search state only)
A2_FIRST_PROBE = False # --a2-first-probe: send A2 then CC in one write (search state only)
SWEEP_A2 = False      # --sweep-a2: cycle the A2 status byte 0..7, one per connection
A2_ONLY = False       # --a2-only: reply with A2 carrying a2_probe.txt payload (no CC)
SWEEP_I = 0
ALT_PROBE = False     # --alt-probe: alternate A2 / CC across connections
ALT_DONE = False
A2_RESULT = False
ALT_CC_COUNT = 0     # --a2-cc-alternate: 奇数连接回 A2、偶数连接回 CC
COOP = False        # --coop: 店内協力联机模式（队伍表+状态广播+CC）
COOP_FAKE = False   # --coop-fake: 附带一个假队友
REAL_FRAMES = False  # --real-frames: 照抄 TPO 抓包里的真帧（A2+T10，之后追加 CC）
CC_AFTER = 3        # 第几次连接起附带 CC（旧的按连接计数方式）
CC_AFTER_HB = 5     # --cc-after-hb=N: 第 N 次心跳后主动推 CC（照抄真机时序）
CONN_N = 0
HANDLE = 0x10400022
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import real_frames as rf
import coop
ALT_CC = False
ACK_CMD = None
ACK_PAYLOAD = ""
RESULT_CMD = None      # --result-cmd=0x84 : reply with this cmd carrying the result
PUSH_ON_ACCEPT = False
LAST_WAS_SEARCH = False
A2_CC_DELAY = None    # --a2-then-cc=<ms>: send A2, wait, then CC on the same connection
SESSION_PROBE = False  # --session-probe: hold the session, push a CC after PUSH_DELAY
PUSH_DELAY = 1.0
PROBE_DELAY = 4.0      # s after S1 before the first probe
PROBE_GAP = 4.5        # s between probe starts (22 s session budget)
PROBE_OBS = 2.0        # s of observation after each probe
VERDICT_FILE = os.path.join(BASE, "data", "probe_verdict.txt")
probe_rot = [0]        # each connection starts one probe further down


def log(msg):
    stamp = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
    line = f"[{stamp}] {msg}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def dump(tag, data):
    hx = data.hex()
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    for i in range(0, len(data), 32):
        log(f"    {tag} {i:04x}  {hx[i*2:i*2+64]:<64}  {asc[i:i+32]}")


# ---------------------------------------------------------------- framing
def sif_frame(outer_type, cmd, payload=b"", f4=0, f8=0, flags=0, iflags=0):
    """[outer: type flags len][inner: cmd flags len f4 f8][payload]"""
    inner = (bytes([cmd & 0xFF, iflags & 0xFF]) + struct.pack(">H", len(payload))
             + struct.pack(">II", f4, f8) + payload)
    return bytes([outer_type & 0x7F, flags & 0xFF]) + struct.pack(">H", len(inner)) + inner


def sif_heartbeat_ack(body):
    """type 0x0C = heartbeat ack; echo the 8-byte heartbeat body."""
    body = body[:8].ljust(8, b"\x00")
    return b"\x0c\x00" + struct.pack(">H", 0x8000 | len(body)) + body


def old_init_ack(vtag=0x11223344, streams_out=8, streams_in=8):
    """The pre-baton-9 hypothesis: 68B ESCTP INIT-ACK, no Sif framing."""
    now = int(time.time() * 1000) & 0xFFFFFFFF
    body = struct.pack(">I", vtag) + struct.pack(">I", now)
    body += struct.pack(">HH", streams_out, streams_in)
    body += struct.pack(">I", now) + struct.pack(">HH", 7, 44) + b"\x00" * 40
    return b"\x00\x00\x00\x00\x02\x00" + struct.pack(">H", 4 + len(body)) + body


def build_candidates(req):
    """Reply sequence for one request frame.

    2026-10-23 09:0x -- sifdump.dll (hooks sub_E7C150) proved the framing is
    right and the client *is* advancing:

        08:57:28  our A2/pl=0 arrives, client state=2  -> case 2 -> state=4
        08:57:29  our A2/pl=0 arrives, client state=4  -> ignored (needs 0x84)

    sub_E7C150 state machine (state -> accepted cmd):
        1: cmd == (conn+0x16 | 0x80)          -> 5   (quick probe path)
        2: cmd == 0xA2 or 0x81                -> 4   (payload[0]==0)
        3: cmd == 0x83 && f4>>28 == 3         -> 4   (payload[2]==0)
        4: cmd == 0x84 && f4>>28 in {3, 0xB}  -> 5   (final ack)
    so blindly sending one candidate per connection wastes the bursts; we now
    walk the whole ladder in order on every connection, 120 ms apart.
    """
    p = req[16:] if len(req) > 16 else b""          # payload of the request
    out = [
        ("S1 cmd=A2 pl=0        (state 1/2)", sif_frame(0x08, 0xA2)),
        ("S2 cmd=A2 pl=echo     (state 2 alt)", sif_frame(0x08, 0xA2, p)),
        ("S3 cmd=83 f4=3 pl=0   (state 3)", sif_frame(0x08, 0x83, b"", f4=0x30000000)),
        ("S4 cmd=84 f4=3 pl=0   (state 4)", sif_frame(0x08, 0x84, b"", f4=0x30000000)),
        ("S5 cmd=84 f4=B pl=0   (state 4 alt)", sif_frame(0x08, 0x84, b"", f4=0xB0000000)),
        ("S6 cmd=84 f4=3 pl=8   (state 4, data)", sif_frame(0x08, 0x84, b"\x00" * 8,
                                                          f4=0x30000000)),
        ("S7 legacy: 68B bare INIT-ACK", old_init_ack()),
    ]
    return out


def build_probes(req):
    """baton 10: what does the app layer want inside cmd=0xA2?

    Every probe is the *same* cmd=0xA2 so the transport state machine never
    changes; only the payload / f4 nibble varies.  P4 is the known killer
    (S2 echo) and stays as the control.  One probe set is walked per
    connection, starting at a rotating offset, so a killer probe only costs
    that one connection.
    """
    p = (req[16:] if len(req) > 16 else b"").ljust(68, b"\x00")[:68]
    return [
        ("P1 a2/empty f4=80000000", sif_frame(0x08, 0xA2, b"", f4=0x80000000)),
        ("P2 a2/echo[0]=A2", sif_frame(0x08, 0xA2, bytes([0xA2]) + p[1:])),
        ("P3 a2/zeros68", sif_frame(0x08, 0xA2, b"\x00" * 68)),
        ("P4 a2/echo-as-is CONTROL", sif_frame(0x08, 0xA2, p)),
    ]


S1_VARIANTS = ["echo", "zeros", "raw"]   # ?????????????????
variant_rot = [0]


def build_cc_frame():
    """Matching-result frame: cmd 0xCC.

    Wire layout that sub_E84C60 (spMcGetMatchingResult) actually decodes:

        payload[20]     prefix length   (aligned up to 4; 0 = no prefix)
        payload[22..23] data length L   (u16 BE)
        payload[24 ..]  prefix (align4(payload[20])) + ntgp packet of L bytes

    sub_E84C60:
        v9 = htons(*(u16*)(p+22));
        memcpy(out+280, p + 24 + align4(p[20]), v9);

    The ntgp packet is [kind][kind][7 bytes][8*20 bytes] = 169 because
    new_packet_if reads the kind once and the object's deserialize reads it again.
    """
    pl = bytearray(24)
    try:
        with open(CC_FILE, "r", encoding="utf-8") as f:
            kv = dict(p.split("=") for p in f.read().split() if "=" in p)
    except Exception:
        kv = {}
    def _i(k, d=0):
        try:
            return int(kv[k], 0) & 0xFFFFFFFF
        except Exception:
            return d
    # candidate size fields inside the 24-byte sphingo header
    for off, key in ((0, "d0"), (4, "d4"), (8, "d8"), (12, "d12")):
        pl[off:off+4] = struct.pack(">I", _i(key))
    pl[16:18] = struct.pack(">H", _i("u16", 0) & 0xFFFF)
    pl[18:20] = struct.pack(">H", _i("u18", 0) & 0xFFFF)
    pl[20] = _i("b20") & 0xFF
    pl[22:24] = struct.pack(">H", _i("u22", 169) & 0xFFFF)
    # data section: hex from cc_fields.txt ("data=..."), default = 169B MtchResult
    data = None
    if "data" in kv:
        try:
            data = bytes.fromhex(kv["data"].replace(",", ""))
        except Exception:
            data = None
    if data is None:
        data = (bytes([0x31, 0x31]) + bytes(7) + bytes(160))
    pl += data
    return sif_frame(0x08, 0xCC, bytes(pl))


def build_cc_result(count=1, player_id=0x11223344):
    """MtchResult, byte-for-byte according to its OWN serializer (sub_533FC0).

    MtchResult::serialize writes (the kind byte comes from the factory, not here):

        byte  kind = 0x31              <- new_packet_if writes this
        byte  f5
        byte  f5b
        word  f6
        word  f8
        byte  f10
        byte  f11
        8 x 20-byte MtchPlayerInfo    (stride 24 in memory, 20 on the wire)

    = 1 + 1 + 1 + 2 + 2 + 1 + 1 = 9 header bytes + 160 = 169 bytes on the wire.

    (So recv_MtchResult's "n = pkt[4]" is f5, not a player count -- the earlier
    variable-count reading was of a different class.)

    The sphingo wrapper in front: payload[20] = 0 (no prefix),
    payload[22..23] = length of this packet, data starts at payload[24].
    """
    pkt = bytearray()
    pkt.append(0x31)                 # kind: MtchResult
    pkt.append(0x00)                 # f5
    pkt.append(0x00)                 # f5b (serializer writes this+5 separately)
    pkt += struct.pack(">H", 0)      # f6
    pkt += struct.pack(">H", 0)      # f8
    pkt.append(0x00)                 # f10
    pkt.append(0x00)                 # f11
    # 2026-10-30：TPO 抓包显示"队长"不是标志位，而是由列表顺序 / 唯一有效条目推出来的。
    # 因此第 0 条记录做成热可改：data/cc_player0.txt 放 40 位十六进制（20 字节），
    # 其余 7 条保持全 0。每次连接重读，改文件即换实验值。
    entries = bytearray(160)
    try:
        with open(CC_PLAYER0_FILE, "r", encoding="utf-8") as f:
            spec = f.read().strip().replace(" ", "").replace("\n", "")
        if spec:
            raw = bytes.fromhex(spec)[:20]
            entries[0:len(raw)] = raw
    except Exception:
        pass
    pkt += entries                   # 8 x 20B MtchPlayerInfo（第 0 条可配）
    pl = bytearray(24)
    pl[20] = 0
    pl[22:24] = struct.pack(">H", len(pkt) & 0xFFFF)
    pl += pkt
    return sif_frame(0x08, 0xCC, bytes(pl))


def _a2_fields():
    """读 a2_probe.txt：<res> <cnt> <cap> <token> [f4] [f8]，每次连接热读。"""
    res, cnt, cap, token, f4, f8 = 0, 1, 4, 0, 0, 0
    try:
        with open(A2_FILE, "r", encoding="utf-8") as f:
            parts = f.read().split()
        if len(parts) >= 4:
            res = int(parts[0]); cnt = int(parts[1])
            cap = int(parts[2]); token = int(parts[3])
        if len(parts) >= 6:
            f4 = int(parts[4], 0) & 0xFFFFFFFF
            f8 = int(parts[5], 0) & 0xFFFFFFFF
    except Exception:
        pass
    return res, cnt, cap, token, f4, f8


def build_variant(req, mode):
    p = (req[16:] if len(req) > 16 else b"").ljust(68, b"\x00")[:68]
    if mode == "echo":
        return sif_frame(0x08, 0xA2, bytes([0xA2]) + p[1:]), "pl=echo[0]=A2(68B)"
    if mode == "echofill":
        # 2026-10-30：**不要误用**。曾以为 84B 回显 A2 是"真机应答"，
        # 实际那来自 10.0.0.7 = 我们自己的服务器（STATE_snapshot_20261026 L169），
        # 而 s1_mode=echo 早在 2026-10-24 就被判失败（NEGATIVE.md L25：客户端每秒重连＝被拒）。
        # 这里保留 echofill 仅作对照实验：回显 + 按 a2_probe.txt 覆盖字段。
        res, cnt, cap, token, f4, f8 = _a2_fields()
        pl = bytearray(bytes([0xA2]) + p[1:])
        pl[0] = res & 0xFF
        pl[4:6] = struct.pack(">H", cnt & 0xFFFF)
        pl[6:8] = struct.pack(">H", cap & 0xFFFF)
        pl[12:16] = struct.pack(">I", token & 0xFFFFFFFF)
        return (sif_frame(0x08, 0xA2, bytes(pl)),
                f"pl=echo+fields res={res} cnt={cnt} cap={cap}")
    if mode == "zeros":
        return sif_frame(0x08, 0xA2, bytes([0xA2]) + b"\x00" * 67), "pl=zeros[0]=A2(68B)"
    if mode == "raw":
        return sif_frame(0x08, 0xA2, p), "pl=raw-echo(68B)"
    return sif_frame(0x08, 0xA2), "pl=0 (16B)"


def build_a2_probe(status=None):
    """A2 whose payload is the struct sub_E84B30 (spMcGetMatchingRsp) reads.

    sub_E84B30, case state 3/4:
        v7 = frame->payload
        b0  = v7[0]              -> if 0, client state = 4
        u16 = htons(*(u16*)(v7+4))  -> out+4
        u16 = htons(*(u16*)(v7+6))  -> out+6
        u32 = htonl(*(u32*)(v7+12)) -> client+20, out+8

    File a2_probe.txt: "<res> <count> <cap> <token>", re-read per connection so the
    values can be changed live without restarting the server.
    """
    res, cnt, cap, token, f4, f8 = 0, 1, 4, 0, 0, 0
    try:
        with open(A2_FILE, "r", encoding="utf-8") as f:
            parts = f.read().split()
        if len(parts) >= 4:
            res, cnt, cap, token = (int(parts[0]), int(parts[1]),
                                    int(parts[2]), int(parts[3]))
        if len(parts) >= 6:
            f4 = int(parts[4], 0) & 0xFFFFFFFF
            f8 = int(parts[5], 0) & 0xFFFFFFFF
    except Exception:
        pass
    if status is not None:
        res = status
    pl = bytearray(16)
    pl[0] = res & 0xFF
    pl[4:6] = struct.pack(">H", cnt & 0xFFFF)
    pl[6:8] = struct.pack(">H", cap & 0xFFFF)
    pl[12:16] = struct.pack(">I", token & 0xFFFFFFFF)
    tag = f"res={res} cnt={cnt} cap={cap} tok=0x{token:X} f4=0x{f4:X} f8=0x{f8:X}"
    return sif_frame(0x08, 0xA2, bytes(pl), f4=f4, f8=f8), tag


def build_ack_cmd(cmd, payload=b""):
    """A bare ACK frame with an arbitrary cmd (no sphingo header, no data)."""
    return sif_frame(0x08, cmd, bytes(payload))


def build_result_cmd(cmd):
    """A result frame with an arbitrary response cmd (0x81/0x84/0xA2/0xCC).

    Rationale: class 1 (0x84) and class 0 (0x81) in sub_E84F60 both queue the
    frame AND set client+9 = 3, exactly like 0xA2. If either of them also makes
    the library raise the matching event (cmd=58) that triggers
    spMcGetMatchingResult, then ONE frame does both jobs -- which is the only way
    around the "one frame per connection" limit.
    """
    pkt = bytearray()
    pkt.append(0x31)                 # MtchResult kind
    # 2026-10-30：f5/f5b/f6/f8 一直填 0，但 MtchResult 自己的序列化器会写这些字段，
    # 其中 f5 曾被读成"人数"。这里按 a2_probe.txt 的 count/cap 填进去试。
    res, cnt, cap, token, _f4, _f8 = _a2_fields()
    pkt.append(cnt & 0xFF)           # f5
    pkt.append(0x00)                 # f5b
    pkt += struct.pack(">H", cnt & 0xFFFF)   # f6
    pkt += struct.pack(">H", cap & 0xFFFF)   # f8
    pkt.append(0x00)                 # f10
    pkt.append(0x00)                 # f11
    entries = bytearray(160)
    try:
        with open(CC_PLAYER0_FILE, "r", encoding="utf-8") as f:
            spec = f.read().strip().replace(" ", "").replace("\n", "")
        if spec:
            raw = bytes.fromhex(spec)[:20]
            entries[0:len(raw)] = raw
    except Exception:
        pass
    pkt += entries
    pl = bytearray(24)
    pl[0] = res & 0xFF
    pl[4:6] = struct.pack(">H", cnt & 0xFFFF)
    pl[6:8] = struct.pack(">H", cap & 0xFFFF)
    pl[20] = 0
    pl[22:24] = struct.pack(">H", len(pkt) & 0xFFFF)
    pl += pkt
    return sif_frame(0x08, cmd, bytes(pl))


def build_a2_result():
    """0xA2 carrying the matching result in its own payload.

    sub_E84F60, cmd 0xA2 (class 2):
        * stores the A2 frame into the queue (0xE85032)
        * [client+9] = 3
    sub_E84B30 (spMcGetMatchingRsp) then reads payload[0] as status
    (0 -> state 4), and sub_E84C60 (spMcGetMatchingResult) pops that same
    frame and parses:  len = htons(payload[22..23]), data at payload+24.

    So the result travels INSIDE the A2, not in a separate 0xCC.
    """
    pkt = bytearray()
    pkt.append(0x31)                 # MtchResult kind
    pkt += bytes(8)                  # f5/f5b/f6/f8/f10/f11
    pkt += bytes(160)                # 8 x 20B players
    # 2026-10-30: status/count/cap/token 改为热读 a2_probe.txt，
    # 便于直接试验"客户端只数记录条数、不校验玩家身份"这一行为特征。
    res, cnt, cap, token, _f4, _f8 = _a2_fields()
    pl = bytearray(24)
    pl[0] = res & 0xFF               # status 0 -> client state becomes 4
    pl[4:6] = struct.pack(">H", cnt & 0xFFFF)   # count
    pl[6:8] = struct.pack(">H", cap & 0xFFFF)   # cap
    pl[12:16] = struct.pack(">I", token & 0xFFFFFFFF)
    pl[20] = 0
    pl[22:24] = struct.pack(">H", len(pkt) & 0xFFFF)
    pl += pkt
    return sif_frame(0x08, 0xA2, bytes(pl))


def build_s1(req):
    """Login ack (first reply) -- payload shape selectable at runtime.

    ``s1_mode.txt`` (read per connection) picks:
        empty : 16B, no payload            (default; session stays alive)
        echo  : 68B, request payload echoed, first byte 0xA2
        zeros : 68B, all zero, first byte 0xA2
        raw   : 68B, request payload echoed unchanged
    """
    mode = "empty"
    try:
        with open(S1_MODE_FILE, "r", encoding="utf-8") as f:
            mode = (f.read().strip() or "empty").lower()
    except Exception:
        pass
    return build_variant(req, mode)


def verdict(line):
    stamp = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
    with open(VERDICT_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{stamp}] {line}\n")
    print(f"[{stamp}] {line}", flush=True)


def probe_run(conn, idx, req, st):
    """Send the probe set on a live session and grade each one by heartbeats."""
    time.sleep(PROBE_DELAY)
    with lock:
        rot = probe_rot[0]
        probe_rot[0] += 1
    seq = build_probes(req)
    k = rot % len(seq)
    seq = seq[k:] + seq[:k]
    t_start = time.time()
    log(f"#{idx} probe set starts at #{k} ({seq[0][0]})")
    for name, frame in seq:
        if st["closed"]:
            return
        hb0 = st["hb"]
        try:
            conn.sendall(frame)
        except OSError as exc:
            verdict(f"#{idx} {name:28s} DEAD   (send failed: {exc.__class__.__name__})")
            return
        log(f"#{idx} PROBE tx {name} ({len(frame)}B) t+{time.time() - t_start:4.1f}s")
        dump("pr", frame)
        time.sleep(PROBE_OBS)
        hb = st["hb"] - hb0
        if st["closed"]:
            verdict(f"#{idx} {name:28s} DEAD   hb_after={hb}  t+{time.time() - t_start:4.1f}s")
            return
        mark = "ALIVE " if hb > 0 else "NO-HB "      # socket up but silent = suspect
        verdict(f"#{idx} {name:28s} {mark} hb_after={hb}  t+{time.time() - t_start:4.1f}s")
        time.sleep(max(0.0, PROBE_GAP - PROBE_OBS))


def parse_frame(pkt):
    """Human readable summary of one received frame."""
    if len(pkt) < 4:
        return "short"
    typ, flg, ln = pkt[0], pkt[1], struct.unpack(">H", pkt[2:4])[0]
    s = f"type=0x{typ:02X} flags=0x{flg:02X} len=0x{ln:04X} ({ln})"
    if typ in (4, 12):
        return s + "  [heartbeat]"
    if len(pkt) >= 16:
        cmd, ifl, iln = pkt[4], pkt[5], struct.unpack(">H", pkt[6:8])[0]
        f4, f8 = struct.unpack(">II", pkt[8:16])
        s += (f"  inner cmd=0x{cmd:02X} iflags=0x{ifl:02X} ilen={iln}"
              f" f4=0x{f4:08X} f8=0x{f8:08X} payload={len(pkt)-16}")
    return s


# ---------------------------------------------------------------- server
def read_frames(conn, hold):
    """Yield complete packets; outer frame = [type][flags][len BE][body]."""
    buf = b""
    conn.settimeout(hold)
    while True:
        try:
            data = conn.recv(4096)
        except socket.timeout:
            return
        except OSError as exc:
            log(f"    recv error {exc!r}")
            return
        if not data:
            return
        buf += data
        while len(buf) >= 4:
            n = struct.unpack(">H", buf[2:4])[0] & 0x7FFF
            total = n + 4
            if len(buf) < total:
                break
            pkt, buf = buf[:total], buf[total:]
            yield pkt


def variant_start():
    try:
        with open(CAND_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def ladder_len(default=7):
    try:
        with open(LADDER_FILE, "r", encoding="utf-8") as f:
            v = int(f.read().strip(), 0)
        return max(1, min(v, 7))
    except Exception:
        return default


def handle(conn, peer, idx, hold):
    global LAST_WAS_SEARCH, CONN_N, HANDLE
    log(f"#{idx} accept {peer[0]}:{peer[1]}")
    if COOP:
        return coop.handle(conn, peer, idx, hold, log, dump, read_frames, fake=COOP_FAKE)
    if PUSH_ON_ACCEPT and LAST_WAS_SEARCH:
        try:
            cc = build_cc_result(1)
            conn.sendall(cc)
            log(f"#{idx} -> CC at accept ({len(cc)}B)")
            dump("tx", cc)
        except Exception as e:
            log(f"#{idx} push-on-accept failed: {e!r}")
    first = True
    st = {"last_rx": time.time(), "closed": False, "hb": 0}
    hb_n = 0
    sess = None          # 本连接的 f8 句柄（真机：一条连接内不变）
    ready_seen = False   # 客户端发过 type-0x10（准备完毕）
    ready_pkt = None     # 客户端那帧 type-0x10（身份字段来源）
    cc_sent = False      # 本连接是否已推过 CC
    try:
        for pkt in read_frames(conn, hold):
            st["last_rx"] = time.time()
            if pkt[0] in (4, 12):
                st["hb"] += 1
            log(f"#{idx} rx {len(pkt)}B  {parse_frame(pkt)}")
            dump("#", pkt)
            if REAL_FRAMES:
              try:
               if True:
                # 2026-10-30：照抄 TPO 抓包（3951 通道）里的真实服务器行为。
                #   心跳 type=0x04      -> 回 0x84（20B，4B 载荷 0）
                #   0x22 且 state=搜索  -> A2(32B, 带载荷) + type0x10(160B)，第 N 次起追加 CC(212B)
                #   其他 state          -> 登录 S1
                if pkt[0] in (4, 12):
                    fr = bytes([0x04, 0x00, 0x00, 0x04]) + bytes(pkt[4:8])   # 2026-10-31: 真机是 8B 04 00 00 04 + 4B 回显
                    conn.sendall(fr)
                    hb_n += 1
                    log(f"#{idx} heartbeat #{hb_n} -> 0x84 real ({len(fr)}B)")
                    if ready_seen and (not cc_sent or (CC_AFTER_HB > 0 and hb_n % CC_AFTER_HB == 0)):
                        _h = sess if sess is not None else HANDLE
                        ccf = rf.cc_req(_h, ready_pkt or pkt)
                        log(f"#{idx} >>> PUSH CC after {hb_n} heartbeats ({len(ccf)}B) handle=0x{_h:08X}")
                        dump("tx", ccf)
                        conn.sendall(ccf)
                        cc_sent = True
                    continue
                if pkt[0] == 0x10:
                    if len(pkt) > 100:   # 只认 380B 那帧（它才带等级/队伍）
                        ready_pkt = pkt
                    ready_seen = True
                    # 2026-10-30: 客户端发 type-0x10(cmd 0x00) -> 真服务器回 188B 的 type-0x10
                    fr = rf.t10_rsp_req(sess if sess is not None else HANDLE, ready_pkt or pkt)
                    if len(pkt) == 44:   # 真机: 44B 请求 -> 196B (8B ack + 188B 帧)
                        fr = bytes([0x04, 0x00, 0x00, 0x04]) + bytes(pkt[4:8]) + fr
                    log(f"#{idx} type-0x10 from client -> REAL T10_RSP ({len(fr)}B)")
                    dump("tx", fr)
                    conn.sendall(fr)
                    continue
                if pkt[0] == 0x08 and len(pkt) > 40:
                    st_off = pkt[40]
                    if st_off in (0x02, 0x04, 0x05):
                        CONN_N += 1
                        if sess is None:
                            sess = HANDLE
                            HANDLE = (HANDLE + 1) & 0xFFFFFFFF
                        parts = [rf.a2(sess), rf.t10(sess)]
                        with_cc = False   # 2026-10-30: CC 改为心跳期间主动推送
                        if with_cc:
                            parts.append(rf.cc(HANDLE))
                        blob = b"".join(parts)
                        log(f"#{idx} state=0x{st_off:02X} -> REAL A2+T10"
                            f"{' +CC' if with_cc else ''} ({len(blob)}B)"
                            f" handle=0x{sess:08X} conn={CONN_N}")
                        dump("tx", blob)
                        conn.sendall(blob)
                        HANDLE = (HANDLE + 1) & 0xFFFFFFFF
                    else:
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> S1 (login)")
                        conn.sendall(reply)
                    continue
              except Exception as _e:
                import traceback
                log(f'#{idx} !! REAL_FRAMES failed: {_e!r}')
                log(traceback.format_exc().replace(chr(10), ' | '))
                raise
            if len(pkt) > 40:
                LAST_WAS_SEARCH = pkt[40] in (0x02, 0x04, 0x05)
            if first and len(pkt) >= 16 and pkt[0] not in (4, 12):
                first = False
                if CC_PROBE:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    if st_off in (0x02, 0x04, 0x05):
                        # one connection = one frame: A2 and CC cannot both get through
                        batch = build_cc_frame()
                        log(f"#{idx} state=0x{st_off:02X} -> CC only ({len(batch)}B, MtchResult)")
                    else:
                        batch, tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> A2 only ({len(batch)}B)")
                    dump("tx", batch)
                    conn.sendall(batch)
                    continue
                if STATE_PROBE:
                    # off40 = login state: 0x00 mode-select / 0x02 just entered search / 0x05 retry
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    off65 = pkt[65] if len(pkt) > 65 else 0xFF
                    off49 = int.from_bytes(pkt[49:53], "little", signed=True) if len(pkt) >= 53 else 0
                    if st_off == 0x00:
                        reply, tag = build_s1(pkt)
                        log(f"#{idx} state=0x00 off65=0x{off65:02X} off49={off49} -> S1 {tag}")
                        dump("tx", reply)
                        conn.sendall(reply)
                        continue
                    i = variant_rot[0] % len(S1_VARIANTS)
                    variant_rot[0] += 1
                    vname = S1_VARIANTS[i]
                    reply, tag = build_variant(pkt, vname)
                    log(f"#{idx} state=0x{st_off:02X} off65=0x{off65:02X} off49={off49} -> VARIANT {vname} {tag}")
                    dump("tx", reply)
                    conn.sendall(reply)
                    continue
                if PROBE_MODE:
                    # S1: the login ack.  S1_MODE picks the payload shape:
                    #   empty (default, proven to keep the session alive)
                    #   echo   -- 68B request payload echoed, first byte 0xA2
                    #   zeros  -- 68B of zero, first byte 0xA2
                    #   raw    -- 68B request payload echoed unchanged
                    reply, s1tag = build_s1(pkt)
                    log(f"#{idx} -> S1 cmd=A2 {s1tag} ({len(reply)}B)")
                    dump("tx", reply)
                    conn.sendall(reply)
                    threading.Thread(target=probe_run,
                                     args=(conn, idx, pkt, st), daemon=True).start()
                    continue
                if ACK_CMD is not None:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> S1 (login)")
                        conn.sendall(reply)
                        continue
                    pl = bytes.fromhex(ACK_PAYLOAD) if ACK_PAYLOAD else b""
                    fr = build_ack_cmd(ACK_CMD, pl)
                    log(f"#{idx} state=0x{st_off:02X} -> ACK cmd=0x{ACK_CMD:02X} ({len(fr)}B)")
                    conn.sendall(fr)
                    continue
                if ALT_CC:
                    global ALT_CC_COUNT
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> S1 (login)")
                        conn.sendall(reply)
                        continue
                    ALT_CC_COUNT += 1
                    if ALT_CC_COUNT % 2 == 1:
                        fr = build_result_cmd(0xA2)
                        log(f"#{idx} state=0x{st_off:02X} -> [ALT] A2+result ({len(fr)}B)")
                    else:
                        fr = build_cc_result(1)
                        log(f"#{idx} state=0x{st_off:02X} -> [ALT] CC only ({len(fr)}B)")
                    dump("tx", fr)
                    conn.sendall(fr)
                    continue
                if A2_RESULT and A2_CC_DELAY is None:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> S1 (login)")
                        conn.sendall(reply)
                        continue
                    a2 = build_result_cmd(RESULT_CMD) if RESULT_CMD is not None else build_a2_result()
                    log(f"#{idx} state=0x{st_off:02X} -> A2 WITH RESULT ({len(a2)}B)")
                    dump("tx", a2)
                    conn.sendall(a2)
                    continue
                if A2_CC_DELAY is not None:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> S1 (login)")
                        conn.sendall(reply)
                        continue
                    a2 = build_result_cmd(RESULT_CMD) if RESULT_CMD is not None else build_a2_probe()[0]
                    cc = build_cc_result(1)
                    log(f"#{idx} state=0x{st_off:02X} -> A2({len(a2)}B) then wait {A2_CC_DELAY*1000:.0f}ms then CC({len(cc)}B)")
                    if A2_CC_DELAY <= 0:
                        # 2026-10-30：拼成一个 TCP 段发，赌解析器会连着读第二帧
                        conn.sendall(bytes(a2) + bytes(cc))
                        log(f"#{idx} sent 0x84+CC in ONE segment ({len(a2)+len(cc)}B)")
                    else:
                        conn.sendall(a2)
                        time.sleep(A2_CC_DELAY)
                        conn.sendall(cc)
                    continue
                if ALT_PROBE:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> S1 (login)")
                        conn.sendall(reply)
                        continue
                    global ALT_DONE
                    if ALT_DONE:
                        ALT_DONE = False
                        cc = build_cc_result(1)
                        log(f"#{idx} state=0x{st_off:02X} -> CC only ({len(cc)}B)")
                        conn.sendall(cc)
                    else:
                        ALT_DONE = True
                        a2 = build_result_cmd(RESULT_CMD) if RESULT_CMD is not None else build_a2_probe()[0]
                        log(f"#{idx} state=0x{st_off:02X} -> A2 only ({len(a2)}B)")
                        conn.sendall(a2)
                    continue
                if A2_ONLY:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> S1 (login)")
                        conn.sendall(reply)
                        continue
                    a2, tag = build_a2_probe()
                    log(f"#{idx} state=0x{st_off:02X} -> A2 only [{tag}] ({len(a2)}B)")
                    conn.sendall(a2)
                    continue
                if SWEEP_A2:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> A2 (not searching)")
                        conn.sendall(reply)
                        continue
                    global SWEEP_I
                    v = SWEEP_I % 8
                    SWEEP_I += 1
                    a2, _t = build_a2_probe(status=v)
                    log(f"#{idx} state=0x{st_off:02X} -> A2 status={v}")
                    conn.sendall(a2)
                    continue
                if A2_FIRST_PROBE:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    if st_off not in (0x02, 0x04, 0x05):
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> A2 (not searching)")
                        conn.sendall(reply)
                        continue
                    a2 = build_result_cmd(RESULT_CMD) if RESULT_CMD is not None else build_a2_probe()[0]
                    cc = build_cc_result(1)
                    batch = a2 + cc
                    log(f"#{idx} state=0x{st_off:02X} -> A2({len(a2)}B)+CC({len(cc)}B) one write")
                    dump("tx", batch)
                    conn.sendall(batch)
                    continue
                if CC_FIRST_PROBE:
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    if st_off not in (0x02, 0x04, 0x05):
                        # boot / card check: behave like --quiet so nothing changes there
                        reply, s1tag = build_s1(pkt)
                        log(f"#{idx} state=0x{st_off:02X} -> A2 (not searching)")
                        conn.sendall(reply)
                        continue
                    cc = build_cc_result(1)
                    a2 = build_result_cmd(RESULT_CMD) if RESULT_CMD is not None else build_a2_probe()[0]
                    batch = cc + a2
                    log(f"#{idx} state=0x{st_off:02X} -> CC({len(cc)}B, result n=1)+A2({len(a2)}B) one write")
                    dump("tx", batch)
                    conn.sendall(batch)
                    continue
                if SESSION_PROBE:
                    # Long-session model, but ONLY when the client is actually searching.
                    # off40 = app state byte: 0x02 entered search / 0x04,0x05 retry.
                    # Anything else (0x00 = boot / card check) must stay silent: pushing a
                    # CC into the boot-time connection killed the client at 0x99437E.
                    st_off = pkt[40] if len(pkt) > 40 else 0xFF
                    LAST_WAS_SEARCH = st_off in (0x02, 0x04, 0x05)
                    if st_off not in (0x02, 0x04, 0x05):
                        log(f"#{idx} state=0x{st_off:02X} -> SESSION skip (not searching)")
                        continue
                    def _push(conn=conn, idx=idx):
                        time.sleep(PUSH_DELAY)
                        try:
                            cc = build_cc_result(1)
                            conn.sendall(cc)
                            log(f"#{idx} -> PUSHED CC after {PUSH_DELAY:.0f}s ({len(cc)}B)")
                            dump("tx", cc)
                        except Exception as e:
                            log(f"#{idx} push failed: {e!r}")
                    threading.Thread(target=_push, daemon=True).start()
                    log(f"#{idx} state=0x{st_off:02X} -> SESSION, will push CC in {PUSH_DELAY:.0f}s")
                    continue
                if SILENT_PROBE:
                    # read the request and send NOTHING; keep the socket open and see
                    # whether the client waits, sends more, or tears the session down.
                    log(f"#{idx} -> SILENT (no reply), holding 5.0s")
                    time.sleep(5.0)
                    continue
                if A2_PROBE:
                    reply, a2tag = build_a2_probe()
                    log(f"#{idx} -> A2 with matching-rsp payload {a2tag} ({len(reply)}B)")
                    dump("tx", reply)
                    conn.sendall(reply)
                    continue
                if QUIET:
                    reply, s1tag = build_s1(pkt)
                    log(f"#{idx} -> S1 cmd=A2 {s1tag} (quiet, 16B) ({len(reply)}B)")
                    dump("tx", reply)
                    conn.sendall(reply)
                    continue
                seq = build_candidates(pkt)
                st0 = variant_start() % len(seq)
                seq = seq[st0:] + seq[:st0]
                nsteps = ladder_len(len(seq))
                for name, reply in seq[:nsteps]:
                    log(f"#{idx} -> {name}  ({len(reply)}B)")
                    dump("tx", reply)
                    conn.sendall(reply)
                    time.sleep(0.12)
                log(f"#{idx} ladder sent {min(nsteps, len(seq))}/{len(seq)} step(s)")
            elif pkt[0] in (4, 12):
                ack = sif_heartbeat_ack(pkt[4:12])
                log(f"#{idx} heartbeat -> ack type0x0C ({len(ack)}B)")
                conn.sendall(ack)
            else:
                log(f"#{idx} *** NEW DATA FRAME type=0x{pkt[0]:02X} from client ***")
                if len(pkt) >= 16:
                    cmd = pkt[4] | 0x80
                    reply = sif_frame(0x08, cmd, pkt[16:])
                    log(f"#{idx} -> ADV reply cmd=0x{cmd:02X} ({len(reply)}B)")
                    dump("tx", reply)
                    conn.sendall(reply)
    finally:
        st["closed"] = True
        try:
            conn.close()
        except OSError:
            pass
        log(f"#{idx} closed")


def main():
    global PORT, HOLD, BIND_IP, PROBE_MODE, QUIET, STATE_PROBE, CC_PROBE, A2_PROBE, SILENT_PROBE, SESSION_PROBE, CC_FIRST_PROBE, A2_FIRST_PROBE, SWEEP_A2, SWEEP_I, A2_ONLY, ALT_PROBE, ALT_DONE, A2_CC_DELAY, PUSH_ON_ACCEPT, LAST_WAS_SEARCH, A2_RESULT, RESULT_CMD, ACK_CMD, ACK_PAYLOAD, REAL_FRAMES, CC_AFTER, CC_AFTER_HB, ALT_CC, COOP, COOP_FAKE
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            PORT = int(args[i + 1])
        if a == "--hold" and i + 1 < len(args):
            HOLD = float(args[i + 1])
        if a == "--bind" and i + 1 < len(args):
            BIND_IP = args[i + 1]
    if "--ladder" in args:          # baton<=9 behaviour (S1..S7 per connection)
        PROBE_MODE = False
    if "--coop" in args:            # 2026-11-01: 店内協力联机模式
        COOP = True
        PROBE_MODE = False
        QUIET = False
    if "--coop-fake" in args:
        COOP = True
        COOP_FAKE = True
        PROBE_MODE = False
        QUIET = False
    if "--real-frames" in args:    # 2026-10-30: 照抄 TPO 抓包真帧
        REAL_FRAMES = True
        PROBE_MODE = False
        QUIET = False
    for a in args:
        if a.startswith("--cc-after="):
            CC_AFTER = int(a.split("=", 1)[1])
    if "--quiet" in args:           # S1 once, then heartbeats only
        QUIET = True
        PROBE_MODE = False
    if "--cc-probe" in args:        # A2 + CC in one send when in search state
        CC_PROBE = True
        PROBE_MODE = False
    for a in args:
        if a.startswith("--a2-then-cc="):
            A2_CC_DELAY = max(0.0, float(a.split("=", 1)[1]) / 1000.0)
            QUIET = False
            PROBE_MODE = False
    for a in args:
        if a.startswith("--ack-cmd="):
            ACK_CMD = int(a.split("=", 1)[1], 0)
            QUIET = False
            PROBE_MODE = False
        if a.startswith("--ack-payload="):
            ACK_PAYLOAD = a.split("=", 1)[1]
        if a.startswith("--result-cmd="):
            RESULT_CMD = int(a.split("=", 1)[1], 0)
            A2_RESULT = True
            QUIET = False
            PROBE_MODE = False
    if "--a2-result" in args:          # put the MtchResult inside the A2 payload
        A2_RESULT = True
        QUIET = False
        PROBE_MODE = False
    if "--push-on-accept" in args:     # send CC right when the socket is accepted
        PUSH_ON_ACCEPT = True
        QUIET = False
        PROBE_MODE = False
    if "--alt-probe" in args:          # alternate A2 and CC across connections
        ALT_PROBE = True
        QUIET = False
        PROBE_MODE = False
    if "--a2-only" in args:            # A2 with the a2_probe.txt payload, nothing else
        A2_ONLY = True
        QUIET = False
        PROBE_MODE = False
    if "--sweep-a2" in args:           # cycle A2 status 0..7
        SWEEP_A2 = True
        QUIET = False
        PROBE_MODE = False
    if "--a2-first-probe" in args:    # A2 then CC in one write
        A2_FIRST_PROBE = True
        QUIET = False
        PROBE_MODE = False
    if "--cc-first-probe" in args:    # CC then A2 in one write
        CC_FIRST_PROBE = True
        QUIET = False
        PROBE_MODE = False
    if "--session-probe" in args:     # hold the session and push a CC later
        SESSION_PROBE = True
        QUIET = False
        PROBE_MODE = False
    if "--silent-probe" in args:      # accept, log, send nothing
        SILENT_PROBE = True
        QUIET = False
        PROBE_MODE = False
    if "--a2-probe" in args:        # A2 carrying the matching-response struct
        A2_PROBE = True
        QUIET = False
        PROBE_MODE = False
    if "--state-probe" in args:     # dispatch on login state byte (off40)
        STATE_PROBE = True
        PROBE_MODE = False
    if "--list" in args:
        demo = bytes(84)
        for i, (n, b) in enumerate(build_probes(demo) if PROBE_MODE
                                   else build_candidates(demo)):
            print(f"{i:2d}  {n:38s} {len(b):3d}B  {b.hex()}")
        return 0

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((BIND_IP, PORT))
    except OSError as exc:
        log(f"bind {BIND_IP}:{PORT} failed: {exc!r}")
        return 1
    srv.listen(8)
    srv.settimeout(1.0)
    log(f"=== match_server up on {BIND_IP}:{PORT} (hold={HOLD:.0f}s) ===")
    log("baton9: reply = [type flags len][cmd=A2 flags len f4 f8][payload]; "
        "candidates H1..H10, start index from variant_start.txt")
    while True:
        try:
            c, p = srv.accept()
        except socket.timeout:
            continue
        with lock:
            conn_seq[0] += 1
            idx = conn_seq[0]
        threading.Thread(target=handle, args=(c, p, idx, HOLD), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
