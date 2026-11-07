"""ALL.Net HTTP responder for the game (POST /a and friends).

Request framing (captured from the game):
    POST /a HTTP/1.0
    User-Agent: ALL.Net_PC_Win2/ver1.0
    Content-Type: application/x-www-form-urlencoded
    <body> = base64(zlib("k=v&k=v"))

Response: plain text "k=v&k=v\n" (text/plain).  If the file
<install>\\data\\allnet_resp.txt exists it is used verbatim (with ${utc}
substituted); otherwise a default minime-style PowerOn response is sent.

Every request/response is appended to <install>\\data\\allnet.log.
"""
import base64

import os

import re

import socket

import struct

import sys

import threading

import time

import zlib

from datetime import datetime, timezone
BASE = os.path.dirname(os.path.abspath(__file__))

try:                      # GBK consoles must not kill the responder
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except (AttributeError, ValueError):
    pass


LOG = os.path.join(BASE, "data", "allnet.log")
RESP_FILE = os.path.join(BASE, "data", "allnet_resp.txt")
# If this file exists, binary ("x-rd2-*") requests get a compressed reply
# whose decompressed payload is exactly this file's bytes.  Delete the file
# to go back to log-only mode (text reply, the client will just reject it).
RD2_PAYLOAD = os.path.join(BASE, "data", "rd2_payload.bin")
# Marker: when this file exists, rd2 requests are answered with the raw
# payload (no Pragma: DFI, no zlib) to exercise sub_8170A0's plain branch.
RD2_PLAIN_ON = os.path.join(BASE, "data", "rd2_plain.on")
# Marker: when this + rd2_payload.bin exist, the router is bypassed and the
# file is sent verbatim (for one-off experiments).
RD2_MANUAL_ON = os.path.join(BASE, "data", "rd2_manual.on")

# Marker (2026-10-22 baton 7): echo the client's own uploaded save back in the
# NetData Start(0x05)/Item(0x09) responses instead of zeros.  Every rd2 request
# carries the 4019-byte card/save record at offset 0x36; returning zeros wipes
# the client's progress (story flags included).  For the experiment the response
# keeps its class size and copies the request prefix, so over-sizing stays safe.
ECHO_SAVE_ON = os.path.join(BASE, "data", "echo_save.on")
# 2026-10-22 baton 8: the End(0x07) response `status` experiment used to be tied to
# the echo switch; keep it independent so v0 (all-zero) responses can be tested
# with status=1.  Present = answer status=1, absent = answer status=0.
END_STATUS1_ON = os.path.join(BASE, "data", "end_status1.on")
# Directory holding per-command raw response overrides: resp_<CMD>.bin
OVERRIDE_DIR = os.path.join(BASE, "data", "resp_override")
ECHO_START_FIXED = os.path.join(BASE, "data", "echo_start_fixed.on")
# 2026-10-23 baton 9: deliberately reproduce the *old* echo bug, which is the
# only state in which the three Online entries + NEW SCENARIO were ever seen
# lit (baton 7).  Old code was `resp[0x36:] = req[0x36:]` while the true
# offsets are req card_body @0x6E / resp card_body @0x0C -- i.e. the response's
# card_body got 0x2A leading zeros + the 56-byte save header + the real save
# shifted by 0x38.  That garbage saturated the unlock bitmask.
# Marker `echo_oldbug.on` (content "last_end" -> source = last End body, else
# the live request).  Takes priority over ECHO_START_FIXED.
ECHO_OLDBUG = os.path.join(BASE, "data", "echo_oldbug.on")
FILL_START_U32 = os.path.join(BASE, "data", "fill_start_u32.on")
# 2026-10-23 (baton 7 request): controlled replay of the "three Online entries
# lit" state WITHOUT touching card_body.  The Start(0x05) response layout is
#   status(4) card_body(6604) user_game_info(1752) 6*u32 rest
# so user_game_info sits at 0x0C+6604 = 0x19D8 .. 0x20B0.  Filling only that
# window with a byte pattern tests whether the "available mode/new quest" bits
# live there (the old-bug replay saturated card_body *and* this window, which is
# why it also faked Clear).  Content = hex/dec byte, default 0x01.
FILL_USERINFO = os.path.join(BASE, "data", "fill_userinfo.on")
# 2026-10-26: range-limited variant of fill_userinfo.
# Content: "<start_hex>,<end_hex>,<value_hex>" relative to user_game_info
# (0x19D8); hot-read per Start request.
FILL_USERINFO_RANGE = os.path.join(BASE, "data", "fill_userinfo_range.txt")
# 2026-10-23 (baton 7 request): Start(0x05) response `status` @0x08 experiment.
# The 18:21 v1 full echo accidentally set status = 0x41373245 ("A72E") and the
# three Online modes became really selectable; every later echo kept status=0
# and they stayed grey.  Content = hex/dec u32, default 0xFFFFFFFF.
SET_START_STATUS = os.path.join(BASE, "data", "set_start_status.on")
# Candidate ladder for the Start(0x04) response `status` mask.  Baton 7 saw
# 0xFFFFFFFF (illegal) and the accidental 0x41373245 ("A72E") both light the
# three Online rows, so status is a flag mask; these are the plausible legal
# values, smallest/most regular first.
START_STATUS_CANDIDATES = [
    0x00000007, 0x0000000F, 0x00000003, 0x00000001, 0x00000005,
    0x00000045, 0x00000015, 0x00000055, 0x000000FF, 0x0000001F,
    0x0000003F, 0x00003F3F, 0x000F0000, 0x001F0000, 0x0F000000,
    0x0000007F, 0x0000FFFF, 0xFFFFFFFF,
]
_status_lock = threading.Lock()
_status_cycle = [0]
# 2026-10-22: the authoritative post-clear save is the one the client uploads in
# the End(0x06) request -- the card the next session starts from does NOT have
# the clear flag.  So remember the last End body and serve its save region in the
# Start(0x05)/Item(0x09) responses.
LAST_END = os.path.join(BASE, "data", "last_end.bin")

# ------------------------------------------------------------------ NetData
# The rd2 body is a NetData message.  All integers are BIG-ENDIAN: the
# deserializer is sub_C40CF0, which does `*out = ntohl(*(u32*)cur)`.
# Requests carry command N, responses carry N+1 and a class-specific size:
#   0x00 NetDataInitRequest     -> 0x01 InitResponse     196 B (sub_9CA540)
#   0x10 NetDataGameConfRequest -> 0x11 GameConfResponse 988 B (sub_9C2210)
NETDATA_MAGIC = 0xB84058BD
# cmd -> (response cmd, response size).  Source: each NetData*Response class's
# vtable -- the slot holding the deserializer thunk is at +0x1C, the size
# getter lands at +0x28 and the command getter at +0x2C (2026-10-21, baton 6).
# Verified against five independently known values (Init 196 / GameConf 988 /
# Ping 1664 / Shop 4692 / Start 8948 -- the last one fixed the crash) and
# against the commands actually observed on the wire (0x0A 0x12 0x14 0x16).
#
# The client throws std::underflow_error when the reply is SHORTER than the
# class size (`if (a3 < vtable[0x30](this)) throw`), so over-sizing is harmless
# but under-sizing kills the whole NetData task -- that is exactly what the old
# "default 988" did to cmd 0x04.
NETDATA_RESP = {
    0x00: (0x01, 196),    # NetDataInitResponse         (sub_9CA540)
    0x02: (0x03, 1664),   # NetDataPingResponse         (sub_9D6C70)
    0x04: (0x05, 8948),   # NetDataStartResponse        (sub_9ED950)
    0x06: (0x07, 22),     # NetDataEndResponse
    0x08: (0x09, 6616),   # NetDataItemResponse
    0x0A: (0x0B, 96),     # NetDataRecognizeResponse
    0x0C: (0x0D, 12),     # NetDataPasscodeResultResponse
    0x0E: (0x0F, 4692),   # NetDataShopResponse         (sub_9E81C0)
    0x10: (0x11, 988),    # NetDataGameConfResponse     (sub_9C2210)
    0x12: (0x13, 485),    # NetDataEventInfoResponse
    0x14: (0x15, 46),     # NetDataCampaignInfoResponse
    0x16: (0x17, 12),     # NetDataFnetRegistResponse
    0x18: (0x19, 12),     # NetDataFnetUnregistResponse
    0x1A: (0x1B, 16),     # NetDataReissueEntryResponse
    0x1C: (0x1D, 6676),   # NetDataReissueExecResponse
    0x1E: (0x1F, 6672),   # NetDataGetAvatarInfoResponse
}


def build_netdata_response(req: bytes):
    """Return (payload, tag) for a NetData request body."""
    if len(req) < 8:
        return None, "short request"
    magic, cmd = struct.unpack(">II", req[:8])
    if magic != NETDATA_MAGIC:
        return None, f"bad magic 0x{magic:08X}"
    if cmd in NETDATA_RESP:
        resp_cmd, size = NETDATA_RESP[cmd]
        tag = f"req cmd=0x{cmd:02X} -> resp cmd=0x{resp_cmd:02X} size={size}"
    else:
        # Unknown command.  The client throws underflow_error when the reply is
        # shorter than its class size, so a big request must never get the small
        # default -- shout in the log instead; that is how a brand new command
        # (e.g. the end-of-session save) gets noticed without playing a game.
        resp_cmd, size = cmd + 1, 988
        tag = (f"!!! UNKNOWN CMD 0x{cmd:02X} (request {len(req)}B) "
               f"-> default {size}B, may underflow")
    b = bytearray(size)
    struct.pack_into(">II", b, 0, NETDATA_MAGIC, resp_cmd)
    # 2026-10-22 baton 8: raw response override for fast experiments.  If a file
    # dongle\resp_<CMD>.bin exists (CMD = response command, e.g. 05 for Start),
    # its bytes are used verbatim (zero padded to the class size) and nothing
    # else is applied.  The file is read per request, so tests need no restart.
    ov_path = os.path.join(OVERRIDE_DIR, f"resp_{resp_cmd:02X}.bin")
    if os.path.exists(ov_path):
        try:
            data = open(ov_path, "rb").read()
            n = min(len(data), size)
            b[0:n] = data[0:n]
            return bytes(b), tag + f" [OVERRIDE {os.path.basename(ov_path)} {n}B]"
        except Exception:
            pass
    # 2026-10-23 baton 9: old-bug replay (see ECHO_OLDBUG).  Kept byte-for-byte
    # equivalent to the baton-7 code so the "all online modes lit" state can be
    # reproduced on demand.
    if cmd in (0x04, 0x08) and os.path.exists(ECHO_OLDBUG):
        # marker content: "<hex off>[:last_end]" e.g. "0x36" / "0x0C" / "0x0C:last_end"
        spec = "0x36"
        try:
            spec = open(ECHO_OLDBUG, "r", encoding="utf-8", errors="replace").read().strip() or "0x36"
        except Exception:
            pass
        use_last = spec.lower().endswith(":last_end")
        if use_last:
            spec = spec[: -len(":last_end")]
        try:
            off = int(spec, 16) if spec.lower().startswith("0x") else int(spec, 0)
        except Exception:
            off = 0x36
        if spec.strip().lower() == "ff":
            # diagnostic: saturate the whole card_body.  If this does NOT light
            # the online rows, the "unlock bits live in the save" theory is dead.
            b[0x0C:0x0C + 6604] = b"\xFF" * 6604
            return bytes(b), tag + " [ECHO-OLDBUG FF card_body=0xFF*6604]"
        src, tag2 = req, "REQ"
        if use_last and os.path.exists(LAST_END):
            try:
                cand = open(LAST_END, "rb").read()
                if len(cand) > off + 64:
                    src, tag2 = cand, "LAST_END"
            except Exception:
                pass
        end = min(len(src), size)
        if off < end:
            b[off:end] = src[off:end]
        return bytes(b), (tag + f" [ECHO-OLDBUG {tag2} off=0x{off:X} len={end - off}"
                                 f" -- reproducing the offset bug]")
    # 2026-10-22 baton 8: corrected save echo for Start(0x04) and Item(0x08).
    # Response layout (sub_9EDAC0): status(4) card_body(6604) user_game_info(1752)
    # Item(0x09) response is just status(4)+card_body(6604)=6616. card_body at 0x0C.
    # Request layout (sub_9EA840): ... card_body at 0x6E.  The old echo copied
    # req[0x36:] -> resp[0x36:], 0x38 bytes off, which corrupted the save.
    if cmd == 0x04:
        # baton 10: we have never looked at what the client actually sends in
        # NetData Start.  Dump the raw request so the fields we currently zero
        # (user_game_info / the 6 u32 tail) can be compared with what the client
        # already knows.
        try:
            with open(os.path.join(BASE, "data", "_am04_req.bin"), "wb") as fh:
                fh.write(req)
            log(f"    [AM04] request dumped {len(req)}B -> _am04_req.bin")
        except Exception:
            pass
    if cmd in (0x04, 0x08) and os.path.exists(ECHO_START_FIXED):
        src = req[0x6E:0x6E + 6604]
        n = min(len(src), size - 0x0C)
        if n > 0:
            b[0x0C:0x0C + n] = src[0:n]
        extra = ''
        if cmd == 0x04 and os.path.exists(FILL_START_U32):
            # the 6 u32 after user_game_info: card_id, play_count, commit_count,
            # use_count, play_count_cmp, session_id.  The request carries the
            # last five in its 56-byte save header at +0x5A..+0x6E.
            vals = req[0x5A:0x6E]
            if len(vals) == 20:
                b[0x20B4:0x20C8] = vals
                extra = ' +u32'
        if cmd == 0x04 and os.path.exists(FILL_USERINFO):
            # controlled replay: fill ONLY user_game_info (0x19D8..0x20B0),
            # never card_body -- tests if the "online modes lit" bits live here
            val = 0x01
            try:
                spec = open(FILL_USERINFO, "r", encoding="utf-8", errors="replace").read().strip()
                if spec:
                    val = int(spec, 16) if spec.lower().startswith("0x") else int(spec, 0)
            except Exception:
                pass
            val &= 0xFF
            lo, hi = 0x19D8, min(0x20B0, size)
            if lo < hi:
                b[lo:hi] = bytes([val]) * (hi - lo)
                extra += f' [FILL-USERINFO 0x{lo:X}..0x{hi:X}={val:02X}]'
        if cmd == 0x04 and os.path.exists(FILL_USERINFO_RANGE):
            try:
                spec = open(FILL_USERINFO_RANGE, "r", encoding="utf-8", errors="replace").read().strip()
                parts = [x.strip() for x in spec.split(",")]
                lo = int(parts[0], 0)
                hi = int(parts[1], 0)
                val = int(parts[2], 0) & 0xFF
                base = 0x19D8
                maxlen = 0x6D8
                lo = max(0, min(lo, maxlen))
                hi = max(0, min(hi, maxlen))
                if lo < hi:
                    b[base + lo:base + hi] = bytes([val]) * (hi - lo)
                    extra += f' [FILL-USERINFO-RANGE {lo:X}..{hi:X}={val:02X}]'
            except Exception as exc:
                extra += f' [FILL-USERINFO-RANGE error {exc!r}]'
        if cmd == 0x04 and os.path.exists(SET_START_STATUS):
            sv = 0xFFFFFFFF
            try:
                spec = open(SET_START_STATUS, "r", encoding="utf-8", errors="replace").read().strip()
                if spec:
                    sv = int(spec, 16) if spec.lower().startswith("0x") else int(spec, 0)
            except Exception:
                pass
            if str(spec).strip().lower() == "cycle":
                # 2026-10-23: walk a candidate ladder, one value per Start(0x04).
                # The three Online rows light when status has the right bits, so
                # the user just re-enters Game Mode Select until the screen
                # changes and we read the winning value back from this log.
                with _status_lock:
                    idx = _status_cycle[0]
                    _status_cycle[0] = (idx + 1) % len(START_STATUS_CANDIDATES)
                sv = START_STATUS_CANDIDATES[idx]
                extra += f' [STATUS-CYCLE #{idx} = 0x{sv:08X}]'
                log(f"    STATUS-CYCLE #{idx}/{len(START_STATUS_CANDIDATES)-1} -> 0x{sv:08X}")
            else:
                sv &= 0xFFFFFFFF
                extra += f' [STATUS=0x{sv:08X}]'
            struct.pack_into(">I", b, 0x08, sv)
        if cmd == 0x04:
            # baton 10: keep the exact bytes we hand back, so the request/response
            # pair can be diffed field by field afterwards.
            try:
                with open(os.path.join(BASE, "data", "_am04_resp.bin"), "wb") as fh:
                    fh.write(bytes(b))
                log(f"    [AM04] response dumped {len(b)}B -> _am04_resp.bin")
            except Exception:
                pass
        return bytes(b), tag + f" [ECHO-START-FIXED req@0x6E -> resp@0x0C {n}B{extra}]"
    if cmd == 0x06:
        try:
            with open(LAST_END, "wb") as f:
                f.write(req)
        except Exception:
            pass
        # 2026-10-22: NetDataEndResponse (22B) layout, from its Binary2Class
        # (sub_9B2790): magic(4) cmd(4) status(4) fieldA(4) fieldB(4) fieldC(2).
        # All-zero may mean "not accepted"; answer status=1 while the marker
        # file exists (independent of the echo switch), keep the rest zero.
        if os.path.exists(END_STATUS1_ON):
            struct.pack_into(">III", b, 8, 1, 0, 0)
            struct.pack_into(">H", b, 20, 0)
    if os.path.exists(ECHO_SAVE_ON) and cmd in (0x04, 0x08):
        # v4: prefer the last End(0x06) body as the save source -- that is the
        # only upload that contains the just-earned clear flags; the card the
        # next session starts from does not have them.
        src = req
        tag = "REQ"
        if os.path.exists(LAST_END):
            try:
                cand = open(LAST_END, "rb").read()
                if len(cand) > 0x36 + 64:
                    src, tag = cand, "LAST_END"
            except Exception:
                pass
        off = 0x36
        end = min(len(src), size)
        if off < end:
            b[off:end] = src[off:end]
        return bytes(b), (f"req cmd=0x{cmd:02X} -> resp cmd=0x{resp_cmd:02X} size={size} "
                          f"[ECHO-SAVE {tag} off=0x{off:X} len={end-off}]")
    return bytes(b), f"req cmd=0x{cmd:02X} -> resp cmd=0x{resp_cmd:02X} size={size}"
BIND = ("0.0.0.0", 80)

DEFAULT_RESP = (
    "stat=1"
    "&uri=http://0.0.0.0/"
    "&host=0.0.0.0"
    "&place_id=123"
    "&name=TEST"
    "&nickname=TEST"
    "&region0=1"
    "&region_name0=W"
    "&region_name1=X"
    "&region_name2=Y"
    "&region_name3=Z"
    "&country=JPN"
    "&allnet_id=456"
    "&client_timezone=+0800"
    "&utc_time=${utc}"
    "&setting="
    "&res_ver=3"
    "&token="
)


def log(msg):
    line = f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def decode_body(raw: bytes) -> str:
    body = raw.strip()
    if not body:
        return ""
    try:
        z = base64.b64decode(body, validate=False)
        if z[:1] == b"\x78":
            return zlib.decompress(z).decode("latin-1", "replace").strip()
        return z[:400].decode("latin-1", "replace")
    except Exception as exc:
        return f"<decode failed: {exc!r}> raw={raw[:200]!r}"


def _now_local():
    """Wall clock as the cabinet should see it.

    SRV_FAKE_TIME=HH:MM:SS keeps the shop inside business hours regardless of
    what the host clock says (00:01 makes the game print "we are closed").
    """
    fake = os.environ.get("SRV_FAKE_TIME", "").strip()
    if fake:
        try:
            hh, mm, ss = (int(x) for x in fake.split(":"))
            base = datetime.now()
            return base.replace(hour=hh, minute=mm, second=ss, microsecond=0)
        except ValueError:
            pass
    return datetime.now()


def utc_now() -> str:
    return _now_local().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def server_time_fields() -> dict:
    """The six integer fields sub_E6B1A0 (0xE6B1A0) parses with strstr+strtol.

    2026-10-21: -44 was *not* "stat= missing" -- sub_E6B2F0 first accepts
    stat=1 (sub_E6B0A0), then requires uri=+host= (sub_E6B140) and finally
    year/month/day/hour/minute/second (sub_E6B1A0).  Each missing field
    returns -44.  The old responder never sent the date fields, which is
    why every body-encoding variant ended in -44.

    2026-10-21 (2nd issue): these fields are also the *shop clock*
    (sub_559C40 -> sub_E69BA0 -> struct tm).  Sending UTC made the cabinet
    think it was 04:53 and show CLOSING_MESSAGE_ADV_CLOSE ("鏈棩銇偛銉笺儬
    銈广偪銉笺儓銇窢銈佸垏銈娿伨銇椼仧").  Send LOCAL time instead -- the arcade is
    "open" whenever the wall clock is in business hours.
    """
    now = _now_local()          # local time; SRV_FAKE_TIME overrides
    return {
        "year": now.strftime("%Y"),
        "month": str(now.month),
        "day": str(now.day),
        "hour": str(now.hour),
        "minute": str(now.minute),
        "second": str(now.second),
    }


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def build_rd2_response(payload: bytes):
    """Reply contract for the binary protocol (sub_816470 request builder,
    sub_8170A0 response validator):

        Pragma: DFI
        x-rd2-comp-crc:   CRC32(zlib(payload))
        x-rd2-comp-len:   len(zlib(payload))
        x-rd2-uncomp-crc: CRC32(payload)
        x-rd2-uncomp-len: len(payload)

    The client checks all four; the body is zlib-inflated into its buffer.
    """
    comp = zlib.compress(payload)
    # NOTE: the client reads these four values with _atoi64() (sub_816FC0 ->
    # sub_816DB0), i.e. DECIMAL -- a "%08x" value like "0f028790" parses as 0
    # and the CRC check silently fails.  Keep them decimal.
    extra = [
        "Pragma: DFI",
        f"x-rd2-comp-crc: {crc32(comp)}",
        f"x-rd2-comp-len: {len(comp)}",
        f"x-rd2-uncomp-crc: {crc32(payload)}",
        f"x-rd2-uncomp-len: {len(payload)}",
        f"Content-Length: {len(comp)}",
        "Connection: close",
    ]
    return comp, extra


def log_binary(body: bytes):
    log(f"    BODYHEX({len(body)}B): {body.hex()}")
    try:
        dec = zlib.decompress(body)
        log(f"    BODY-INFLATE({len(dec)}B): {dec[:600]!r}")
    except Exception as exc:
        log(f"    BODY-INFLATE failed: {exc!r}")
        for wbits in (15, -15, 31):
            try:
                dec = zlib.decompress(body, wbits)
                log(f"    BODY-INFLATE(wbits={wbits}) ({len(dec)}B): {dec[:600]!r}")
                break
            except Exception:
                pass


def build_response():
    """Returns (body_bytes, extra_header_lines)."""
    extra_headers = []
    try:
        with open(RESP_FILE, "r", encoding="utf-8-sig") as f:
            txt = f.read()
        log("using custom response from allnet_resp.txt")
    except FileNotFoundError:
        txt = DEFAULT_RESP
    txt = txt.replace("${utc}", utc_now())
    for k, v in server_time_fields().items():
        txt = txt.replace("${" + k + "}", v)
    if not txt.endswith("\n"):
        txt += "\n"
    raw = txt.encode("latin-1", "replace")
    # first line selects the body encoding:
    #   #zlib      -> raw zlib stream
    #   #b64zlib   -> base64(zlib(text))   (same framing the client sends)
    #   #b64       -> base64(text)
    #   #dfi       -> Pragma: DFI + base64(zlib(text)) + "\n"  (what the client wants)
    #   anything else -> plain text
    if txt.startswith("#"):
        marker, _, rest = txt.partition("\n")
        body = rest.encode("latin-1", "replace")
        marker = marker.strip().lower()
        log(f"response mode: {marker}")
        if marker == "#zlib":
            return zlib.compress(body), extra_headers
        if marker == "#b64zlib":
            return base64.b64encode(zlib.compress(body)), extra_headers
        if marker == "#b64":
            return base64.b64encode(body), extra_headers
        if marker in ("#dfi", "#dfi1", "#dfi2", "#dfi3", "#dfi4", "#dfi5"):
            # sub_E6BBF0: response must carry "Pragma: DFI" -> v5==1 ->
            # sub_E6BD40 decodes each \r\n-terminated line as base64, then
            # zlib-inflates the concatenation (inflateInit2 windowBits=15).
            # Variants 1..5 are the remaining unknowns from the -44 checklist.
            extra_headers.append("Pragma: DFI")
            text = body
            wrap, end, lead, textnl = 76, "\r\n", b"", True
            if marker == "#dfi1":
                wrap = 0                     # one single base64 line
            elif marker == "#dfi2":
                wrap = 64                    # different line width
            elif marker == "#dfi3":
                end = "\n"                   # last line LF only
            elif marker == "#dfi4":
                lead = b"\r\n"               # extra CRLF before the b64
            elif marker == "#dfi5":
                textnl = False               # compress text without trailing \n
            if not textnl and text.endswith(b"\n"):
                text = text[:-1]
            b64 = base64.b64encode(zlib.compress(text)).decode("ascii")
            if wrap:
                lines = [b64[i:i + wrap] for i in range(0, len(b64), wrap)] or [""]
            else:
                lines = [b64]
            term = "\n" if marker == "#dfi3" else "\r\n"
            payload = ("\r\n".join(lines) + term).encode("ascii")
            return lead + payload, extra_headers
    return raw, extra_headers


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(BIND)
    except OSError as exc:
        log(f"bind {BIND} failed: {exc!r}")
        return 1
    srv.listen(32)
    srv.settimeout(1.0)
    log(f"ALL.Net responder on {BIND[0]}:{BIND[1]}")
    # NOTE (baton 6, 2026-10-21): this used to be a hard `deadline = time.time()
    # + 3600`.  It killed the responder exactly one hour after start, so the
    # 13:15 session silently lost ALL.Net at 14:15:53 -- the game kept running,
    # the rd2 chain stopped, and every HUD icon went dark mid-session.  Run
    # until the process is killed; pass `--hours N` only if a cap is wanted.
    deadline = None
    for i, a in enumerate(sys.argv):
        if a == "--hours" and i + 1 < len(sys.argv):
            deadline = time.time() + float(sys.argv[i + 1]) * 3600
    n = 0
    while deadline is None or time.time() < deadline:
        try:
            conn, peer = srv.accept()
        except socket.timeout:
            continue
        n += 1
        conn.settimeout(3.0)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            headers = head.decode("latin-1", "replace")
            m = re.search(r"(?im)^Content-Length:\s*(\d+)", headers)
            need = int(m.group(1)) if m else 0
            body = rest
            while len(body) < need:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk
            first = headers.split("\r\n")[0] if headers else "?"
            log(f"#{n} {peer[0]}:{peer[1]}  {first}")
            for line in headers.split("\r\n")[1:12]:
                if line.strip():
                    log(f"    {line}")
            text = decode_body(body)
            is_rd2 = b"x-rd2-uncomp-len" in data.lower()
            if is_rd2:
                log_binary(body)
                req = None
                try:
                    req = zlib.decompress(body)
                except Exception:
                    pass
                payload, tag = None, ""
                if os.path.exists(RD2_MANUAL_ON) and os.path.exists(RD2_PAYLOAD):
                    payload = open(RD2_PAYLOAD, "rb").read()
                    tag = "manual override"
                elif req is not None:
                    payload, tag = build_netdata_response(req)
                if payload is None:
                    log("    RD2: no request payload, sending text reply")
                    resp, extra = build_response()
                else:
                    log(f"    RD2 {tag} -> {len(payload)}B")
                    if os.path.exists(RD2_PLAIN_ON):
                        # No Pragma/DFI and no compression: sub_8170A0 takes
                        # the "raw body" branch and the NetData parser sees
                        # the payload bytes directly.
                        resp = payload
                        extra = [
                            "Content-Type: application/octet-stream",
                            f"Content-Length: {len(payload)}",
                            "Connection: close",
                        ]
                        log(f"    RD2 PLAIN RESP {len(payload)}B")
                    else:
                        resp, extra = build_rd2_response(payload)
                        log(f"    RD2 DFI RESP payload={len(payload)}B comp={len(resp)}B")
            else:
                log(f"    BODY({len(body)}B) -> {text[:400]}")
                resp, extra = build_response()
            log(f"    RESP: {resp[:120]!r}{' (+%d extra headers)' % len(extra) if extra else ''}")
            hdr = b"HTTP/1.0 200 OK\r\n"
            for h in extra:
                hdr += h.encode("latin-1") + b"\r\n"
            if not extra:
                hdr += (
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(resp)).encode() + b"\r\n"
                    b"Connection: close\r\n"
                )
            hdr += b"\r\n"
            conn.sendall(hdr + resp)
        except Exception as exc:
            log(f"#{n} error: {exc!r}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
    log("exit")
    return 0


if __name__ == "__main__":
    sys.exit(main())

