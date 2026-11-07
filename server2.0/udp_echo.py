"""UDP sniffer/responder for the game's spSif match probe.

The game binds <local>:23456 and sends 8-byte datagrams to <match host>:52002:

    magic(4) = 00 01 8E 8E   +   counter/timestamp(4)

`--pong` answers with the 12-byte reply that spSif actually parses
(sub_E80F60 -> magic(4) ts(4) len(1) status(1) pad(2)).  `--echo` mirrors the
8-byte ping back, which spSif **rejects**: bytes 8/9 are absent, the
`*(BYTE*)(a1+9) <= 1` check fails, and the ping never completes.

Measured 2026-10-21 14:0x (same game process, live A/B):
    --echo  -> spSif state 1 / result 0 (never answered), HUD 全国 dark
    --pong  -> spSif state 2 / result 3 (ok),               HUD 全国 green

Usage:  python udp_echo.py [--echo | --pong | --reply HEXBYTES]
"""
import socket
import os
import sys
import os
import time
import os
BASE = os.path.dirname(os.path.abspath(__file__))

BIND = ("0.0.0.0", 52002)
LOG = os.path.join(BASE, "data", "udp_echo.log")


def log(line):
    stamp = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
    print(f"[{stamp}] {line}", flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"[{stamp}] {line}\n")


def pong_for(ping):
    """spSif ping reply: echo magic+ts, then len=0, status=0, 2 pad bytes."""
    return ping[:8].ljust(8, b"\x00") + b"\x00" * 4


def main():
    reply = None
    if len(sys.argv) >= 2 and sys.argv[1] == "--echo":
        reply = "echo"
    elif len(sys.argv) >= 2 and sys.argv[1] == "--pong":
        reply = "pong"
    elif len(sys.argv) >= 3 and sys.argv[1] == "--reply":
        reply = bytes.fromhex(sys.argv[2])

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(BIND)
    s.settimeout(1.0)
    log(f"listening on {BIND[0]}:{BIND[1]} reply={reply if isinstance(reply,str) else (reply.hex() if reply else None)}")
    while True:
        try:
            data, peer = s.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError as exc:
            log(f"recv error: {exc!r}")
            break
        log(f"rx {peer[0]}:{peer[1]} len={len(data)} {data.hex()}")
        if reply is not None:
            if reply == "echo":
                out = data
            elif reply == "pong":
                out = pong_for(data)
            else:
                out = reply
            s.sendto(out, peer)
            log(f"tx {peer[0]}:{peer[1]} {out.hex()}")


if __name__ == "__main__":
    main()
