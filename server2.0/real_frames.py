# -*- coding: utf-8 -*-
import struct
"""从 2026-10-30 17:05~17:07 的 TPO 抓包中提取的真实服务器帧（3951 通道）。

A2/f4/f8 句柄来自抓包：f4=0xB0400000 固定，f8=0x10400022 起每次 +1。
使用时用 patch(handle) 把 f8（以及 A2 载荷末尾的回显）改成指定值。
"""

REAL_A2 = bytes.fromhex(
    "0800001ca2000010b040000010400022000000000005001e0000000010400022")
REAL_T10 = bytes.fromhex(
    "1000009c0000008eb040000010400022000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000001000000020000004600000001000000020000001e000000460000001e0000")
REAL_84 = bytes.fromhex(
    "0800001084000004b04000001040002200000000")
REAL_T10_RSP = bytes.fromhex(
    "100000b8000000a9b04000001040002300000000300100000010400023040200020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

REAL_CC = bytes.fromhex(
    "080000d0cc0000c4b04000001040002330400001a484f69a000000000f71000000020008000000a931020068780024000010400023040200020001000000000000000000001040002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

F4 = 0xB0400000
F8_BASE = 0x10400022


def _patch_f8(frame, f8):
    b = bytearray(frame)
    struct.pack_into(">I", b, 12, f8 & 0xFFFFFFFF)   # 内层 f8
    return bytes(b)


def a2(f8):
    b = bytearray(_patch_f8(REAL_A2, f8))
    struct.pack_into(">I", b, 28, f8 & 0xFFFFFFFF)   # 载荷末尾回显
    return bytes(b)


def t10(f8):
    return _patch_f8(REAL_T10, f8)


def ack04(f8):
    """服务器对客户端 20B「0x04 确认帧」的应答（2026-11-07 从抓包抄的）。

    抓包：server -> client = 08 00 00 10 | 04 00 00 04 | <f8> | b0 40 00 00 | 00000000
    而 84 00 00 04 那一帧是**客户端回给服务器**的，以前被我们当成服务器应答发回去，
    客户端收到自己的 ack 就判协议违规、立刻断开（画面转本地模拟 → 通信异常图标）。
    """
    return (bytes.fromhex('08000010') + bytes.fromhex('04000004') +
            (f8 & 0xFFFFFFFF).to_bytes(4, 'big') + bytes.fromhex('b0400000') + bytes(4))


def ack84(f8):
    return _patch_f8(REAL_84, f8)


def cc(f8):
    """CC，把所有句柄都改成当前会话。

    依据 2026-10-31 全流程抓包：真机 CC 里出现两个句柄
      0x1040000A = 当前会话 f8
      0x1040000B = f8 + 1（队伍/下一对象）
    抓包底本用的是 0x23 / 0x24，所以这里统一替换。
    """
    b = bytearray(REAL_CC)
    cur = (f8 & 0xFFFFFFFF).to_bytes(4, 'big')
    nxt = ((f8 + 1) & 0xFFFFFFFF).to_bytes(4, 'big')
    for old, rep in ((b'\x10\x40\x00\x23', cur), (b'\x10\x40\x00\x24', nxt)):
        i = 0
        while True:
            i = bytes(b).find(old, i)
            if i < 0:
                break
            b[i:i + 4] = rep
            i += 4
    return bytes(b)

def a2_echo(f8, req):
    """A2，但载荷 [4:6] 回显请求帧的 [0x2F:0x31]（抓包对比得出）。"""
    b = bytearray(a2(f8))
    if len(req) >= 0x31:
        b[20:22] = bytes(req[0x2F:0x31])
    return bytes(b)

def t10_rsp(f8):
    """客户端发 type=0x10(cmd 0x00) 后，真服务器回的 188 字节帧。

    ★ 载荷内部也引用了句柄，必须一起替换。
    """
    return _patch_all_handles(REAL_T10_RSP, f8)

def _patch_all_handles(frame, f8):
    """把帧里所有 0x104000XX 形式的句柄统一替换成 f8（含载荷内部引用）。"""
    b = bytearray(frame)
    needle = b'\x10\x40\x00'
    val = f8.to_bytes(4, 'big')
    i = 0
    while True:
        i = bytes(b).find(needle, i)
        if i < 0:
            break
        b[i:i+4] = val
        i += 4
    return bytes(b)


def _patch_identity(frame, req, cc_mode):
    """把客户端准备帧里的等级/队伍值回显进帧。"""
    b = bytearray(frame)
    if len(req) > 0x23:
        if cc_mode:
            b[0x35] = req[0x20]
            b[0x38] = req[0x23]
        else:
            b[0x1D] = req[0x20]
            b[0x20] = req[0x23]
    return bytes(b)


def cc_req(f8, req):
    """按客户端准备帧回显身份字段的 CC。"""
    return _patch_identity(cc(f8), req, True)


def t10_rsp_req(f8, req):
    """按客户端准备帧回显身份字段的 T10_RSP。"""
    return _patch_identity(t10_rsp(f8), req, False)
