# -*- coding: utf-8 -*-
"""3953 UDP 服务器：先实现握手（hello -> 68B 回复 -> 8B ack）。

握手依据 2026-11-03 两台真机 TP 全量抓包（coop/2P20261103154847.pcap）：

  UP 32B  id=0        type=0x01  hello，载荷[0:4]=客户端 id X
  DN 68B  id=X        type=0x02  载荷含 Y（服务器分配）、X、20B 随机数
  UP 48B  id=Y        type=0x0A  客户端确认
  DN  8B  id=X        type=0x0B  ack

2026-11-04 补的两条（真机抓包实测）：
  · 每条 UP 28B 心跳都要回 20B ack（type 0x0300，echo msgid），不回客户端会一直重传；
  · 建玩家对象(44B)/建 body(76B) 是「请求-应答」，收到就回，不能按时间轴盲发。

用法:
    python udp3953.py --port 3953 --serve
"""

import argparse
import os
import random
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import world_replay

DEFAULT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'udp3953.log')

_stats = {}
_last_flush = time.time()
_peers = {}
_sessions = {}
_sock = None
_next_player_h = 0x10400025
_ip_players = {}               # ip -> player_h：**按机台固定**，重连不换号
_profiles = {}                 # player_h -> 客户端自己上报的档案原始包（Step 2 用）
BODY_H = 0x6040000D            # 全局 body 对象（两台真机抓包里服务端给的都是它）
_next_body_h = 0x6040000d      # 2026-11-06 起不再使用，保留只为老脚本 import 不报错


def log_line(path, text):
    with open(path, 'a', encoding='utf-8', newline='\n') as f:
        f.write(text + '\n')


def build_reply_68(x_id, y_id, nonce):
    """DN 68B (type 0x02)：照抄抓包结构，替换 X/Y/随机数。"""
    body = bytearray()
    body += struct.pack('>I', y_id)
    body += bytes.fromhex('00040000')
    body += bytes.fromhex('00110011')
    body += struct.pack('>I', y_id)
    body += bytes.fromhex('0007002c')
    body += struct.pack('>I', y_id)
    body += struct.pack('>I', x_id)
    body += struct.pack('>I', x_id)
    body += bytes.fromhex('000cd29e')
    body += bytes.fromhex('000001a1')
    body += nonce
    assert len(body) == 60, len(body)
    return struct.pack('>I', x_id) + bytes([0x02, 0x00]) + struct.pack('>H', 4 + len(body)) + bytes(body)


_fwd_seq = [0]


def forward_profile(src_addr, payload):
    """把某人的档案转发给其他会话。

    2026-11-05 第三次修正：档案内容描述的是【上传者】，不是收件人。
    以前按收件人的句柄打补丁，.10 收到的档案里写着自己的句柄，客户端会把它
    当成"我自己"，队友实体永远建不出来。正确做法：
      1) 用上传者会话的 X/Y/player/body/peer 把整帧内容打好补丁；
      2) 再按收件人改写包头（源 id、目标 id=Y+0x24、序号）。
    """
    src = _sessions.get(src_addr)
    if not src or not src.get('player_h'):
        return 0
    sp = src['player_h']
    base = world_replay.build_profile(src.get('X'), src.get('Y'), sp,
                                      src.get('body_h'),
                                      src.get('peer_h') or ((sp - 1) & 0xFFFFFFFF), 0)
    if not base:
        return 0
    sent = 0
    # 抓包显示服务器把每份档案发给【所有人】，包括上传者自己
    for addr, sess in list(_sessions.items()):
        x = sess.get('X')
        y = sess.get('Y')
        if not x or not y:
            continue
        _fwd_seq[0] = (_fwd_seq[0] + 1) & 0xFFFF
        pkt = bytearray(base)
        pkt[0:4] = struct.pack('>I', x)
        pkt[8:12] = struct.pack('>I', (y + 0x24) & 0xFFFFFFFF)
        pkt[14:16] = struct.pack('>H', _fwd_seq[0])
        try:
            _sock.sendto(bytes(pkt), addr)
            sent += 1
        except Exception:
            pass
    return sent


def build_object_48(x_id, obj_id, counter, body_h, player_h, tick):
    """DN 48B：给客户端分配/确认它的玩家对象。"""
    pay = bytearray()
    pay += struct.pack('>I', obj_id)
    pay += struct.pack('>HH', 0x0010, counter & 0xFFFF)
    pay += bytes.fromhex('1000001c')
    pay += bytes.fromhex('0000000d')
    pay += struct.pack('>I', body_h)
    pay += struct.pack('>I', player_h)
    pay += bytes.fromhex('00000000')
    pay += bytes([0x11])
    pay += struct.pack('>I', player_h)
    pay += struct.pack('>I', tick & 0xFFFFFFFF)
    pay += bytes.fromhex('000000')
    assert len(pay) == 40, len(pay)
    return (struct.pack('>I', x_id) + bytes([0x00, 0x03]) +
            struct.pack('>H', 4 + len(pay)) + bytes(pay))

def build_sack(vtag, cum_tsn, rwnd=0x00040000):
    """构造 SACK chunk（20 字节，与真机一致）。"""
    body = struct.pack('>I', cum_tsn & 0xFFFFFFFF) + struct.pack('>I', rwnd) + b'\x00\x00' + b'\x00\x00'
    return (struct.pack('>I', vtag & 0xFFFFFFFF) + bytes([0x03, 0x00]) +
            struct.pack('>H', 4 + len(body)) + body)


RELAY_MARKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'relay_state.on')
STAGE_OBJ = 0x5040000C          # 客户端状态回传里"我"后面跟的那个 stage 对象（判据用）
_last_relay_log = {}


def relay_state(data, addr, sock, log):
    """把某台客户端回传的状态帧转给对方 —— 这就是"服务器合并两台状态"的最小实现。

    2026-11-06：真机同一场里，下行 236B 是 `(对方号, 自己号, …, 世界钟)`，
    而客户端在 LoadFinish 之后会把收到的那一帧**原样回传**（`(自己号, 0x5040000C, …, 同一个钟)`）。
    真机服务器把两台的这种回传合并后再下发；我们以前只回放抓包那份，
    客户端回传的状态从来没进过对方的世界 —— 所以 CG 之后对方就没了。

    这里只做最小一步：把 A 的回传转给 B，把 [24:28] 填 A 的玩家号、[28:32] 填 B 的玩家号，
    vtag 换成 B 的 X，其余字节原样。开关：data\\relay_state.on 存在时启用（热读）。
    """
    if not os.path.exists(RELAY_MARKER):
        return 0
    if len(data) < 32 or data[4] != 0xBF or data[5] != 0x03:
        return 0
    # 判据：BF03 里 [28:32] 是 stage 对象 -> 这就是"我自己的状态"回传
    # （下行对应位置的 [24:28]/[28:32] 是"对方号 / 自己号"）
    if struct.unpack_from('>I', data, 28)[0] != STAGE_OBJ:
        return 0
    src = _sessions.get(addr)
    if not src or not src.get('player_h'):
        return 0
    sent = 0
    for dst, sess in list(_sessions.items()):
        if dst == addr or not sess.get('X') or not sess.get('player_h'):
            continue
        pkt = bytearray(data)
        pkt[0:4] = struct.pack('>I', sess['X'])
        pkt[24:28] = struct.pack('>I', src['player_h'])      # 谁的状态
        pkt[28:32] = struct.pack('>I', sess['player_h'])     # 发给谁
        try:
            sock.sendto(bytes(pkt), dst)
            sent += 1
        except Exception:
            pass
    if sent:
        now = time.time()
        if now - _last_relay_log.get(addr, 0) > 2.0:
            _last_relay_log[addr] = now
            log('   -> 状态转发 %dB（player 0x%08X -> peer）'
                % (len(data), src['player_h']))
    return sent


def _ctrl_req(data):
    """认出 sid=0 控制通道的「建玩家 / 建 body」请求。

    2026-11-06：判别键必须是 **sid==0 + PPID**，不能只看 chunk 长度。
    真机在 +10s 之后还会发一个同样 len=0x0028 的 44B，那是 sid=4 的另一条消息
    （ppid=0x04008008），按长度判断会把心跳误答成 36B 建对象应答。

    返回 (sid, ppid, tsn, payload) 或 None。
    """
    if len(data) < 20:
        return None
    ln = (data[6] << 8) | data[7]
    if ln < 20 or 4 + ln > len(data):
        return None
    sid = struct.unpack_from('>H', data, 12)[0]
    ppid = struct.unpack_from('>I', data, 16)[0]
    if sid != 0 or ppid not in (world_replay.CTRL_PPID_PLAYER, world_replay.CTRL_PPID_BODY):
        return None
    tsn = struct.unpack_from('>I', data, 8)[0]
    return sid, ppid, tsn, data[20:4 + ln]


def ctrl_reply(st, data, log=None):
    """sid=0 控制请求 → 应答包。同一请求块重传时返回缓存里的**同一个包**。

    返回 (pkt, req_sid, req_ppid, req_tsn, cached)；认不出/无会话返回 None。
    只有这里会给 sid=0 分配 SSN，别的路径不碰 SSN。
    """
    r = _ctrl_req(data)
    if r is None:
        return None
    req_sid, req_ppid, req_tsn, req_pay = r
    if not st.get('X') or st.get('tsn_next') is None:
        return None
    # 44B 里 [4:8] 是客户端从 CC 拿到的玩家句柄，采纳它（否则它不认这个对象）
    if req_ppid == world_replay.CTRL_PPID_PLAYER and len(req_pay) >= 8:
        prop = struct.unpack_from('>I', req_pay, 4)[0]
        if (prop >> 20) == 0x104 and prop != st.get('player_h'):
            if log:
                log('   => 采纳客户端句柄 0x%08X（原 0x%08X）'
                    % (prop, st.get('player_h') or 0))
            st['player_h'] = prop
            st['adopted'] = True          # 2026-11-07 早：回放线程靠它判断"号已定稿"
            _recompute_peers()
    key = (req_sid, req_tsn)
    cache = st.setdefault('replies', {})
    if key in cache:
        return cache[key], req_sid, req_ppid, req_tsn, True
    ssn = st.setdefault('ssn', {}).get(req_sid, 0)
    if req_ppid == world_replay.CTRL_PPID_PLAYER:
        pkt = world_replay.build_player_obj_reply(st['X'], ssn, st['player_h'], req_pay)
    else:
        pkt = world_replay.build_body_obj_reply(st['X'], ssn, st['player_h'],
                                                st['body_h'], req_pay)
    if not pkt:
        return None
    pkt = world_replay.renumber_tsn(pkt, st)          # 填 TSN（= tsn_next++）
    cache[key] = pkt
    while len(cache) > 8:                             # 只留最近 8 条应答
        cache.pop(next(iter(cache)))
    st['ssn'][req_sid] = (ssn + 1) & 0xFFFF
    return pkt, req_sid, req_ppid, req_tsn, False


def build_ack_8(x_id):
    """DN 8B (type 0x0B)。"""
    return struct.pack('>I', x_id) + bytes([0x0B, 0x00]) + struct.pack('>H', 4)


def build_msg_ack(x_id, up):
    """DN 20B (type 0x0300)：心跳 ack。【已被 build_sack() 取代，2026-11-06】

    `build_sack()` 对它等价（同样的 20B 布局、同样的 rwnd），但能带任意 cum TSN，
    现在所有上行 DATA 都走 build_sack，这个函数只留着防止外部脚本 import 报错。
    """
    return (struct.pack('>I', x_id) + bytes([0x03, 0x00]) + struct.pack('>H', 0x10) +
            bytes(up[8:12]) + bytes(up[12:14]) + bytes.fromhex('0000') + bytes(4))


def _recompute_peers():
    """给每条活跃会话算出"对方"的玩家句柄（真机里是 0x10400024 那个）。

    场上是 2 人局，所以"对方"就是另一条会话的 player_h；只剩一台时退化成
    player_h-1，跟真机 self=0x25 / peer=0x24 的排布一致，至少不是悬空值。
    """
    now = time.time()
    live = [s for s in _sessions.values()
            if s.get('player_h') and now - s.get('last', 0) < 120]
    for s in live:
        others = [o for o in live if o is not s]
        # 取最近还有包的那条当对方，避免指到已经作废的旧会话
        other = max(others, key=lambda o: o.get('last', 0)) if others else None
        s['peer_h'] = other['player_h'] if other else (s['player_h'] - 1) & 0xFFFFFFFF
        s['peer_body_h'] = (other.get('body_h') if other else None) or BODY_H


def main():
    global _last_flush, _next_player_h, _next_body_h
    ap = argparse.ArgumentParser()
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=3953)
    ap.add_argument('--log', default=DEFAULT_LOG)
    ap.add_argument('--head', type=int, default=80)
    ap.add_argument('--save-first', type=int, default=3)
    ap.add_argument('--relay', action='store_true')
    ap.add_argument('--serve', action='store_true', help='实现握手（hello->68B->ack）')
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))

    mode = 'serve' if args.serve else ('relay' if args.relay else 'listen-only')
    log_line(args.log, '=== udp%d %s on %s:%d  (%s) ==='
             % (args.port, mode, args.bind, args.port, time.strftime('%Y-%m-%d %H:%M:%S')))
    print('udp%d %s on %s:%d' % (args.port, mode, args.bind, args.port), flush=True)

    global _sock
    _sock = sock
    seen = {}
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_line(args.log, 'recv error: %r' % (e,))
            continue

        key = '%s:%d' % (addr[0], addr[1])
        st = _stats.setdefault(key, [0, 0])
        st[0] += 1
        st[1] += len(data)
        _peers[addr] = time.time()
        _sess_seen = _sessions.get(addr)
        if _sess_seen is not None:
            _sess_seen['last'] = time.time()      # 心跳线程靠它判断客户端还在不在

        ts = time.strftime('%H:%M:%S') + ('.%03d' % (int(time.time() * 1000) % 1000))
        log_line(args.log, '%s %s len=%d %s' % (ts, key, len(data), data[:args.head].hex(' ')))

        n = seen.get(len(data), 0)
        if n < args.save_first:
            seen[len(data)] = n + 1
            with open(os.path.join(os.path.dirname(args.log), 'udp3953_%d.bin' % len(data)), 'wb') as f:
                f.write(data)

        # ---- 握手 ----
        if args.serve and len(data) >= 8:
            sid = struct.unpack_from('>I', data, 0)[0]
            typ = data[4]
            # 2026-11-06: SCTP 可靠层 —— 收到 DATA 必须回 SACK，否则客户端一直重传
            if typ == 0x00 and len(data) >= 16:
                try:
                    tsn = struct.unpack_from('>I', data, 8)[0]
                    st = _sessions.setdefault(addr, {'X': sid, 'Y': 0, 'nonce': b'',
                                                     'last': 0, 'profile': b'', 'obj_n': 0})
                    st['recv_tsn'] = tsn
                    x = st.get('X') or sid
                    sock.sendto(build_sack(x, tsn), addr)
                    log_line(args.log, '   => SACK cum=%08X -> %s:%d' % (tsn, addr[0], addr[1]))
                except Exception as e:
                    log_line(args.log, '   => SACK 失败 %r' % (e,))
            if typ == 0xBF and len(data) >= 32:
                # 2026-11-06：客户端回传的 0x95/0xC5 状态帧 -> 转给对方（见 relay_state）
                try:
                    relay_state(data, addr, sock, lambda m: log_line(args.log, m))
                except Exception as e:
                    log_line(args.log, '   -> 状态转发失败 %r' % (e,))
            if typ == 0x01 and len(data) >= 12:
                x_id = struct.unpack_from('>I', data, 8)[0]
                y_id = random.getrandbits(32)
                nonce = os.urandom(20)
                # 2026-11-05: 同一台机重连时，先丢掉它的旧会话。
                # 否则 _recompute_peers 可能把"对方"指到上一局的句柄，
                # 开场帧里的 peer 变成悬空 ID，客户端拼不出场、不发 LoadFinish。
                for old in [a for a in list(_sessions) if a != addr and a[0] == addr[0]]:
                    _sessions.pop(old, None)
                st0 = _sessions.get(addr) or {}
                st0.update({'X': x_id, 'Y': y_id, 'nonce': nonce, 'last': time.time(),
                            't0': time.time(), 'profile': st0.get('profile', b''),
                            'obj_n': 0,
                            # 2026-11-06：新连接 = 新 association，sid=0 的 SSN 与应答缓存都重来
                            'ssn': {}, 'replies': {}, 'recv_tsn': None,
                            # SCTP: 68B 里宣告的 Initial TSN = Y，DATA 的 TSN 必须从它起连续
                            'tsn_next': y_id})
                # 2026-11-06 晚（Step 1 续）：3953 这边也是**每来一次 hello 就 +1**，
                # 客户端重连几次之后临时号会爬到 0x2A/0x2E —— 而 world_replay 是拿 hello 时的
                # player_h 去挑模板集的（templates_for），于是同一台机会在"主机流/加入方流"
                # 之间漂移。改成按 IP 固定，和 coop 一致。
                if addr[0] not in _ip_players:
                    _ip_players[addr[0]] = _next_player_h
                    _next_player_h += 1
                st0['player_h'] = _ip_players[addr[0]]
                # 2026-11-06: **body 是全局对象**，不是按会话分配。
                # 证据：11-03 主机/加入方两份抓包里，服务端「建 body 应答」给的 body 都是
                # 0x6040000D；1264B 大帧的 off24 两台也完全相同。玩家号才按收件人改写。
                # 以前这里按会话 +1，第二台拿到 0x6040000E —— 它把自己和对方都映射成 0x0E，
                # 两个实体撞成一个号，表现就是"CG 里渲染出来、进场面就没了"。
                st0['body_h'] = BODY_H
                _sessions[addr] = st0
                _recompute_peers()
                reply = build_reply_68(x_id, y_id, nonce)
                sock.sendto(reply, addr)
                log_line(args.log, '   => hello X=0x%08X -> reply 68B X=0x%08X Y=0x%08X'
                         % (x_id, x_id, y_id))
                # 2026-11-04: 按真机时间轴重放"场景初始化"这一串下行帧
                if world_replay.enabled():
                    world_replay.start(sock, addr, st0, lambda m: log_line(args.log, m),
                                       profile_of=lambda h: _profiles.get(h))
                    log_line(args.log, '   => world 重放启动 player=0x%08X body=0x%08X peer=0x%08X 模板=%s'
                             % (st0['player_h'], st0['body_h'], st0.get('peer_h') or 0,
                                world_replay.templates_for(st0['player_h']).__name__))
            elif typ == 0x00 and len(data) == 28:
                tail_h = struct.unpack_from('>I', data, 24)[0] if len(data) >= 28 else 0
                if tail_h:
                    log_line(args.log, '   << 客户端自带句柄 0x%08X' % tail_h)
                st = _sessions.get(addr)
                if st is None:
                    st = _sessions.setdefault(addr, {'X': sid, 'Y': 0, 'nonce': b'',
                                                     'last': 0, 'profile': b'', 'obj_n': 0})
                if 'player_h' not in st:
                    st['player_h'] = _next_player_h
                    st['body_h'] = BODY_H          # 全局对象，见 hello 分支的注释
                    _next_player_h += 1
                    log_line(args.log, '   => 分配句柄 player=0x%08X body=0x%08X'
                             % (st['player_h'], st['body_h']))
                if world_replay.enabled():
                    # 2026-11-06: 20B ack 已由上面「收到 DATA 就回 SACK」统一处理
                    # （build_msg_ack 与 build_sack 的字节完全相同，别再重复发一条）。
                    if st.get('player_h') is not None:
                        # 后续帧交给重放线程，避免重复
                        continue
                st['obj_n'] = st.get('obj_n', 0) + 1
                tick = int(time.time() * 1000) & 0xFFFFFFFF
                pkt = build_object_48(sid,
                                      (st.get('Y') or 0) + 3 + st['obj_n'],
                                      st['obj_n'],
                                      st['body_h'], st['player_h'], tick)
                _sock.sendto(pkt, addr)
            elif typ == 0x00 and _ctrl_req(data) is not None:
                # 2026-11-06 方向 B：sid=0 控制通道改成**结构化构造**（见 ctrl_reply），
                # 不再给 36B/44B 模板做整帧字节补丁 —— 以前句柄一撞号就会把玩家号
                # 写成对方号，客户端直接不受理 36B。
                st = _sessions.get(addr)
                if st is None or not st.get('X') or st.get('tsn_next') is None:
                    log_line(args.log, '   => 忽略控制请求（无会话）')
                    continue
                if not world_replay.enabled():
                    continue
                res = ctrl_reply(st, data, log=lambda m: log_line(args.log, m))
                if not res:
                    log_line(args.log, '   => 控制请求无法应答，忽略 %dB' % len(data))
                    continue
                pkt, req_sid, req_ppid, req_tsn, cached = res
                sock.sendto(pkt, addr)
                log_line(args.log, '   => %s ppid=0x%02X -> %dB sid=%d ssn=%d tsn=0x%08X%s'
                         % ('重发应答' if cached else '应答', req_ppid, len(pkt), req_sid,
                            struct.unpack_from('>H', pkt, 14)[0],
                            struct.unpack_from('>I', pkt, 8)[0],
                            '（请求块重传）' if cached else ''))
            elif len(data) >= 1000:
                # 大厅里的两种大包：
                #   >=1240B 是玩家档案（真机 1252/1268），要转发成固定 1264B；
                #   ~1228B 是"世界成员记录"上报，真机回一条 1236B（含两个玩家句柄）。
                # 2026-11-05: 之前两种都按档案转发，1228 被错发成 1264，
                # 客户端收到后直接失去响应。
                st = _sessions.get(addr)
                if st is None:
                    st = _sessions.setdefault(addr, {'X': sid, 'Y': 0, 'nonce': b'',
                                                     'last': time.time(), 'profile': b''})
                # 2026-11-05: 不再收到就立刻回 —— 那样序号对不上，会被 ESCTP
                # 重排窗口整包丢掉。这两帧改为按抓包时间点从时间轴注入
                # （见 world_templates.TIMED / world_replay.start），这里只记日志。
                if len(data) >= 1240:
                    st['profile'] = data[8:]
                    # Step 2：按玩家号记住**原始包**（偏移 41/60/115/130/134 都是相对原始包的）
                    if st.get('player_h'):
                        _profiles[st['player_h']] = data
                    # 2026-11-07 Step 2 前置：把每台**自己上报的档案**落盘，
                    # 用来和 1264B 模板做逐字节比对，求出"身份区"（名字/等级/卡名/基板号）的偏移。
                    # 只写文件，不改协议。
                    try:
                        _pf = os.path.join(os.path.dirname(args.log),
                                           'profile_%s.bin' % addr[0].replace('.', '_'))
                        with open(_pf, 'wb') as _f:
                            _f.write(data)
                    except Exception:
                        pass
                    log_line(args.log, '   => 档案 %dB（等时间轴 +19589ms 注入 1264B）' % len(data))
                else:
                    log_line(args.log, '   => 成员记录 %dB（等时间轴 +19590ms 注入 1236B）' % len(data))
            elif typ == 0x0A:
                s = _sessions.get(addr)
                x = s['X'] if s else sid
                # 2026-11-05：真机服务器 3.5 秒才回 COOKIE_ACK（SCTP cookie 处理慢），
                # 客户端在这期间会重传一次 COOKIE_ECHO，然后才发建玩家(44B @3.33s)
                # 和建 body(76B @3.58s)。我们 10ms 就回，客户端 0.1s 就建玩家，
                # 整条时间线错位，后面 CUSTOMIZE_SEL/DATA 根本走不到（实测不上报档案）。
                # 所以这里照真机节奏延迟 3.4 秒再回。
                if s is not None and not s.get('cookie_ack_scheduled'):
                    s['cookie_ack_scheduled'] = True

                    def _late_cookie_ack(x_id=x, dst=addr, log=args.log):
                        time.sleep(3.4)
                        try:
                            sock.sendto(build_ack_8(x_id), dst)
                            log_line(log, '   => COOKIE_ACK 8B 延迟 3.4s 发出 (X=0x%08X)' % x_id)
                        except Exception:
                            pass

                    threading.Thread(target=_late_cookie_ack, daemon=True).start()
                    log_line(args.log, '   => 0x0A COOKIE_ECHO，安排 3.4s 后回 COOKIE_ACK')
                else:
                    log_line(args.log, '   => 0x0A 重传，忽略（延迟 ack 已安排）')

        if args.relay:
            now = time.time()
            for peer, last in list(_peers.items()):
                if peer == addr:
                    continue
                if now - last > 60:
                    _peers.pop(peer, None)
                    continue
                try:
                    sock.sendto(data, peer)
                    log_line(args.log, '   -> relay %dB to %s:%d' % (len(data), peer[0], peer[1]))
                except Exception as e:
                    log_line(args.log, '   -> relay to %s failed %r' % (peer, e))

        if time.time() - _last_flush >= 30:
            summary = ', '.join('%s=%d包/%dB' % (k, v[0], v[1]) for k, v in _stats.items())
            log_line(args.log, '--- 30s 汇总: %s' % summary)
            print('30s: %s' % summary, flush=True)
            _last_flush = time.time()

    sock.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
