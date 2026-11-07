# -*- coding: utf-8 -*-
"""店内協力 联机逻辑（服务器侧）。

依据 2026-10-31 两台真机实测（本项目真机抓包实测）：
    0x22 搜索   -> A2(32B) + T10(160B)
    380B 数据帧 -> 登记队员（等级/队伍），广播 188B 状态帧
    44B  准备帧 -> 置准备位，广播状态帧
    全员就绪    -> 延时 CC_DELAY 秒后，给每人推 CC(212B)

设计原则：
    · 状态机单向，不实现"取消/踢人/超时"（街机语义，客户端自己会兜底）
    · 广播是核心：任何变化都推 188B，客户端靠它维持队伍
"""

import os
import threading
import time

import coop_templates as ct
import real_frames as rf

REC = 20                 # 玩家记录长度
STATE_HDR = 9            # 状态帧载荷头长度
STATE_REC_OFF = 25       # 状态帧里第一条记录的偏移（16 内层头 + 9）
CC_HDR = 49              # CC 里第一条记录的偏移（16 + 24 + 9）
CC_DELAY = 3.0           # 全员就绪后多久发 CC（真机约 15s，先取短一点便于测试）
MAX_PLAYERS = 8

_lock = threading.Lock()
_members = []            # [{conn, handle, level, team, ready, fake, last}]
_next_handle = 0x10400022
# 2026-11-06: 真机 2P 对局里两名玩家的号是**连号** —— 先到的 0x10400025、后到的 0x10400024
# （主机抓包 self=0x25/peer=0x24；加入方抓包 self=0x24/peer=0x25；服务端下行 236B 两台收到的
#  槽位字节完全一样，都是 0x25/0x24）。以前从 0x22 起每次 +2，实际发出去是 0x26/0x28，
#  客户端按号映射场上槽位时对不上 —— 场上看不见对方、两边都显示"挂了"。
# 2026-11-07 01:1x **定案（现场卡面反推）**：客户端把 **0x10400025 当 1P、0x10400024 当 2P**。
# 证据：卡面上 1P 卡显示 FOR_new(Lv2) = 0x25 的档案，2P 卡显示 second(Lv11) = 0x24 的档案；
#       而先开房那台被发成 0x24 → 被摆到 2P（现场红字："这里应该是1P现在是2P"）。
# 所以先开房（=应该当 1P 的那台）必须拿 0x10400025。
# 配对沿用真机观察到的 25/24、27/26 这种"成对倒序"：一局内先到拿大号、后到拿小号。
_HANDLE_SLOTS = [0x10400025, 0x10400024, 0x10400027, 0x10400026,
                 0x10400029, 0x10400028, 0x1040002B, 0x1040002A]
_used_handles = set()
FAKE_HANDLE = 0x1040002F      # 假队友专用（槽位表外，绝不占真人号）
_conn_handles = {}       # ip -> 句柄。**按机台固定**，重连复用（2026-11-06 晚上修）
_all_ready_at = None
_cc_sent = False
_cc_timer = None


# ---------------------------------------------------------------- 帧构造

def _rec(handle, level, team, ready):
    b = bytearray(REC)
    b[0:4] = (handle & 0xFFFFFFFF).to_bytes(4, 'big')
    b[4] = level & 0xFF
    b[5] = 0x02
    b[6] = 0x00
    b[7] = team & 0xFF
    b[8] = 0x00
    b[9] = 1 if ready else 0
    return bytes(b)


def _fill(f, base, members):
    for i in range(MAX_PLAYERS):
        off = base + i * REC
        f[off:off + REC] = _rec(*members[i][:4]) if i < len(members) else bytes(REC)


# 2026-11-03: 真机对第一个 0x22(state=0x00) 的回复模板（176B），只替换 f8。
REAL_INIT_176 = bytes.fromhex(
    "1000009c0000008eb04000001040002300000000050000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000050000"
    "0001000000020000004600000001000000020000001e000000460000001e0000"
    "04000004300001000400000430000200"
)


def init_frame(f8, clear_tail=True):
    b = bytearray(REAL_INIT_176)
    b[12:16] = f8.to_bytes(4, 'big')
    if clear_tail:
        # 2026-11-04 实验：真机那份尾部带着 1/2 号座位的数据；
        # 我们这局只有 1 个真人，清零试试客户端是否还报错。
        for i in range(0x84, len(b)):
            b[i] = 0
    return bytes(b)


def _self_last(members, f8):
    """把收件人自己排到最后（真机顺序：先对方，后自己）。"""
    self_m = [m for m in members if m[0] == f8]
    others = [m for m in members if m[0] != f8]
    return others + self_m


def state_frame(f8, members):
    """188B 状态帧；members = [(handle, level, team, ready), ...]"""
    f = bytearray(ct.REAL_STATE)
    f[12:16] = (f8 & 0xFFFFFFFF).to_bytes(4, 'big')
    f[21] = len(members)
    _fill(f, STATE_REC_OFF, members)
    return bytes(f)


def cc_frame(f8, members, server_ip=None):
    """212B 匹配结果；members 同上。"""
    f = bytearray(ct.REAL_CC2)
    f[12:16] = (f8 & 0xFFFFFFFF).to_bytes(4, 'big')
    if server_ip:
        # 载荷 [4:8] = 对局数据发往哪个 IP；模板里是抓包服务器的公网 IP
        try:
            f[20:24] = bytes(int(x) for x in server_ip.split('.'))
        except Exception:
            pass
    f[41] = len(members)
    _fill(f, CC_HDR, members)
    return bytes(f)


# ---------------------------------------------------------------- 队伍

def _snapshot():
    """队伍快照，**按玩家号升序**。

    2026-11-07 00:3x 修：真机两份抓包（CC2 与 188B 状态帧）里两条记录的顺序都是
    `0x10400024` 在前、`0x10400025` 在后 —— 也就是**升序**，而房主（1P/0x25）在最后一条。
    客户端把"最后一条"当 Leader；我们原来按入队顺序填（先连上的 0x25 在前），
    结果加入方（2P/0x24）被标成了 Leader。改成升序即可与抓包逐字节一致。
    """
    return sorted(((m['handle'], m['level'], m['team'], m['ready']) for m in _members),
                  key=lambda x: x[0])


LEADER_IP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'leader_ip.txt')
LEADER_HANDLE = 0x10400024          # 抓包互证：成员记录帧第二格永远是它 = 房主/1P


def _leader_ip():
    r"""哪个 IP 当房主（拿 0x10400024）。

    依据（2026-11-07 01:3x，两份抓包互证）：成员记录帧的第二个句柄格永远是 0x10400024，
    主机那份是 [自身 0x25, 0x24]、加入方那份是 [自身 0x24, 0x24] —— 所以 0x24 = 房主 = 1P。
    谁拿 0x24 谁就显示成 1P；而"谁先连上"每轮不固定，固定按顺序发号会让 1P 时对时错。
    所以改成**按 IP 指定**：默认 10.0.0.10（左机），可用 data\leader_ip.txt 覆盖。
    """
    try:
        with open(LEADER_IP_FILE, 'r', encoding='utf-8') as f:
            ip = f.read().strip()
            if ip:
                return ip
    except Exception:
        pass
    return '10.0.0.10'


def _alloc_handle(ip=None):
    """发号：**按机台固定**，同一台机重连复用同一个号。

    2026-11-06 晚修（Bug B）：以前是"每建立一条连接就发一个新号"。看代码像是"一次连接只发一个"
    （5 个调用点都有 `if sess is None` 保护），但客户端会**反复重连** ——
    实测 `.15` 一轮里连了 9 次（30011→30018），9 次把发号表抽干，
    结果第二台拿到 0x10400026/0x27，永远落不到 0x10400024。
    现在按对端 IP 记住号：`.10` 和 `.15` 各自固定，重连不换号。

    号的顺序照真机两份抓包：先到的 0x10400025、后到的 0x10400024
    （主机视角 self=0x25/peer=0x24，加入方视角反之）。客户端会把这个号写回 create-player，
    3953 侧采纳它 —— 所以这里发什么号，场上就用什么号。
    """
    global _next_handle
    if ip is not None and ip in _conn_handles:
        return _conn_handles[ip]
    h = None
    # 2026-11-07 01:3x：**房主（1P）固定拿 0x10400024**，按 IP 指定，不看谁先连。
    # 依据见 _leader_ip() 的注释（成员记录帧第二格永远是 0x24）。其余人从表里取剩下的号。
    if ip is not None and ip == _leader_ip() and LEADER_HANDLE not in _used_handles:
        h = LEADER_HANDLE
    for cand in _HANDLE_SLOTS:
        if h is not None:
            break
        if cand not in _used_handles:
            h = cand
            break
    if h is None:
        h = _next_handle
        _next_handle = (_next_handle + 2) & 0xFFFFFFFF
    _used_handles.add(h)
    if ip is not None:
        _conn_handles[ip] = h
    return h


def reset():
    global _members, _next_handle, _all_ready_at, _cc_sent, _cc_timer
    with _lock:
        if _cc_timer is not None:
            _cc_timer.cancel()
            _cc_timer = None
        _members = []
        _next_handle = 0x10400022
        _used_handles.clear()
        _conn_handles.clear()
        _all_ready_at = None
        _cc_sent = False


def parse_identity(pkt):
    """从数据帧里找身份块 `10 40 00 XX | 等级 | 02 | 00 | 队伍`。

    真机抓包里偏移是 0x1C 起，但不同客户端版本会浮动，
    所以按模式查找：找到 10 40 00 后，+4 是等级、+7 是队伍。
    """
    i = pkt.find(b'\x10\x40\x00', 0x10)
    if i < 0 or i + 8 > len(pkt):
        return None, None
    return pkt[i + 4], pkt[i + 7]


def add_fake(level=5, team=0x0B, ready=False, handle=0x10400023):
    """加一个"假队友"（单机验证用）。已有则不重复加。"""
    global _all_ready_at
    with _lock:
        if any(m['fake'] for m in _members):
            return False
        _members.append({
            'conn': None, 'handle': handle, 'level': level, 'team': team,
            'ready': ready, 'fake': True, 'last': time.time(),
        })
        _all_ready_at = None
        return True


def _join(conn, handle, level, team):
    with _lock:
        for m in _members:
            if m['conn'] is conn:
                m['level'] = level
                m['team'] = team
                m['last'] = time.time()
                return m['handle']
        _members.append({
            'conn': conn, 'handle': handle, 'level': level, 'team': team,
            'ready': False, 'fake': False, 'last': time.time(),
        })
        return handle


def _set_ready(conn, ready=True):
    """置准备位（不在这里判定全员就绪，避免重入锁）。"""
    with _lock:
        for m in _members:
            if m['conn'] is conn:
                m['ready'] = ready
                m['last'] = time.time()
                return True
    return False


def set_fake_ready():
    with _lock:
        for m in _members:
            if m['fake']:
                m['ready'] = True


def _check_all_ready(log=None):
    """全员就绪时安排一次定时发送（只安排一次）。"""
    global _all_ready_at, _cc_timer
    with _lock:
        if _all_ready_at is not None or not _members:
            return False
        if not all(m['ready'] for m in _members):
            return False
        _all_ready_at = time.time()
        if _cc_timer is not None:
            return False
        t = threading.Timer(CC_DELAY, _send_cc_now, args=(log,))
        t.daemon = True
        _cc_timer = t
        t.start()
        return True


def _send_cc_now(log=None):
    """定时器到点：把 CC 发给队里所有真人。"""
    global _cc_sent, _cc_timer
    with _lock:
        _cc_timer = None
        if _cc_sent or not _members:
            return
        snap = _snapshot()
        targets = [(m['conn'], m['handle']) for m in _members if not m['fake']]
        _cc_sent = True
    for conn, f8 in targets:
        try:
            try:
                ip = conn.getsockname()[0]
            except Exception:
                ip = None
            fr = cc_frame(f8, snap, ip)
            conn.sendall(fr)
            if log:
                log(f">>> CC -> 0x{f8:08X} ({len(fr)}B, {len(snap)} players) [timer]")
        except Exception as e:
            if log:
                log(f"send CC to 0x{f8:08X} failed: {e!r}")


def _drop(conn):
    with _lock:
        before = len(_members)
        _members[:] = [m for m in _members if m['conn'] is not conn]
        return len(_members) != before



def remove_fakes():
    global _all_ready_at
    with _lock:
        _members[:] = [m for m in _members if not m['fake']]
        if not all(m['ready'] for m in _members):
            _all_ready_at = None


def sync_fake(log=None):
    """只有单人时才塞假队友；一旦有两个真人就撤掉。"""
    with _lock:
        reals = [m for m in _members if not m['fake']]
        fakes = [m for m in _members if m['fake']]
    if len(reals) == 1 and not fakes:
        # 2026-11-07 01:0x：假队友**不能占用真人的槽位号**。
        # 以前它从 _HANDLE_SLOTS 里拿，先到的单人会把 0x10400025 吃掉，
        # 第二台真机只能拿 0x10400026 → 落到列表第 3 格、中间空一格，客户端就不开打了。
        # 现在给它一个槽位表外的号，真人进来时撤掉，不参与槽位分配。
        fh = FAKE_HANDLE
        add_fake(handle=fh)
        if log:
            log('coop: 单人 -> 已塞入假队友 handle=0x%08X' % fh)
    elif len(reals) >= 2 and fakes:
        remove_fakes()
        if log:
            log('coop: 已有 %d 个真人 -> 撤掉假队友' % len(reals))

def broadcast(log=None, dump=None):
    """给队里每个真人推当前状态帧。"""
    with _lock:
        snap = _snapshot()
        targets = [(m['conn'], m['handle']) for m in _members if not m['fake']]
    if log:
        try:
            parts = []
            for h, lv, tm, rdy in snap:
                parts.append('0x%08X lv%d team%02X %s' % (
                    h, lv, tm, 'READY' if rdy else '-'))
            log('BROADCAST ' + ' | '.join(parts))
        except Exception:
            pass
    for conn, f8 in targets:
        try:
            conn.sendall(state_frame(f8, snap))
        except Exception as e:
            if log:
                log(f"broadcast to 0x{f8:08X} failed: {e!r}")


def _tick(log=None, dump=None):
    """检查是否该发 CC。"""
    global _cc_sent
    with _lock:
        if _cc_sent or _all_ready_at is None:
            return
        if time.time() - _all_ready_at < CC_DELAY:
            return
        snap = _snapshot()
        targets = [(m['conn'], m['handle']) for m in _members if not m['fake']]
        _cc_sent = True
    for conn, f8 in targets:
        try:
            try:
                ip = conn.getsockname()[0]
            except Exception:
                ip = None
            fr = cc_frame(f8, snap, ip)
            conn.sendall(fr)
            if log:
                # 2026-11-07：带上收件人 IP 与两条记录的号/等级/队伍 —— 画面上的 1P/2P/Leader
                # 到底从哪个字段来，只能靠这个把日志和屏幕对上。
                recs = ' | '.join('0x%08X lv%d t%02X' % (h, lv, tm) for h, lv, tm, _rd in snap)
                log(f">>> CC -> 0x{f8:08X} ip={ip} ({len(fr)}B) 记录: {recs}")
                if dump:
                    dump("tx", fr)
        except Exception as e:
            if log:
                log(f"send CC to 0x{f8:08X} failed: {e!r}")


# ---------------------------------------------------------------- 连接处理

def handle(conn, peer, idx, hold, log, dump, read_frames, fake=False):
    """接一条连接，按联机协议应答。"""
    global _cc_sent
    sess = None
    log(f"#{idx} coop: {peer[0]}:{peer[1]} start")

    try:
        for pkt in read_frames(conn, hold):
            # 2026-11-01: 逐帧日志（排查看不到客户端动作的问题）
            try:
                log(f"#{idx} coop rx {len(pkt)}B type=0x{pkt[0]:02X}")
            except Exception:
                pass
            if pkt[0] in (4, 12):
                conn.sendall(bytes([0x04, 0x00, 0x00, 0x04]) + bytes(pkt[4:8]))
                if sess is not None:
                    _tick(log, dump)   # 2026-11-04: 撤掉每秒推状态的实验，回到只在 join/ready 时广播
                continue

            if pkt[0] == 0x10:
                if len(pkt) > 100:                     # 380B：身份
                    if sess is None:
                        sess = _alloc_handle(peer[0])
                    level, team = parse_identity(pkt)
                    if level is None:
                        level, team = 1, 0
                    _join(conn, sess, level, team)
                    log(f"#{idx} coop: join handle=0x{sess:08X} lv={level} team={team:02X}")
                    if fake:
                        sync_fake(log)
                    broadcast(log, dump)
                elif len(pkt) == 44:                   # 44B：准备
                    if sess is None:
                        sess = _alloc_handle(peer[0])
                    lv, tm = parse_identity(pkt)
                    _join(conn, sess, lv if lv is not None else 1,
                          tm if tm is not None else 0)
                    _set_ready(conn, True)
                    log(f"#{idx} coop: ready handle=0x{sess:08X}")
                    if fake:
                        set_fake_ready()
                    if _check_all_ready(log):
                        log(f"#{idx} coop: 全员就绪，{CC_DELAY:.0f}s 后发 CC")
                    broadcast(log, dump)
                    _tick(log, dump)
                continue

            if pkt[0] == 0x08 and len(pkt) == 20 and pkt[4] == 0x04:
                # 客户端在 CC 之后的确认帧，真机回 0x84(20B)
                if sess is None:
                    sess = _alloc_handle(peer[0])
                # 2026-11-07 01:0x：ack04 退回 ack84 —— 抓包里服务器那一帧确实是 04 开头，
                # 但实测换成 ack04 后客户端收到 CC 就不再走 3953（0.4s 后回去查 keychip.version）。
                # 23:52 与 00:45 两轮能进 stage 用的都是 ack84，先保持能进局的行为。
                conn.sendall(rf.ack84(sess))
                log(f"#{idx} coop: 0x04 -> 0x84 handle=0x{sess:08X}")
                continue

            if pkt[0] == 0x08 and len(pkt) > 40:
                st = pkt[40]
                # 2026-11-03: 打印原始请求，便于和真机抓包逐字节比对
                try:
                    log(f"#{idx} coop REQ {len(pkt)}B {pkt.hex(' ')}")
                except Exception:
                    pass
                if st in (0x02, 0x04, 0x05):
                    if sess is None:
                        sess = _alloc_handle(peer[0])
                    conn.sendall(rf.a2(sess) + rf.t10(sess))
                    log(f"#{idx} coop: search(0x{st:02X}) -> A2+T10 handle=0x{sess:08X}")
                else:
                    # 2026-11-03: state=0x00 是"进入模式"的请求，真机抓包里
                    # 服务器回 A2 + 状态帧（不是 CC）。
                    # 2026-11-03 21:40: TypeError 修好后重新启用。
                    # 真机对第一个 0x22(state=0x00) 就是回 A2 + 176B 初始帧。
                    if sess is None:
                        sess = _alloc_handle(peer[0])
                    # 2026-11-04: 实验开关。data\silent_state0.on 存在时【不回】
                    # 用来判断"通信失败"是不是我们这两帧造成的。
                    import os as _os
                    _silent = _os.path.exists(
                        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                                      'data', 'silent_state0.on'))
                    if _silent:
                        log(f"#{idx} coop: state=0x{st:02X} (SILENT 实验)")
                    else:
                        conn.sendall(rf.a2(sess) + init_frame(sess, clear_tail=False))
                    log(f"#{idx} coop: state=0x{st:02X} -> A2 + 初始帧 handle=0x{sess:08X}")

                continue
    except Exception as e:
        log(f"#{idx} coop: 异常 {e!r}")

    dropped = _drop(conn)
    if dropped:
        with _lock:
            real = [m for m in _members if not m['fake']]
        log(f"#{idx} coop: 断线，队伍剩 {len(_members)} 人")
        broadcast(log, dump)
        if not real:
            # 真人全走了 → 整队清空（假队友也不留，下一局重新开始）
            reset()
            log(f"#{idx} coop: 队伍已清空，等待下一局")
        elif fake:
            sync_fake(log)
            broadcast(log, dump)
    log(f"#{idx} coop: closed")
