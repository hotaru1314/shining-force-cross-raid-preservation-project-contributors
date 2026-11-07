# -*- coding: utf-8 -*-
"""world_replay.py —— 把真机握手的下行帧序列按时间重放给客户端。

用途：补上"场景初始化"（建玩家对象 / 建 body 对象 / 下发状态 / +35.8s 的开场帧），
客户端只有收到这一整套，才会采纳服务器分配的句柄并进到场内。

2026-11-05：
  · 模板窗口延长到 42s，包含 +35.8s 起的 type 0xBF03 开场帧（里面有对方句柄）；
  · patch_frame 增加 peer（对方玩家句柄）替换，不能再把真机的 0x10400024 原样发出去；
  · 时间轴播完后继续 1Hz 发 24B/48B，真机在 24.6~35.8s 之间也是一直在发的，
    我们之前播完就静默，客户端等不到开场就退回大厅。

开关：data/world_replay.on 存在时启用（热读）。
"""
import os
import struct
import threading
import time

import world_templates as wt

try:                                    # 加入方视角（11-03 另一台机抓到的那份）
    import world_templates_joiner as wt_joiner
except Exception:                       # 没生成过就退回单一模板
    wt_joiner = None

HOST_PLAYER_H = 0x10400025              # 先到的那台（coop.py 发号表的第一位）

BASE = os.path.dirname(os.path.abspath(__file__))
MARKER = os.path.join(BASE, 'data', 'world_replay.on')

KEEPALIVE_QUIET = 15.0     # 客户端 15 秒没包就停掉这条会话的心跳


RELAY_MARKER = os.path.join(BASE, 'data', 'relay_state.on')
IDENTITY_OFF = os.path.join(BASE, 'data', 'profile_identity.off')   # 存在则**不做**身份覆盖
SKIP_BIGSNAP = os.path.join(BASE, 'data', 'skip_bigsnap.on')        # 存在则**不回放** 400~1200B 的快照帧
SKIP_MARKER = os.path.join(BASE, 'data', 'relay_skip_replay.on')


def relay_skip_enabled():
    return os.path.exists(SKIP_MARKER)


def relay_state_enabled():
    return os.path.exists(RELAY_MARKER)


def _is_state_frame(frame):
    """0x95 / 0xC5：真机服务器发的"世界钟 + 两台状态"帧。

    开着 relay_state 时这些帧不再回放（改由 udp3953 用两台客户端的实时回传现拼），
    否则客户端会同时收到"抓包那份"和"对账那份"，两边打架。
    """
    # 188B / 236B：真机服务器发的"世界钟 + 两台状态"同步帧（小帧）；
    # 292B / 100B 是完整快照，照旧回放（`_is_state_frame` 不能把它们也砍掉）。
    return (180 <= len(frame) <= 240 and frame[4] == 0xBF
            and (struct.unpack_from('>I', frame, 28)[0] >> 20) == 0x104)


def templates_for(player_h):
    """按玩家号挑模板集。

    2026-11-06: 真机给**主机**和**加入方**发的下行不是同一套帧 ——
    主机拿 292B 大快照，加入方拿 100B 小快照 + 高频 236B/188B（实测）。
    以前两份都喂主机那份，加入方看到的是它从没见过的帧型。
    """
    if player_h == HOST_PLAYER_H or wt_joiner is None:
        return wt
    return wt_joiner


def enabled():
    return os.path.exists(MARKER)


def _sub(buf, old, new):
    """把 buf 里的 4 字节大端值 old 换成 new。"""
    if old == new:
        return bytes(buf)
    return bytes(buf).replace(old.to_bytes(4, 'big'), new.to_bytes(4, 'big'))


def _sub_table(x, y, player, body, peer, tpl=None):
    """单趟替换用的查表：真机值 → 我们的值。"""
    t = tpl or wt
    m = {t.REAL_X: x, t.REAL_PLAYER: player, t.REAL_PEER: peer, t.REAL_BODY: body}
    for k in range(16):
        m[(t.REAL_X + k) & 0xFFFFFFFF] = (x + k) & 0xFFFFFFFF
    # 抓包里的对象号是从 Y 开始连号分配的，最大到 Y+126（0x2C5FC25B..0x2C5FC2DA）。
    # 以前只替换前 24 个，后面的对象 ID 一直发的是真机会话的号。
    for k in range(128):
        m[(t.REAL_Y + k) & 0xFFFFFFFF] = (y + k) & 0xFFFFFFFF
    return m


def patch_frame(frame, x, y, player, body, peer, tpl=None):
    """把整帧里"真机的号"换成"我们的号"。

    2026-11-06：改成**单趟**替换。以前是 `_sub(REAL_PLAYER) → _sub(REAL_PEER) → …`
    一步一步来，后一趟看得见前一趟刚写进去的字节。于是只要某台机的 `player_h`
    正好等于 `REAL_PEER`(0x10400024)，第一趟刚写对的玩家号就会被第二趟改成"对方号"，
    客户端拿到的是别人的句柄 —— 22:49 那轮两台机一台过、一台卡在 36B，就是这个原因。
    单趟查表、写过的位置不再重扫，从结构上不可能再级联。
    """
    m = _sub_table(x, y, player, body, peer, tpl)
    b, o = bytearray(frame), 0
    while o + 4 <= len(b):
        nv = m.get(int.from_bytes(b[o:o + 4], 'big'))
        if nv is None:
            o += 1
        else:
            b[o:o + 4] = nv.to_bytes(4, 'big')
            o += 4
    return bytes(b)


def build_reactive(req_len, x, y, player, body, peer):
    """【已弃用 2026-11-06】整帧模板版应答，保留只为老自测还能跑。

    新代码走下面的 `build_player_obj_reply()` / `build_body_obj_reply()`：
    sid=0 这条控制通道改为按字段结构化构造，不再对 36B/44B 模板做字节补丁。
    """
    frame = wt.REACTIVE.get(req_len)
    if not frame:
        return None
    return patch_frame(frame, x, y, player, body, peer)



def profile_frag_offsets(frame):
    """找出帧里「档案首片」的载荷起始偏移。

    档案（1264B 那两条、以及加入方模板里两个 1280B 三合一帧）都是分片 DATA：
    首片 flags=0x02、载荷 1196B、**PPID=0x100004d0**，尾片 flags=0x01。
    身份区在首片载荷里：载荷 +21 起（= 整包偏移 41），到载荷 +1176（= 整包 1196）止。
    用 PPID 认，避免把 1236B「成员记录」（PPID=0x100004b4，也是 1196 首片）当成档案。
    """
    out = []
    o, n = 4, len(frame)
    while o + 4 <= n:
        typ, fl = frame[o], frame[o + 1]
        ln = (frame[o + 2] << 8) | frame[o + 3]
        if ln < 4 or o + ln > n:
            break
        if typ == 0 and fl == 0x02 and ln - 16 >= 1196:
            ppid = (frame[o + 12] << 24) | (frame[o + 13] << 16) | (frame[o + 14] << 8) | frame[o + 15]
            if ppid == 0x100004d0:
                out.append(o + 16)
        o += (ln + 3) & ~3
    return out


ID_OFF, ID_END = 21, 1176        # 身份区在"档案首片载荷"里的范围

# ---- Step 2（2026-11-07）：1264B 档案的身份区 ---------------------------------
# 偏移是拿两份真机上传（1268B）和模板逐字节对齐出来的，实测对齐结论：
#   [41:52]    基板号 11B ASCII
#   [60:84]    名字 24B（全角 UTF-8，补零）
#   [115]      等级
#   [130:134]  总得分 u32 BE
#   [134:158]  通り名 24B ASCII（补零）
# 只覆盖这几个离散字段，**1217 附近那段嵌套结构一个字节都不碰**（11-05 踩过 len=0 死循环）。
PROFILE_SLOT_ORDER = (0x10400024, 0x10400025)
# 2026-11-07 09:4x 定案（读模板自身的三个句柄字段得出，不再猜）：
#   两套模板里 1264B 帧的顺序**都是 [0x24 的档案, 0x25 的档案]**，而且 **off37 = "这份档案描述的是谁"**：
#     host   帧1 off37=0x24(对方) / 帧2 off37=0x25(自己)
#     joiner 帧1 off37=0x24(自己) / 帧2 off37=0x25(对方)
#   所以帧序必须按 subject 升序填，并且**每帧的 off37 要跟着 subject 写**（以前统一按"对方"打补丁，
#   joiner 那台就把自己当成了对方 —— 于是画面里对方的名字显示成自己）。


def patch_profile_identity(frame, subj):
    """把这个槽位玩家的身份字段覆盖成**他自己上报**的值。

    2026-11-07 00:3x 修正：以前用"基板号"去认这份档案描述的是谁 —— 错了。
    抓包里两帧 1264B 的顺序是**按槽位**的（主机视角、加入方视角都一样）：
        第 1 帧 = 0x10400025（1P）的档案
        第 2 帧 = 0x10400024（2P）的档案
    而"谁坐哪个槽"每轮都可能变（先连上的拿 0x25），所以必须**按帧序配上号，再取那个号的真实上传**。
    用基板号认的话，只要两台机的基板号与抓包里那两台对调，身份就会整体互换 —— 实测就是这么错的。

    只覆盖这 5 个离散字段；**1216 之后（嵌套结构）一个字节都不碰**。
    """
    if not subj or len(frame) < 1216 or len(subj) < 1216:
        return frame
    # 2026-11-07 00:4x：**整段搬 [41:1216]**，不再只挑 5 个字段。
    # 依据：同一个玩家的"服务端转发帧"和"客户端上传帧"在 [160:1216] 只差 59 字节，
    # 而且全是玩家数据（通り名 <通り名> / プレイヤー名 <プレイヤー名> / 称号 / 装备单字节…），
    # 结构同构 —— 所以把这一整段换成主体自己的上传，卡面上的名字/等级/得分/装备/称号一次到位。
    # 1216 之后（嵌套尾部）保持模板原样，那是 11-05 len=0 死循环的来源。
    b = bytearray(frame)
    b[41:1216] = subj[41:1216]
    return bytes(b)


# ---- sid=0 控制通道：结构化构造（2026-11-06，方向 B） ----------------------
# 真机抓包里这条通道只有两条消息：建玩家对象、建 body 对象。
# 字段语义（实测）：
#   建玩家应答 16B = [0x83000004][echo 请求 magic1][player][echo 请求 magic2]
#   建 body 应答 24B = [0x9100000C][body 的兄弟对象][player][echo 请求 magic4][类别][body]
# PPID 一律等于应用层载荷长度（真机 0x10 / 0x18 / 0x28 都是长度）。

CTRL_PPID_PLAYER = 0x18         # 客户端 44B 建玩家请求的 PPID（= 载荷 24B）
CTRL_PPID_BODY = 0x28           # 客户端 76B 建 body 请求的 PPID（= 载荷 40B）
CTRL_MAGIC_PLAYER = 0x83000004  # 建玩家应答头
CTRL_MAGIC_BODY = 0x9100000C    # 建 body 应答头
BODY_SIBLING = 0x5040000C       # 44B 应答里 body 的兄弟对象：抓包里是常量，无来源可推
BODY_CLASS = 0x40400002         # 类别标记，同上


def data_packet(vtag, tsn, sid, ssn, payload):
    """拼一个只含单个 DATA chunk 的包（flags=0x03 = 起止合一），PPID = 载荷长度。"""
    ln = 16 + len(payload)
    return (struct.pack('>I', vtag & 0xFFFFFFFF) + bytes([0x00, 0x03]) +
            struct.pack('>H', ln) + struct.pack('>I', tsn & 0xFFFFFFFF) +
            struct.pack('>HH', sid & 0xFFFF, ssn & 0xFFFF) +
            struct.pack('>I', len(payload)) + bytes(payload))


def build_player_obj_reply(vtag, ssn, player, req_payload, tsn=0):
    """DN 36B：应答客户端 44B「建玩家对象」。

    请求里 [8:12] 和 [12:16] 是客户端自己带的魔数（30400001 / 00010000），
    真机是原样 echo 回去的 —— 我们也 echo，比写死模板更稳。
    tsn 默认留 0，由 renumber_tsn() 填（自测时才显式给）。
    """
    if len(req_payload) < 16:
        return None
    pay = (struct.pack('>I', CTRL_MAGIC_PLAYER) + bytes(req_payload[8:12]) +
           struct.pack('>I', player & 0xFFFFFFFF) + bytes(req_payload[12:16]))
    return data_packet(vtag, tsn, 0, ssn, pay)


def build_body_obj_reply(vtag, ssn, player, body, req_payload, tsn=0):
    """DN 44B：应答客户端 76B「建 body」。

    请求里 [12:16] 是客户端带的魔数（00020000），原样 echo。
    BODY_SIBLING / BODY_CLASS 是抓包常量：请求里不带、也没别处能推出来，
    将来若发现它们跟 body 连号分配，再改成推导。
    """
    if len(req_payload) < 16:
        return None
    pay = (struct.pack('>I', CTRL_MAGIC_BODY) + struct.pack('>I', BODY_SIBLING) +
           struct.pack('>I', player & 0xFFFFFFFF) + bytes(req_payload[12:16]) +
           struct.pack('>I', BODY_CLASS) + struct.pack('>I', body & 0xFFFFFFFF))
    return data_packet(vtag, tsn, 0, ssn, pay)


def build_profile(x, y, player, body, peer, seq=None):
    """转发档案：直接拿真机那份 1264B 整帧打补丁，不再自己重拼。

    2026-11-05 第四次修正：**不要改 [+14:+16] 的序号**。
    整条重放流用的是抓包原序号（19.4s 时已经走到 0x15 附近），
    我们以前把它改成自己的计数器 1/2/3，客户端重排缓冲直接当旧包丢掉，
    于是 CUSTOMIZE_DATA 永远完不成 → 进不了 LOADING → 不发 LoadFinish。
    模板里的序号本来就对应 19.4 秒那个时间点，保持原样即可。
    """
    if not wt.PROFILE:
        return None
    return patch_frame(wt.PROFILE, x, y, player, body, peer)


def build_presence(x, y, player, body, peer):
    """世界成员记录（1236B）：客户端上报 1228B 之后回它一条。

    真机这条里同时带着两个玩家句柄（自己和对方），客户端靠它确认"场上有几个人"。
    """
    if not wt.PRESENCE:
        return None
    return patch_frame(wt.PRESENCE, x, y, player, body, peer)


def renumber_tsn(pkt, sess):
    """SCTP 层：把每个 DATA chunk 的 TSN 换成会话计数器，从 Initial TSN(Y) 起连续。

    2026-11-05 关键修正：真机抓包里的 TSN 是那一局的实际计数——第一个被捕获的
    DATA chunk 就已经是 `Y+0x35`（前面 53 个块抓包没抓到/已发过）。我们原样重放，
    客户端从 Initial TSN=Y 开始等，缺 Y..Y+52 这 53 个块，**整个重排缓冲永久卡住**。
    现象正好是：SACK/心跳这些非 DATA 块照常走（传输层看着活着），
    但游戏层一个包都收不到（recv_* 全部零调用）。

    所以每条会话维护 tsn_next（初值 = 68B 里宣告的 Initial TSN = Y），
    每发一个 DATA chunk 就 +1。
    """
    nxt = sess.get('tsn_next')
    if nxt is None:
        return pkt
    buf = bytearray(pkt)
    off, n = 4, len(buf)
    while off + 4 <= n:
        typ = buf[off]
        ln = (buf[off + 2] << 8) | buf[off + 3]
        if ln < 4 or off + ln > n:
            break
        if typ == 0:                       # SCTP DATA
            struct.pack_into('>I', buf, off + 4, nxt & 0xFFFFFFFF)
            nxt += 1
        off += (ln + 3) & ~3
    sess['tsn_next'] = nxt & 0xFFFFFFFF
    return bytes(buf)


def _build_24(x, obj, seq):
    pay = (struct.pack('>I', obj) + bytes.fromhex('0004') + struct.pack('>H', seq & 0xFFFF) +
           bytes.fromhex('04000004') + bytes.fromhex('30000100'))
    return struct.pack('>I', x) + bytes([0x00, 0x03]) + struct.pack('>H', 0x14) + pay


def _build_48(x, obj, seq, body, player, tick):
    pay = (struct.pack('>I', obj) + struct.pack('>HH', 0x0010, seq & 0xFFFF) +
           bytes.fromhex('1000001c') + bytes.fromhex('0000000d') +
           struct.pack('>I', body) + struct.pack('>I', player) +
           bytes.fromhex('00000000') + bytes([0x11]) + struct.pack('>I', player) +
           struct.pack('>I', tick & 0xFFFFFFFF) + bytes.fromhex('000000'))
    assert len(pay) == 40, len(pay)
    return struct.pack('>I', x) + bytes([0x00, 0x03]) + struct.pack('>H', 0x2c) + pay


def _tick(sock, addr, sess, n):
    x = sess.get('X')
    y = sess.get('Y')
    player = sess.get('player_h')
    body = sess.get('body_h')
    peer = sess.get('peer_h')
    if not all((x, y, player, body, peer)):
        return 0
    obj = (y + 0x34 + n) & 0xFFFFFFFF
    sock.sendto(renumber_tsn(_build_24(x, obj, n), sess), addr)
    sock.sendto(renumber_tsn(_build_48(x, (obj + 1) & 0xFFFFFFFF, n, body, player,
                                       int(time.time() * 1000)), sess), addr)
    return 2


def _timeline(tpl=None):
    """把时间轴帧和「按抓包时间点插回的大帧」合并成一个有序事件表。

    2026-11-06: TIMED 的每一项现在是 (dt, kind, bytes) —— 大帧自带字节，
    不再复用 PROFILE/PRESENCE 两份模板（复用会把同一 SSN 发两次、还漏掉 SSN 23/24）。
    """
    t = tpl or wt
    ev = [(dt, 'frame', b) for dt, b in t.FRAMES]
    for item in getattr(t, 'TIMED', []):
        if len(item) == 3:
            ev.append((item[0], item[1], item[2]))
        # 旧格式 (dt, kind) 没有字节，只能跳过；重新跑 tools\gen_world_templates.py 即可
    ev.sort(key=lambda x: x[0])
    return ev


def start(sock, addr, sess, log, t0=None, tpl=None, profile_of=None):
    """后台线程：按真机时间轴把帧发给 addr，播完后接着 1Hz 心跳。

    sess 是 udp3953 的会话字典（X/Y/player_h/body_h/peer_h/last），
    每帧现读，这样 44B 请求里采纳的句柄能立刻生效。
    第 0 帧是 68B 握手回复本身，调用方已经发过，这里跳过。

    2026-11-05: 1264 档案 / 1236 成员记录改成**按抓包时间点**塞回时间轴
    （TIMED），不再收到客户端上报就立刻发——那样序号对不上，
    会被 ESCTP 重排窗口整包丢掉（实测 recv_CustomizeDataAllV1 从未被调用）。
    """
    def run():
        base = t0 if t0 is not None else time.time()
        # 2026-11-06 晚：**等客户端把 CC 里的号提上来再定角色**。
        # hello 时的 player_h 是 3953 临时发的（重连会爬号），真正定角色的是
        # create-player 里采纳的那个（~3.45s）；第一帧在 4.09s，来得及。
        use = tpl
        n_profile = 0
        if use is None:
            # 2026-11-07 早修：这里原来等的是"号变成 0x25/0x24 之一"，可是 hello 时发的**临时号**
            # 本来就是 0x25 —— 条件立刻满足，模板在"采纳"之前就定死了。实测两台都跑了 host 模板，
            # 所以无论怎么改帧序画面都不变。改成**等 adopted 标记**（create-player 里采纳后置位）。
            deadline = time.time() + 3.9
            while time.time() < deadline and not sess.get('adopted'):
                time.sleep(0.05)
            use = templates_for(sess.get('player_h'))
        replay_name = 'joiner' if use is not wt else 'host'

        sent = 0
        try:
            for i, (dt, kind, frame) in enumerate(_timeline(use)):
                if i == 0:
                    continue
                wait = base + dt / 1000.0 - time.time()
                if wait > 0:
                    time.sleep(wait)
                if kind == 'frame' and 400 <= len(frame) < 1200 and os.path.exists(SKIP_BIGSNAP):
                    # 2026-11-07 早：这些 400~1200B 的"世界快照"是我们从抓包回放的，
                    # 里面带着**录像里那两个角色的外观/装备**。实测"自己那个人是对的、对方装备错"，
                    # 所以对方外观大概率来自这里。开关打开后只靠转发的真机状态帧描述对方，
                    # 用来验证"外观到底来自快照还是来自转发"。
                    continue
                if kind == 'frame':
                    # 2026-11-06: 默认**不跳过**。188B 就是开场帧，砍掉它客户端根本进不了 stage
                    #（实测：砍了之后 .10 卡 NOW LOADING、.15 连着重连 9 次）。
                    # 真要 A/B 才建 data\relay_skip_replay.on。
                    if relay_skip_enabled() and _is_state_frame(frame):
                        continue
                    pkt = patch_frame(frame, sess['X'], sess['Y'], sess['player_h'],
                                      sess['body_h'], sess['peer_h'], use)
                elif kind in ('profile_self', 'profile_peer', 'presence'):
                    # 2026-11-06：这三类大帧的包头都是【收件人】的 body(off24)/player(off28)，
                    # off37 是"另一方"（自己档案里指对方，对方档案里指自己），
                    # 所以统一按收件人打补丁；两帧 1264B 的内容差异（名字/基板号）留在模板里。
                    peer = sess.get('peer_h') or ((sess['player_h'] - 1) & 0xFFFFFFFF)
                    pkt = patch_frame(frame, sess['X'], sess['Y'], sess['player_h'],
                                      sess['body_h'], peer, use)
                else:
                    continue
                if not pkt:
                    continue
                if profile_of is not None and not os.path.exists(IDENTITY_OFF):
                    for _off in profile_frag_offsets(pkt):
                        slot_h = PROFILE_SLOT_ORDER[n_profile % 2]
                        n_profile += 1
                        _up = profile_of(slot_h)
                        _b = bytearray(pkt)
                        _ok = bool(_up) and len(_up) >= 1196 and len(_b) >= _off + ID_END
                        if _ok:
                            _b[_off + ID_OFF:_off + ID_END] = _up[41:1196]
                            # off37（载荷 +17）= "这份档案描述的是谁"，必须等于该槽位玩家的号
                            _b[_off + 17:_off + 21] = slot_h.to_bytes(4, 'big')
                            pkt = bytes(_b)
                        log('   => 档案身份 +%dms 槽位 0x%08X %s 基板=%s 名=%s'
                            % (dt, slot_h, ('已用真实上传覆盖' if _ok else '无该槽上传，保持模板'),
                               pkt[_off + ID_OFF:_off + ID_OFF + 11].decode('ascii', 'replace'),
                               pkt[_off + ID_OFF + 19:_off + ID_OFF + 43].split(b'\x00')[0].decode('utf-8', 'replace')))
                sock.sendto(renumber_tsn(pkt, sess), addr)
                sent += 1
                if sent <= 5 or sent % 25 == 0 or (dt >= 35000 and len(pkt) >= 180):
                    log('   => world +%dms %dB' % (dt, len(pkt)))
                if len(pkt) == 188 and dt >= 35800:
                    log('   => 开场帧 player=0x%08X peer=0x%08X body=0x%08X'
                        % (sess['player_h'], sess['peer_h'], sess['body_h']))
                elif kind in ('profile_self', 'profile_peer', 'presence'):
                    ssn = (struct.unpack_from('>H', pkt, 14)[0]
                           if len(pkt) >= 16 and pkt[4] == 0x00 else -1)
                    log('   => 时间轴注入 %s +%dms %dB sid=%d ssn=%d'
                        % (kind, dt, len(pkt),
                           struct.unpack_from('>H', pkt, 12)[0] if ssn >= 0 else -1, ssn))
            log('   => world 重放完成（%d 帧，%s 模板），转入 1Hz 心跳' % (sent, replay_name))

            n = 0
            while True:
                time.sleep(1.0)
                if time.time() - sess.get('last', 0) > KEEPALIVE_QUIET:
                    log('   => world 心跳停止（客户端已静默）')
                    return
                try:
                    _tick(sock, addr, sess, n)
                except OSError:
                    # 对端已经关了端口，Windows 回 ICMP 不可达，继续发只会刷错误
                    log('   => world 心跳停止（对端端口已关闭）')
                    return
                n += 1
        except Exception as e:
            log('   => world replay 中止 %r（已发 %d 帧）' % (e, sent))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t
