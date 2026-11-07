#!/usr/bin/env python3
r"""launch_client.py -- portable launcher (CMD/Python, no PowerShell needed).

Same job as launch_client.ps1:
  client.json -> cfg\\dnsmap.txt + cfg\\poke.cfg (forcenet)
  -> local PCP (127.0.0.1:4010x) -> check remote :80/:52000
  -> stop old game -> inject bin\\tpfake.dll + bin\\probe.dll

Run (from CMD, admin not required for this; admin only for card creation):
    python\python.exe launch_client.py
    launch_client.bat

Options: --server-ip IP  --game-dir DIR  --no-pcp  --no-launch  --debug  --force
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
CFG_DIR = os.path.join(ROOT, 'cfg')
BIN_DIR = os.path.join(ROOT, 'bin')
LOG_DIR = os.path.join(ROOT, 'logs')
PCP_DIR = os.path.join(ROOT, 'pcp')

DETACHED_PROCESS = 0x00000008
CREATE_NO_WINDOW = 0x08000000

# tpfake 自己会加载 connlog/windower/glcap/probe/serialfake/touchfake，
# 所以这里只补它不加载的 profiletx（卡面字段）。
# 2026-11-07: 去掉 probe_focus.dll —— 与 tpfake 自载的 probe.dll 撞车（崩在 +0x382b）
CORE = ['tpfake.dll', 'profiletx.dll']
EXTRA = ['appdump12.dll', 'sendlog.dll', 'esctp_tap.dll', 'sifdump.dll',
         'filefail.dll', 'sessdump.dll', 'handump.dll', 'taildump.dll',
         'recvlog.dll']


def say(msg: str) -> None:
    print(msg, flush=True)


def port_up(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        return s.connect_ex(('127.0.0.1', port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def remote_tcp(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout):
            return True
    except OSError:
        return False


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))       # no packet is sent
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.') and not ip.startswith('169.254.'):
                return ip
    except OSError:
        pass
    return '127.0.0.1'


def start_pcp(cfg: dict, game_dir: str) -> None:
    ports = [40100, 40102, 40104, 40106, 40110, 40113, 40114]
    pcp_cfg = cfg.get('pcp') or {}
    if pcp_cfg.get('ports'):
        ports = [int(p) for p in pcp_cfg['ports']]
    if port_up(40100) and port_up(40106):
        say('  already up, reusing it')
        say('  (if you just updated pcp_server.py, close it first: taskkill /F /IM python.exe)')
        return
    py = os.path.join(ROOT, 'python', 'python.exe')
    if not os.path.exists(py):
        py = sys.executable
    addr = str(pcp_cfg.get('networkaddr') or 'auto')
    if addr in ('auto', ''):
        addr = local_ip()
    pcp_py = os.path.join(PCP_DIR, 'pcp_server.py')
    if not os.path.exists(pcp_py):
        raise SystemExit('missing pcp\\pcp_server.py')
    ds_table = os.path.join(game_dir, 'SBVB_Table.dat')
    if not os.path.exists(ds_table):
        say('  [!] SBVB_Table.dat not found in game_dir -- keychip.ssd.proof will fail')
    args = [py, pcp_py, '--ports', ','.join(str(p) for p in ports),
            '--networkaddr', addr, '--log', os.path.join(LOG_DIR, 'pcp.log'),
            '--ds-table', ds_table]
    # 2026-11-03: keychip ID 每台机台必须不同（档案里的基板标识由它决定）
    if pcp_cfg.get('keyid'):
        args += ['--keyid', str(pcp_cfg['keyid'])]
    if pcp_cfg.get('mainid'):
        args += ['--mainid', str(pcp_cfg['mainid'])]
    say('  starting: %s --networkaddr %s' % (os.path.basename(py), addr))
    out = open(os.path.join(LOG_DIR, 'pcp.out.txt'), 'ab')
    err = open(os.path.join(LOG_DIR, 'pcp.err.txt'), 'ab')
    subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                     creationflags=DETACHED_PROCESS)
    for _ in range(20):
        time.sleep(0.25)
        if port_up(40100):
            say('  PCP is up')
            return
    say('  [!] PCP did not open 40100 -- see logs\\pcp.err.txt')


def load_client_json(path: str) -> dict:
    """Parse client.json; tolerate Windows paths written with single backslashes."""
    with open(path, 'r', encoding='utf-8-sig') as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        if 'Invalid \\escape' not in str(exc):
            raise
        # "D:\shiningforce" -> "D:\\shiningforce" (keep real JSON escapes like \\n)
        fixed = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)
        return json.loads(fixed)



# ---------------------------------------------------------------- profile 校验
PROFILE_SLOTS = [
    ('nickname',      134, '卡面右上 通り名'),
    ('shop_name',     254, '店铺名（机台级）'),
    ('team_member_1', 335, '队伍成员 #1（卡面左上）'),
    ('team_member_2', 383, '队伍成员 #2'),
    ('team_member_3', 431, '队伍成员 #3'),
    ('team_member_4', 479, '队伍成员 #4'),
]


def _profile_char_ok(ch: str) -> bool:
    """只允许英文（半角 ASCII 可打印）或日文（假名/全角符号/汉字）。"""
    o = ord(ch)
    return (0x20 <= o <= 0x7E) or (0x3000 <= o <= 0x30FF) or (0xFF01 <= o <= 0xFF60) or (0x4E00 <= o <= 0x9FFF)


def _check_profile(cfg: dict) -> dict:
    """校验 client.json 的 profile 段；返回 {键: 值}（只含有内容的项）。

    说明：客户端目前是自己从游戏数据里取这 6 个值，本文件暂时只做登记与校验，
    改完启动时会打印实际取值；写入对局档案需要服务端按槽覆盖（见 client.json 的 _生效方式）。
    """
    prof = cfg.get('profile') or {}
    out = {}
    bad = []
    for key, off, desc in PROFILE_SLOTS:
        val = str(prof.get(key) or '')
        if not val:
            continue
        data = val.encode('utf-8')
        if len(data) > 23:
            bad.append('%s 超长：%d 字节（上限 23）' % (key, len(data)))
        for ch in val:
            if not _profile_char_ok(ch):
                bad.append('%s 含不支持的字符 %r（只能用英文或日文）' % (key, ch))
                break
        out[key] = val
    if bad:
        for b in bad:
            say('  [!] profile: ' + b)
    if out:
        say('=== profile（只读登记；写入档案需服务端覆盖）===')
        for key, off, desc in PROFILE_SLOTS:
            if key in out:
                say('  %-12s = %-10s  偏移 %3d  %s' % (key, out[key], off, desc))
    return out



def _write_profile_cfg(cfg: dict) -> None:
    """把 client.json 的 profile 段写成 cfg\\profile_fields.txt 供 profilepatch.dll 读取。

    board_id 由 pcp.keyid 推出（去 '-' 取前 11 位），两台机各自配置即可。
    """
    prof = cfg.get('profile') or {}
    pcp = cfg.get('pcp') or {}
    keyid = str(pcp.get('keyid') or '')
    serial = keyid.replace('-', '')[:11]
    lines = ['# 由 launch_client.py 从 client.json 自动生成；请改 client.json',
             'board_id=' + serial, '']
    for key, off, desc in PROFILE_SLOTS:
        lines.append('# %s（偏移 %d）；空值 = 不改这一项' % (desc, off))
        lines.append('%s=%s' % (key, str(prof.get(key) or '')))
    path = os.path.join(ROOT, 'cfg', 'profile_fields.txt')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(lines) + '\n')
    say('  profile_fields.txt -> %s (board %s)' % (os.path.relpath(path, ROOT), serial or '(no keyid)'))

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--server-ip', default='')
    ap.add_argument('--game-dir', default='')
    ap.add_argument('--no-pcp', action='store_true')
    ap.add_argument('--no-launch', action='store_true')
    ap.add_argument('--debug', action='store_true', help='inject the 8 log-only hooks too')
    ap.add_argument('--force', action='store_true', help='ignore game exe hash mismatch')
    args = ap.parse_args()

    os.makedirs(LOG_DIR, exist_ok=True)
    # 2026-11-07: 每次启动都盖一条"到场记录"，用来区分"启动器没跑"和"跑了但注入失败"。
    try:
        _launch_log = os.path.join(LOG_DIR, 'launcher.out.txt')
        with open(_launch_log, 'w', encoding='utf-8') as _fh:
            _fh.write('launcher start %s  pid=%d  argv=%r\n'
                      % (time.strftime('%Y-%m-%d %H:%M:%S'), os.getpid(), sys.argv[1:]))
        print('launcher log -> %s' % _launch_log)
    except Exception as _e:
        print('[!] cannot write launcher log: %r' % (_e,))
    cfg = load_client_json(os.path.join(ROOT, 'client.json'))
    _check_profile(cfg)
    _write_profile_cfg(cfg)

    server_ip = args.server_ip or str(cfg.get('server_ip') or '')
    game_dir = args.game_dir or str(cfg.get('game_dir') or '')
    if not server_ip:
        raise SystemExit('client.json: server_ip is empty')
    if not game_dir:
        raise SystemExit('client.json: game_dir is empty')
    if not os.path.isabs(game_dir):
        game_dir = os.path.join(ROOT, game_dir)
    game_dir = os.path.normpath(game_dir)      # accepts D:/... or D:\\...

    exe_name = str(cfg.get('exe') or 'project_f-ringedge-release.exe')
    exe = os.path.join(game_dir, exe_name)
    if not os.path.exists(exe):
        raise SystemExit('game exe not found: %s' % exe)

    expected = str(cfg.get('exe_sha256') or '').upper()
    if expected:
        h = hashlib.sha256(open(exe, 'rb').read()).hexdigest().upper()
        if h != expected:
            msg = 'game exe SHA256 mismatch\n  expected %s\n  actual   %s' % (expected, h)
            if not args.force:
                raise SystemExit(msg + '\n(use --force only if you know the build is compatible)')
            say('[!] ' + msg + '  (continuing because --force)')

    say('=== [1/5] config (server %s) ===' % server_ip)
    names = ['naominet.jp', 'ib.naominet.jp', 'bbrouter.loc', 'tenporouter.loc', 'aime.naominet.jp']
    with open(os.path.join(CFG_DIR, 'dnsmap.txt'), 'w', encoding='ascii', newline='') as fh:
        for n in names:
            fh.write('%s=%s\r\n' % (n, server_ip))
    poke_path = os.path.join(CFG_DIR, 'poke.cfg')
    with open(poke_path, 'r', encoding='utf-8-sig', errors='replace') as fh:
        poke = fh.read()
    if re.search(r'(?m)^forcenet\s+\S+', poke):
        poke = re.sub(r'(?m)^forcenet\s+\S+', 'forcenet ' + server_ip, poke)
    else:
        poke += '\r\nforcenet %s\r\n' % server_ip
    with open(poke_path, 'w', encoding='utf-8', newline='') as fh:
        fh.write(poke)
    say('  dnsmap.txt -> %s (5 entries)' % server_ip)
    say('  poke.cfg   -> forcenet %s' % server_ip)

    say('=== [2/5] remote server ===')
    ok80 = remote_tcp(server_ip, 80)
    ok52 = remote_tcp(server_ip, 52000)
    say('  %s:80    %s' % (server_ip, 'UP' if ok80 else 'DOWN'))
    say('  %s:52000 %s' % (server_ip, 'UP' if ok52 else 'DOWN'))
    if not (ok80 and ok52):
        say('  [!] one of the remote services is down -- the three status lights will not all be green.')

    say('=== [3/5] local PCP (127.0.0.1:4010x) ===')
    if args.no_pcp:
        say('  skipped (--no-pcp)')
    else:
        start_pcp(cfg, game_dir)

    if not os.path.exists(r'C:\iccard.bin'):
        say('  [!] C:\\iccard.bin is missing -- insert a card (or run setup_card.bat once as admin).')

    say('=== [4/5] stop old game + inject ===')
    subprocess.run(['taskkill', '/F', '/IM', 'project_f-ringedge-release.exe'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   creationflags=CREATE_NO_WINDOW)
    time.sleep(2)

    if args.no_launch:
        say('  skipped injection (--no-launch)')
    else:
        inj = os.path.join(BIN_DIR, 'inject_multi.exe')
        if not os.path.exists(inj):
            raise SystemExit('missing bin\\inject_multi.exe')
        names = CORE + (EXTRA if args.debug else [])
        dlls = [os.path.join(BIN_DIR, n) for n in names]
        cmd = [inj, '--log', os.path.join(LOG_DIR, 'game_out.txt'), exe_name] + dlls
        out = open(os.path.join(LOG_DIR, 'inject.out.txt'), 'wb')
        err = open(os.path.join(LOG_DIR, 'inject.err.txt'), 'wb')
        try:
            rc = subprocess.run(cmd, cwd=game_dir, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err, timeout=90,
                                creationflags=CREATE_NO_WINDOW).returncode
        except subprocess.TimeoutExpired:
            rc = -1
            say('  [!] inject_multi timed out')
        if rc != 0:
            say('  [!] inject_multi rc=%s; see logs\\inject.err.txt' % rc)
        time.sleep(3)
        try:
            out_ps = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq project_f-ringedge-release.exe', '/NH'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                creationflags=CREATE_NO_WINDOW).stdout
            if 'project_f-ringedge-release' in out_ps:
                say('  game is running')
            else:
                say('  [!] game process not found -- check logs\\inject.err.txt')
        except OSError:
            say('  (tasklist unavailable; check the game window)')

    say('=== [5/5] done ===')
    say('')
    say('Hotkeys: F2 = insert IC card, F10 = eject, F1 = coin.')
    say('Check: three status lights green on Game Mode Select;')
    say('       a card that has played at least one story quest shows the Online modes selectable.')
    say('Logs:  logs\\ (tpfake/connlog/probe/pcp/...)')
    return 0


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(errors='replace')
    except (AttributeError, ValueError):
        pass
    sys.exit(main())
