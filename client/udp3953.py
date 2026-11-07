# -*- coding: utf-8 -*-
"""3953 UDP 监听器（只收不发，纯记录）。

用途：客户端进局后会把对局数据发到 CC 里指定的地址:3953。
我们现在没有这个服务，数据全进了黑洞——先接住、记下来，看清格式再写中转。

用法:
    python udp3953.py --port 3953 --log data/udp3953.log
"""

import argparse
import os
import socket
import struct
import sys
import time

DEFAULT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'udp3953.log')

_stats = {}          # src -> [包数, 字节数]
_start = time.time()
_last_flush = time.time()


def log_line(path, text):
    with open(path, 'a', encoding='utf-8', newline='\n') as f:
        f.write(text + '\n')


def main():
    global _last_flush
    ap = argparse.ArgumentParser()
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=3953)
    ap.add_argument('--log', default=DEFAULT_LOG)
    ap.add_argument('--head', type=int, default=80, help='每包记录前多少字节')
    ap.add_argument('--save-first', type=int, default=3, help='每种长度前 N 个包存原始文件')
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    log_line(args.log, '=== udp%d listening on %s:%d  (%s) ==='
             % (args.port, args.bind, args.port, time.strftime('%Y-%m-%d %H:%M:%S')))
    print('udp%d listening on %s:%d' % (args.port, args.bind, args.port), flush=True)

    seen = {}
    pkt = 0
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_line(args.log, 'recv error: %r' % (e,))
            continue
        pkt += 1
        key = '%s:%d' % (addr[0], addr[1])
        st = _stats.setdefault(key, [0, 0])
        st[0] += 1
        st[1] += len(data)
        ts = time.strftime('%H:%M:%S') + ('.%03d' % (int(time.time() * 1000) % 1000))
        log_line(args.log, '%s %s len=%d %s' % (ts, key, len(data), data[:args.head].hex(' ')))

        n = seen.get(len(data), 0)
        if n < args.save_first:
            seen[len(data)] = n + 1
            dump = os.path.join(os.path.dirname(args.log), 'udp3953_%d.bin' % len(data))
            with open(dump, 'wb') as f:
                f.write(data)

        if time.time() - _last_flush >= 30:
            summary = ', '.join('%s=%d包/%dB' % (k, v[0], v[1]) for k, v in _stats.items())
            log_line(args.log, '--- 30s 汇总: %s' % summary)
            print('30s: %s' % summary, flush=True)
            _last_flush = time.time()

    sock.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
