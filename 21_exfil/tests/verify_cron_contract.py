#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cron.d 加载期契约守卫。

为什么需要它
------------
`verify_cron_exec.py` 证明的是"条目会被一个符合 Vixie 语义的调度器解析并触发"，
但它替代不了真实 cron 的**加载期**行为。而 cron 恰恰以"静默不执行"著称：
条目写进去了、文件格式看着也对、没有任何报错，作业却一次都没跑过。

以下每一条都是真实 cron（Vixie / Debian cron）在加载 /etc/cron.d/* 时的硬行为，
违反任意一条都会导致**整个文件被跳过**，而 syslog 之外没有任何可见症状：

  C1 文件名不含 '.'      —— cron 只扫描不含点的文件名。camd.conf / camd.cron
                            会被完全忽略，这是部署中最常见的一类。
  C2 作业行有 user 字段  —— /etc/cron.d 与用户级 crontab 格式不同，第 6 个字段
                            必须是用户名。漏写会被当成 user="/path/to/cmd"，
                            报 bad username 并跳过。
  C3 非 group/other 可写 —— group/other 有写位时 cron 拒绝加载（bad mode）。
  C4 owner 为 root       —— Debian cron 要求 /etc/cron.d 下文件属主为 root。
  C5 PATH 显式设置       —— cron 默认 PATH 极窄（/usr/bin:/bin）。camd 装在
                            /usr/local/bin，不显式设 PATH 时命令找不到，
                            而 cron 的输出默认丢弃，表现为"从没执行过"。
  C6 文件以换行结尾      —— 末行无换行的条目会被忽略（真实实现细节）。
  C7 命令存在且可执行    —— 指向不存在的路径时 cron 每秒记一次错但不报警。

正向 7 条 + 反向 6 条。反向**缺一不可**：不做反向，这 7 条就是恒绿的摆设。
"""

import os
import re
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXFIL = os.path.dirname(HERE)
ROOT = os.path.dirname(EXFIL)
ONEKEY = os.path.join(EXFIL, "onekey.sh")
MAKE_ONEKEY = os.path.join(EXFIL, "make_onekey.py")
CAMD = os.path.join(ROOT, "agent_windows", "build", "linux", "camd")

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                         ("  -- " + detail) if detail else ""))
    return bool(ok)


def load_onekey():
    """生成一键脚本（含真实 camd 产物），返回路径。"""
    if not os.path.exists(ONEKEY) or not os.path.exists(MAKE_ONEKEY):
        return None
    if not os.path.exists(CAMD):
        r = subprocess.run(["make", "-C", os.path.join(ROOT, "agent_windows")],
                           capture_output=True, text=True, timeout=900)
        if not os.path.exists(CAMD):
            return None
    out = os.path.join(tempfile.gettempdir(), "ok_croncontract.sh")
    r = subprocess.run([sys.executable, MAKE_ONEKEY, "amd64=" + CAMD, "-o", out],
                       capture_output=True, text=True, timeout=300)
    return out if r.returncode == 0 and os.path.exists(out) else None


def install(onekey, prefix):
    env = dict(os.environ, PREFIX=prefix)
    r = subprocess.run(["sh", onekey, "install", "--c2", "127.0.0.1:1",
                        "--backend", "v4l2"],
                       env=env, capture_output=True, text=True, timeout=300)
    return r.returncode, r.stdout + r.stderr


def find_cron_file(prefix):
    d = os.path.join(prefix, "etc", "cron.d")
    if not os.path.isdir(d):
        return None
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        if os.path.isfile(p):
            return p
    return None


CRON_FIELD_RE = re.compile(r"^[0-9*/,\-]+$")


def is_job_line(s):
    """作业行：前 5 个字段都是 cron 时间表达式。

    不能用"字段数==7"来识别——作业行带参数时是 9 个字段
    （`M H D M W user cmd --batches 1`），那个判据会让反向注入静默失效，
    表现为"注入未被抓到"，实则是注入根本没写进去。
    """
    f = s.split()
    return len(f) >= 7 and all(CRON_FIELD_RE.match(x) for x in f[:5])


def job_lines(text):
    """作业行：非空、非注释、非 NAME=value。"""
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if "=" in s.split()[0]:
            continue
        out.append(s)
    return out


# ---------------------------------------------------------------- 契约判据

def c1_name(path, _text):
    base = os.path.basename(path)
    return "." not in base, "文件名 %s" % base


def c2_user(_path, text):
    jobs = job_lines(text)
    if not jobs:
        return False, "无作业行"
    bad = []
    for j in jobs:
        f = j.split()
        if len(f) < 7:
            bad.append("字段数 %d(<7)" % len(f))
            continue
        # 第 6 字段必须是用户名而非绝对路径
        if f[5].startswith("/"):
            bad.append("user 字段是路径: %s" % f[5])
    return not bad, ("; ".join(bad)) if bad else "user=%s" % job_lines(text)[0].split()[5]


def c3_mode(path, _text):
    m = os.stat(path).st_mode
    gw = bool(m & stat.S_IWGRP)
    ow = bool(m & stat.S_IWOTH)
    return not (gw or ow), "mode=%o group_w=%s other_w=%s" % (
        stat.S_IMODE(m), gw, ow)


def c4_owner(path, _text):
    st = os.stat(path)
    return st.st_uid == 0, "uid=%d" % st.st_uid


def c5_path(_path, text):
    has = any(ln.strip().startswith("PATH=") for ln in text.splitlines())
    return has, "PATH 显式设置" if has else "缺 PATH——cron 默认 PATH 找不到 /usr/local/bin"


def c6_newline(path, _text):
    with open(path, "rb") as f:
        data = f.read()
    ok = data.endswith(b"\n")
    return ok, "末字节 %r" % (data[-1:] if data else b"")


def c7_cmd(_path, text):
    jobs = job_lines(text)
    if not jobs:
        return False, "无作业行"
    cmd = jobs[0].split()[6]
    if not cmd.startswith("/"):
        return False, "命令非绝对路径: %s" % cmd
    if not os.path.exists(cmd):
        return False, "命令不存在: %s" % cmd
    if not os.access(cmd, os.X_OK):
        return False, "命令不可执行: %s" % cmd
    return True, cmd


CHECKS = [("C1", c1_name), ("C2", c2_user), ("C3", c3_mode),
          ("C4", c4_owner), ("C5", c5_path), ("C6", c6_newline),
          ("C7", c7_cmd)]


def run_checks(path):
    with open(path, "r", errors="replace") as f:
        text = f.read()
    return {cid: fn(path, text) for cid, fn in CHECKS}


# ---------------------------------------------------------------- 主流程

def main():
    onekey = load_onekey()
    if not onekey:
        check("P0 一键脚本可用", False, "生成器或 camd 缺失")
        return 1

    prefix = tempfile.mkdtemp(prefix="croncontract_")
    # 假根里必须造发行版特征文件。
    #
    # 形态探测一律按 $PREFIX/etc 判定（部署脚本与 camd 内部 persist 同源，
    # 不同源就会互相抵消：部署写 cron.d、camd 按自己探测结果删掉并改写
    # /etc/crontab —— 实测复现过，install 退出 0 而 cron.d 目录为空）。
    # 空假根没有任何特征文件，按"未知 -> 通用路径"落到 /etc/crontab 回退
    # 形态，本文件验的是 Debian 系目标上的 cron.d 驻留，故显式造 debian 特征。
    os.makedirs(os.path.join(prefix, "etc"), exist_ok=True)
    with open(os.path.join(prefix, "etc", "debian_version"), "w") as f:
        f.write("12.4\n")
    rc, out = install(onekey, prefix)
    path = find_cron_file(prefix)
    if not path:
        check("P0b install 写出 cron 条目", False, "rc=%d %s" % (rc, out[-200:]))
        return 1
    check("P0b install 写出 cron 条目", True, path)

    res = run_checks(path)
    for cid, fn in CHECKS:
        ok, detail = res[cid]
        check("%s %s" % (cid, fn.__doc__ or cid), ok, detail)

    # ---------------------------------------------------------- 反向注入
    # 每条都为真 cron 的一个真实失效原因；不做反向，上面 7 条就是恒绿。
    reverse = []

    # R1: 文件名含点 —— cron 完全忽略该文件
    d = os.path.dirname(path)
    dotted = os.path.join(d, os.path.basename(path) + ".conf")
    os.rename(path, dotted)
    ok, _ = c1_name(dotted, "")
    reverse.append(("R1 文件名含点被 cron 忽略", not ok))
    os.rename(dotted, path)

    # R2: 作业行漏 user 字段
    with open(path) as f:
        orig = f.read()
    lines = orig.splitlines()
    fixed = []
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and "=" not in s.split()[0] and is_job_line(s):
            f_ = s.split()
            fixed.append(" ".join(f_[:5] + f_[6:]))   # 去掉第 6 字段(user)
        else:
            fixed.append(ln)
    with open(path, "w") as f:
        f.write("\n".join(fixed) + "\n")
    ok, _ = c2_user(path, open(path).read())
    reverse.append(("R2 漏 user 字段", not ok))
    with open(path, "w") as f:
        f.write(orig)

    # R3: group/other 可写
    old = stat.S_IMODE(os.stat(path).st_mode)
    os.chmod(path, 0o666)
    ok, _ = c3_mode(path, "")
    reverse.append(("R3 group/other 可写", not ok))
    os.chmod(path, old)

    # R4: 去掉 PATH 行
    no_path = "\n".join(l for l in orig.splitlines()
                        if not l.strip().startswith("PATH=")) + "\n"
    with open(path, "w") as f:
        f.write(no_path)
    ok, _ = c5_path(path, no_path)
    reverse.append(("R4 缺 PATH", not ok))
    with open(path, "w") as f:
        f.write(orig)

    # R5: 末行无换行
    with open(path, "w") as f:
        f.write(orig.rstrip("\n"))
    ok, _ = c6_newline(path, "")
    reverse.append(("R5 末行无换行", not ok))
    with open(path, "w") as f:
        f.write(orig)

    # R6: 命令指向不存在的路径
    broke = orig.replace(job_lines(orig)[0].split()[6], "/nonexistent/nope")
    with open(path, "w") as f:
        f.write(broke)
    ok, _ = c7_cmd(path, broke)
    reverse.append(("R6 命令不存在", not ok))
    with open(path, "w") as f:
        f.write(orig)

    for name, caught in reverse:
        check(name, caught, "注入被抓到" if caught else "注入未被抓到——断言恒绿")

    n_pass = sum(1 for _, ok, _ in results if ok)
    n_fail = len(results) - n_pass
    print("\n=== result: %d pass, %d fail ===" % (n_pass, n_fail))
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
