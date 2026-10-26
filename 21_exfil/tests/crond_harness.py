#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cron.d 调度与执行器（测试用，非驻留组件）。

为什么需要它
------------
本沙盒（以及多数容器镜像）里**没有任何 cron 守护进程**：
    /usr/sbin/cron、/usr/sbin/crond、busybox crond 全部不存在，
    且无外网（apt / pip 均 403），装不上真实实现。
于是 "cron 条目已写" 长期停留在**未执行**状态 —— 部署报告里那一行
"cron 条目已写入（分位 N）" 从来没有被证明过真的会跑。

这个脚本补的就是"执行"这一半：
  * 按 Vixie cron.d 的真实语义解析条目文件
    （注释行、NAME=value 环境行、m h dom mon dow user command 作业行）
  * 时刻匹配时用 /bin/sh -c 真实执行，环境取自文件内的赋值与 SHELL/PATH
  * 同一 (作业, 分钟) 只触发一次，避免一分钟里重复拉起
  * 若环境里存在真实 cron/crond，则优先启动真实实现并据实报告

它替代的是**调度器**，不是被调度的内容：命令行是被测脚本真实生成的，
执行的是真实的 camd 二进制。这一点在验证脚本里显式打印。

用法
----
    crond_harness.py --file /etc/cron.d/camd --once          # 立即执行一次
    crond_harness.py --file /etc/cron.d/camd --serve 150     # 按分钟调度，最长 150s
    crond_harness.py --check-parser                          # 表达式解析器自检
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
DAYS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}


class Field:
    """一个 cron 字段：`*`、`*/n`、`a`、`a-b`、`a-b/n`、`a,b,c` 及其组合。"""

    def __init__(self, spec, lo, hi, names=None):
        self.spec = spec
        self.lo, self.hi = lo, hi
        self.names = names or {}
        self.values = self._parse(spec)

    def _parse(self, spec):
        out = set()
        for part in spec.split(","):
            part = part.strip().lower()
            if not part:
                raise ValueError("空字段段")
            step = 1
            if "/" in part:
                part, _, s = part.partition("/")
                if not s.isdigit() or int(s) == 0:
                    raise ValueError("步长非法: %s" % spec)
                step = int(s)
            if part == "*":
                lo, hi = self.lo, self.hi
            elif "-" in part:
                a, _, b = part.partition("-")
                lo = self._num(a)
                hi = self._num(b)
            else:
                lo = hi = self._num(part)
            if lo < self.lo or hi > self.hi:
                raise ValueError("取值越界: %s" % spec)
            if lo > hi:                      # 允许 22-2 这类跨零点区间
                out.update(list(range(lo, self.hi + 1)) + list(range(self.lo, hi + 1)))
            else:
                out.update(range(lo, hi + 1, step))
        return out

    def _num(self, tok):
        tok = tok.strip().lower()
        if tok in self.names:
            return self.names[tok]
        if not tok.lstrip("+").isdigit():
            raise ValueError("非法取值: %s" % tok)
        return int(tok)

    def match(self, v):
        return v in self.values


class Job:
    def __init__(self, minute, hour, dom, mon, dow, user, cmd, lineno):
        self.minute = Field(minute, 0, 59)
        self.hour = Field(hour, 0, 23)
        self.dom = Field(dom, 1, 31)
        self.mon = Field(mon, 1, 12, MONTHS)
        # cron 的周字段允许 0-7，7 等同 0（周日）。Field 只做区间展开，
        # 不会知道 7 与 0 是同一天，必须在这里归一 —— 否则 `7` 表达的
        # "周日" 永远匹配不上，条目静默地永不触发。
        self.dow = Field(dow, 0, 7, DAYS)
        if 7 in self.dow.values:
            self.dow.values.add(0)
        self.user = user
        self.cmd = cmd
        self.lineno = lineno
        self.last_fired = None

    def match(self, now):
        if not (self.minute.match(now.minute) and self.hour.match(now.hour)
                and self.mon.match(now.month)):
            return False
        # Vixie cron 语义：日与周只要有一个不是 `*`，两者是"或"关系。
        # 这里按"字段是否写死"判断，而不是看解析出的集合是否全集 —— 否则
        # `*/1` 会被误判为 `*`，语义翻转。
        dom_star = self.dom.spec.strip() == "*"
        dow_star = self.dow.spec.strip() == "*"
        if dom_star and dow_star:
            return True
        if dom_star:
            return self.dow.match(now.isoweekday() % 7)
        if dow_star:
            return self.dom.match(now.day)
        return self.dom.match(now.day) or self.dow.match(now.isoweekday() % 7)


def parse_cron_file(path):
    """返回 (env_dict, jobs)。环境行 NAME=value 会被收集，不参与调度。"""
    if not os.path.isfile(path):
        raise SystemExit("[FATAL] 条目文件不存在: %s" % path)
    env, jobs = {}, []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "=" in s and not s.startswith("@") and len(s.split()) == 1:
                k, _, v = s.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
                continue
            parts = s.split(None, 6)
            if len(parts) < 7:
                raise SystemExit("[FATAL] %s:%d 字段不足 7 个: %r"
                                 % (path, lineno, s))
            jobs.append(Job(parts[0], parts[1], parts[2], parts[3],
                            parts[4], parts[5], parts[6], lineno))
    return env, jobs


def run_job(job, env, log_path, tag):
    """真实执行：/bin/sh -c，环境并入文件内的赋值。"""
    os_env = dict(os.environ)
    os_env.update({k: v for k, v in env.items() if k != "MAILTO"})
    shell = os_env.get("SHELL", "/bin/sh")
    os_env.setdefault("PATH", "/usr/bin:/bin")
    if job.user and job.user != "root" and os.geteuid() == 0:
        argv = ["runuser", "-u", job.user, "--", shell, "-c", job.cmd]
    else:
        argv = [shell, "-c", job.cmd]
    with open(log_path, "a", encoding="utf-8", errors="replace") as lg:
        lg.write("=== [%s] %s 第%d行: %s\n"
                 % (tag, datetime.now().isoformat(timespec="seconds"),
                    job.lineno, job.cmd))
        lg.flush()
        p = subprocess.run(argv, env=os_env, stdout=lg, stderr=lg)
        lg.write("=== [%s] exit=%d\n" % (tag, p.returncode))
    return p.returncode


def find_real_daemon():
    """环境里若存在真实 cron 实现，优先用它（本沙盒实测不存在）。"""
    for name in ("cron", "crond", "busybox"):
        p = shutil.which(name)
        if not p:
            continue
        if os.path.basename(p) == "busybox":
            rc = subprocess.run([p, "crond", "--help"],
                                capture_output=True).returncode
            if rc == 0:
                return p + " crond"
            continue
        return p
    return None


def selfcheck_parser():
    """解析器自检：表达式 -> ( minute, hour, dom, mon, dow, 期望是否匹配 )。"""
    def mt(spec, v, lo, hi, names=None):
        return v in Field(spec, lo, hi, names).values

    cases = [
        ("*", 37, 0, 59, None, True),
        ("*/5", 15, 0, 59, None, True),
        ("*/5", 16, 0, 59, None, False),
        ("7", 7, 0, 59, None, True),
        ("7", 8, 0, 59, None, False),
        ("10-20", 15, 0, 59, None, True),
        ("10-20", 21, 0, 59, None, False),
        ("10-20/5", 15, 0, 59, None, True),
        ("10-20/5", 16, 0, 59, None, False),
        ("0,15,30,45", 30, 0, 59, None, True),
        ("0,15,30,45", 31, 0, 59, None, False),
        ("22-2", 23, 0, 23, None, True),      # 跨零点
        ("22-2", 12, 0, 23, None, False),
        ("mar", 3, 1, 12, MONTHS, True),
        ("tue", 2, 0, 7, DAYS, True),
        ("7", 7, 0, 7, DAYS, True),           # Field 层：7 本身合法
        ("60", 60, 0, 59, None, False),       # 越界：不抛异常也应为 False
    ]
    bad = []
    for spec, v, lo, hi, names, want in cases:
        try:
            got = mt(spec, v, lo, hi, names)
        except ValueError:
            got = False
        if got != want:
            bad.append("%s vs %s -> %s, 期望 %s" % (spec, v, got, want))

    # 非法输入必须抛异常，而不是静默解析成别的语义
    for spec in ("*/0", "abc", "1-2-3"):
        try:
            Field(spec, 0, 59)
            bad.append("%s 本应非法却被接受" % spec)
        except ValueError:
            pass

    # 日/周的"或"语义：dom 写死、dow 为 * 时只看 dom
    # 注意：期望值必须自己算对。第一版我把 now 写成 10 月 15 日却断言
    # "dom=1 应匹配"，是自检自己的期望值错了 —— 这类错误会让守卫
    # 把正确实现判成错误，与恒绿同等有害。
    j = Job("0", "*", "1", "*", "*", "root", "true", 1)
    now = datetime(2026, 10, 1, 0, 0)         # 1 日，周四
    if not j.match(now):
        bad.append("dom=1/dow=* 在 1 日应匹配")
    j2 = Job("0", "*", "2", "*", "*", "root", "true", 1)
    if j2.match(now):
        bad.append("dom=2/dow=* 在 1 日不应匹配")
    # dow=7 必须等同周日（0）。归一在 Job 层做，Field 层不做，
    # 所以这条必须在 Job 层断言 —— 放在 Field 表里会永远为假。
    sun = datetime(2026, 10, 4, 0, 0)         # 周日
    jd = Job("0", "*", "*", "*", "7", "root", "true", 1)
    if not jd.match(sun):
        bad.append("dow=7 在周日应匹配（7 必须归一为 0）")
    jd2 = Job("0", "*", "*", "*", "7", "root", "true", 1)
    if jd2.match(datetime(2026, 10, 5, 0, 0)):   # 周一
        bad.append("dow=7 在周一不应匹配")

    if bad:
        for b in bad:
            print("[FAIL] 解析器自检: %s" % b)
        return 1
    print("[PASS] 解析器自检: %d 例 + 3 例非法输入 + 2 例日/周或语义" % len(cases))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="/etc/cron.d/camd")
    ap.add_argument("--once", action="store_true", help="立即执行一次（不等时刻）")
    ap.add_argument("--serve", type=int, default=0, help="按分钟调度的最长秒数")
    ap.add_argument("--log", default="/data/cron_harness.log")
    ap.add_argument("--stop-after", type=int, default=1,
                    help="执行多少次后退出，0=不限")
    ap.add_argument("--check-parser", action="store_true")
    args = ap.parse_args()

    if args.check_parser:
        return selfcheck_parser()

    real = find_real_daemon()
    if real and not args.once:
        # 有真实实现就用真实实现，并据实报告，不用替代实现冒充。
        print("SCHEDULER=real:%s" % real)
        subprocess.Popen(real.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        time.sleep(2)
        return 0
    print("SCHEDULER=harness")

    env, jobs = parse_cron_file(args.file)
    if not jobs:
        print("[FATAL] 条目文件里没有任何作业行: %s" % args.file)
        return 1
    print("JOBS=%d ENV_KEYS=%s" % (len(jobs), sorted(env.keys())))

    if args.once:
        rc = run_job(jobs[0], env, args.log, "once")
        print("ONCE_EXIT=%d" % rc)
        return 0 if rc == 0 else 1

    fired = 0
    deadline = time.time() + args.serve
    while time.time() < deadline:
        now = datetime.now()
        for j in jobs:
            if not j.match(now):
                continue
            key = now.strftime("%Y%m%d%H%M")
            if j.last_fired == key:
                continue
            j.last_fired = key
            rc = run_job(j, env, args.log, "serve")
            fired += 1
            print("FIRED minute=%s exit=%d" % (key, rc))
            if args.stop_after and fired >= args.stop_after:
                return 0
        time.sleep(5)
    print("TIMEOUT fired=%d" % fired)
    return 1 if fired == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
