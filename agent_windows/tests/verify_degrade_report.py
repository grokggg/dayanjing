#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""降级可见性守卫（上层接线层）。

与 verify_v4l2_degrade.py 的分工：

    verify_v4l2_degrade.py   验的是"后端能区分三种降级"（能力层）
    本守卫                   验的是"上层真把降级说出口"（接线层）

为什么还要单独验接线层：能力层全绿不代表运维看得到。后端算出了
DEVICE_BUSY，若没有人把它读出来显示，那 C2 侧依旧只看到"有合法 JPEG、
零报错、持续送达"，与真人画面完全无法区分。这条守卫生存的理由就是防止
"能力建好了、但没人消费"这种情况无声地发生。

覆盖三处消费点：
    1. camd --probe         运维主动问"这台机器能不能采真人画面"
    2. cam_daemon 自检      常驻进程自己把"当前是假画面"说进 journal
    3. onekey.sh status     部署报告里的一行

反向验证是硬要求：三处消费点里任何一处"查不到"都比"查到了但值不对"更
危险——前者静默失效，后者至少会红。
"""

import os
import subprocess
import sys

MOD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(MOD)
BUILD = os.path.join(MOD, "build", "linux")
CAMD = os.path.join(BUILD, "camd")
SHIM_SRC = os.path.join(MOD, "tests", "v4l2sim_shim.c")
SHIM_SO = os.path.join(BUILD, "v4l2sim_shim.so")
BACKING = "/tmp/v4l2sim"
DEV = "/dev/video0"
DAEMON = os.path.join(MOD, "src", "cam_daemon.c")
MOCK = os.path.join(MOD, "src", "cam_mock.c")
ONEKEY = os.path.join(ROOT, "21_exfil", "onekey.sh")

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[OK]   %s%s" % (name, ("  -- " + detail) if detail else ""))
    else:
        FAIL += 1
        print("[FAIL] %s  -- %s" % (name, detail))
    return cond


def finish():
    print("-" * 62)
    print("结果: %d PASS / %d FAIL" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


def sh(cmd, env=None, timeout=180, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True,
                          env=env, timeout=timeout, cwd=cwd)


def build_camd(static=True, timeout=600):
    cmd = ["make", "build/linux/camd"]
    if not static:
        cmd = ["make", "STATIC=0", "build/linux/camd"]
    return sh(cmd, cwd=MOD, timeout=timeout)


def parse_kv(out):
    kv = {}
    for line in (out or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def probe(env_extra=None, use_shim=False):
    env = dict(os.environ)
    env.setdefault("V4L2SIM_FMT", "yuyv")
    env.setdefault("V4L2SIM_W", "320")
    env.setdefault("V4L2SIM_H", "240")
    if env_extra:
        env.update(env_extra)
    if use_shim:
        env["LD_PRELOAD"] = SHIM_SO
    r = sh([CAMD, "--probe", "--backend", "v4l2"], env=env)
    return parse_kv(r.stdout), r.returncode


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def write(p, s):
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)
    # 必须 touch：make 按 mtime 判重编。仅还原文件内容而不更新时间戳，
    # make 会认为源文件没变、跳过重编，库里仍是注入版——表现为"还原后
    # 依然红"，极易被误读成修复无效。
    os.utime(p, None)


def main():
    print("=" * 62)
    print("降级可见性守卫（上层接线）")
    print("=" * 62)

    if not os.path.exists(CAMD):
        check("前置：camd 已构建", False, CAMD)
        return finish()

    # ---------- F1 合成源不得自称真设备 ----------
    r = sh([CAMD, "--probe", "--backend", "mock"])
    kv = parse_kv(r.stdout)
    check("F1 合成源 DEGRADE=1（不得报真设备）",
          kv.get("DEGRADE") == "1",
          "DEGRADE=%s REAL_FRAME=%s" % (kv.get("DEGRADE"),
                                        kv.get("REAL_FRAME")))
    check("F1b 合成源 REAL_FRAME=no", kv.get("REAL_FRAME") == "no",
          kv.get("REAL_FRAME", ""))

    # ---------- F2 无设备：DEGRADE=1 ----------
    kv, rc = probe()
    check("F2 无设备 DEGRADE=1", kv.get("DEGRADE") == "1",
          "DEGRADE=%s rc=%d" % (kv.get("DEGRADE"), rc))

    # ---------- F3/F4 真设备与被占用（需 shim，故要求动态链接） ----------
    # camd 默认 -static：LD_PRELOAD 对静态二进制无效，ioctl 计数会全 0，
    # 于是"真设备"与"被占用"都退化成 NO_DEVICE，两条断言会一起假通过。
    # 用 STATIC=0 重建后再测；此步失败必须显式报出，不能静默跳过。
    rb = build_camd(static=False)
    if not check("前置：动态版 camd 可构建（shim 前提）",
                 rb.returncode == 0, (rb.stderr or "")[-200:]):
        return finish()

    r = sh(["cc", "-std=c99", "-O2", "-shared", "-fPIC",
            "-o", SHIM_SO, SHIM_SRC, "-ldl"], timeout=300)
    if not check("前置：shim 构建成功", r.returncode == 0,
                 (r.stderr or "")[-200:]):
        return finish()

    os.makedirs(BACKING, exist_ok=True)
    if not os.path.exists(DEV):
        subprocess.run(["mknod", DEV, "c", "81", "0"],
                       capture_output=True, timeout=60)

    kv, _ = probe({"V4L2SIM_STATE": os.path.join(BACKING, "rep_ok.txt")},
                  use_shim=True)
    check("F3 --probe 真设备报 DEGRADE=0/REAL_FRAME=yes",
          kv.get("DEGRADE") == "0" and kv.get("REAL_FRAME") == "yes",
          "DEGRADE=%s REAL_FRAME=%s" % (kv.get("DEGRADE"),
                                        kv.get("REAL_FRAME")))

    kv, _ = probe({"V4L2SIM_STATE": os.path.join(BACKING, "rep_busy.txt"),
                   "V4L2SIM_REQBUFS_BUSY": "1"}, use_shim=True)
    check("F4 --probe 被占用报 DEGRADE=2/REAL_FRAME=no",
          kv.get("DEGRADE") == "2" and kv.get("REAL_FRAME") == "no",
          "DEGRADE=%s REAL_FRAME=%s" % (kv.get("DEGRADE"),
                                        kv.get("REAL_FRAME")))

    # ---------- F5 常驻进程自己要说出口 ----------
    dsrc = read(DAEMON)
    call = "cd_report_degrade(c);"
    anchor = "uint32_t n = c->cfg->persist_recheck_batches;"
    if call not in dsrc or anchor not in dsrc:
        check("F5 自检钩子里调用了降级上报", False, "源码未命中")
    else:
        check("F5 自检钩子里调用了降级上报", True, "cam_daemon.c")
        check("F5b 上报在驻留自检之前（自检提前 return 也说得出口）",
              dsrc.index(call) < dsrc.index(anchor), "顺序")

    # 初值必须是 -1 而非 0：0 是合法的"真设备"态，初值取 0 会让
    # "装上后一直是假画面"这个最该报的情况被"与上次相同"永远吞掉。
    check("F5c last_degrade 初值为 -1（不是 0）",
          "actx.last_degrade = -1;" in dsrc, "cam_daemon.c")

    # ---------- F6 关掉驻留自检不得连带关掉画面上报 ----------
    # 判据必须能真的变红：写成恒真表达式就等于没这条。这里用"旧写法不存在"
    # 作为判据——一旦有人改回 ensure_persist && persist_recheck_batches，
    # 下面立刻红。
    check("F6 自检安装条件不要求 persist_recheck_batches 非 0",
          "if (cfg->ensure_persist) {" in dsrc
          and "cfg->ensure_persist && cfg->persist_recheck_batches"
          not in dsrc,
          "ensure_persist 单独决定")

    # ---------- F7 onekey.sh status 要显示 ----------
    osrc = read(ONEKEY)
    check("F7 onekey.sh status 输出设备画面一行",
          "设备画面: %s" in osrc, "21_exfil/onekey.sh")
    check("F7b status 区分三种降级文案",
          '0) _dt="设备画面（真）"' in osrc
          and '2) _dt="设备存在但打不开' in osrc, "case 分支")

    # ---------- F8 合成源显式声明降级 ----------
    check("F8 mock 后端显式置 CAM_DEGRADE_NO_DEVICE",
          "m->api.degrade          = CAM_DEGRADE_NO_DEVICE;" in read(MOCK),
          "cam_mock.c")

    # ---------- R1 反向：合成源沿用默认 0 必须被抓到 ----------
    msrc = read(MOCK)
    decl = "m->api.degrade          = CAM_DEGRADE_NO_DEVICE;"
    if decl not in msrc:
        check("R1 反向：mock 缺显式降级声明", False, "无法注入")
        return finish()
    try:
        write(MOCK, msrc.replace(decl, "/* 反向注入：沿用默认 0 */"))
        build_camd(static=False)
        kv = parse_kv(sh([CAMD, "--probe", "--backend", "mock"]).stdout)
        check("R1 反向：谎报真设备被抓到（F1 非恒绿）",
              kv.get("DEGRADE") == "0" and kv.get("REAL_FRAME") == "yes",
              "退化下 DEGRADE=%s（与 F1 的 1 不同）" % kv.get("DEGRADE"))
    finally:
        write(MOCK, msrc)
        build_camd(static=False)

    # ---------- R2 反向：去掉上报调用，静态断言必须红 ----------
    try:
        patched = dsrc.replace("    " + call + "\n", "")
        if patched == dsrc:
            check("R2 反向：注入未命中", False, "cd_report_degrade 调用")
        else:
            write(DAEMON, patched)
            check("R2 反向：缺上报被抓到（F5 非恒绿）",
                  call not in read(DAEMON), "静态断言失效")
    finally:
        write(DAEMON, dsrc)
        build_camd(static=False)

    # 还原后必须回到 F5 通过态，否则上面的"还原"是假的
    check("R3 还原后上报调用已恢复", call in read(DAEMON), "cam_daemon.c")

    # 恢复默认静态构建，避免留下动态版影响后续守卫
    build_camd(static=True)

    return finish()


if __name__ == "__main__":
    sys.exit(main())
