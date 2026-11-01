#!/usr/bin/env python3
"""
DAYANJING v4 — 21_exfil/tests/verify_v4l2_abi.py

V4L2 内核 ABI 守卫（红线 R1b）。

背景：沙盒没有摄像头，agent_windows/src/cam_linux_v4l2.c 里 USE_V4L2=1
那条真设备分支的 ioctl/mmap 代码从未被执行过。本守卫用用户态设备
（tests/v4l2_simdev.c，基于 FUSE）把它依赖的内核 ABI 真跑一遍：

    open → QUERYCAP → S_FMT(MJPEG 失败) → S_FMT(YUYV) → REQBUFS →
    QUERYBUF → mmap → QBUF → STREAMON → DQBUF → 取帧

验证的是"ioctl 命令号、结构体布局与大小、mmap 取帧语义"与内核一致。
这些若错了，真机上的表现是 ENOTTY/EINVAL/段错误，而此前无任何东西验过。

【R1 仍然 BLOCKED】本守卫不证明"能采到真实摄像头画面"。真字符设备
在本环境造不出来，三条路均已实证堵死，详见 v4l2_simdev.c 头注。

反向验证：R1(--bad-offset) / R2(--no-devcaps)。不做这两条，
MMAP 与 CAPS_OK 断言就是恒绿的。
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXFIL = os.path.dirname(HERE)
REPO = os.path.dirname(EXFIL)
BUILD = os.path.join(EXFIL, "build", "v4l2abi")
BACKEND = os.path.join(REPO, "agent_windows", "src", "cam_linux_v4l2.c")
MNT = "/tmp/dy_v4l2abi_mnt"

results = []


def chk(cond, name, detail=""):
    results.append((bool(cond), name, detail))
    print(("  [OK] " if cond else "  [FAIL] ") + name + (("  " + detail) if detail else ""))


def kv(out):
    """按 token 解析：探针一行可能含多对 KEY=VALUE（如 QUERYCAP 行带
    driver/caps/devcaps/structsz）。按行 split("=",1) 会把后半截当成一个值，
    导致 int() 解析失败——首版就栽在这里，症状是"断言全红但数据其实是对的"。
    """
    d = {}
    for line in out.splitlines():
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                d[k.strip()] = v.strip()
    return d


def gj(d, k, default):
    """从已解析字典取整数；值可能是 '-1 errno=22'，取首 token。"""
    try:
        return int(d.get(k, str(default)).split()[0])
    except (ValueError, IndexError, AttributeError):
        return default


def build():
    os.makedirs(BUILD, exist_ok=True)
    sim = os.path.join(BUILD, "v4l2_simdev")
    probe = os.path.join(BUILD, "v4l2_abi_probe")
    for src, dst in ((os.path.join(HERE, "v4l2_simdev.c"), sim),
                     (os.path.join(HERE, "v4l2_abi_probe.c"), probe)):
        r = subprocess.run(["gcc", "-O1", "-Wall", "-Wextra", "-std=gnu11",
                            "-o", dst, src], capture_output=True, text=True)
        if r.returncode != 0:
            print("[FATAL] 编译失败: %s\n%s" % (src, r.stderr[:800]))
            return None, None
        if r.stderr.strip():
            print("[FATAL] 编译非零警告: %s\n%s" % (src, r.stderr[:800]))
            return None, None
    return sim, probe


def run_case(sim, probe, args, status_path):
    """起设备 → 跑探针 → 收摊。设备起不来必须 FATAL，不能静默继续。"""
    subprocess.run(["umount", "-l", MNT], capture_output=True)
    subprocess.run(["rm", "-rf", MNT])
    os.makedirs(MNT, exist_ok=True)
    if os.path.exists(status_path):
        os.remove(status_path)
    errf = open(os.path.join(BUILD, "sim.err"), "wb")
    outf = open(os.path.join(BUILD, "sim.out"), "wb")
    p = subprocess.Popen([sim, MNT, status_path] + args,
                         start_new_session=True, stderr=errf, stdout=outf)
    time.sleep(1.8)
    if p.poll() is not None:
        errf.close()
        err = open(os.path.join(BUILD, "sim.err")).read()
        print("[FATAL] 仿真设备未启动（已退出）: %s" % err[:300])
        subprocess.run(["umount", "-l", MNT], capture_output=True)
        return None, None
    st_mode = subprocess.run(["stat", "-c", "%F", os.path.join(MNT, "video0")],
                             capture_output=True, text=True)
    try:
        r = subprocess.run([probe, os.path.join(MNT, "video0")],
                           capture_output=True, text=True, timeout=40)
    except subprocess.TimeoutExpired:
        r = None
    time.sleep(0.3)
    p.terminate()
    try:
        p.wait(timeout=3)
    except Exception:
        p.kill()
    subprocess.run(["umount", "-l", MNT], capture_output=True)
    out = r.stdout if r else ""
    status = open(status_path).read() if os.path.exists(status_path) else ""
    return kv(out), (status if status else None), st_mode.stdout.strip()


def main():
    if os.geteuid() != 0:
        print("[FATAL] 挂载 FUSE 需要 root")
        return 1
    sim, probe = build()
    if not sim:
        return 1
    if not os.path.exists(BACKEND):
        print("[FATAL] 找不到后端源码: %s" % BACKEND)
        return 1

    print("=== F1-F12 正向：V4L2 内核 ABI 全序列 ===")
    d, st, mode = run_case(sim, probe, [], os.path.join(BUILD, "ok.txt"))
    if d is None:
        return 1
    if st is None:
        print("[FATAL] 设备未产出状态文件 —— 探针根本没跑起来")
        return 1

    def gi(k):
        try:
            return int(d.get(k, "-9999"))
        except ValueError:
            return -9999

    def gs(k):
        return d.get(k, "?")

    chk(gi("OPEN") == 0, "F1  open() 成功", gs("OPEN"))
    chk(gi("QUERYCAP") == 0, "F2  VIDIOC_QUERYCAP 成功（命令号与结构体大小被内核接受）",
        "qcap_structsz=%s" % gs("qcap_structsz"))
    caps = gi("caps")
    chk(bool(caps & 0x80000000), "F3  capabilities 带 V4L2_CAP_DEVICE_CAPS",
        "caps=0x%x" % caps)
    chk(gi("CAPS_OK") == 1, "F4  能力判据通过（device_caps 含 CAPTURE|STREAMING）",
        "effcaps=0x%x" % gi("effcaps"))
    chk(gi("S_FMT_MJPEG_RC") == -1, "F5  S_FMT(MJPEG) 被拒 —— 触发后端回退分支",
        "errno=%s" % gs("errno"))
    chk(gi("S_FMT_YUYV") == 0 and gi("w") == 640 and gi("h") == 480,
        "F6  S_FMT(YUYV) 成功且尺寸回显一致", "%sx%s" % (d.get("w"), d.get("h")))
    chk(gi("sizeimage") == 640 * 480 * 2, "F7  sizeimage 与 YUYV422 一致",
        "%s == %d" % (gs("sizeimage"), 640 * 480 * 2))
    chk(gi("REQBUFS") == 0 and gi("count") >= 1, "F8  REQBUFS 成功")
    chk(gi("QUERYBUF") == 0 and gi("length") == 640 * 480 * 2, "F9  QUERYBUF 长度正确")
    chk(gi("page_aligned") == 1, "F10 QUERYBUF m.offset 页对齐（mmap 前提）")
    chk(gi("MMAP") == 0, "F11 mmap 成功 —— 后端取帧所依赖的通路真实可用")
    chk(gi("DQBUF0") == 0 and gi("bytesused") == 640 * 480 * 2,
        "F12 DQBUF 返回真实帧长度", "bytesused=%s" % d.get("bytesused"))

    p0 = d.get("PIX0", "")
    p1 = d.get("PIX100000", "")
    chk(len(p0) == 16 and len(p1) == 16 and p0 != p1,
        "F13 mmap 区域是真图案（两处像素不同，非单色/全零填充）",
        "PIX0=%s PIX100000=%s" % (p0, p1))
    chk(gi("PIXVARIETY") >= 8, "F14 帧内不同字节值种类 >= 8（真像素而非填充）",
        "variety=%s" % gs("PIXVARIETY"))
    fn = 0
    for line in st.splitlines():
        if line.startswith("frame_no="):
            fn = int(line.split("=")[1])
    chk(fn >= 2, "F15 设备确实推进了帧（frame_no>=2）", "frame_no=%d" % fn)

    src = open(BACKEND).read()
    chk("V4L2_CAP_DEVICE_CAPS" in src and "device_caps" in src,
        "S1  后端源码含 DEVICE_CAPS 条件判据（与探针镜像同源，防脱钩）")

    print("=== R1/R2 反向：证明 F11 与 F4 不是恒绿 ===")
    d2, _, _ = run_case(sim, probe, ["--bad-offset"], os.path.join(BUILD, "bad.txt"))
    if d2 is None:
        return 1
    chk(gj(d2, "MMAP", 0) == -1,
        "R1  m.offset 非页对齐时 mmap 必失败 —— F11 有鉴别力",
        "MMAP=%s" % d2.get("MMAP"))

    d3, _, _ = run_case(sim, probe, ["--no-devcaps"], os.path.join(BUILD, "nocaps.txt"))
    if d3 is None:
        return 1
    chk(gj(d3, "CAPS_OK", 1) == 0,
        "R2  老驱动形态（无 DEVICE_CAPS、无采集能力）判据应失败 —— F4 有鉴别力",
        "CAPS_OK=%s effcaps=%s" % (d3.get("CAPS_OK"), d3.get("effcaps")))

    bad = [r for r in results if not r[0]]
    print("\n共 %d 项，通过 %d，失败 %d" % (len(results), len(results) - len(bad), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
