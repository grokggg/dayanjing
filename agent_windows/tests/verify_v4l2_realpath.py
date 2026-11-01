#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_v4l2_realpath —— 驱动**真实的 cam_linux_v4l2.c 真设备代码路径**。

为什么必须有它：
  沙盒没有摄像头硬件，长期以来的验证全部落在"合成帧降级分支"上。那条
  分支与真设备路径在 probe 输出上**完全无法区分**：两者都输出
  CAPTURE=OK、同样的帧长。于是"摄像头链路已验证"这句话，此前从未包含
  "真 V4L2 代码路径被执行过"这一层。

  本守卫用 LD_PRELOAD 的用户态 V4L2 ABI 模拟器（tests/v4l2sim_shim.c）
  让 /dev/video0 按 ABI 回应，probe 则只调 cam_source_create("v4l2")
  -> open -> capture，与真机调用路径一致。因此被验证的是产品代码本身。

  独立证据是 shim 落盘的 ioctl 计数：MMAP/DQBUF 等计数为 0 或未生成，
  即证明走的仍是降级分支。没有这条状态文件，"真路径"与"降级"就不可
  区分，整个守卫会退化成在合成帧上自证。

判据三层，缺一层即被绕过：
  F1-F15  正向：采集 + 转码 + 流持续 + ioctl 计数非零
  S1      静态：产品源码确实含真 V4L2 ioctl 调用
  R1/R2   反向：两条都必须能被复现出"失败/消失"，否则正向断言是恒绿的

注意：shim 依赖 /tmp/v4l2sim 目录存在（backing 文件用 mkstemp 建在其下）。
  目录缺失时 shim 的 open 返回 ENODEV -> 探测失败 -> 静默走降级分支，
  计数全 0。本脚本显式创建该目录。
"""
import os
import subprocess
import sys
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)
BUILD = os.path.join(MOD, "build", "linux")
PROBE = os.path.join(BUILD, "v4l2_realpath_probe")
SHIM_SRC = os.path.join(HERE, "v4l2sim_shim.c")
SHIM_SO = os.path.join(BUILD, "v4l2sim_shim.so")
SRC_V4L2 = os.path.join(MOD, "src", "cam_linux_v4l2.c")

DEV = "/dev/video0"
BACKING_DIR = "/tmp/v4l2sim"

W, H = 320, 240
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("%s %s%s" % ("[OK]  " if ok else "[FAIL]", name,
                       ("  -- " + detail) if detail else ""))
    return bool(ok)


def parse_kv(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def build_shim():
    os.makedirs(BUILD, exist_ok=True)
    r = subprocess.run(["cc", "-std=c99", "-O2", "-shared", "-fPIC",
                        "-o", SHIM_SO, SHIM_SRC, "-ldl"],
                       capture_output=True, text=True, timeout=180)
    return r.returncode == 0, (r.stderr or "").strip()[:200]


def ensure_dev():
    """确保 /dev/video0 存在且是字符设备（主设备号 81）。"""
    if os.path.exists(DEV):
        try:
            import stat
            st = os.stat(DEV)
            return stat.S_ISCHR(st.st_mode), "已存在"
        except Exception as e:
            return False, str(e)
    r = subprocess.run(["mknod", DEV, "c", "81", "0"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, (r.stderr or "").strip()[:120]
    return True, "已创建"


def run_probe(env_extra, state_path):
    env = dict(os.environ)
    env["LD_PRELOAD"] = SHIM_SO
    env["V4L2SIM_STATE"] = state_path
    env["V4L2SIM_FMT"] = "yuyv"
    env.update(env_extra)
    if os.path.exists(state_path):
        os.remove(state_path)
    r = subprocess.run([PROBE, "v4l2"], capture_output=True, text=True,
                       timeout=180, env=env)
    return parse_kv(r.stdout), r.returncode


def read_state(path):
    if not os.path.exists(path):
        return None
    d = {}
    for line in open(path):
        if "=" in line:
            k, v = line.split("=", 1)
            try:
                d[k.strip()] = int(v.strip())
            except ValueError:
                pass
    return d


def main():
    if not os.path.exists(PROBE):
        check("前置：v4l2_realpath_probe 已构建", False, PROBE)
        return 1

    ok, d = build_shim()
    if not check("前置：V4L2 ABI 模拟器已编译", ok, d):
        return 1

    # shim 的 backing 文件建在此目录下；缺失会让 open 失败并静默降级
    os.makedirs(BACKING_DIR, exist_ok=True)

    ok, d = ensure_dev()
    if not check("前置：/dev/video0 可用（字符设备）", ok, d):
        return 1

    st_path = "/tmp/v4l2sim_state.txt"
    kv, rc = run_probe({}, st_path)
    st = read_state(st_path)

    def gv(k, default=""):
        return kv.get(k, default)

    # ---- 正向 ----
    check("F1  create(v4l2) 成功", gv("CREATE") == "OK", gv("CREATE"))
    check("F2  open 成功", gv("OPEN") == "OK", gv("OPEN_ERR"))
    check("F3  capture 成功", gv("CAPTURE") == "OK", gv("CAPTURE_ERR"))
    check("F4  帧分辨率 320x240",
          gv("FRAME_W") == str(W) and gv("FRAME_H") == str(H),
          "%sx%s" % (gv("FRAME_W"), gv("FRAME_H")))
    flen = int(gv("FRAME_LEN", "0"))
    check("F5  帧长 == W*H*2（YUYV422）", flen == W * H * 2, "%d" % flen)
    nz = int(gv("NONZERO", "0"))
    check("F6  帧内容非全零（>90% 非零字节）", flen and nz > flen * 0.9,
          "nonzero=%d/%d" % (nz, flen))
    check("F7  原始帧不是 JPEG（必须走转码而非直通）",
          gv("IS_JPEG_MAGIC") == "0", gv("IS_JPEG_MAGIC"))
    plen = int(gv("PROBE_LEN", "0"))
    check("F8  容量探测成功且长度 > 0", gv("PROBE") == "OK" and plen > 0,
          "PROBE_LEN=%d" % plen)
    check("F9  转码成功", gv("TRANSFORM") == "OK", gv("TRANSFORM"))
    jlen = int(gv("JPEG_LEN", "0"))
    check("F10 转码长度与探测一致", jlen == plen and jlen > 0,
          "jpeg=%d probe=%d" % (jlen, plen))
    check("F11 输出是合法 JPEG（SOI+EOI）",
          gv("JPEG_MAGIC") == "1" and gv("JPEG_EOI") == "1",
          "magic=%s eoi=%s" % (gv("JPEG_MAGIC"), gv("JPEG_EOI")))
    check("F12 输出分辨率与源一致", gv("JPEG_DIMS_MATCH") == "1",
          "%sx%s" % (gv("JPEG_W"), gv("JPEG_H")))
    check("F13 后续仍能连续取帧（流未断）", gv("EXTRA_FRAMES") == "3",
          "extra=%s" % gv("EXTRA_FRAMES"))

    # ---- 真路径的独立证据：ioctl 计数 ----
    if st is None:
        check("F14 真路径证据：mmap 被调用", False, "状态文件未生成（走了降级分支）")
        check("F15 真路径证据：DQBUF 被调用", False, "状态文件未生成（走了降级分支）")
    else:
        check("F14 真路径证据：mmap 被调用（非零）", st.get("MMAP", 0) >= 1,
              "MMAP=%d" % st.get("MMAP", 0))
        check("F15 真路径证据：DQBUF 被调用（非零）", st.get("DQBUF", 0) >= 1,
              "DQBUF=%d" % st.get("DQBUF", 0))

    # ---- 静态 ----
    src = open(SRC_V4L2, encoding="utf-8", errors="replace").read()
    check("S1  产品源码含真 V4L2 ioctl 调用",
          ("VIDIOC_DQBUF" in src) and ("VIDIOC_QUERYCAP" in src)
          and ("mmap" in src),
          "DQBUF=%d QUERYCAP=%d mmap=%d"
          % (src.count("VIDIOC_DQBUF"), src.count("VIDIOC_QUERYCAP"),
             src.count("mmap")))

    # ---- 反向 1：设备不可用时，真路径证据必须消失 ----
    # 若这条不成立，F14/F15 就是恒绿的：降级分支同样能给出 CAPTURE=OK。
    moved = False
    try:
        if os.path.exists(DEV):
            os.rename(DEV, DEV + ".bak")
            moved = True
        kv2, _ = run_probe({}, "/tmp/v4l2sim_state_r1.txt")
        st2 = read_state("/tmp/v4l2sim_state_r1.txt")
        disappeared = (st2 is None) or (sum(st2.values()) == 0)
        check("R1  设备不可用时真路径证据必须消失（反证 F14/F15 有鉴别力）",
              disappeared,
              "降级分支 CAPTURE=%s，ioctl 计数=%s"
              % (kv2.get("CAPTURE"), "全 0/无文件" if disappeared else
                 str(st2)))
    finally:
        if moved and os.path.exists(DEV + ".bak"):
            os.rename(DEV + ".bak", DEV)

    # ---- 反向 2：出队失败必须被感知，不能回退成合成帧 ----
    kv3, _ = run_probe({"V4L2SIM_NODQBUF": "1"}, "/tmp/v4l2sim_state_r2.txt")
    check("R2  DQBUF 失败时 capture 必须失败（不得静默返回合成帧）",
          kv3.get("CAPTURE") == "FAIL",
          "CAPTURE=%s ERR=%s" % (kv3.get("CAPTURE"), kv3.get("CAPTURE_ERR")))

    nfail = sum(1 for _, ok, _ in results if not ok)
    print("\n共 %d 项，失败 %d" % (len(results), nfail))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
