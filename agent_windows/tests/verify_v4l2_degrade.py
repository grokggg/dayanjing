#!/usr/bin/env python3
"""
verify_v4l2_degrade.py — V4L2 降级可见性守卫

要防的失效：
  cam_linux_v4l2.c 在 V4L2 初始化失败时静默切到内置合成帧，且 open 仍返回
  CAM_OK。于是两种处境在调用方看来完全一样——都是 CAPTURE=OK、都有合法
  JPEG、都零报错：

    A. 一个采集设备都没有（无摄像头机器）—— 合法降级
    B. 设备存在且是采集设备，但打不开 —— 最常见成因是摄像头正被别的进程
       占用（视频会议/直播已开流）：open 与格式协商都过，REQBUFS/STREAMON
       才失败

  B 在随机真机上是高频场景，而它此前与 A 无从区分：那台机器明明有摄像头，
  运维看到"一切正常"，收到的却是棋盘格。这是最难发现的一类失效——不报错、
  不失败，只是画面一直是假的。

本守卫用 V4L2 ABI 模拟器（tests/v4l2sim_shim.c）造出三种处境，断言
DEGRADE 必须把它们分开：0=真设备 / 1=无设备 / 2=有设备但打不开。

反向验证不可省：若只断言"被占用时 DEGRADE==2"，那么一个把 found_capture_dev
恒置 0 的退化实现会让该场景报 1 而被判失败——但反过来，若没有反向验证，
"永远返回 2"的实现同样能让正向变绿。R1 证明判据真的能鉴别。
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)
BUILD = os.path.join(MOD, "build", "linux")
PROBE = os.path.join(BUILD, "v4l2_realpath_probe")
SHIM_SRC = os.path.join(HERE, "v4l2sim_shim.c")
SHIM_SO = os.path.join(BUILD, "v4l2sim_shim.so")
SRC_V4L2 = os.path.join(MOD, "src", "cam_linux_v4l2.c")

DEV = "/dev/video0"
BACKING = "/tmp/v4l2sim"

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


def ensure_devnode():
    """造 /dev/video0 字符设备节点（主设备号 81）。

    stat 的 S_ISCHR 判据要求它是字符设备；驱动是否真的在，由 shim 决定。
    """
    if os.path.exists(DEV):
        return True
    r = subprocess.run(["mknod", DEV, "c", "81", "0"],
                       capture_output=True, text=True, timeout=60)
    return r.returncode == 0


def run_probe(state_path, extra_env=None, use_shim=True):
    """跑一次 probe，返回 (kv, ioctl_state, rc)。"""
    env = dict(os.environ)
    env["V4L2SIM_STATE"] = state_path
    env["V4L2SIM_FMT"] = "yuyv"
    env["V4L2SIM_W"] = "320"
    env["V4L2SIM_H"] = "240"
    if extra_env:
        env.update(extra_env)
    if use_shim:
        env["LD_PRELOAD"] = SHIM_SO

    try:
        os.remove(state_path)
    except OSError:
        pass

    try:
        r = subprocess.run([PROBE, "v4l2"], capture_output=True, text=True,
                           env=env, timeout=120)
        out = r.stdout or ""
    except subprocess.TimeoutExpired:
        return {}, "", "TIMEOUT"

    state = ""
    try:
        with open(state_path) as f:
            state = f.read()
    except OSError:
        pass
    return parse_kv(out), state, ""


def main():
    print("=" * 62)
    print("V4L2 降级可见性守卫")
    print("=" * 62)

    if not os.path.exists(PROBE):
        check("前置：probe 已构建", False, PROBE)
        return finish()
    ok, err = build_shim()
    if not check("前置：shim 构建成功", ok, err):
        return finish()
    os.makedirs(BACKING, exist_ok=True)
    if not check("前置：/dev/video0 节点可用", ensure_devnode()):
        return finish()

    # ---------- F1 真设备：DEGRADE 必须为 0 ----------
    kv, state, err = run_probe(os.path.join(BACKING, "deg_ok.txt"))
    if err:
        check("F1 真设备场景可跑", False, err)
    else:
        d = kv.get("DEGRADE", "?")
        check("F1 真设备 DEGRADE=0（像素来自设备）", d == "0",
              "DEGRADE=%s  MMAP=%s" % (d, "MMAP=1" in state))
        check("F1b 真设备确实走了 mmap 路径", "MMAP=1" in state,
              state.replace("\n", " "))

    # ---------- F2 设备被占用：DEGRADE 必须为 2 ----------
    kv, state, err = run_probe(os.path.join(BACKING, "deg_busy.txt"),
                               {"V4L2SIM_REQBUFS_BUSY": "1"})
    if err:
        check("F2 被占用场景可跑", False, err)
    else:
        d = kv.get("DEGRADE", "?")
        check("F2 设备被占用 DEGRADE=2（不是静默降级）", d == "2",
              "DEGRADE=%s" % d)
        # 佐证：真路径确实没走通，所以此刻产出的是合成帧
        check("F2b 被占用时真路径确未走通（MMAP=0）", "MMAP=0" in state,
              state.replace("\n", " "))
        check("F2c 被占用时流程仍不中断（CAPTURE=OK）",
              kv.get("CAPTURE") == "OK", "CAPTURE=%s" % kv.get("CAPTURE"))

    # ---------- F3 无可用设备：DEGRADE 必须为 1（合法降级） ----------
    kv, state, err = run_probe(os.path.join(BACKING, "deg_none.txt"),
                               use_shim=False)
    if err:
        check("F3 无设备场景可跑", False, err)
    else:
        d = kv.get("DEGRADE", "?")
        check("F3 无可用设备 DEGRADE=1（合法降级）", d == "1",
              "DEGRADE=%s" % d)
        check("F3b 无设备时流程仍不中断（CAPTURE=OK）",
              kv.get("CAPTURE") == "OK", "CAPTURE=%s" % kv.get("CAPTURE"))

    # ---------- F4 静态：可见性接口真的存在 ----------
    try:
        with open(SRC_V4L2) as f:
            src = f.read()
    except OSError:
        src = ""
    check("F4 源码按 found_capture_dev 区分两种降级",
          "found_capture_dev ? CAM_DEGRADE_DEVICE_BUSY" in src)
    check("F4b 真设备路径显式置 CAM_DEGRADE_NONE",
          "self->degrade = CAM_DEGRADE_NONE" in src)

    # ---------- R1 反向：退化实现必须被抓到 ----------
    r1 = reverse_check()
    check("R1 反向：退化实现被抓到（判据非恒绿）", r1,
          "" if r1 else "退化实现未被识别，F2 可能是恒绿")

    return finish()


def reverse_check():
    """把修复退回成"不区分两种降级"，F2 必须变红。

    注入点：把三元表达式换成恒 NO_DEVICE。这样"设备被占用"会报 1，
    与"无设备"混为一谈——正是修复前的真实行为。
    """
    try:
        with open(SRC_V4L2) as f:
            orig = f.read()
    except OSError:
        return False

    target = ("self->degrade = found_capture_dev ? CAM_DEGRADE_DEVICE_BUSY\n"
              "                                      : CAM_DEGRADE_NO_DEVICE;")
    if target not in orig:
        print("  [R1] 未找到注入锚点，跳过")
        return False

    backup = orig
    injected = orig.replace(
        target,
        "self->degrade = CAM_DEGRADE_NO_DEVICE;  /* R1 注入 */")

    tmp_probe = PROBE + ".r1"
    ok = False
    try:
        with open(SRC_V4L2, "w") as f:
            f.write(injected)
        try:
            subprocess.run(["touch", SRC_V4L2], timeout=30)
        except Exception:
            pass
        # 重编 probe（含 v4l2 后端）
        b = subprocess.run(["make", "-C", MOD, "build/linux/v4l2_realpath_probe"],
                           capture_output=True, text=True, timeout=300)
        if b.returncode != 0:
            print("  [R1] 重编失败")
            return False
        kv, state, err = run_probe(os.path.join(BACKING, "deg_busy_r1.txt"),
                                   {"V4L2SIM_REQBUFS_BUSY": "1"})
        if err:
            print("  [R1] probe 超时")
            return False
        d = kv.get("DEGRADE", "?")
        print("  [R1] 退化实现下 被占用场景 DEGRADE=%s（应为 1，且与 F2 的 2 不同）" % d)
        # 关键：退化后必须报 1 —— 若仍报 2，说明注入没生效或判据不敏感
        ok = (d == "1")
    finally:
        with open(SRC_V4L2, "w") as f:
            f.write(backup)
        try:
            subprocess.run(["touch", SRC_V4L2], timeout=30)
        except Exception:
            pass
        subprocess.run(["make", "-C", MOD, "build/linux/v4l2_realpath_probe"],
                       capture_output=True, text=True, timeout=300)
    return ok


def finish():
    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    print("-" * 62)
    print("结果: %d PASS / %d FAIL" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
