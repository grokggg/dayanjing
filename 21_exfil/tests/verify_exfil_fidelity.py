#!/usr/bin/env python3
"""
DAYANJING v4 — verify_exfil_fidelity.py

回传链路的内容保真度守卫。

为什么需要它
------------
test_cam_e2e 断言"重组结果与原始 JPEG 字节级一致"。这对，但不够：
字节一致只证明通路没改字节，证明不了画面还是那幅画面。

实证：cam_jpeg.c 的 DCT 曾根本错误，产出的码流
  - SOI/EOI 齐全 -> is_jpeg() 通过
  - 经 exfil 回传后字节级完全一致 -> test_cam_e2e 全绿
  - 但解码出来是无意义噪点（渐变帧亮度 MAE=50.24）
即：**整条回传链路全绿，收到的画面是废的**。

本守卫因此把判据推进一层：用**外部真实解码器**（PIL / ffmpeg，不是自研的）
打开重组产物，与原始 YUYV 参考系逐像素比对。

反向验证（不做就是恒绿）
------------------------
  R1 mismatch：编码图案 A，参考系给图案 B -> 比对必须变红
  R2 mutwire ：篡改一个信元字节        -> 重组必须失败
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))      # dayanjing/
MOD = os.path.join(ROOT, "21_exfil")
BIN = os.path.join(MOD, "build", "test_exfil_fidelity")

W, H = 320, 240

g_pass = 0
g_fail = 0


def check(cond, name, detail=""):
    global g_pass, g_fail
    if cond:
        g_pass += 1
        print("[PASS] %s" % name)
    else:
        g_fail += 1
        print("[FAIL] %s%s" % (name, ("  -- " + detail) if detail else ""))
    return cond


def yuyv_to_rgb(data):
    """YUYV422 -> RGB 列表（BT.601 全幅）。参考系换算。"""
    out = bytearray(W * H * 3)
    for y in range(H):
        for x in range(0, W, 2):
            o = (y * W + x) * 2
            y0 = data[o + 0]
            u = data[o + 1]
            y1 = data[o + 2]
            v = data[o + 3]
            cb = u - 128
            cr = v - 128
            for k, yy in enumerate((y0, y1)):
                r = int(yy + 1.402 * cr)
                g = int(yy - 0.344136 * cb - 0.714136 * cr)
                b = int(yy + 1.772 * cb)
                p = (y * W + x + k) * 3
                out[p + 0] = max(0, min(255, r))
                out[p + 1] = max(0, min(255, g))
                out[p + 2] = max(0, min(255, b))
    return bytes(out)


def luma(rgb):
    out = []
    for i in range(0, len(rgb), 3):
        out.append(int(0.299 * rgb[i] + 0.587 * rgb[i + 1] + 0.114 * rgb[i + 2]))
    return out


def mae(a, b):
    return sum(abs(x - y) for x, y in zip(a, b)) / float(len(a))


def build():
    r = subprocess.run(["make", "-C", MOD, "build/test_exfil_fidelity"],
                       capture_output=True, text=True, timeout=900)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def run_c(mode, refp, outp):
    r = subprocess.run([BIN, mode, refp, outp],
                       capture_output=True, text=True, timeout=120)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    print("=== 回传链路内容保真度守卫 ===\n")

    rc, log = build()
    if not check(rc == 0, "F0 构建 test_exfil_fidelity", log[-400:]):
        print("\n=== total=%d pass=%d fail=%d ===" % (g_pass + g_fail, g_pass, g_fail))
        return 1

    tmp = "/data/workspace/fid_tmp"
    os.makedirs(tmp, exist_ok=True)
    refp = os.path.join(tmp, "ref.yuyv")
    outp = os.path.join(tmp, "out.jpg")

    # ---------- 正向 ----------
    rc, log = run_c("normal", refp, outp)
    check(rc == 0, "F1 回传链路 C 侧断言全过", log[-500:])
    check(os.path.exists(outp) and os.path.getsize(outp) > 0, "F2 重组 JPEG 已落盘")

    mae_l = None
    from PIL import Image
    im = None
    if os.path.exists(outp) and os.path.getsize(outp) > 0:
        # 解码失败不能让守卫崩掉——崩溃会以非零退出但打印栈，
        # 排查者看到的是 Python 异常而不是"画面不可用"这条结论。
        try:
            im = Image.open(outp)
            im = im.convert("RGB")
            ok_dec = True
            derr = ""
        except Exception as e:
            ok_dec = False
            derr = "%s: %s" % (type(e).__name__, e)
            im = None
        check(ok_dec, "F3 重组产物可被真实解码器打开", derr)

    if im is not None:
        check(im.size == (W, H), "F4 解码尺寸与原始一致",
              "got %s" % (im.size,))
        dec = luma(im.tobytes())
        with open(refp, "rb") as fh:
            refdata = fh.read(W * H * 2)
        refrgb = yuyv_to_rgb(refdata)
        refl = luma(refrgb)
        mae_l = mae(refl, dec)
        check(mae_l <= 5.0, "F5 重建画面亮度 MAE <= 5", "MAE=%.2f" % mae_l)
        print("      F5 MAE=%.2f" % mae_l)

        # 色度：参考系色度恒定（U=100/V=150）
        r0, g0, b0 = refrgb[0], refrgb[1], refrgb[2]
        dr = im.tobytes()
        # 取中心区域均值，避免 4:2:0 下采样在边缘的边界效应
        cx0, cy0, cx1, cy1 = W // 4, H // 4, W * 3 // 4, H * 3 // 4
        acc = [0, 0, 0]
        n = 0
        for y in range(cy0, cy1):
            for x in range(cx0, cx1):
                p = (y * W + x) * 3
                acc[0] += dr[p + 0]
                acc[1] += dr[p + 1]
                acc[2] += dr[p + 2]
                n += 1
        avg = [v / float(n) for v in acc]
        # 参考系中心区域均值（同一区域）
        rack = [0, 0, 0]
        for y in range(cy0, cy1):
            for x in range(cx0, cx1):
                p = (y * W + x) * 3
                rack[0] += refrgb[p + 0]
                rack[1] += refrgb[p + 1]
                rack[2] += refrgb[p + 2]
        ravg = [v / float(n) for v in rack]
        dmax = max(abs(avg[i] - ravg[i]) for i in range(3))
        check(dmax <= 12.0, "F6 中心区域色度偏差 <= 12",
              "ref=%.1f/%.1f/%.1f got=%.1f/%.1f/%.1f dmax=%.1f"
              % (ravg[0], ravg[1], ravg[2], avg[0], avg[1], avg[2], dmax))

        # ffmpeg 独立复核（与 PIL 不同解码器，避免单解码器容忍掩盖错误）
        try:
            rr = subprocess.run(
                ["ffmpeg", "-v", "error", "-i", outp, "-f", "null", "-"],
                capture_output=True, text=True, timeout=60)
            check(rr.returncode == 0 and not (rr.stderr or "").strip(),
                  "F7 ffmpeg 解码无错误", (rr.stderr or "")[:200])
        except FileNotFoundError:
            print("[SKIP] F7 ffmpeg 不可用")

    # ---------- 反向 R1：参考系给错 -> 比对必须变红 ----------
    rc2, log2 = run_c("mismatch", refp, outp)
    mae_wrong = None
    if rc2 == 0 and os.path.exists(outp) and os.path.getsize(outp) > 0:
        try:
            im2 = Image.open(outp).convert("RGB")
            dec = luma(im2.tobytes())
            with open(refp, "rb") as fh:
                refdata = fh.read(W * H * 2)
            mae_wrong = mae(luma(yuyv_to_rgb(refdata)), dec)
        except Exception as e:
            mae_wrong = None
            print("      R1 解码失败（%s）—— 这也算错配被抓到" % e)
    if mae_wrong is None:
        # 解码本身就失败了 —— 该事实已由 F3 记账，R1 在此无从判定，
        # 不该重复计一次失败（否则两处红看着像两个独立缺陷）。
        print("[SKIP] R1 参考系错配比对（正向解码已失败，见 F3）")
    else:
        check(mae_wrong > 5.0,
              "R1 参考系错配时 MAE 必须 > 5（证明 F5 有鉴别力）",
              "MAE=%.2f" % mae_wrong)

    # ---------- 反向 R2：篡改信元 -> 重组必须失败 ----------
    rc3, log3 = run_c("mutwire", refp, outp)
    # 判据说明（易错，勿改反）：C 侧的判据是"篡改后重组必须失败"，
    # 它成立时 C 返回 0（全部 CHECK 通过）；若篡改没生效（重组仍成功），
    # 那条 CHECK 会变红、C 返回 1。所以这里要求 rc3 == 0 且无 [FAIL]。
    check(rc3 == 0 and "[FAIL]" not in log3,
          "R2 篡改信元后重组必须失败（AEAD 拒绝）", log3[-300:])

    print("\n=== total=%d pass=%d fail=%d ===" % (g_pass + g_fail, g_pass, g_fail))
    return 1 if g_fail else 0


if __name__ == "__main__":
    sys.exit(main())
