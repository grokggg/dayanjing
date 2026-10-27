#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_jpeg_decode —— 摄像头转码产物的**真解码**守卫。

为什么必须有它：
  cam_jpeg.c 里连续藏着四个缺陷，而既有测试一路全绿，因为判据只是
  is_jpeg()：校验 SOI(FFD8)/EOI(FFD9) 两个魔数 + 段结构。mock 后端产的是
  1x1 桩帧、走 MJPEG 直通，根本不经过真实分辨率转码。于是
  "摄像头链路已验证" 这句话从未包含 "画面能打开" 这一层。

  已抓到的四个（前两个本轮修，后两个上轮修）：
    1. DHT 表类 Tc 写成 2/3（JPEG 只允许 0/1）→ 任何解码器都打不开
    2. DC 预测值调用方自行重算、负数取整方向不同 → 误差逐块线性累积
    3. Huffman 表按"出现顺序"落位而查询用"符号值" → 高位 AC 码长度恒 0
    4. 码字左对齐而取位取低位 → 整条码流错位

  四个都不是"段结构不对"，而是"结构对、内容错"。只有真解码器能抓。

判据分三层，缺一层就会被绕过：
  A. 双解码器都能打开（PIL + ffmpeg，避免单一实现的容错差异）
  B. 字节级：DHT 的 Tc 字段必须合法（静态判据，不依赖能否联网装解码器）
  C. 内容级：平坦帧解码后的亮度必须等于已知输入值
     —— 没有 C，前两条会在"能打开但全黑/全乱"时依然全绿。
"""
import os
import subprocess
import sys
import shutil
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)
BUILD = os.path.join(MOD, "build", "linux")
PROBE = os.path.join(BUILD, "jpeg_dump_probe")

W, H = 320, 240

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("%s %s%s" % ("[OK]  " if ok else "[FAIL]", name,
                       ("  -- " + detail) if detail else ""))


def read_dht_tc(path):
    """返回该 JPEG 中所有 DHT 段的 (Tc, Th) 列表。"""
    d = open(path, "rb").read()
    out = []
    i = 2
    while i < len(d) - 1:
        if d[i] != 0xFF:
            break
        m = d[i + 1]
        if m in (0xD8, 0xD9, 0x01) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if m == 0xDA:
            break
        L = struct.unpack(">H", d[i + 2:i + 4])[0]
        if m == 0xC4:
            p = i + 4
            end = i + 2 + L
            while p < end:
                tc = d[p] >> 4
                th = d[p] & 15
                p += 1
                counts = d[p:p + 16]
                p += 16
                p += sum(counts)
                out.append((tc, th))
        i += 2 + L
    return out


def pil_decode(path):
    from PIL import Image
    im = Image.open(path)
    im.load()
    return im


def ffmpeg_decode(path):
    r = subprocess.run(["ffmpeg", "-v", "error", "-i", path, "-f", "null", "-"],
                       capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stderr or "").strip()


def main():
    if not os.path.exists(PROBE):
        check("前置：jpeg_dump_probe 已构建", False, PROBE)
        return 1
    if shutil.which("ffmpeg") is None:
        check("前置：ffmpeg 可用", False, "无 ffmpeg，无法做双解码器交叉验证")
        return 1

    outdir = os.path.join(MOD, "build", "jpegdec")
    shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir, exist_ok=True)

    r = subprocess.run([PROBE, outdir], capture_output=True, text=True, timeout=120)
    print(r.stdout.strip())
    if r.returncode != 0:
        check("前置：probe 产出帧", False, "rc=%d" % r.returncode)
        return 1

    # ---- A. 双解码器 ----
    for tag in ("frame_noise", "frame_gradient", "frame_solid",
                "frame_ramp", "frame_flat"):
        p = os.path.join(outdir, tag + ".jpg")
        try:
            im = pil_decode(p)
            check("A/%s PIL 可解码且尺寸正确" % tag,
                  im.size == (W, H), "size=%s" % (im.size,))
        except Exception as e:
            check("A/%s PIL 可解码且尺寸正确" % tag, False,
                  "%s: %s" % (type(e).__name__, e))

        rc, err = ffmpeg_decode(p)
        check("A/%s ffmpeg 解码无错误" % tag, rc == 0 and err == "",
              (err[:120] if err else "rc=%d" % rc))

    # ---- B. DHT 表类合法性（本轮缺陷 1 的永久判据）----
    p = os.path.join(outdir, "frame_gradient.jpg")
    tc_list = read_dht_tc(p)
    bad = [t for t in tc_list if t[0] > 1]
    check("B/1 DHT 表类 Tc 全部合法（0=DC 1=AC）", not bad,
          "Tc/Th=%s 非法项=%s" % (tc_list, bad))
    check("B/2 四个 DHT 段齐备（DC0/AC0/DC1/AC1）",
          sorted(tc_list) == [(0, 0), (0, 1), (1, 0), (1, 1)],
          "实际=%s" % sorted(tc_list))

    # ---- C. 内容级 ----
    import numpy as np
    from PIL import Image

    # C1：纯灰帧（输入块全零）必须完全均匀。它对任何 DC 缩放因子都不敏感，
    # 所以只能证明"无累积漂移"，证明不了绝对值——C2 才是绝对值判据。
    a = np.asarray(Image.open(os.path.join(outdir, "frame_solid.jpg"))
                   .convert("RGB")).astype(int)
    check("C/1 纯灰帧解码完全均匀 (128,128,128)",
          a.min() == 128 and a.max() == 128,
          "min=%d max=%d" % (a.min(), a.max()))

    # C2：平坦非零帧的亮度必须等于已知输入值 140。
    a = np.asarray(Image.open(os.path.join(outdir, "frame_flat.jpg"))
                   .convert("RGB")).astype(float)
    R, G, B = a[..., 0], a[..., 1], a[..., 2]
    Y = 0.299 * R + 0.587 * G + 0.114 * B
    check("C/2 平坦帧亮度等于输入值 140（±3）", abs(Y.mean() - 140.0) <= 3.0,
          "decoded Y=%.1f" % Y.mean())

    # C3：灰阶斜坡必须单调递增（左暗右亮）。只校验结构不校验数值，
    # 用于抓"块序错乱 / DC 累积漂移"这类让画面左右颠倒的缺陷。
    g = np.asarray(Image.open(os.path.join(outdir, "frame_ramp.jpg"))
                   .convert("L")).astype(float)
    prof = g.mean(axis=0)
    check("C/3 灰阶斜坡左暗右亮且整体递增",
          prof[0] < prof[len(prof) // 2] < prof[-1],
          "x0=%.1f xmid=%.1f xend=%.1f" % (prof[0], prof[len(prof) // 2], prof[-1]))

    nfail = sum(1 for _, ok, _ in results if not ok)
    print("\n共 %d 项，失败 %d" % (len(results), nfail))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
