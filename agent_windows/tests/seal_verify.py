#!/usr/bin/env python3
"""
agent_windows/tests/seal_verify.py

读取 C 测试落盘的交付字节（JPEG 帧），用 00_crypto 已验证的 GCM
实现完成密封→解密还原验证。

对应 C 侧 tests/test_pipeline.c 的第 5 步（交付字节落盘）。
两个测试共同构成"采集→转码→密封"全链路验证。
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, '..', '..', '00_crypto'))

from crypto_layer import GCM  # noqa: E402

PASS, FAIL = [], []
def check(cond, name):
    if cond:
        PASS.append(name)
        print(f"  [PASS] {name}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}")

def is_jpeg(data):
    return len(data) >= 8 and data[:2] == b'\xff\xd8' and data[-2:] == b'\xff\xd9'

def main():
    print("[*] agent_windows 密封环节验证（Python 侧，对接 00_crypto）")
    print("[*] ======================================================")

    key = b'\x42' * 16
    files = sorted(
        f for f in os.listdir('/tmp')
        if f.startswith('dj_deliver_') and f.endswith('.bin')
    )
    check(len(files) > 0, f"找到 C 侧落盘的交付字节文件（{len(files)} 个）")

    sealed_count = 0
    for fn in files:
        path = os.path.join('/tmp', fn)
        plain = open(path, 'rb').read()
        check(is_jpeg(plain), f"{fn} 是合法 JPEG（密封前）")

        g = GCM(key)
        iv, ct, tag = g.encrypt(plain)
        check(len(ct) == len(plain), f"{fn} GCM 加密输出长度一致")

        g2 = GCM(key)
        got = g2.decrypt(iv, ct, tag)
        check(got == plain, f"{fn} GCM 解密还原与原文一致")
        if got == plain:
            sealed_count += 1

    check(sealed_count == len(files),
          f"全部 {len(files)} 帧 JPEG 经 GCM 密封→解密还原一致")

    # 篡改检测：改一位应解密失败
    if files:
        plain = open(os.path.join('/tmp', files[0]), 'rb').read()
        g = GCM(key)
        iv, ct, tag = g.encrypt(plain)
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        g3 = GCM(key)
        try:
            g3.decrypt(iv, bytes(tampered), tag)
            check(False, "篡改密文应解密失败")
        except Exception:
            check(True, "篡改密文被正确拒绝（完整性校验生效）")

    print("[*] ======================================================")
    print(f"[*] 结果: {len(PASS)}/{len(PASS)+len(FAIL)} 通过")
    print(f"[*] 失败: {len(FAIL)} 项")
    sys.exit(0 if not FAIL else 1)

if __name__ == '__main__':
    main()
