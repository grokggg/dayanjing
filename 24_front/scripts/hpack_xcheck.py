#!/usr/bin/env python3
"""用独立的 python-hpack 实现解码 C 侧产出的 HPACK 头块。

为什么需要：自编自解会掩盖"两边按同样错误理解实现"的情况。让第三方独立
实现来解我们产出的字节，才能证明编码符合 RFC 7541，而不是自己对得上。

用法：
    ./build/dump_hpack | python3 scripts/hpack_xcheck.py

python-hpack 不是运行时依赖，只用于验证；未安装时退出码 77（SKIP），
不算测试失败。
"""
import sys
import binascii

try:
    import hpack
except ImportError:
    print("[SKIP] python-hpack 未安装，跳过跨实现交叉验证")
    sys.exit(77)


def main():
    ok = fail = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) != 5:
            print("[FAIL] 输入格式错误: %r" % line[:48])
            fail += 1
            continue
        hexs, method, scheme, path, authority = parts
        raw = binascii.unhexlify(hexs)

        # 每条用全新 Decoder：不共享动态表，避免上一条的状态影响本条
        try:
            got = hpack.Decoder().decode(raw)
        except Exception as ex:
            print("[FAIL] 独立实现解码异常: %s" % ex)
            fail += 1
            continue

        want = [(':method', method), (':scheme', scheme),
                (':path', path), (':authority', authority)]
        if got != want:
            print("[FAIL] 语义不符 期望=%r 实得=%r" % (want, got))
            fail += 1
            continue

        # 硬规则 2：:authority 必须是 never-indexed literal（前缀 0x1_，名索引 1 -> 0x11）
        ab = authority.encode()
        marker = bytes([0x11, len(ab)]) + ab
        if marker not in raw:
            print("[FAIL] :authority 不是 never-indexed literal（缺 0x11 前缀）")
            fail += 1
            continue

        print("[PASS] %-4s %-24s -> %r" % (method, authority, got))
        ok += 1

    print("=== xcheck %d/%d passed ===" % (ok, ok + fail))
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
