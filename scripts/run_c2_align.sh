#!/bin/sh
# 02_c2（C） 与 13_c2_server（Python）的双向协议对齐。
#
# 为什么要单独一个驱动
# --------------------
# 这个测试跨两种语言、三个步骤，任意一步单独跑都没有意义：
#   1) Python 侧派生会话密钥并密封一帧 -> /tmp/py_seal.bin
#   2) C 侧用同样的固定输入派生密钥、解开该帧、再密封响应 -> /tmp/c_seal.bin
#   3) Python 侧解开 C 的响应帧
# 历史上 test_align.c 写了却从未被任何 Makefile 引用，因此这套断言
# 一次都没执行过——两端协议是否漂移无人知晓。
#
# 硬规则
# ------
# * 开始前清空夹具：否则上次的 /tmp/py_seal.bin 会让"Python 侧已改动"
#   看起来仍然一致（陈旧产物型假通过）。
# * 结束后清空夹具：使 test_align 在此之外被单独执行时返回 77(SKIP)，
#   而不是拿着旧夹具冒认通过。
# * C 侧返回 77 视为失败：本脚本已生成夹具，此时 SKIP 说明夹具没生效，
#   不能当成"环境不具备"放过。
# * verify 前必须确认 /tmp/c_seal.bin 是本轮写出的，否则读陈旧文件会假通过。
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PY="$ROOT/13_c2_server/tools/align_proto.py"
C="$ROOT/02_c2"
TMPP="/tmp/py_seal.bin"
TMPC="/tmp/c_seal.bin"

echo "=== c2_align（C <-> Python 双向协议对齐） ==="

rm -f "$TMPP" "$TMPC" /tmp/align_key_c2s.bin /tmp/align_key_s2c.bin \
      /tmp/align_expect.bin /tmp/align_expect_rsp.bin

if [ ! -f "$PY" ]; then
    echo "  [FAIL] 缺少 $PY"
    exit 1
fi

# 1) 编译 C 侧（编译漂移在此暴露：从未编译过的测试最容易腐坏）
if ! (cd "$C" && make align >/tmp/c2_align_build.log 2>&1); then
    echo "  [FAIL] make align 失败"
    tail -5 /tmp/c2_align_build.log | sed 's/^/         /'
    exit 1
fi

# 2) Python 侧生成夹具
if ! python3 "$PY" seal >/tmp/c2_align_seal.log 2>&1; then
    echo "  [FAIL] align_proto.py seal 失败"
    tail -5 /tmp/c2_align_seal.log | sed 's/^/         /'
    exit 1
fi
[ -f "$TMPP" ] || { echo "  [FAIL] seal 未产出 $TMPP"; exit 1; }

# 3) C 侧：解 Python 的帧 + 密封响应
rm -f "$TMPC"
"$C/build/test_align" >/tmp/c2_align_c.log 2>&1
rc=$?
sed 's/^/         /' /tmp/c2_align_c.log | grep -E 'FAIL|SKIP|total=' | head -8
if [ $rc -eq 77 ]; then
    echo "  [FAIL] C 侧返回 77(SKIP)：夹具已生成却仍跳过，说明夹具路径不一致"
    exit 1
fi
if [ $rc -ne 0 ]; then
    echo "  [FAIL] C 侧对齐失败 rc=$rc"
    grep -E '^  FAIL' /tmp/c2_align_c.log | sed 's/^/         /'
    exit 1
fi
if [ ! -f "$TMPC" ]; then
    echo "  [FAIL] C 侧未写出 $TMPC，verify 会读到陈旧文件"
    exit 1
fi

# 4) Python 侧验证 C 的响应帧
if ! python3 "$PY" verify >/tmp/c2_align_verify.log 2>&1; then
    echo "  [FAIL] align_proto.py verify 失败"
    tail -5 /tmp/c2_align_verify.log | sed 's/^/         /'
    exit 1
fi

echo "  [PASS] 密钥派生 + 帧格式双向一致（C 侧断言 + Python 侧 verify）"

# 5) 收尾清空，避免旧夹具让后续裸跑冒认通过
rm -f "$TMPP" "$TMPC" /tmp/align_key_c2s.bin /tmp/align_key_s2c.bin \
      /tmp/align_expect.bin /tmp/align_expect_rsp.bin

# 同时移除二进制本身：回归的通用扫描会执行 build/ 下任何 test_*，
# 而本测试单独被执行时必然返回 77(SKIP)——报告里就会出现一条无意义的
# "02_c2 SKIP"。它只在专用驱动下有意义，因此不留在 build/ 里。
rm -f "$C/build/test_align"
exit 0
