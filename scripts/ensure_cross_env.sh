#!/bin/sh
# 恢复跨架构验证所需的环境依赖（ziglang 交叉编译器 + qiling 模拟器）。
#
# 为什么需要它：R4（arm64 真产物）与 R4b（跨架构真执行）的证据依赖这两个
# pip 包。沙盒会不定期清理它们——已发生三次。一旦缺失：
#   - 探针失败 → 红线判 STALE（有证据但无法复现）
#   - 巡检 ALARM → 整条 make test 变红
# 而 STALE 的报警是对的：凭一份无法复现的证据声称"已验证"就是伪造。
# 所以正确做法不是放宽判据，而是把环境恢复做成一条命令、可重复执行。
#
# 用法: sh scripts/ensure_cross_env.sh [--force]
# 退出码: 0 = 依赖齐备（本来就有或安装成功）；1 = 装不上（红线仍 STALE）
set -u
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

have_zig()  { python3 -c 'import ziglang'  >/dev/null 2>&1; }
have_qil()  { python3 -c 'import qiling'   >/dev/null 2>&1; }

rc=0

if [ "$FORCE" = 1 ] || ! have_zig; then
    echo "[..] 安装 ziglang（PyPI 预编译 wheel，含全目标 musl 头与静态库）"
    python3 -m pip install --quiet ziglang 2>&1 | tail -3
fi
if have_zig; then
    echo "[OK] ziglang 可用: $(python3 -c 'import ziglang,os;print(os.path.dirname(ziglang.__file__))')"
else
    echo "[FAIL] ziglang 不可用 —— R4 仍将判 STALE/BLOCKED"; rc=1
fi

if [ "$FORCE" = 1 ] || ! have_qil; then
    echo "[..] 安装 qiling（纯 Python 用户态模拟器，支持 arm64/arm Linux ELF）"
    python3 -m pip install --quiet qiling 2>&1 | tail -3
fi
if have_qil; then
    echo "[OK] qiling 可用"
else
    echo "[FAIL] qiling 不可用 —— R4b 仍将判 STALE/BLOCKED"; rc=1
fi

exit $rc
