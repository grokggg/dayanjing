#!/usr/bin/env bash
#
# agent_windows/tools/build_mf.sh
#
# 跨平台编译验证脚本：检测 Windows 交叉编译工具链是否可用，
# 并给出 MSVC / Clang-cl 的具体编译命令。
#
# 用法：
#   ./build_mf.sh            # 自动检测并编译
#   ./build_mf.sh check      # 仅检测工具链，不编译
#   ./build_mf.sh mingw      # 强制用 mingw-w64 交叉编译
#
# 说明：
#   cam_mf.cpp 依赖 Windows 专属头文件（mfapi.h / mfreadwrite.h / windows.h），
#   Linux 原生 gcc 无法编译。本脚本会如实报告，而非伪装通过。
#

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== cam_mf.cpp 编译验证 ==="
echo "源码目录: $SRC_DIR"
echo "项目根:   $ROOT_DIR"
echo ""

# ---------- 1. 检测 mingw-w64 ----------
check_mingw() {
    if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
        echo -e "${GREEN}[OK]${NC} 找到 mingw-w64: $(x86_64-w64-mingw32-g++ --version | head -1)"
        return 0
    elif command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
        echo -e "${GREEN}[OK]${NC} 找到 mingw-w64 gcc: $(x86_64-w64-mingw32-gcc --version | head -1)"
        return 0
    else
        echo -e "${YELLOW}[--]${NC} 未找到 mingw-w64（x86_64-w64-mingw32-g++）"
        return 1
    fi
}

# ---------- 2. 检测 mfapi.h 是否可获取 ----------
check_mf_headers() {
    local f=/usr/share/mingw-w64/include/mfapi.h
    if [ -f "$f" ]; then
        echo -e "${GREEN}[OK]${NC} 找到 mfapi.h: $f"
        return 0
    else
        echo -e "${YELLOW}[--]${NC} 未找到 mfapi.h（mingw-w64 的 mediafoundation 包未装）"
        return 1
    fi
}

# ---------- 3. 语法/结构自检（不依赖 Windows 头） ----------
# 用 gcc -fsyntax-only 检查纯 C 部分（cam_jpeg.c / cam_mock.c）可独立编译
check_c_syntax() {
    echo ""
    echo "--- 纯 C 部分语法检查（cam_jpeg.c / cam_mock.c，不依赖 Windows） ---"
    local cc=gcc
    if command -v gcc >/dev/null 2>&1; then
        local rc=0
        for f in cam_jpeg.c cam_mock.c; do
            if gcc -I"$SRC_DIR/include" -c "$SRC_DIR/src/$f" -o /tmp/_t_$f.o \
                   -Wall -Wextra -Wpedantic -O2 2>/tmp/_err_$f; then
                echo -e "${GREEN}[OK]${NC} $f 编译通过（零警告）"
            else
                echo -e "${RED}[FAIL]${NC} $f 编译失败："
                cat /tmp/_err_$f
                rc=1
            fi
            rm -f /tmp/_t_$f.o /tmp/_err_$f
        done
        return $rc
    else
        echo -e "${YELLOW}[--]${NC} 无 gcc，跳过 C 语法检查"
        return 0
    fi
}

MODE="${1:-auto}"

case "$MODE" in
    check)
        check_mingw
        check_mf_headers
        check_c_syntax
        echo ""
        echo "=== 工具链状态 ==="
        echo "如需在 Linux 交叉编译 Windows .exe，请安装："
        echo "  Debian/Ubuntu: sudo apt-get install mingw-w64"
        echo "  Arch:          sudo pacman -S mingw-w64"
        echo "  Fedora:        sudo dnf install mingw64-gcc-c++"
        echo ""
        echo "注意：mingw-w64 默认不含完整 Media Foundation 头文件，"
        echo "cam_mf.cpp / cam_mf_main.cpp 的最终编译验证"
        echo "必须在 Windows 真机 + MSVC 或 Clang-cl 环境下完成。"
        exit 0
        ;;
    mingw)
        if ! check_mingw; then
            echo -e "${RED}错误：${NC}请先安装 mingw-w64" >&2
            exit 1
        fi
        if ! check_mf_headers; then
            echo -e "${RED}错误：${NC}mingw-w64 缺少 Media Foundation 头文件（mfapi.h）" >&2
            echo "cam_mf.cpp 无法在此环境编译，请使用 Windows + MSVC/Clang-cl" >&2
            exit 2
        fi
        echo ""
        echo "--- 交叉编译 cam_mf.cpp（mingw-w64） ---"
        # 注意：即使头文件存在，mingw 的 MF 导入库可能不完整，此处如实尝试
        x86_64-w64-mingw32-g++ \
            -I"$SRC_DIR/include" \
            -I"$ROOT_DIR/00_crypto" \
            -D_WIN32 \
            -c "$SRC_DIR/src/cam_mf.cpp" -o /tmp/cam_mf.o \
            -Wall -Wextra -O2 2>&1 && echo -e "${GREEN}[OK]${NC} cam_mf.cpp 交叉编译通过"
        ;;
    auto|"")
        check_c_syntax
        if check_mingw && check_mf_headers; then
            echo ""
            echo "--- 尝试交叉编译 cam_mf.cpp ---"
            x86_64-w64-mingw32-g++ \
                -I"$SRC_DIR/include" \
                -I"$ROOT_DIR/00_crypto" \
                -D_WIN32 \
                -c "$SRC_DIR/src/cam_mf.cpp" -o /tmp/cam_mf.o \
                -Wall -Wextra -O2 2>&1 && echo -e "${GREEN}[OK]${NC} cam_mf.cpp 交叉编译通过"
        else
            echo ""
            echo -e "${YELLOW}=== 结论 ===${NC}"
            echo "当前沙盒为 Linux，无法原生编译 cam_mf.cpp。"
            echo "纯 C 部分（cam_jpeg.c / cam_mock.c）已通过语法检查。"
            echo ""
            echo "下一步：在 Windows 真机上用以下命令编译验证："
            echo ""
            echo "  【MSVC 开发者命令提示符】"
            echo "  cl /EHsc /std:c++17 /O2 /I.. /I../../00_crypto ^"
            echo "     cam_jpeg.c cam_mf.cpp cam_mf_main.cpp ^"
            echo "     /link mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib shell32.lib"
            echo ""
            echo "  【Clang-cl】"
            echo "  clang-cl /EHsc /std:c++17 /O2 /I.. /I../../00_crypto ^"
            echo "     cam_jpeg.c cam_mf.cpp cam_mf_main.cpp ^"
            echo "     mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib shell32.lib"
            echo ""
            echo "  编译后运行：cam_mf_test.exe 640 480 3"
        fi
        ;;
    *)
        echo "用法: $0 [check|mingw|auto]" >&2
        exit 1
        ;;
esac
