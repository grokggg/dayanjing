# agent_windows/Makefile
#
# 构建策略（平台分层，避免 Windows 源码污染 Linux 构建）：
#
#   all / test  —— Linux 可编译测试目标。只编译跨平台纯 C 源码：
#                    src/cam_jpeg.c   （YUYV422→JPEG 编码器，纯 C99）
#                    src/cam_mock.c   （Mock 采集后端，纯 C）
#                    include/camera.h （公共接口）
#                  Windows 专属后端 src/cam_mf.cpp / src/cam_mf_main.cpp
#                  被 #ifdef _WIN32 整体包裹，Linux 下不参与编译、不参与链接。
#
#   win         —— Windows 后端编译目标（可选）。需要 MinGW 交叉工具链或
#                  MSVC；Linux 沙盒无 windows.h / mfapi.h，检测到无工具链
#                  时打印跳过信息并返回 0（不是错误）。

CC       ?= cc
CXX      ?= g++

CFLAGS   ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Iinclude
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude
LDLIBS   ?= -lm

BUILD     := build/linux
PORT_SRCS := src/cam_jpeg.c src/cam_mock.c
PORT_OBJS := $(PORT_SRCS:src/%.c=$(BUILD)/%.o)

TESTS     := test_pipeline test_linux_extra
TEST_BINS := $(TESTS:%=$(BUILD)/%)

.PHONY: all test clean win dirs

all: $(TEST_BINS)

dirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/camera.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

# 每个测试二进制 = 该测试源码 + 跨平台内核源码
$(BUILD)/test_%: tests/test_%.c $(PORT_OBJS) | dirs
	$(CC) $(CFLAGS) $< $(PORT_OBJS) -o $@ $(LDLIBS)

test: $(TEST_BINS)
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "=== $$t ==="; \
		./$$t || fail=1; \
	done; \
	exit $$fail

# Windows 后端：仅在检测到 MinGW 交叉工具链时真正编译
win: | dirs
	@if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then \
		x86_64-w64-mingw32-g++ $(CXXFLAGS) -c src/cam_mf.cpp -o $(BUILD)/cam_mf.o \
			&& echo "win: cam_mf.cpp 编译 OK"; \
	else \
		echo "win: 跳过（无 Windows 工具链 / windows.h；cam_mf.cpp 不参与 Linux 构建）"; \
	fi

clean:
	rm -rf build
