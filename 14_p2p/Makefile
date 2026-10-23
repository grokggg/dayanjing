CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -I../08_lateral/include -I../02_c2/include -I../00_crypto/include
LATLIB  := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o
BUILD   := build

# 上游产物未声明依赖：上游 clean 后本模块链接报
#   "ld: cannot find ../08_lateral/build/proxy.o"
# 真实原因（上游没构建）一个字都不提，排查必然跑偏。
#
# 无条件触发上游构建，由上游 make 自身做增量判断（产物已最新时仅一次时间戳比较）。
# 不能只在"产物缺失"时触发：上游源码改了但产物仍在，下游会静默链接陈旧代码且无任何
# 报错 —— 实测过，本模块曾长期链接着改 proxy.c 之前的旧 .o，而全仓测试照绿。
#
# 用读取阶段 $(shell) 而非目标级规则，是因为 LATLIB 被多个链接行直接引用。
# 不会与 08_lateral 的 $(P2P_RESOLV) 规则形成递归：build/proxy.o 编译时仅需本模块
# 头文件，不会再回头要 14_p2p 的产物，链条在叶子处终止。
_LAT_TRIG := $(shell $(MAKE) -C ../08_lateral --no-print-directory build/proxy.o build/lateral.o >/dev/null)
_LAT_MISSING := $(filter-out $(wildcard $(LATLIB)),$(LATLIB))
ifneq ($(strip $(_LAT_MISSING)),)
$(error 08_lateral 未产出 $(_LAT_MISSING)，且上游构建未报错 —— 请检查 ../08_lateral/Makefile)
endif

# 02_c2 的帧层 AEAD + 00_crypto 的 GCM/SHA（E2EE 隧道依赖，密码学只此一处实现）
# crypto_hash.o 提供 HKDF，供 p2p_tunnel_init_from_session 从会话密钥派生隧道密钥
C2OBJS  := $(BUILD)/c2.o $(BUILD)/c2_frame.o $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o $(BUILD)/crypto_x25519.o

all: $(BUILD)/libp2p.a $(BUILD)/p2p_node $(BUILD)/test_cover $(BUILD)/test_mix_cover

$(BUILD)/libp2p.a: $(BUILD)/mesh.o $(BUILD)/relay.o $(BUILD)/crypto.o $(BUILD)/route.o $(BUILD)/onion.o $(BUILD)/onion_route.o $(BUILD)/cell.o $(BUILD)/hopkey.o $(BUILD)/mix.o $(BUILD)/mix_cover.o $(BUILD)/resolv.o $(BUILD)/cover.o $(BUILD)/cover_budget.o
	ar rcs $@ $^

$(BUILD)/mesh.o: src/mesh.c include/p2p.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# QoS 路由与数据面联动：电路头编解码 + 逐跳动态转发
$(BUILD)/route.o: src/route.c include/p2p.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 洋葱路由：分层加密，中间跳看不到完整路径与最终目标
$(BUILD)/onion.o: src/onion.c include/p2p_onion.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/onion_route.o: src/onion_route.c include/p2p.h include/p2p_onion.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 自研 A 记录解析（RFC1035 over UDP），取代 getaddrinfo（静态链接无 NSS 依赖）
$(BUILD)/resolv.o: src/resolv.c include/p2p_resolv.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_resolv: tests/test_resolv.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

$(BUILD)/relay.o: src/relay.c include/p2p.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 定长信元层：固定 512 字节线上长度 + 填充 + 抖动 + 覆盖流量
$(BUILD)/cell.o: src/cell.c include/p2p_cell.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 自适应覆盖流量：覆盖速率随实测数据速率与信道字节成本联动
$(BUILD)/cover.o: src/cover.c include/p2p_cover.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_cover: tests/test_cover.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

# 覆盖预算按真实带宽自适应：实测 kbps -> 字节预算（含多跳木桶与冲突诊断）
$(BUILD)/cover_budget.o: src/cover_budget.c include/p2p_cover_budget.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_cover_budget: tests/test_cover_budget.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

$(BUILD)/crypto.o: src/crypto.c include/p2p_crypto.h ../02_c2/include/c2_frame.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 跳静态密钥轮换：把 ephemeral-static 补成真前向保密（epoch 轮换 + 私钥安全擦除）
$(BUILD)/hopkey.o: src/hopkey.c include/p2p_hopkey.h include/p2p_onion.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 混时序：时间片内跨流交错（保流内序）+ 每片恒定输出（不足补覆盖）
$(BUILD)/mix.o: src/mix.c include/p2p_mix.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 覆盖流量 -> 真实数据面的驱动层：把 cover 速率接到 cell/mix 的实际发送上
$(BUILD)/mix_cover.o: src/mix_cover.c include/p2p_mix.h include/p2p_cover.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_mix_cover: tests/test_mix_cover.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS)

$(BUILD)/c2_frame.o: ../02_c2/src/c2_frame.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto_gcm.o: ../00_crypto/src/crypto_gcm.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto_hash.o: ../00_crypto/src/crypto_hash.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# X25519：洋葱层密钥协商（ephemeral-static），取代原来的全网共享 master
$(BUILD)/crypto_x25519.o: ../00_crypto/src/crypto_x25519.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 02_c2 握手状态机 + 会话密钥派生（test_e2ee 的握手接入需要）
$(BUILD)/c2.o: ../02_c2/src/c2.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_mesh: tests/test_mesh.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

$(BUILD)/test_chain: tests/test_chain.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

$(BUILD)/test_e2ee: tests/test_e2ee.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS)

$(BUILD)/test_qos: tests/test_qos.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

# QoS 与数据面联动：真进程 + 真 socket，路径由 QoS 算出并驱动逐跳转发
$(BUILD)/test_route: tests/test_route.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

$(BUILD)/test_cell: tests/test_cell.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS)

# 单坏信元的恢复能力（AUTH 后流位置仍前进，链路不被单个坏字节打死）
$(BUILD)/test_cell_resync: tests/test_cell_resync.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS)

# 真实带宽探测：快/慢 sink 真实进程 + 真实 socket
$(BUILD)/test_bw: tests/test_bw.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

# 可独立部署的节点守护进程（配置驱动，无需重新编译即可换拓扑）
$(BUILD)/p2p_node: src/node.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS) -lpthread

# 静态制品：可直接 scp 到目标机运行，不依赖目标机任何开发库
STATIC := static
$(STATIC)/p2p_node: src/node.c
	mkdir -p $(STATIC)
	$(CC) $(CFLAGS) -static -o $@ $< \
	  $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS) -lpthread

$(BUILD):
	mkdir -p $(BUILD)

# 洋葱测试同时依赖密码学目标（层密钥 HKDF + 层加密 GCM）
$(BUILD)/test_onion: tests/test_onion.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS)

# 跳静态密钥轮换 / 前向保密
$(BUILD)/test_hopkey: tests/test_hopkey.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS)

# 混时序
$(BUILD)/test_mix: tests/test_mix.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a $(C2OBJS)

# 探测调度：低频 + 错峰（含真实回环 listener 探测）
$(BUILD)/test_probesched: tests/test_probesched.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(LATLIB) $(BUILD)/libp2p.a

test: $(BUILD)/test_mesh $(BUILD)/test_qos $(BUILD)/test_chain $(BUILD)/test_e2ee $(BUILD)/test_route $(BUILD)/test_onion $(BUILD)/test_cell $(BUILD)/test_bw $(BUILD)/test_hopkey $(BUILD)/test_mix $(BUILD)/test_mix_cover $(BUILD)/test_probesched $(BUILD)/test_resolv $(BUILD)/test_cover $(BUILD)/test_cell_resync $(BUILD)/test_cover_budget
	./$(BUILD)/test_mesh
	./$(BUILD)/test_qos
	./$(BUILD)/test_chain
	./$(BUILD)/test_e2ee
	./$(BUILD)/test_route
	./$(BUILD)/test_onion
	./$(BUILD)/test_cell
	./$(BUILD)/test_cell_resync
	./$(BUILD)/test_bw
	./$(BUILD)/test_hopkey
	./$(BUILD)/test_mix
	./$(BUILD)/test_mix_cover
	./$(BUILD)/test_probesched
	./$(BUILD)/test_resolv
	./$(BUILD)/test_cover
	./$(BUILD)/test_cover_budget

inspect: all
	@echo "== 符号表（14_p2p 公开接口） =="
	@nm -g --defined-only $(BUILD)/libp2p.a | awk '$$2=="T"{print "  "$$3}'

clean:
	rm -rf $(BUILD)

.PHONY: all test clean inspect static

static: $(STATIC)/p2p_node
	@file $(STATIC)/p2p_node | cut -c1-120
	@echo "== 动态依赖检查 =="
	@ldd $(STATIC)/p2p_node 2>&1 | head -3
