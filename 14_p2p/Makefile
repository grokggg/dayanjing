CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -I../08_lateral/include -I../02_c2/include -I../00_crypto/include
LATLIB  := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o
BUILD   := build

# 02_c2 的帧层 AEAD + 00_crypto 的 GCM/SHA（E2EE 隧道依赖，密码学只此一处实现）
# crypto_hash.o 提供 HKDF，供 p2p_tunnel_init_from_session 从会话密钥派生隧道密钥
C2OBJS  := $(BUILD)/c2.o $(BUILD)/c2_frame.o $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o $(BUILD)/crypto_x25519.o

all: $(BUILD)/libp2p.a $(BUILD)/p2p_node

$(BUILD)/libp2p.a: $(BUILD)/mesh.o $(BUILD)/relay.o $(BUILD)/crypto.o $(BUILD)/route.o $(BUILD)/onion.o $(BUILD)/onion_route.o $(BUILD)/cell.o $(BUILD)/hopkey.o $(BUILD)/mix.o $(BUILD)/resolv.o
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
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD)/relay.o: src/relay.c include/p2p.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 定长信元层：固定 512 字节线上长度 + 填充 + 抖动 + 覆盖流量
$(BUILD)/cell.o: src/cell.c include/p2p_cell.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto.o: src/crypto.c include/p2p_crypto.h ../02_c2/include/c2_frame.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 跳静态密钥轮换：把 ephemeral-static 补成真前向保密（epoch 轮换 + 私钥安全擦除）
$(BUILD)/hopkey.o: src/hopkey.c include/p2p_hopkey.h include/p2p_onion.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# 混时序：时间片内跨流交错（保流内序）+ 每片恒定输出（不足补覆盖）
$(BUILD)/mix.o: src/mix.c include/p2p_mix.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

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
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD)/test_chain: tests/test_chain.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD)/test_e2ee: tests/test_e2ee.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB)

$(BUILD)/test_qos: tests/test_qos.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

# QoS 与数据面联动：真进程 + 真 socket，路径由 QoS 算出并驱动逐跳转发
$(BUILD)/test_route: tests/test_route.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD)/test_cell: tests/test_cell.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB)

# 真实带宽探测：快/慢 sink 真实进程 + 真实 socket
$(BUILD)/test_bw: tests/test_bw.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

# 可独立部署的节点守护进程（配置驱动，无需重新编译即可换拓扑）
$(BUILD)/p2p_node: src/node.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB) -lpthread

# 静态制品：可直接 scp 到目标机运行，不依赖目标机任何开发库
STATIC := static
$(STATIC)/p2p_node: src/node.c
	mkdir -p $(STATIC)
	$(CC) $(CFLAGS) -static -o $@ $< \
	  $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB) -lpthread

$(BUILD):
	mkdir -p $(BUILD)

# 洋葱测试同时依赖密码学目标（层密钥 HKDF + 层加密 GCM）
$(BUILD)/test_onion: tests/test_onion.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB)

# 跳静态密钥轮换 / 前向保密
$(BUILD)/test_hopkey: tests/test_hopkey.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB)

# 混时序
$(BUILD)/test_mix: tests/test_mix.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB)

# 探测调度：低频 + 错峰（含真实回环 listener 探测）
$(BUILD)/test_probesched: tests/test_probesched.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

test: $(BUILD)/test_mesh $(BUILD)/test_qos $(BUILD)/test_chain $(BUILD)/test_e2ee $(BUILD)/test_route $(BUILD)/test_onion $(BUILD)/test_cell $(BUILD)/test_bw $(BUILD)/test_hopkey $(BUILD)/test_mix $(BUILD)/test_probesched $(BUILD)/test_resolv
	./$(BUILD)/test_mesh
	./$(BUILD)/test_qos
	./$(BUILD)/test_chain
	./$(BUILD)/test_e2ee
	./$(BUILD)/test_route
	./$(BUILD)/test_onion
	./$(BUILD)/test_cell
	./$(BUILD)/test_bw
	./$(BUILD)/test_hopkey
	./$(BUILD)/test_mix
	./$(BUILD)/test_probesched
	./$(BUILD)/test_resolv

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
