CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -I../08_lateral/include -I../02_c2/include -I../00_crypto/include
LATLIB  := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o
BUILD   := build

# 02_c2 的帧层 AEAD + 00_crypto 的 GCM/SHA（E2EE 隧道依赖，密码学只此一处实现）
# crypto_hash.o 提供 HKDF，供 p2p_tunnel_init_from_session 从会话密钥派生隧道密钥
C2OBJS  := $(BUILD)/c2.o $(BUILD)/c2_frame.o $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o

all: $(BUILD)/libp2p.a

$(BUILD)/libp2p.a: $(BUILD)/mesh.o $(BUILD)/relay.o $(BUILD)/crypto.o $(BUILD)/route.o $(BUILD)/onion.o $(BUILD)/onion_route.o
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

$(BUILD)/relay.o: src/relay.c include/p2p.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto.o: src/crypto.c include/p2p_crypto.h ../02_c2/include/c2_frame.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/c2_frame.o: ../02_c2/src/c2_frame.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto_gcm.o: ../00_crypto/src/crypto_gcm.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto_hash.o: ../00_crypto/src/crypto_hash.c | $(BUILD)
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

$(BUILD):
	mkdir -p $(BUILD)

# 洋葱测试同时依赖密码学目标（层密钥 HKDF + 层加密 GCM）
$(BUILD)/test_onion: tests/test_onion.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB)

test: $(BUILD)/test_mesh $(BUILD)/test_qos $(BUILD)/test_chain $(BUILD)/test_e2ee $(BUILD)/test_route $(BUILD)/test_onion
	./$(BUILD)/test_mesh
	./$(BUILD)/test_qos
	./$(BUILD)/test_chain
	./$(BUILD)/test_e2ee
	./$(BUILD)/test_route
	./$(BUILD)/test_onion

inspect: all
	@echo "== 符号表（14_p2p 公开接口） =="
	@nm -g --defined-only $(BUILD)/libp2p.a | awk '$$2=="T"{print "  "$$3}'

clean:
	rm -rf $(BUILD)

.PHONY: all test clean inspect
