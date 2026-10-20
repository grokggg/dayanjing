CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -I../08_lateral/include -I../02_c2/include -I../00_crypto/include
LATLIB  := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o
BUILD   := build

# 02_c2 的帧层 AEAD + 00_crypto 的 GCM/SHA（E2EE 隧道依赖，密码学只此一处实现）
# crypto_hash.o 提供 HKDF，供 p2p_tunnel_init_from_session 从会话密钥派生隧道密钥
C2OBJS  := $(BUILD)/c2_frame.o $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o

all: $(BUILD)/libp2p.a

$(BUILD)/libp2p.a: $(BUILD)/mesh.o $(BUILD)/relay.o $(BUILD)/crypto.o
	ar rcs $@ $^

$(BUILD)/mesh.o: src/mesh.c include/p2p.h | $(BUILD)
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

$(BUILD)/test_mesh: tests/test_mesh.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD)/test_chain: tests/test_chain.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD)/test_e2ee: tests/test_e2ee.c $(BUILD)/libp2p.a $(C2OBJS)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(C2OBJS) $(LATLIB)

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_mesh $(BUILD)/test_chain $(BUILD)/test_e2ee
	./$(BUILD)/test_mesh
	./$(BUILD)/test_chain
	./$(BUILD)/test_e2ee

inspect: all
	@echo "== 符号表（14_p2p 公开接口） =="
	@nm -g --defined-only $(BUILD)/libp2p.a | awk '$$2=="T"{print "  "$$3}'

clean:
	rm -rf $(BUILD)

.PHONY: all test clean inspect
