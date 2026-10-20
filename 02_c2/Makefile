# DAYANJING v3 — 02_c2 Makefile
#
# 依赖：00_crypto（crypto_hash.o / crypto_gcm.o）
# e2e 额外依赖：agent_windows（cam_jpeg.o / cam_mock.o）

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -std=c11
CFLAGS  += -Iinclude -I../00_crypto/include -I../agent_windows/include
LDFLAGS ?=

BUILD   := build
HDR     := include/c2.h include/c2_frame.h ../00_crypto/include/crypto_hash.h \
           ../00_crypto/include/crypto_gcm.h

.PHONY: all clean test mkdirs inspect e2e

all: mkdirs $(BUILD)/test_c2 $(BUILD)/test_c2_frame

mkdirs:
	@mkdir -p $(BUILD)

# ---- 依赖模块目标文件 ----
$(BUILD)/crypto_hash.o: ../00_crypto/src/crypto_hash.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto_gcm.o: ../00_crypto/src/crypto_gcm.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/c2.o: src/c2.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/c2_frame.o: src/c2_frame.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

# ---- 测试 ----
$(BUILD)/test_c2: $(BUILD)/c2.o $(BUILD)/crypto_hash.o tests/test_c2.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) tests/test_c2.c $(BUILD)/c2.o $(BUILD)/crypto_hash.o -o $@ $(LDFLAGS)

$(BUILD)/test_c2_frame: $(BUILD)/c2_frame.o $(BUILD)/crypto_gcm.o tests/test_c2_frame.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) tests/test_c2_frame.c $(BUILD)/c2_frame.o $(BUILD)/crypto_gcm.o -o $@ $(LDFLAGS)

test: all
	./$(BUILD)/test_c2
	./$(BUILD)/test_c2_frame

# ---- 端到端：采集 -> 封装 -> 落盘（供 Python 侧解封验证） ----
$(BUILD)/cam_jpeg.o: ../agent_windows/src/cam_jpeg.c | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cam_mock.o: ../agent_windows/src/cam_mock.c | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/e2e_capture: tools/e2e_capture.c $(BUILD)/c2.o $(BUILD)/c2_frame.o \
                      $(BUILD)/crypto_hash.o $(BUILD)/crypto_gcm.o \
                      $(BUILD)/cam_jpeg.o $(BUILD)/cam_mock.o $(HDR) | mkdirs
	$(CC) $(CFLAGS) tools/e2e_capture.c $(BUILD)/c2.o $(BUILD)/c2_frame.o \
	      $(BUILD)/crypto_hash.o $(BUILD)/crypto_gcm.o \
	      $(BUILD)/cam_jpeg.o $(BUILD)/cam_mock.o -o $@ $(LDFLAGS) -lm

e2e: $(BUILD)/e2e_capture
	./$(BUILD)/e2e_capture

inspect: all
	@echo "== 符号表（c2 / c2_frame 公开接口） =="
	@nm -g --defined-only $(BUILD)/c2.o $(BUILD)/c2_frame.o | awk '{print "  "$$3}'

clean:
	rm -rf $(BUILD)
