# DAYANJING v3 — 02_c2 Makefile
#
# 依赖：00_crypto 的 crypto_hash.o（SHA-256/HMAC/HKDF）

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -std=c11
CFLAGS  += -Iinclude -I../00_crypto/include
LDFLAGS ?=

BUILD   := build
HDR     := include/c2.h ../00_crypto/include/crypto_hash.h
TEST    := tests/test_c2.c

.PHONY: all clean test mkdirs inspect

all: mkdirs $(BUILD)/test_c2

mkdirs:
	@mkdir -p $(BUILD)

$(BUILD)/crypto_hash.o: ../00_crypto/src/crypto_hash.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/c2.o: src/c2.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_c2: $(BUILD)/c2.o $(BUILD)/crypto_hash.o $(TEST) $(HDR) | mkdirs
	$(CC) $(CFLAGS) $(TEST) $(BUILD)/c2.o $(BUILD)/crypto_hash.o -o $@ $(LDFLAGS)

test: $(BUILD)/test_c2
	./$(BUILD)/test_c2

inspect: $(BUILD)/test_c2
	@echo "== 符号表（c2 公开接口） =="
	@nm -g --defined-only $(BUILD)/c2.o | awk '{print "  "$$3}'
	@echo "== 敏感字符串扫描 =="
	@strings $(BUILD)/test_c2 | grep -Ei "implant-alpha|PSK|master" || echo "  (仅测试常量，无运行时敏感标识)"

clean:
	rm -rf $(BUILD)
