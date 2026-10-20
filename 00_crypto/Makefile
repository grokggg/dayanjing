# DAYANJING v3 — 00_crypto Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -std=c11
CFLAGS  += -Iinclude -D_GNU_SOURCE
LDFLAGS ?=

BUILD   := build
SRC     := src/crypto_gcm.c
HDR     := include/crypto_gcm.h
TEST    := tests/test_gcm.c

TARGET  := $(BUILD)/test_gcm
OBJS    := $(BUILD)/crypto_gcm.o

.PHONY: all clean test mkdirs inspect run

all: mkdirs $(TARGET)

mkdirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(TEST) $(HDR) | mkdirs
	$(CC) $(CFLAGS) $(TEST) $(OBJS) -o $@ $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

inspect: $(TARGET)
	@echo "== 敏感字符串扫描（应为空） =="
	@strings $(TARGET) | grep -Ei "crypto_layer|key_derivation|PSK|session" || echo "  (无明文敏感标识)"
	@echo "== 汇编指令 =="
	@objdump -d $(TARGET) | grep -c "<aes128_encrypt_block>:" | xargs -I{} echo "  aes128_encrypt_block 出现 {} 次"

clean:
	rm -rf $(BUILD)
