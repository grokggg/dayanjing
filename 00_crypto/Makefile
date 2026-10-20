# DAYANJING v3 — 00_crypto Makefile

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -std=c11
CFLAGS  += -Iinclude -D_GNU_SOURCE
LDFLAGS ?=

BUILD   := build
SRC     := src/crypto_gcm.c src/crypto_hash.c
HDR     := include/crypto_gcm.h include/crypto_hash.h

OBJS    := $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o

.PHONY: all clean test mkdirs inspect

all: mkdirs $(BUILD)/test_gcm $(BUILD)/test_hash

mkdirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_gcm: $(BUILD)/crypto_gcm.o tests/test_gcm.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) tests/test_gcm.c $(BUILD)/crypto_gcm.o -o $@ $(LDFLAGS)

$(BUILD)/test_hash: $(BUILD)/crypto_hash.o tests/test_hash.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) tests/test_hash.c $(BUILD)/crypto_hash.o -o $@ $(LDFLAGS)

test: all
	./$(BUILD)/test_gcm
	./$(BUILD)/test_hash

inspect: all
	@echo "== 敏感字符串扫描（应为空） =="
	@strings $(BUILD)/test_gcm $(BUILD)/test_hash \
	  | grep -Ei "crypto_layer|key_derivation|PSK|session" || echo "  (无明文敏感标识)"
	@echo "== 符号表 =="
	@nm -g --defined-only $(BUILD)/crypto_hash.o | awk '{print "  "$$3}'

clean:
	rm -rf $(BUILD)
