# DAYANJING v4 — 17_loader Makefile

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -Iinclude -I../00_crypto/include
LDFLAGS ?=

BUILD   := build
CRYPTDIR := ../00_crypto
CRYPT_SRC := $(CRYPTDIR)/src/crypto_gcm.c $(CRYPTDIR)/src/crypto_hash.c
CRYPT_OBJ := $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o

SRC     := src/pe.c src/reflect.c src/shellcode.c
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o) $(CRYPT_OBJ)
TESTSRC := tests/test_loader.c
TESTBIN := $(BUILD)/test_loader

.PHONY: all test clean inspect

all: $(TESTBIN)

$(BUILD):
	mkdir -p $(BUILD)

$(CRYPT_OBJ): | $(BUILD)
	$(CC) $(CFLAGS) -c $(CRYPTDIR)/src/$(basename $(@F)).c -o $@

$(BUILD)/%.o: src/%.c include/loader.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTBIN): $(OBJ) $(TESTSRC) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(TESTSRC) -o $@ $(LDFLAGS)

test: $(TESTBIN)
	./$(TESTBIN)

clean:
	rm -rf $(BUILD)

inspect: $(TESTBIN)
	@echo "== 敏感字符串扫描（应为空） =="
	@strings $(TESTBIN) | grep -Ei "openssl|/home/|/Users/|passwd" || echo "  (无)"
	@echo "== 导出符号 =="
	@nm -g --defined-only $(BUILD)/pe.o | awk '{print "  "$$3}'
	@nm -g --defined-only $(BUILD)/reflect.o | awk '{print "  "$$3}'
	@nm -g --defined-only $(BUILD)/shellcode.o | awk '{print "  "$$3}'
