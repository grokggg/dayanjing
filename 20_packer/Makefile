# DAYANJING v4 — 20_packer Makefile

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -D_DEFAULT_SOURCE -Iinclude -I../00_crypto/include
LDFLAGS ?=

BUILD    := build
CRYPTDIR := ../00_crypto
CRYPT_SRC := $(CRYPTDIR)/src/crypto_gcm.c $(CRYPTDIR)/src/crypto_hash.c
CRYPT_OBJ := $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o

SRC     := src/lzss.c src/pack.c src/mexec.c
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o) $(CRYPT_OBJ)

TESTSRC := tests/test_packer.c
TESTBIN := $(BUILD)/test_packer

# mexec 真机验证目标：静态链接，避免 execveat 后再依赖动态加载器
TARGETSRC := tests/mexec_target.c
TARGETBIN := $(BUILD)/mexec_target

.PHONY: all test clean inspect static

all: $(TESTBIN)

$(BUILD):
	mkdir -p $(BUILD)

$(CRYPT_OBJ): | $(BUILD)
	$(CC) $(CFLAGS) -c $(CRYPTDIR)/src/$(basename $(@F)).c -o $@

$(BUILD)/%.o: src/%.c include/packer.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGETBIN): $(TARGETSRC) | $(BUILD)
	$(CC) $(CFLAGS) -static $(TARGETSRC) -o $@ $(LDFLAGS)

# 测试进程以模块目录为 cwd 运行，依赖 build/mexec_target 存在
$(TESTBIN): $(OBJ) $(TESTSRC) $(TARGETBIN) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(TESTSRC) -o $@ $(LDFLAGS)

test: $(TESTBIN)
	./$(TESTBIN)

static: CFLAGS += -static
static: clean $(TESTBIN)
	@file $(TESTBIN) | sed 's/^/  /'

clean:
	rm -rf $(BUILD)

inspect: $(TESTBIN)
	@echo "== 动态依赖（应仅 libc） =="
	@ldd $(TESTBIN) 2>&1 | sed 's/^/  /' || true
	@echo "== 第三方符号扫描（应为空） =="
	@nm -D $(TESTBIN) 2>/dev/null | grep -Ei "EVP_|SSL_|dlopen|dlsym|zlib|inflate" || echo "  (无)"
	@echo "== 敏感字符串扫描（应为空） =="
	@strings $(TESTBIN) | grep -Ei "openssl|/home/|/Users/|/etc/passwd" || echo "  (无)"
	@echo "== 导出符号 =="
	@nm -g --defined-only $(BUILD)/lzss.o  | awk '{print "  "$$3}'
	@nm -g --defined-only $(BUILD)/pack.o  | awk '{print "  "$$3}'
	@nm -g --defined-only $(BUILD)/mexec.o | awk '{print "  "$$3}'
