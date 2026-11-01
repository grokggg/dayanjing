# DAYANJING v4 — 23_lkm Makefile
# 内核态操作核心（版本自适应）
#
# 本层不加载模块、不需要内核头文件：所有操作表达为"给定偏移的裸内存读改"，
# 经 lkm_mem 回调完成，因此在用户态 mock 内存上即可逐字节断言。
# cred 偏移来自 22_kern 的运行时探测（/proc/kallsyms + /proc/kcore）。

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -D_DEFAULT_SOURCE -Iinclude -I../22_kern/include
LDFLAGS ?=

BUILD   := build
KERNDIR := ../22_kern

SRC     := src/lkm.c
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o)
BIN     := $(BUILD)/test_lkm

.PHONY: all test clean inspect static kern

all: $(BIN)

$(BUILD):
	mkdir -p $(BUILD)

# 22_kern 的对象：集成用例需要它解析真实符号与探测布局
kern:
	$(MAKE) -C $(KERNDIR) all

$(BUILD)/%.o: src/%.c include/lkm.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJ) tests/test_lkm.c | $(BUILD) kern
	$(CC) $(CFLAGS) $(OBJ) tests/test_lkm.c $(KERNDIR)/build/ksym.o \
	      $(KERNDIR)/build/kcore.o $(KERNDIR)/build/kern.o -o $@ $(LDFLAGS)

test: $(BIN)
	./$(BIN)

clean:
	rm -rf $(BUILD)

inspect: all
	@echo "--- 动态依赖 ---"
	@ldd $(BIN) | grep -cE 'libssl|libcrypto' || true
	@echo "--- 第三方符号 ---"
	@nm -D $(BIN) 2>/dev/null | grep -cE 'EVP_|SSL_|dlopen|dlsym' || true
	@echo "--- 敏感字符串 ---"
	@strings -a $(BIN) | grep -cE 'openssl|/home/|/Users/|/etc/passwd|github' || true

static: CFLAGS += -static
static: clean all
