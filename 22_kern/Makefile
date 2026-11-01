# DAYANJING v4 — 22_kern Makefile
# 内核符号解析 / 内核内存读取 / 运行时布局探测 / hook 方案
# 注意：本层全部运行在用户态，不加载模块、不修改内核。
#       kcore 需要 root 或 CAP_SYS_RAWIO；无权限时集成用例会 SKIP 而非造假。

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -D_DEFAULT_SOURCE -Iinclude
LDFLAGS ?=

BUILD   := build

SRC     := src/ksym.c src/kcore.c src/kern.c
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o)

# 解析器单测：用合成 kallsyms 文件，不依赖真实内核环境
KSYMBIN := $(BUILD)/test_ksym
# 集成测试：读真实 /proc/kallsyms 与 /proc/kcore
KERNBIN := $(BUILD)/test_kern

.PHONY: all test clean inspect static

all: $(KSYMBIN) $(KERNBIN)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/kern.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(KSYMBIN): $(OBJ) tests/test_ksym.c | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) tests/test_ksym.c -o $@ $(LDFLAGS)

$(KERNBIN): $(OBJ) tests/test_kern.c | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) tests/test_kern.c -o $@ $(LDFLAGS)

test: $(KSYMBIN) $(KERNBIN)
	./$(KSYMBIN)
	./$(KERNBIN)

clean:
	rm -rf $(BUILD)

inspect: all
	@echo "--- 动态依赖 ---"
	@ldd $(KERNBIN) | grep -cE 'libssl|libcrypto' || true
	@echo "--- 第三方符号 ---"
	@nm -D $(KERNBIN) 2>/dev/null | grep -cE 'EVP_|SSL_|dlopen|dlsym' || true

static: CFLAGS += -static
static: clean all
