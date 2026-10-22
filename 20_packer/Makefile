# DAYANJING v4 — 20_packer Makefile

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -D_DEFAULT_SOURCE -Iinclude -I../00_crypto/include
LDFLAGS ?=

BUILD    := build
CRYPTDIR := ../00_crypto
CRYPT_SRC := $(CRYPTDIR)/src/crypto_gcm.c $(CRYPTDIR)/src/crypto_hash.c $(CRYPTDIR)/src/crypto_x25519.c
CRYPT_OBJ := $(BUILD)/crypto_gcm.o $(BUILD)/crypto_hash.o $(BUILD)/crypto_x25519.o

SRC     := src/lzss.c src/pack.c src/bind.c src/mexec.c \
           src/binding.c src/keyrot.c src/artifact.c src/poly.c \
           src/shaped.c
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o) $(CRYPT_OBJ)

TESTSRC := tests/test_packer.c
TESTBIN := $(BUILD)/test_packer

# 会话绑定单元测试
BINDSRC := tests/test_bind.c
BINDBIN := $(BUILD)/test_bind

# v3 制品单元测试：规范化绑定 + 纪元联动 + 前向保密
V3SRC := tests/test_v3.c
V3BIN := $(BUILD)/test_v3

# 多态引擎测试：真机执行 + 独立解密 + 跨构建区分度
POLYSRC := tests/test_poly.c
POLYBIN := $(BUILD)/test_poly

# Windows x64（MS x64 ABI）多态存根测试：真机执行 + 非易失寄存器保持
WPOLYSRC := tests/test_poly_win64.c
WPOLYBIN := $(BUILD)/test_poly_win64

# v4 多态头制品测试：跨构建逐字节取证 + v3 对照
SHAPEDSRC := tests/test_shaped.c
SHAPEDBIN := $(BUILD)/test_shaped

# mexec 真机验证目标：静态链接，避免 execveat 后再依赖动态加载器
TARGETSRC := tests/mexec_target.c
TARGETBIN := $(BUILD)/mexec_target

.PHONY: all test clean inspect static

# 注意：GNU make 在读取阶段即展开规则依赖，而 $(INTGBIN)/$(V3BIN) 定义在
# 本文件后部。此处写显式路径，避免展开成空导致目标被静默跳过。
all: $(BUILD)/test_packer $(BUILD)/test_bind \
     $(BUILD)/test_c2_packer $(BUILD)/test_v3 $(BUILD)/test_poly \
     $(BUILD)/test_poly_win64 $(BUILD)/test_shaped

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

$(BINDBIN): $(OBJ) $(BINDSRC) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(BINDSRC) -o $@ $(LDFLAGS)

$(V3BIN): $(OBJ) $(V3SRC) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(V3SRC) -o $@ $(LDFLAGS)

$(POLYBIN): $(OBJ) $(POLYSRC) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(POLYSRC) -o $@ $(LDFLAGS)

# v3 对照用例需要 pk_pack_core，故额外给 -Isrc
$(WPOLYBIN): $(OBJ) $(WPOLYSRC) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(WPOLYSRC) -o $@ $(LDFLAGS)

# v3 对照用例需要 pk_pack_core，故额外给 -Isrc
$(SHAPEDBIN): $(OBJ) $(SHAPEDSRC) | $(BUILD)
	$(CC) $(CFLAGS) -Isrc $(OBJ) $(SHAPEDSRC) -o $@ $(LDFLAGS)

# 与 02_c2 联编：真实会话密钥 -> 制品绑定 -> 解包
C2DIR   := ../02_c2
C2OBJ   := $(BUILD)/c2.o $(BUILD)/c2_frame.o
INTGSRC := tests/test_c2_packer.c
INTGBIN := $(BUILD)/test_c2_packer

$(BUILD)/c2.o: $(C2DIR)/src/c2.c | $(BUILD)
	$(CC) $(CFLAGS) -I$(C2DIR)/include -c $< -o $@

$(BUILD)/c2_frame.o: $(C2DIR)/src/c2_frame.c | $(BUILD)
	$(CC) $(CFLAGS) -I$(C2DIR)/include -c $< -o $@

$(INTGBIN): $(OBJ) $(C2OBJ) $(INTGSRC) | $(BUILD)
	$(CC) $(CFLAGS) -I$(C2DIR)/include $(OBJ) $(C2OBJ) $(INTGSRC) -o $@ $(LDFLAGS)

test: $(BUILD)/test_packer $(BUILD)/test_bind \
      $(BUILD)/test_c2_packer $(BUILD)/test_v3 $(BUILD)/test_poly \
      $(BUILD)/test_poly_win64 $(BUILD)/test_shaped
	./$(TESTBIN)
	./$(BINDBIN)
	./$(INTGBIN)
	./$(V3BIN)
	./$(POLYBIN)
	./$(WPOLYBIN)
	./$(SHAPEDBIN)

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
	@nm -g --defined-only $(BUILD)/poly.o  | awk '{print "  "$$3}'
	@nm -g --defined-only $(BUILD)/shaped.o | awk '{print "  "$$3}'
