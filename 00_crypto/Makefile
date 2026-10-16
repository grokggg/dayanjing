# 00_crypto/ Makefile
# 自包含密码学库：ChaCha20 / Poly1305 / ChaCha20-Poly1305 AEAD / HMAC-SHA256 / HKDF-SHA256

CC      ?= gcc
AR      ?= ar
RANLIB  ?= ranlib

# 严格编译：与 06_db/、11_edr_bypass/ 保持一致的检查强度
CFLAGS  ?= -O2 -std=c11 -D_GNU_SOURCE \
           -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wcast-align -Wpointer-arith \
           -Wno-unused-parameter \
           -Wconversion -Wsign-conversion \
           -fvisibility=hidden -fstack-protector-strong \
           -Iinclude

LDFLAGS ?=

BUILD := build
LIB   := $(BUILD)/libcrypto.a
SO    := $(BUILD)/libcrypto.so

# 对象文件（按依赖顺序排列，让链接器能正确解析）
OBJS  := $(BUILD)/crypto_mem.o \
         $(BUILD)/crypto_sha256.o \
         $(BUILD)/crypto_hmac.o \
         $(BUILD)/crypto_chacha20.o \
         $(BUILD)/crypto_poly1305.o \
         $(BUILD)/crypto_aead.o \
         $(BUILD)/crypto_session.o

# 测试二进制
TESTS := test_rng test_sha256 test_hmac test_kdf test_chacha20 \
         test_poly1305 test_aead test_session test_e2e

.PHONY: all clean test mkdirs test-one strip-audit strings-audit

all: mkdirs $(LIB) $(SO)

mkdirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/crypto.h | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(SO): $(OBJS)
	$(CC) -shared -o $@ $^

# ---- 测试 ----
# 默认链接静态库（build/libcrypto.a），避免运行时依赖 LD_LIBRARY_PATH
test: all
	@for t in $(TESTS); do \
		echo "=== building $$t ==="; \
		$(CC) $(CFLAGS) tests/$$t.c $(BUILD)/libcrypto.a -o $(BUILD)/$$t || exit 1; \
	done
	@for t in $(TESTS); do \
		echo "=== running $$t ==="; \
		$(BUILD)/$$t || exit 1; \
	done

# 单独跑某个测试：make test-one T=test_aead
test-one: all
	$(CC) $(CFLAGS) tests/$(T).c $(BUILD)/libcrypto.a -o $(BUILD)/$(T)
	$(BUILD)/$(T)

# ---- 二进制审计（与 06_db/ 保持一致的验收口径）----
strip-audit: $(LIB)
	cp $(LIB) $(BUILD)/libcrypto_stripped.a
	strip --strip-debug $(BUILD)/libcrypto_stripped.a
	@echo "--- 全局符号（应为 0）---"
	nm -g $(BUILD)/libcrypto_stripped.a 2>/dev/null | grep -vE '^($$|        U )' | grep -E ' [A-Z] ' || echo "(无外部符号)"
	@echo "--- 公开 API 是否仍可链接 ---"
	$(CC) -c tests/test_aead.c -o $(BUILD)/_t.o 2>/dev/null
	ld -o /dev/null -lc $(BUILD)/_t.o $(BUILD)/libcrypto_stripped.a 2>&1 | head -5 || true

strings-audit: $(LIB)
	@echo "--- 字符串扫描（应无敏感明文）---"
	strings $(LIB) | grep -Ei 'expand|key|nonce|poly|chacha|hmac|sha' | head || echo "(无敏感字符串)"

clean:
	rm -rf $(BUILD)
	rm -f *.o *.a
	rm -f test_*.db test_*.db-* test_vectors.h
