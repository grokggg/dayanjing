# 25_tls — 自研 TLS 1.2 客户端
# 测试二进制统一落在 build/，与仓库其它模块一致（全仓回归脚本按此约定查找）。
CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
          -Iinclude -I../00_crypto/include \
          -DTLS_TESTDATA="\"$(CURDIR)/tests/data\""
LDFLAGS =

BUILD   = build
CRYPTO  = ../00_crypto/src/crypto_gcm.c \
          ../00_crypto/src/crypto_hash.c \
          ../00_crypto/src/crypto_x25519.c

SRCS    = src/bn.c src/asn1.c src/rsa.c src/x509.c src/tls.c src/tls_server.c
OBJS    = $(SRCS:.c=.o) $(CRYPTO:.c=.o)

TESTS   = $(BUILD)/test_bn $(BUILD)/test_asn1 $(BUILD)/test_x509 $(BUILD)/test_tls \
          $(BUILD)/test_tls_srv

.PHONY: all clean test inspect

all: $(TESTS)

$(BUILD):
	mkdir -p $(BUILD)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_bn: tests/test_bn.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_asn1: tests/test_asn1.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_x509: tests/test_x509.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_tls: tests/test_tls.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/test_tls_srv: tests/test_tls_srv.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

# 素材由 OpenSSL 生成，用于跨实现交叉验证；缺失时先跑 scripts/gen_testdata.sh
testdata:
	sh scripts/gen_testdata.sh

test: $(TESTS)
	@fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		timeout 300 $$t || fail=1; \
	done; \
	exit $$fail

inspect: $(TESTS)
	@echo "--- dynamic deps ---"; ldd $(BUILD)/test_tls | grep -Ei "ssl|crypto" || echo "none"
	@echo "--- third-party symbols ---"; nm -u $(BUILD)/test_tls | grep -Ei "EVP_|SSL_|dlopen|dlsym" || echo "none"
	@echo "--- sensitive strings ---"; strings $(BUILD)/test_tls | grep -Ei "openssl|/home/|/Users/|/etc/passwd" || echo "none"

clean:
	rm -rf $(BUILD) $(OBJS)
