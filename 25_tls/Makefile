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
          $(BUILD)/test_tls_srv $(BUILD)/test_tls_ch

# 跨实现互操作工具：把服务端/客户端挂到真实 TCP 端口，与 OpenSSL 的
# s_client / s_server 对连。它们不是单元测试，由 scripts/interop_openssl.sh 驱动。
TOOLS   = $(BUILD)/tls_srv_tcp $(BUILD)/tls_cli_tcp

.PHONY: all clean test inspect

all: $(TESTS) $(TOOLS)

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

# 真实 ClientHello 解析器健壮性：必须进默认目标，否则又是一个"写了没接"的测试
$(BUILD)/test_tls_ch: tests/test_tls_ch.c tests/clienthello_default.h $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/tls_srv_tcp: tools/tls_srv_tcp.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/tls_cli_tcp: tools/tls_cli_tcp.c $(OBJS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

# 素材由 OpenSSL 生成，用于跨实现交叉验证；缺失时先跑 scripts/gen_testdata.sh
testdata:
	sh scripts/gen_testdata.sh

# interop 必须与单元测试走同一条入口：它是唯一能证明"符合协议"的检查，
# 只放在文档里的话迟早没人跑。缺 openssl 时跳过而不是失败——
# 不能让环境差异把"没验证"伪装成"验证通过"，所以跳过要显式打印出来。
test: $(TESTS) $(TOOLS)
	@fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		timeout 300 $$t || fail=1; \
	done; \
	if command -v openssl >/dev/null 2>&1; then \
		echo "=== interop A (自研服务端 <- OpenSSL) ==="; \
		sh scripts/interop_openssl.sh A || fail=1; \
		echo "=== interop B (自研客户端 -> OpenSSL) ==="; \
		sh scripts/interop_openssl.sh B || fail=1; \
	else \
		echo "=== interop SKIPPED: 未找到 openssl（未验证，不是通过）==="; \
	fi; \
	exit $$fail

inspect: $(TESTS)
	@echo "--- dynamic deps ---"; ldd $(BUILD)/test_tls | grep -Ei "ssl|crypto" || echo "none"
	@echo "--- third-party symbols ---"; nm -u $(BUILD)/test_tls | grep -Ei "EVP_|SSL_|dlopen|dlsym" || echo "none"
	@echo "--- sensitive strings ---"; strings $(BUILD)/test_tls | grep -Ei "openssl|/home/|/Users/|/etc/passwd" || echo "none"

interop: $(TOOLS)
	sh scripts/interop_openssl.sh

clean:
	rm -rf $(BUILD) $(OBJS)
