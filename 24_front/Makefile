# 24_front — 域前置 HTTP 层（建立在 25_tls 自研 TLS 之上）
CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
          -Iinclude -I../25_tls/include -I../00_crypto/include \
          -DFRONT_TLS_DATA="\"$(CURDIR)/../25_tls/tests/data\""
LDFLAGS =

BUILD   = build
TLS     = ../25_tls/src/bn.c ../25_tls/src/asn1.c ../25_tls/src/rsa.c \
          ../25_tls/src/x509.c ../25_tls/src/tls.c \
          ../25_tls/src/tls_server.c
CRYPTO  = ../00_crypto/src/crypto_gcm.c ../00_crypto/src/crypto_hash.c \
          ../00_crypto/src/crypto_x25519.c

SRCS    = src/front.c src/h2.c $(TLS) $(CRYPTO)

.PHONY: all clean test inspect testdata

# 本模块复用 25_tls 的测试夹具（FRONT_TLS_DATA 指向 ../25_tls/tests/data），
# 而该目录被 .gitignore 忽略、不入库。只构建/测试本模块时若夹具缺失，
# 症状是"证书校验失败"，排查会被引向本模块代码，而非"上游夹具没生成"。
# 故显式声明依赖，缺失即委托 25_tls 的生成器产出。
TLS_FIXTURES := ../25_tls/tests/data/leaf.pem ../25_tls/tests/data/ca.pem \
                ../25_tls/tests/data/leaf.key

$(TLS_FIXTURES):
	$(MAKE) -C ../25_tls testdata

# 默认目标必须是 all。此前文件里第一个非点目标是证书夹具规则，
# GNU make 于是把它当默认目标——裸 make 只生成夹具，一个测试都不构建，退出码还是 0。
# 与 agent_windows(upstream-deps) 同类，是该类问题的延续。
.DEFAULT_GOAL := all
all: $(TLS_FIXTURES) $(BUILD)/test_front $(BUILD)/test_h2 $(BUILD)/test_front_h2 \
     $(BUILD)/test_huffman $(BUILD)/dump_hpack $(BUILD)/test_front_real

testdata: $(TLS_FIXTURES)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_front: tests/test_front.c $(SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) -o $@ $(LDFLAGS)

$(BUILD)/dump_hpack: tests/dump_hpack.c src/h2.c $(TLS) $(CRYPTO) | $(BUILD)
	$(CC) $(CFLAGS) $< src/h2.c $(TLS) $(CRYPTO) -o $@ $(LDFLAGS)

$(BUILD)/test_h2: tests/test_h2.c src/h2.c $(TLS) $(CRYPTO) | $(BUILD)
	$(CC) $(CFLAGS) $< src/h2.c $(TLS) $(CRYPTO) -o $@ $(LDFLAGS)

$(BUILD)/test_front_h2: tests/test_front_h2.c $(SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) -o $@ $(LDFLAGS)

$(BUILD)/test_huffman: tests/test_huffman.c $(SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) -o $@ $(LDFLAGS)

$(BUILD)/test_front_real: tests/test_front_real.c $(SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) -o $@ $(LDFLAGS)

test: $(TLS_FIXTURES) $(BUILD)/test_front $(BUILD)/test_h2 $(BUILD)/test_front_h2 \
      $(BUILD)/test_huffman $(BUILD)/test_front_real
	@timeout 300 $(BUILD)/test_front
	@timeout 120 $(BUILD)/test_h2
	@timeout 120 $(BUILD)/test_front_h2
	@HF_CASES=$(CURDIR)/tests/data/hf_cases.txt timeout 120 $(BUILD)/test_huffman || \
	  ([ $$? -eq 77 ] && echo "[SKIP] huffman 交叉验证跳过" && exit 0)
	@timeout 300 $(BUILD)/test_front_real

inspect: $(BUILD)/test_front
	@echo "--- dynamic deps ---"; ldd $(BUILD)/test_front | grep -Ei "ssl|crypto" || echo "none"
	@echo "--- third-party symbols ---"; nm -u $(BUILD)/test_front | grep -Ei "EVP_|SSL_|dlopen|dlsym" || echo "none"
	@echo "--- sensitive strings ---"; strings $(BUILD)/test_front | grep -Ei "openssl|/home/|/Users/|/etc/passwd" || echo "none"

# 跨实现交叉验证：需要 python-hpack，未安装时脚本返回 77（SKIP，不算失败）
xcheck: $(BUILD)/dump_hpack
	@$(BUILD)/dump_hpack | python3 scripts/hpack_xcheck.py || \
	  ([ $$? -eq 77 ] && echo "[SKIP] 交叉验证跳过" && exit 0)

clean:
	rm -rf $(BUILD)
