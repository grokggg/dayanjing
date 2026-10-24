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

.PHONY: all clean test inspect

all: $(BUILD)/test_front $(BUILD)/test_h2 $(BUILD)/test_front_h2 $(BUILD)/test_huffman \
     $(BUILD)/dump_hpack $(BUILD)/test_front_real

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

test: $(BUILD)/test_front $(BUILD)/test_h2 $(BUILD)/test_front_h2 \
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
