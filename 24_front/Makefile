# 24_front — 域前置 HTTP 层（建立在 25_tls 自研 TLS 之上）
CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
          -Iinclude -I../25_tls/include -I../00_crypto/include
LDFLAGS =

BUILD   = build
TLS     = ../25_tls/src/bn.c ../25_tls/src/asn1.c ../25_tls/src/rsa.c \
          ../25_tls/src/x509.c ../25_tls/src/tls.c
CRYPTO  = ../00_crypto/src/crypto_gcm.c ../00_crypto/src/crypto_hash.c \
          ../00_crypto/src/crypto_x25519.c

SRCS    = src/front.c $(TLS) $(CRYPTO)

.PHONY: all clean test inspect

all: $(BUILD)/test_front

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_front: tests/test_front.c $(SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $< $(SRCS) -o $@ $(LDFLAGS)

test: $(BUILD)/test_front
	@timeout 300 $(BUILD)/test_front

inspect: $(BUILD)/test_front
	@echo "--- dynamic deps ---"; ldd $(BUILD)/test_front | grep -Ei "ssl|crypto" || echo "none"
	@echo "--- third-party symbols ---"; nm -u $(BUILD)/test_front | grep -Ei "EVP_|SSL_|dlopen|dlsym" || echo "none"
	@echo "--- sensitive strings ---"; strings $(BUILD)/test_front | grep -Ei "openssl|/home/|/Users/|/etc/passwd" || echo "none"

clean:
	rm -rf $(BUILD)
