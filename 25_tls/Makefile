# 25_tls — 自研 TLS 1.2 客户端
CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
          -Iinclude -I../00_crypto/include
LDFLAGS =

CRYPTO  = ../00_crypto/src/crypto_gcm.c \
          ../00_crypto/src/crypto_hash.c \
          ../00_crypto/src/crypto_x25519.c

SRCS    = src/bn.c src/asn1.c src/rsa.c src/x509.c src/tls.c
OBJS    = $(SRCS:.c=.o) $(CRYPTO:.c=.o)

TESTS   = tests/test_bn tests/test_asn1 tests/test_x509 tests/test_tls

.PHONY: all clean test inspect

all: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_bn: tests/test_bn.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

tests/test_asn1: tests/test_asn1.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

tests/test_x509: tests/test_x509.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

tests/test_tls: tests/test_tls.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@ $(LDFLAGS)

test: $(TESTS)
	@fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || fail=1; \
	done; \
	exit $$fail

inspect: tests/test_tls
	@echo "--- dynamic deps ---"; ldd tests/test_tls | grep -Ei "ssl|crypto" || echo "none"
	@echo "--- third-party symbols ---"; nm -u tests/test_tls | grep -Ei "EVP_|SSL_|dlopen|dlsym" || echo "none"
	@echo "--- sensitive strings ---"; strings tests/test_tls | grep -Ei "openssl|/home/|/Users/|/etc/passwd" || echo "none"

clean:
	rm -f $(OBJS) $(TESTS)
