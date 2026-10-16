CC      ?= gcc
CFLAGS  ?= -O2 -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
          -Wmissing-prototypes -Wcast-align -Wno-pointer-arith \
          -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fvisibility=hidden
CPPFLAGS = -Iinclude -I../00_crypto/include
CRYPTO_A = ../00_crypto/build/libcrypto.a

BUILD = build
LIB   = $(BUILD)/libproto.a
OBJS  = $(BUILD)/proto.o $(BUILD)/replay.o

.PHONY: all clean test staticcheck

all: $(LIB)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

$(BUILD):
	mkdir -p $(BUILD)

test: $(LIB) $(CRYPTO_A)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iinclude tests/test_proto.c $(LIB) $(CRYPTO_A) -o $(BUILD)/test_proto
	$(BUILD)/test_proto

staticcheck:
	nm -g --defined-only $(LIB) | awk '$$2=="T" {print $$3}' | sort
	! strings $(LIB) | grep -E 'PSK|secret|password' || true

clean:
	rm -rf $(BUILD)
