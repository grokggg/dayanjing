CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11 -fvisibility=hidden \
           -Iinclude -I../00_crypto/include -I../01_proto/include -I../02_c2/include
LDFLAGS ?= -L../00_crypto/build -L../01_proto/build -L../02_c2/build
LDLIBS  ?= -lcrypto -lproto -lc2 -lpthread

BUILD_DIR := build
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=build/%.o)
TESTS   := $(wildcard tests/test_*.c)
TEST_BINS := $(TESTS:tests/test_%.c=build/test_%)

AR := ar
RANLIB := ranlib

all: build/libserver.a

build/libserver.a: $(OBJECTS) | build
	$(AR) rcs $@ $^
	$(RANLIB) $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/test_%: tests/test_%.c build/libserver.a | build
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) build/libserver.a $(LDLIBS)

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "=== $$(basename $$t) ==="; ./$$t || exit 1; done

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: all test clean
