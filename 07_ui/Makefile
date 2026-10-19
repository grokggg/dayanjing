CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11 -fvisibility=hidden \
           -Iinclude -Iinclude \
           -I../00_crypto/include -I../01_proto/include \
           -I../02_c2/include -I../03_transport/include \
           -I../05_server/include
LDFLAGS ?= -L../00_crypto/build -L../01_proto/build -L../02_c2/build \
           -L../03_transport/build -L../05_server/build
LDLIBS  ?= -lcrypto -lproto -lc2 -ltransport -lserver -lpthread

BUILD_DIR := build
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=build/%.o)
TESTS   := $(wildcard tests/test_*.c)
TEST_BINS := $(TESTS:tests/%.c=build/%)

AR := ar
RANLIB := ranlib

.PHONY: all test clean

all: build/libui.a

build/libui.a: $(OBJECTS) | build
	$(AR) rcs $@ $^
	$(RANLIB) $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/test_%: tests/test_%.c build/libui.a | build
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) build/libui.a $(LDLIBS)

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "=== $$(basename $$t) ==="; \
		./$$t || exit 1; \
	done

build:
	mkdir -p build

clean:
	rm -rf build
