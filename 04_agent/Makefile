CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11 -fvisibility=hidden \
           -Iinclude -I../00_crypto/include
AR      ?= ar
RANLIB  ?= ranlib

BUILD_DIR := build
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=build/%.o)
TESTS   := $(wildcard tests/test_*.c)
TEST_BINS := $(TESTS:tests/test_%.c=build/test_%)

LIB := build/libagent.a

.SUFFIXES:
.SECONDARY:

all: $(LIB)

$(LIB): $(OBJECTS) | build
	$(AR) rcs $@ $^
	$(RANLIB) $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%: tests/test_%.c $(LIB) | build
	$(CC) $(CFLAGS) $< -o $@ $(LIB) ../00_crypto/build/libcrypto.a -lpthread

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "=== $$(basename $$t) ==="; ./$$t || exit 1; done

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: all test clean
