# 02_c2/Makefile
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11 -fvisibility=hidden \
           -Iinclude -I../00_crypto/include -I../01_proto/include
LDFLAGS ?= -L../00_crypto/build -L../01_proto/build
LDLIBS  ?= -lcrypto -lproto -lpthread

BUILD_DIR := build
SRC_DIR   := src
TEST_DIR  := tests

CRYPTO_LIB := ../00_crypto/build/libcrypto.a
PROTO_LIB  := ../01_proto/build/libproto.a

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TESTS   := $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS := $(TESTS:$(TEST_DIR)/%.c=$(BUILD_DIR)/%)

.PHONY: all clean test

all: $(BUILD_DIR)/libc2.a

$(BUILD_DIR)/libc2.a: $(OBJECTS) | $(BUILD_DIR)
	$(AR) rcs $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(BUILD_DIR)/libc2.a | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(BUILD_DIR)/libc2.a $(PROTO_LIB) $(CRYPTO_LIB) $(LDLIBS)

test: $(TEST_BINS)
	@pass=0; fail=0; \
	for t in $(TEST_BINS); do \
		echo "=== $$(basename $$t) ==="; \
		if ./$$t > /dev/null 2>&1; then \
			pass=$$((pass+1)); echo "[PASS] $$(basename $$t)"; \
		else \
			fail=$$((fail+1)); echo "[FAIL] $$(basename $$t)"; \
			./$$t; \
		fi; \
	done; \
	echo "=============================="; \
	echo "PASS: $$pass / FAIL: $$fail"; \
	if [ $$fail -ne 0 ]; then exit 1; fi

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

# 依赖：先构建下层库
$(CRYPTO_LIB):
	$(MAKE) -C ../00_crypto all

$(PROTO_LIB):
	$(MAKE) -C ../01_proto all
