CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Iinclude
LDFLAGS ?=

SRC_DIR := src
TST_DIR := tests
BUILD   := build

LIB_SRCS := $(SRC_DIR)/frame.c
LIB_OBJ  := $(LIB_SRCS:$(SRC_DIR)/%.c=$(BUILD)/%.o)

TST_SRC  := $(TST_DIR)/test_frame.c
TST_OBJ  := $(TST_SRC:$(TST_DIR)/%.c=$(BUILD)/%.o)
TST_BIN  := $(BUILD)/test_frame

.PHONY: all clean test
all: $(TST_BIN)

$(BUILD)/%.o: $(SRC_DIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: $(TST_DIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TST_BIN): $(LIB_OBJ) $(TST_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

$(BUILD):
	mkdir -p $(BUILD)

test: $(TST_BIN)
	./$(TST_BIN)

clean:
	rm -rf $(BUILD)
