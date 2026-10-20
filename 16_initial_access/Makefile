CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS ?=

BUILD   := build
SRC     := $(wildcard src/*.c)
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o)
TESTSRC := tests/test_initial.c
TESTBIN := $(BUILD)/test_initial

all: $(TESTBIN)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTBIN): $(OBJ) $(TESTSRC) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(TESTSRC) -o $@ $(LDFLAGS)

$(BUILD):
	mkdir -p $(BUILD)

test: $(TESTBIN)
	./$(TESTBIN)

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
