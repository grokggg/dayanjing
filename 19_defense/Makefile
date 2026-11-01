# DAYANJING v4 — 19_defense Makefile

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -Iinclude

BUILD   := build

SRC     := src/debug.c src/sandbox.c src/vm.c src/hook.c src/evade.c
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o)
TESTSRC := tests/test_defense.c
TESTBIN := $(BUILD)/test_defense

.PHONY: all test clean inspect

all: $(TESTBIN)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/defense.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTBIN): $(OBJ) $(TESTSRC) | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(TESTSRC) -o $@

test: $(TESTBIN)
	./$(TESTBIN)

clean:
	rm -rf $(BUILD)

inspect: $(TESTBIN)
	@echo "== 敏感字符串扫描（应为空） =="
	@strings $(TESTBIN) | grep -Ei "openssl|/home/|/Users/|passwd" || echo "  (无)"
	@echo "== 导出符号 =="
	@for o in $(OBJ); do nm -g --defined-only $$o | awk '{print "  "$$3}'; done
