# DAYANJING v4 — 18_privilege Makefile

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CFLAGS  += -Iinclude

BUILD   := build

SRC     := src/version.c src/kernel.c src/sudo.c src/polkit.c src/suid.c
OBJ     := $(SRC:src/%.c=$(BUILD)/%.o)
TESTSRC := tests/test_privilege.c
TESTBIN := $(BUILD)/test_privilege

.PHONY: all test clean inspect

all: $(TESTBIN)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/privilege.h | $(BUILD)
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
