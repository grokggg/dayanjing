CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libevasion.a

$(BUILD)/libevasion.a: $(BUILD)/evasion.o
	ar rcs $@ $^

$(BUILD)/evasion.o: src/evasion.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_evasion: tests/test_evasion.c $(BUILD)/libevasion.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libevasion.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_evasion
	./$(BUILD)/test_evasion

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
