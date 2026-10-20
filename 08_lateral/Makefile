CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/liblateral.a

$(BUILD)/liblateral.a: $(BUILD)/lateral.o
	ar rcs $@ $^

$(BUILD)/lateral.o: src/lateral.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_lateral: tests/test_lateral.c $(BUILD)/liblateral.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/liblateral.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_lateral
	./$(BUILD)/test_lateral

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
