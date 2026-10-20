CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libpersist.a

$(BUILD)/libpersist.a: $(BUILD)/persist.o
	ar rcs $@ $^

$(BUILD)/persist.o: src/persist.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_persist: tests/test_persist.c $(BUILD)/libpersist.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libpersist.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_persist
	./$(BUILD)/test_persist

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
