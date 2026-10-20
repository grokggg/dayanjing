CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libserver.a

$(BUILD)/libserver.a: $(BUILD)/session.o
	ar rcs $@ $^

$(BUILD)/session.o: src/session.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_session: tests/test_session.c $(BUILD)/libserver.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libserver.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_session
	./$(BUILD)/test_session

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
