CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libtransport.a

$(BUILD)/libtransport.a: $(BUILD)/transport.o
	ar rcs $@ $^

$(BUILD)/transport.o: src/transport.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_transport: tests/test_transport.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_transport
	./$(BUILD)/test_transport

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
