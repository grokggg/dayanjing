CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libui.a

$(BUILD)/libui.a: $(BUILD)/http.o
	ar rcs $@ $^

$(BUILD)/http.o: src/http.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_http: tests/test_http.c $(BUILD)/libui.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libui.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_http
	./$(BUILD)/test_http

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
