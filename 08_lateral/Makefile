CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build
LDLIBS ?=

all: $(BUILD)/liblateral.a

$(BUILD)/liblateral.a: $(BUILD)/lateral.o $(BUILD)/proxy.o
	ar rcs $@ $^

$(BUILD)/lateral.o: src/lateral.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/proxy.o: src/proxy.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_lateral: tests/test_lateral.c $(BUILD)/liblateral.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/liblateral.a $(LDLIBS)

$(BUILD)/test_proxy: tests/test_proxy.c $(BUILD)/liblateral.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/liblateral.a $(LDLIBS)

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_lateral $(BUILD)/test_proxy
	./$(BUILD)/test_lateral
	./$(BUILD)/test_proxy

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
