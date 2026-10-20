CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libagent.a

$(BUILD)/libagent.a: $(BUILD)/agent.o
	ar rcs $@ $^

$(BUILD)/agent.o: src/agent.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_agent: tests/test_agent.c $(BUILD)/libagent.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libagent.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_agent
	./$(BUILD)/test_agent

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
