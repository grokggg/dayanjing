CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build
all: $(BUILD)/libagent.a $(BUILD)/test_agent $(BUILD)/test_loop
$(BUILD):
	mkdir -p $(BUILD)
$(BUILD)/agent.o: src/agent.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/loop.o: src/loop.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/libagent.a: $(BUILD)/agent.o $(BUILD)/loop.o
	ar rcs $@ $^
$(BUILD)/test_agent: tests/test_agent.c $(BUILD)/libagent.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libagent.a
$(BUILD)/test_loop: tests/test_loop.c $(BUILD)/libagent.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libagent.a
test: all
	./$(BUILD)/test_agent
	./$(BUILD)/test_loop
clean:
	rm -rf $(BUILD)
