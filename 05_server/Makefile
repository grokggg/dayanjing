CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libserver.a $(BUILD)/test_session $(BUILD)/test_loop

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/session.o: src/session.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/loop.o: src/loop.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/libserver.a: $(BUILD)/session.o $(BUILD)/loop.o
	ar rcs $@ $^

$(BUILD)/test_session: tests/test_session.c $(BUILD)/libserver.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libserver.a

$(BUILD)/test_loop: tests/test_loop.c $(BUILD)/libserver.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libserver.a

test: all
	./$(BUILD)/test_session
	./$(BUILD)/test_loop

clean:
	rm -rf $(BUILD)
