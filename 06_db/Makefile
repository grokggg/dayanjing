CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libdb.a

$(BUILD)/libdb.a: $(BUILD)/db.o
	ar rcs $@ $^

$(BUILD)/db.o: src/db.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_db: tests/test_db.c $(BUILD)/libdb.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libdb.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_db
	./$(BUILD)/test_db

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
