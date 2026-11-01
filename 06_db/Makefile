CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build
all: $(BUILD)/libdb.a $(BUILD)/test_db $(BUILD)/test_index
$(BUILD):
	mkdir -p $(BUILD)
$(BUILD)/db.o: src/db.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/index.o: src/index.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/libdb.a: $(BUILD)/db.o $(BUILD)/index.o
	ar rcs $@ $^
$(BUILD)/test_db: tests/test_db.c $(BUILD)/libdb.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libdb.a
$(BUILD)/test_index: tests/test_index.c $(BUILD)/libdb.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libdb.a
test: all
	./$(BUILD)/test_db
	./$(BUILD)/test_index
clean:
	rm -rf $(BUILD)
