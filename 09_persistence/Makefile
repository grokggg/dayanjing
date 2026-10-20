CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build
all: $(BUILD)/libpersist.a $(BUILD)/test_persist $(BUILD)/test_enum
$(BUILD):
	mkdir -p $(BUILD)
$(BUILD)/persist.o: src/persist.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/enum.o: src/enum.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/libpersist.a: $(BUILD)/persist.o $(BUILD)/enum.o
	ar rcs $@ $^
$(BUILD)/test_persist: tests/test_persist.c $(BUILD)/libpersist.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libpersist.a
$(BUILD)/test_enum: tests/test_enum.c $(BUILD)/libpersist.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libpersist.a
test: all
	./$(BUILD)/test_persist
	./$(BUILD)/test_enum
clean:
	rm -rf $(BUILD)
