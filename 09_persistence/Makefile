CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build
all: $(BUILD)/libpersist.a $(BUILD)/test_persist $(BUILD)/test_enum \
     $(BUILD)/test_persist_partial $(BUILD)/test_persist_user
$(BUILD):
	mkdir -p $(BUILD)
$(BUILD)/persist.o: src/persist.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/libpersist.a: $(BUILD)/persist.o
	ar rcs $@ $^
$(BUILD)/test_persist: tests/test_persist.c $(BUILD)/libpersist.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libpersist.a
$(BUILD)/test_enum: tests/test_enum.c $(BUILD)/libpersist.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libpersist.a
$(BUILD)/test_persist_partial: tests/test_persist_partial.c $(BUILD)/libpersist.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libpersist.a
$(BUILD)/test_persist_user: tests/test_persist_user.c $(BUILD)/libpersist.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libpersist.a
test: all
	./$(BUILD)/test_persist
	./$(BUILD)/test_enum
	./$(BUILD)/test_persist_partial
	./$(BUILD)/test_persist_user
clean:
	rm -rf $(BUILD)
