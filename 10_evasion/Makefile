CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build
all: $(BUILD)/libevasion.a $(BUILD)/test_evasion $(BUILD)/test_sched
$(BUILD):
	mkdir -p $(BUILD)
$(BUILD)/evasion.o: src/evasion.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/sched.o: src/sched.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/libevasion.a: $(BUILD)/evasion.o $(BUILD)/sched.o
	ar rcs $@ $^
$(BUILD)/test_evasion: tests/test_evasion.c $(BUILD)/libevasion.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libevasion.a
$(BUILD)/test_sched: tests/test_sched.c $(BUILD)/libevasion.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libevasion.a
test: all
	./$(BUILD)/test_evasion
	./$(BUILD)/test_sched
clean:
	rm -rf $(BUILD)
