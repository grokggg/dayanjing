CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build
all: $(BUILD)/libui.a $(BUILD)/test_http $(BUILD)/test_ui
$(BUILD):
	mkdir -p $(BUILD)
$(BUILD)/http.o: src/http.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/ui.o: src/ui.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/libui.a: $(BUILD)/http.o $(BUILD)/ui.o
	ar rcs $@ $^
$(BUILD)/test_http: tests/test_http.c $(BUILD)/libui.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libui.a
$(BUILD)/test_ui: tests/test_ui.c $(BUILD)/libui.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libui.a
test: all
	./$(BUILD)/test_http
	./$(BUILD)/test_ui
clean:
	rm -rf $(BUILD)
