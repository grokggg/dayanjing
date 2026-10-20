CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude
BUILD := build

all: $(BUILD)/libtransport.a $(BUILD)/test_transport $(BUILD)/test_net $(BUILD)/test_dnstun $(BUILD)/test_dnspub

$(BUILD)/libtransport.a: $(BUILD)/transport.o $(BUILD)/net.o $(BUILD)/dnstun.o
	ar rcs $@ $^

$(BUILD)/transport.o: src/transport.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/net.o: src/net.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/dnstun.o: src/dnstun.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_transport: tests/test_transport.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/test_net: tests/test_net.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/test_dnstun: tests/test_dnstun.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD)/test_dnspub: tests/test_dnspub.c $(BUILD)/libtransport.a | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtransport.a

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_transport $(BUILD)/test_net $(BUILD)/test_dnstun
	./$(BUILD)/test_transport
	./$(BUILD)/test_net
	./$(BUILD)/test_dnstun

clean:
	rm -rf $(BUILD)
