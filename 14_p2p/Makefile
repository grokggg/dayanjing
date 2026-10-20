CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude -I../08_lateral/include
LATLIB  := ../08_lateral/build/proxy.o ../08_lateral/build/lateral.o
BUILD   := build

all: $(BUILD)/libp2p.a

$(BUILD)/libp2p.a: $(BUILD)/mesh.o $(BUILD)/relay.o
	ar rcs $@ $^

$(BUILD)/mesh.o: src/mesh.c include/p2p.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/relay.o: src/relay.c include/p2p.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_mesh: tests/test_mesh.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD)/test_chain: tests/test_chain.c $(BUILD)/libp2p.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libp2p.a $(LATLIB)

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_mesh $(BUILD)/test_chain
	./$(BUILD)/test_mesh
	./$(BUILD)/test_chain

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
