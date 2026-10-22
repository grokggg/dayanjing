CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
          -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L \
          -Iinclude -I../00_crypto/include
LDFLAGS =

SRC   = src/cred.c src/target.c src/exec.c src/spread.c src/orch.c
OBJ   = $(SRC:.c=.o)
CRYO  = ../00_crypto/build/crypto_hash.o
TEST  = build/test_lateral_auto

.PHONY: all clean test

all: $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

$(TEST): tests/test_lateral_auto.c $(OBJ) $(CRYO) | build
	$(CC) $(CFLAGS) $< $(OBJ) $(CRYO) -o $@ $(LDFLAGS)

test: $(TEST)
	./$(TEST)

clean:
	rm -f $(OBJ) $(TEST)
