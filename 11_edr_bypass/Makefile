CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -std=c11
CFLAGS  += -Iinclude -D_GNU_SOURCE
LDFLAGS ?=
AS      ?= $(CC)

BUILD := build
SRC_C := src/direct_syscall.c src/pe_image.c
SRC_S := asm/syscall_asm.S
HDR   := include/direct_syscall.h include/pe_image.h

TARGET := $(BUILD)/test_direct_syscall
OBJS   := $(BUILD)/direct_syscall.o $(BUILD)/pe_image.o $(BUILD)/syscall_asm.o

.PHONY: all clean test mkdirs inspect

all: mkdirs $(TARGET)

mkdirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: asm/%.S | mkdirs
	$(AS) -c $< -o $@

$(TARGET): $(OBJS) tests/test_direct_syscall.c $(HDR) | mkdirs
	$(CC) $(CFLAGS) tests/test_direct_syscall.c $(OBJS) -o $@ $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

inspect: $(TARGET)
	@echo "--- syscall 指令检查 ---"
	objdump -d $(TARGET) | grep -E 'syscall_ret|<syscall|syscall\b' || true
	@echo "--- 明文 Zw 函数名检查（应为空）---"
	strings $(TARGET) | grep -E '^Zw[A-Z]' || echo "(无明文 Zw* 名称)"

clean:
	rm -rf $(BUILD)
