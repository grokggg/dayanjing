# 11_edr_bypass/Makefile
#
# 直接系统调用绕过 EDR 用户态 hook
# 目标：纯 C11，零第三方依赖，可移植（Linux 测试 / Windows 真机）

CC      ?= gcc
AR      ?= ar
# 隐蔽性加固：
#   -fno-ident                 移除 .comment / 编译器标识串
#   -fno-asynchronous-unwind-tables  移除 .eh_frame（含函数名映射）
#   -g0                       不生成任何调试信息
#   -fvisibility=hidden        默认隐藏所有符号
#   -ffunction-sections        每个函数独立节，便于链接时回收
#   -fdata-sections
#   -Wl,--strip-all           链接产物剥离符号表
#   -Wl,--discard-all         同上
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wcast-align -Wpointer-arith -std=c11 \
           -fno-ident -fno-asynchronous-unwind-tables -g0 \
           -fvisibility=hidden \
           -ffunction-sections -fdata-sections
CFLAGS  += -D_GNU_SOURCE
CPPFLAGS ?= -Iinclude
LDFLAGS ?= -Wl,--gc-sections
# DS_API 在 direct_syscall.h 中定义，默认 -fvisibility=hidden 下仅导出头文件声明
# 的内部函数（ds_map_open / rva_to_offset / scan_mov_eax_imm32 / ds_syscall_stub
# 等）均不出现在符号表中。

# 严格模式：开启符号转换检查，模拟 Windows 真机编译告警敏感度
CFLAGS_STRICT ?= $(CFLAGS) -Wconversion -Wsign-conversion

BUILD := build
LIB    := $(BUILD)/libdirect_syscall.a
SRC_C  := src/direct_syscall.c
HDR    := include/direct_syscall.h
OBJS   := $(BUILD)/direct_syscall.o
TEST   := $(BUILD)/direct_syscall_test
REAL_PE := tools/test_ntdll.dll
REALTEST := $(BUILD)/real_pe_test

.PHONY: all clean test inspect realtest strict paranoid pegen help

all: $(LIB)

help:
	@echo "targets:"
	@echo "  all      构建静态库 $(LIB)"
	@echo "  test     编译并运行单元测试（mock PE）"
	@echo "  realtest 编译并运行真实 PE 验证（自动生成 $(REAL_PE)）"
	@echo "  inspect  反汇编检查 syscall 指令与字符串残留"
	@echo "  pegen    仅生成真实感 PE 文件"
	@echo "  clean    清理构建产物"

pegen: $(REAL_PE)

$(REAL_PE): tools/build_real_pe.py
	@python3 tools/build_real_pe.py $(REAL_PE)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) rcs $@ $^
	$(STRIP) --strip-all $@  2>/dev/null || strip --strip-all $@ || true

# strict target：开启 -Wconversion -Wsign-conversion，作为兼容性验证
strict: CFLAGS := $(CFLAGS_STRICT)
strict: $(LIB) $(TEST) $(REALTEST)

$(TEST): tests/test_direct_syscall.c $(LIB) $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) tests/test_direct_syscall.c $(OBJS) -o $@ $(LDFLAGS)

test: $(TEST)
	@echo "--- 运行单元测试 ---"
	./$(TEST)

inspect: $(TEST) $(REALTEST)
	@echo "=== [1/4] 反汇编：检查 syscall 指令 ==="
	objdump -d $(TEST) | grep -E "syscall|syscall_stub" | head -5 || echo "(无 syscall 指令 — 当前为 Linux 占位实现)"
	@echo ""
	@echo "=== [2/4] strings：检查可识别模块特征字符串 ==="
	@for f in $(TEST) $(REALTEST); do \
		echo "--- $$f ---"; \
		strings $$f | grep -iE "direct_syscall|\.c:|ds_syscall|ds_invoke|ds_resolve|syscall_stub|Zw[A-Z]|Nt[A-Z]" \
			| head -10 || echo "(无 ds_* / Zw* / Nt* 明文残留)"; \
	done
	@echo ""
	@echo "=== [3/4] 符号表：内部函数应不可见 ==="
	@for f in $(TEST) $(REALTEST); do \
		echo "--- $$f ---"; \
		objdump -t $$f 2>/dev/null | grep -E "ds_map_open|ds_syscall_stub|rva_to_offset|scan_mov_eax" \
			| head -5 || echo "(内部函数未导出 — visibility=hidden 生效)"; \
	done
	@echo ""
	@echo "=== [4/4] 静态库：应无 .strtab / 应无文件内符号 ==="
	@objdump -t $(LIB) 2>/dev/null | grep -E "ds_map_open|ds_syscall_stub|rva_to_offset" \
		| head -5 || echo "(静态库内部符号已剥离)"

# 极致隐蔽检查：直接检查目标文件
paranoid: $(OBJS)
	@echo "=== 目标文件原始字符串（编译期残留）==="
	@strings $(OBJS) | grep -iE "direct_syscall|\.c:" | head -10 || echo "(目标文件无源文件名残留)"

$(REALTEST): tests/test_real_pe.c $(LIB) $(HDR) $(REAL_PE) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) tests/test_real_pe.c $(OBJS) -o $@ $(LDFLAGS)

realtest: $(REALTEST)
	@echo "--- 运行真实 PE 验证测试 ---"
	./$(REALTEST)

clean:
	rm -rf $(BUILD)
