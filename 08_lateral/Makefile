CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude -I../14_p2p/include
BUILD := build
LDLIBS ?=

all: $(BUILD)/liblateral.a

$(BUILD)/liblateral.a: $(BUILD)/lateral.o $(BUILD)/proxy.o
	ar rcs $@ $^

$(BUILD)/lateral.o: src/lateral.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/proxy.o: src/proxy.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# proxy.c 使用 14_p2p 的自研解析（p2p_resolve_sa）以根除 NSS。
# 静态库按命令行从左到右只扫描一次：被依赖者必须写在依赖者之后，
# 否则处理 liblateral.a 时尚未出现该符号需求，轮到它时库已扫完 -> 未定义。
# 21_exfil 曾因同样的顺序问题链接失败，这里同步修正。
P2P_RESOLV := ../14_p2p/build/resolv.o

$(BUILD)/test_lateral: tests/test_lateral.c $(BUILD)/liblateral.a $(P2P_RESOLV) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/liblateral.a $(P2P_RESOLV) $(LDLIBS)

$(BUILD)/test_proxy: tests/test_proxy.c $(BUILD)/liblateral.a $(P2P_RESOLV) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/liblateral.a $(P2P_RESOLV) $(LDLIBS)

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_lateral $(BUILD)/test_proxy
	./$(BUILD)/test_lateral
	./$(BUILD)/test_proxy

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
