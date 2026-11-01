CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Iinclude -I../14_p2p/include
BUILD := build
LDLIBS ?=

# 默认目标必须产出全部测试二进制。回归脚本先 `make` 再执行 build/ 下的
# test_*，若 all 只产出库，则被执行的是上一次 `make test` 留下的陈旧产物
# —— 源码改动后它们永不重建，报绿却测的是旧代码（实测：清空 build 后
# make 产出 0 个测试二进制，而 build/ 里仍躺着 2 个旧文件）。
TESTBINS := $(BUILD)/test_lateral $(BUILD)/test_proxy

all: $(BUILD)/liblateral.a $(TESTBINS)

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

# 上游产物没有声明依赖时，make 会直接报 "No rule to make target"，
# 而真实原因是上游没构建 —— 排查时必然跑偏。
# 这里不能用读取阶段的 $(shell make -C ..)：08_lateral 与 14_p2p 互为上下游，
# 双方在解析期就互相触发会无限递归。改为目标级规则，只在真正需要该产物时触发，
# 且只请求具体目标（build/resolv.o 是叶子，不会再回头触发本模块）。
$(P2P_RESOLV): FORCE
	@$(MAKE) -C ../14_p2p --no-print-directory $(patsubst ../14_p2p/%,%,$@)

FORCE:

.PHONY: FORCE

$(BUILD)/test_lateral: tests/test_lateral.c $(BUILD)/liblateral.a $(P2P_RESOLV) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/liblateral.a $(P2P_RESOLV) $(LDLIBS)

$(BUILD)/test_proxy: tests/test_proxy.c $(BUILD)/liblateral.a $(P2P_RESOLV) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/liblateral.a $(P2P_RESOLV) $(LDLIBS)

$(BUILD):
	mkdir -p $(BUILD)

test: $(TESTBINS)
	./$(BUILD)/test_lateral
	./$(BUILD)/test_proxy

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
