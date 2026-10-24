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

# 必须把测试二进制纳入默认目标：回归脚本 run_c 只跑 `make` 后扫描
# build/test_*。若默认目标只产出 .o，build/ 里没有测试可执行文件时回归
# 会**跑零个测试并判 PASS** —— 实测触发：清除 build/ 后 make 只编译 .o，
# 而此前"通过"完全依赖 build/ 里的残留二进制。
all: $(OBJ) $(TEST) $(E2E)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

# 上游产物未声明依赖：上游 clean 后本模块链接报 "No rule to make target"，
# 真实原因（上游没构建）完全不提，排查必然跑偏。
# 挂 FORCE 无条件触发，由上游 make 自身做增量判断（产物已最新时开销极小）。
# 两个上游都无上游（00_crypto 与 09_persistence 均不引用 ../），无递归风险。
$(CRYO): FORCE
	@$(MAKE) -C ../00_crypto --no-print-directory build/crypto_hash.o

FORCE:

.PHONY: FORCE

$(TEST): tests/test_lateral_auto.c $(OBJ) $(CRYO) | build
	$(CC) $(CFLAGS) $< $(OBJ) $(CRYO) -o $@ $(LDFLAGS)

# 凭据层 -> 持久化层 端到端：依赖 09_persistence（新模块依赖旧模块，方向合理）。
# 核心断言是"真实 ssh-keygen -l 能解析落盘的 authorized_keys"，
# 任何类型/blob 错配都会在此暴露。
E2E    = build/test_sshkey_e2e
PERSIST_LIB = ../09_persistence/build/libpersist.a

$(PERSIST_LIB): FORCE
	@$(MAKE) -C ../09_persistence --no-print-directory build/libpersist.a

$(E2E): tests/test_sshkey_e2e.c $(OBJ) $(CRYO) $(PERSIST_LIB) | build
	$(CC) $(CFLAGS) -I../09_persistence/include $< $(OBJ) $(CRYO) \
		$(PERSIST_LIB) -o $@ $(LDFLAGS)

test: $(TEST) $(E2E)
	./$(TEST)
	./$(E2E) /tmp

clean:
	rm -f $(OBJ) $(TEST) $(E2E)
