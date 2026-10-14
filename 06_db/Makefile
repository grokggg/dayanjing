CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wcast-align -Wpointer-arith \
           -Wconversion -Wsign-conversion \
           -std=c11 -D_GNU_SOURCE -fPIC -fvisibility=hidden \
           -Wno-unused-parameter
LDFLAGS ?= -ldl -lpthread

BUILD := build
LIB   := $(BUILD)/libdb.a
LIBS  := $(BUILD)/libdb_stripped.a
OBJS  := $(BUILD)/db_sqlite.o $(BUILD)/db_pool.o $(BUILD)/db_kw.o

TESTS := test_db_core test_db_pool test_db_wipe test_db_backup

.PHONY: all clean test mkdirs $(TESTS)

all: mkdirs $(LIB)

mkdirs:
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c include/db.h include/db_sql_kw.h | mkdirs
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

$(LIB): $(OBJS)
	ar rcs $@ $^

# 静态库只 strip 调试段（保留符号表供链接器使用）
# 内部符号的隐藏由编译期 -fvisibility=hidden + DB_API 显式导出实现
$(LIBS): $(LIB)
	cp $< $@
	strip --strip-debug $@
	ranlib $@
	@echo "  [strip] $(LIBS) 调试段已清除（符号表保留供链接）"

# 单个测试目标
test_db_core: $(BUILD)/test_db_core
test_db_pool: $(BUILD)/test_db_pool
test_db_wipe:  $(BUILD)/test_db_wipe
test_db_backup: $(BUILD)/test_db_backup

$(BUILD)/test_db_core: tests/test_db_core.c $(LIB)
	$(CC) $(CFLAGS) -Iinclude $< -L$(BUILD) -ldb $(LDFLAGS) -o $@

$(BUILD)/test_db_pool: tests/test_db_pool.c $(LIB)
	$(CC) $(CFLAGS) -Iinclude $< -L$(BUILD) -ldb $(LDFLAGS) -o $@

$(BUILD)/test_db_wipe: tests/test_db_wipe.c $(LIB)
	$(CC) $(CFLAGS) -Iinclude $< -L$(BUILD) -ldb $(LDFLAGS) -o $@

$(BUILD)/test_db_backup: tests/test_db_backup.c $(LIB)
	$(CC) $(CFLAGS) -Iinclude $< -L$(BUILD) -ldb $(LDFLAGS) -o $@

test: $(LIB) $(addprefix $(BUILD)/,$(TESTS))
	@echo "===== Running tests ====="
	$(BUILD)/test_db_core
	$(BUILD)/test_db_pool
	$(BUILD)/test_db_wipe
	$(BUILD)/test_db_backup
	@echo ""
	@echo "===== Binary hygiene audit ====="
	@echo "--- SQL plaintext in static lib (should be empty):"
	@strings $(LIB) | grep -E 'PRAGMA|BEGIN|COMMIT|ROLLBACK|VACUUM|INSERT|SELECT|DELETE|CREATE|sqlite_master' | head -20 || echo "  (clean)"
	@echo "--- Public API symbols:"
	@nm -g $(LIB) | grep ' T ' | sed 's/^/  /'
	@echo "--- Internal symbols (should be local):"
	@nm $(LIB) | grep -E 'db_sqlite|db_kw_' | head -10 || echo "  (none visible)"

clean:
	rm -f /tmp/test_db_*.db /tmp/test_db_*.db-wal /tmp/test_db_*.db-shm
	rm -rf $(BUILD)
