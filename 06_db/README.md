# `06_db/` — 持久化层

SQLite 引擎封装 + 连接池 + 反取证擦除。

## 设计要点

- **dlsym 运行时解析 SQLite**：不依赖系统头文件，规避手写声明的 ABI 偏差
- **XOR(0x5A) 密文 SQL**：所有 SQL 关键字在二进制中以密文存储，运行时解码
- **符号隐藏**：`-fvisibility=hidden` + `DB_API` 显式导出，内部符号不可见
- **预编译语句优先**：所有外部输入走 `bind`，杜绝注入
- **WAL + Online Backup**：运行时热备不锁库
- **安全擦除**：覆写主库/journal/WAL/SHM 并 unlink

## 编译

```bash
make all          # 编译静态库 libdb.a
make test         # 编译并运行全部测试 + 二进制审计
```

需要：GCC 4.6+、`libsqlite3.so.0`、`-ldl -lpthread`。

## 测试

| 测试 | 覆盖 |
|---|---|
| `test_db_core` | CRUD、预编译语句、事务、嵌套 SAVEPOINT、约束映射 |
| `test_db_pool` | 6 线程 × 30 轮并发借还、无泄漏 |
| `test_db_wipe` | 100 行数据 → 擦除 → 主库/WAL/SHM 全部移除 |
| `test_db_backup` | Online Backup 100 行 → 目标库数据完整 |

## 接口速览

```c
struct db_config cfg = {
    .engine = DB_ENGINE_SQLITE,
    .path_or_dbname = "data.db",
    .create_if_missing = true,
    .busy_timeout_ms = 3000,
};
db_t *db = NULL;
db_open(&cfg, &db);

db_exec(db, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)");

db_stmt_t *s = NULL;
db_prepare(db, "INSERT INTO t(v) VALUES(?)", &s);
db_bind_text(s, 1, "hello", -1);
db_step(s);          // DB_DONE
db_finalize(s);

/* 事务 */
db_tx_begin(db);
// ...
db_tx_commit(db);    // 或 db_tx_rollback(db)

db_close(db);
```

## 二进制审计

```bash
strings build/libdb.a | grep -Ei "pragma|vacuum|begin|commit|rollback|select|insert"
# 输出应为空
```

## 反取证

```c
db_secure_wipe(db, "data.db");   /* 覆写 + 清理 journal/WAL/SHM */
db_backup(src, "backup.db");     /* Online Backup 热备 */
```
