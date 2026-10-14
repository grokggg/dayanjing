/*
 * test_db_core.c -- db/ 核心层测试（CRUD + 事务 + 嵌套 SAVEPOINT）
 */

#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define TEST_DB "/tmp/test_db_core.db"

static void cleanup(void) {
    unlink(TEST_DB);
    unlink(TEST_DB "-journal");
    unlink(TEST_DB "-wal");
    unlink(TEST_DB "-shm");
}

int main(void) {
    atexit(cleanup);
    printf("[*] db/ 核心层测试\n");

    struct db_config cfg = {
        .engine = DB_ENGINE_SQLITE,
        .path_or_dbname = TEST_DB,
        .create_if_missing = true,
        .busy_timeout_ms = 3000,
    };

    struct db *db = NULL;
    db_err_t rc = db_open(&cfg, &db);
    assert(rc == DB_OK && db != NULL);
    printf("  [+] db_open (WAL) OK\n");

    /* 建表 */
    rc = db_exec(db, "CREATE TABLE IF NOT EXISTS t ("
                     "id INTEGER PRIMARY KEY, name TEXT, val BLOB)");
    assert(rc == DB_OK);
    printf("  [+] CREATE TABLE OK\n");

    /* 插入 */
    db_stmt_t *s = NULL;
    rc = db_prepare(db, "INSERT INTO t(name,val) VALUES(?,?)", &s);
    assert(rc == DB_OK);
    rc = db_bind_text(s, 1, "hello", -1);
    assert(rc == DB_OK);
    uint8_t blob[] = {0xde, 0xad, 0xbe, 0xef};
    rc = db_bind_blob(s, 2, blob, sizeof(blob));
    assert(rc == DB_OK);
    rc = db_step(s);
    assert(rc == DB_DONE);
    db_finalize(s);
    assert(db_last_insert_id(db) == 1);
    printf("  [+] INSERT (bind_text+bind_blob) OK, last_id=%llu\n",
           (unsigned long long)db_last_insert_id(db));

    /* 查询 */
    rc = db_prepare(db, "SELECT id,name,val FROM t WHERE id=?", &s);
    assert(rc == DB_OK);
    rc = db_bind_int64(s, 1, 1);
    assert(rc == DB_OK);
    rc = db_step(s);
    assert(rc == DB_OK);
    assert(db_col_int64(s, 0) == 1);
    assert(strcmp(db_col_text(s, 1), "hello") == 0);
    size_t blen = 0;
    const void *b = db_col_blob(s, 2, &blen);
    assert(blen == 4 && memcmp(b, blob, 4) == 0);
    db_finalize(s);
    printf("  [+] SELECT (all types) OK\n");

    /* 事务回滚 */
    rc = db_tx_begin(db);
    assert(rc == DB_OK);
    db_exec(db, "INSERT INTO t(name) VALUES('rollback_me')");
    rc = db_tx_rollback(db);
    assert(rc == DB_OK);

    rc = db_prepare(db, "SELECT COUNT(*) FROM t WHERE name='rollback_me'", &s);
    db_step(s);
    int cnt = db_col_int(s, 0);
    db_finalize(s);
    assert(cnt == 0);
    printf("  [+] TX rollback OK\n");

    /* 嵌套 SAVEPOINT */
    rc = db_tx_begin(db);
    assert(rc == DB_OK);
    rc = db_tx_begin(db);  /* 嵌套 */
    assert(rc == DB_OK);
    db_exec(db, "INSERT INTO t(name) VALUES('nested')");
    rc = db_tx_rollback(db);
    assert(rc == DB_OK);
    rc = db_tx_commit(db);
    assert(rc == DB_OK);

    rc = db_prepare(db, "SELECT COUNT(*) FROM t WHERE name='nested'", &s);
    db_step(s);
    cnt = db_col_int(s, 0);
    db_finalize(s);
    assert(cnt == 0);
    printf("  [+] nested SAVEPOINT rollback OK\n");

    /* 约束违反 */
    rc = db_prepare(db, "INSERT INTO t(id,name) VALUES(1,'dup')", &s);
    assert(rc == DB_OK);
    rc = db_step(s);
    assert(rc == DB_CONSTRAINT);
    db_finalize(s);
    printf("  [+] CONSTRAINT violation mapped OK\n");

    db_close(db);
    printf("\n[+] db/ 核心层全部通过\n");
    return 0;
}
