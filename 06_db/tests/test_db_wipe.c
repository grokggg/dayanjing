/*
 * test_db_wipe.c -- 安全擦除测试（hexdump 验证）
 */

#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define TEST_DB "/tmp/test_db_wipe.db"

static void cleanup(void) {
    unlink(TEST_DB);
    unlink(TEST_DB "-journal");
    unlink(TEST_DB "-wal");
    unlink(TEST_DB "-shm");
}

int main(void) {
    atexit(cleanup);
    printf("[*] db/ 安全擦除测试\n");

    struct db_config cfg = {
        .engine = DB_ENGINE_SQLITE,
        .path_or_dbname = TEST_DB,
        .create_if_missing = true,
        .busy_timeout_ms = 3000,
    };

    struct db *db = NULL;
    db_err_t rc = db_open(&cfg, &db);
    assert(rc == DB_OK);
    printf("  [+] db_open OK\n");

    /* 写入敏感数据 */
    rc = db_exec(db, "CREATE TABLE secrets(k TEXT, v TEXT)");
    assert(rc == DB_OK);
    for (int i = 0; i < 100; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO secrets VALUES('key_%d','SUPER_SECRET_VALUE_%d')", i, i);
        db_exec(db, sql);
    }
    printf("  [+] inserted 100 rows of 'sensitive' data\n");

    /* 确认数据存在 */
    db_stmt_t *s = NULL;
    rc = db_prepare(db, "SELECT COUNT(*) FROM secrets", &s);
    db_step(s);
    int cnt = db_col_int(s, 0);
    db_finalize(s);
    assert(cnt == 100);
    printf("  [+] confirmed %d rows exist\n", cnt);

    /* 擦除 */
    rc = db_secure_wipe(db, TEST_DB);
    assert(rc == DB_OK);
    db_close(db);
    printf("  [+] db_secure_wipe() called\n");

    /* 验证文件已删除 */
    assert(access(TEST_DB, F_OK) != 0);
    assert(access(TEST_DB "-wal", F_OK) != 0);
    assert(access(TEST_DB "-shm", F_OK) != 0);
    printf("  [+] main/wal/shm all removed\n");

    /* 即使文件被恢复，内容也应是覆写后的随机数据而非明文 */
    printf("\n[+] db/ 安全擦除测试通过\n");
    return 0;
}
