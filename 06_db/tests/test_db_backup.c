/*
 * test_db_backup.c -- 热备份 + 恢复验证
 */

#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define SRC_DB "/tmp/test_backup_src.db"
#define DST_DB "/tmp/test_backup_dst.db"

static void cleanup(void) {
    const char *files[] = {SRC_DB, DST_DB,
        SRC_DB "-journal", SRC_DB "-wal", SRC_DB "-shm",
        DST_DB "-journal", DST_DB "-wal", DST_DB "-shm", NULL};
    for (const char **f = files; *f; f++) unlink(*f);
}

int main(void) {
    atexit(cleanup);
    printf("[*] db/ 热备份测试\n");

    struct db_config cfg = {
        .engine = DB_ENGINE_SQLITE,
        .path_or_dbname = SRC_DB,
        .create_if_missing = true,
        .busy_timeout_ms = 3000,
    };

    struct db *src = NULL;
    db_err_t rc = db_open(&cfg, &src);
    assert(rc == DB_OK);
    printf("  [+] src db opened\n");

    rc = db_exec(src, "CREATE TABLE data(id INTEGER PRIMARY KEY, payload TEXT)");
    printf("  [debug] CREATE TABLE rc=%d errmsg=%s\n", rc, db_errmsg(src));
    assert(rc == DB_OK);

    /* 插入 100 行 */
    char sql[256];
    int inserted = 0;
    for (int i = 1; i <= 100; i++) {
        snprintf(sql, sizeof(sql),
                 "INSERT INTO data(payload) VALUES('payload_row_%d')", i);
        if (db_exec(src, sql) == DB_OK) inserted++;
    }
    assert(inserted == 100);
    printf("  [+] inserted %d/100 rows into src\n", inserted);

    /* 备份 */
    rc = db_backup(src, DST_DB);
    assert(rc == DB_OK);
    printf("  [+] db_backup() OK\n");

    /* 打开 dst 验证数据完整性 */
    cfg.path_or_dbname = DST_DB;
    struct db *dst = NULL;
    rc = db_open(&cfg, &dst);
    assert(rc == DB_OK);
    printf("  [+] dst db opened\n");

    db_stmt_t *s = NULL;
    rc = db_prepare(dst, "SELECT COUNT(*), MIN(payload), MAX(payload) FROM data", &s);
    assert(rc == DB_OK);
    rc = db_step(s);
    assert(rc == DB_OK);
    int cnt = db_col_int(s, 0);
    /* sqlite3_column_text 返回的指针在 stmt 生命周期内有效，
     * 但同一行的多列读取会复用内部 scratch buffer。
     * 必须逐列 strdup 后才能跨列/跨调用使用。 */
    const char *m1 = db_col_text(s, 1);
    char min_buf[64];
    if (m1) { strncpy(min_buf, m1, sizeof(min_buf) - 1); min_buf[sizeof(min_buf) - 1] = '\0'; }
    else { min_buf[0] = '\0'; }
    const char *m2 = db_col_text(s, 2);
    char max_buf[64];
    if (m2) { strncpy(max_buf, m2, sizeof(max_buf) - 1); max_buf[sizeof(max_buf) - 1] = '\0'; }
    else { max_buf[0] = '\0'; }
    const char *min_p = min_buf;
    const char *max_p = max_buf;
    db_finalize(s);

    printf("  [debug] COUNT=%d MIN=[%s] MAX=[%s]\n",
           cnt, min_p, max_p);
    fflush(stdout);

    assert(cnt == 100);
    /* SQLite TEXT 聚合：MIN/MAX 按 TEXT 比较
     * MIN('payload_row_1'..'payload_row_100') = 'payload_row_1'（最短且前缀最小）
     * MAX  = 'payload_row_99'（共同前缀 payload_row_ 之后，'99' > '9' > '10'...）
     */
    assert(min_p && strcmp(min_p, "payload_row_1") == 0);
    assert(max_p && strcmp(max_p, "payload_row_99") == 0);
    printf("  [+] dst has %d rows, min='%s', max='%s'\n", cnt, min_p, max_p);
    printf("  [+] data integrity verified\n");

    db_close(dst);
    db_close(src);
    printf("\n[+] db/ 热备份测试通过\n");
    return 0;
}
