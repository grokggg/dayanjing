/*
 * db_kw.c -- XOR 运行时解码器（0x5A 密钥）
 *
 * 所有 SQL 关键字以密文形式存储在 db_sql_kw_table 中，
 * 运行时解码并缓存，避免二进制中残留明文 SQL。
 */

#include <stdio.h>
#include "db.h"
#include "db_sql_kw.h"

#include <stdlib.h>
#include <string.h>

#define DB_KW_XOR_KEY  0x5A
#define DB_KW_MAX_LEN  256

/* 解码缓存：槽位 i 存 kw i 的明文，未解码时为 NULL */
static char *db_kw_cache[DB_SQL_KW_COUNT];
static int   db_kw_initialized = 0;

static void db_kw_init(void) {
    if (db_kw_initialized) return;
    memset(db_kw_cache, 0, sizeof(db_kw_cache));
    db_kw_initialized = 1;
}

/* 解码指定 kw 到静态缓冲区并返回 */
const char *db_kw_decode(int idx) {
    if (idx < 0 || idx >= DB_SQL_KW_COUNT) return "";

    db_kw_init();

    if (db_kw_cache[idx]) return db_kw_cache[idx];

    const struct db_kw *kw = &db_sql_kw_table[idx];
    /* 长度 +1 用于截断位（len 不含终止符） */
    int need = kw->len + 2;
    char *buf = malloc((size_t)need);
    if (!buf) return "";

    for (int i = 0; i < kw->len; i++) {
        buf[i] = (char)(kw->data[i] ^ DB_KW_XOR_KEY);
    }
    buf[kw->len] = '\0';

    db_kw_cache[idx] = buf;
    return buf;
}

/*
 * db_kw_get -- 获取解码后的 SQL 关键字
 *
 * 返回的指针在下一次 db_kw_format 调用前有效（内部缓存）。
 * 调用方不应 free 它。
 */
const char *db_kw_get(int idx) {
    return db_kw_decode(idx);
}

/*
 * db_kw_format -- 格式化带参数的 SQL
 *
 * 类似 snprintf，但源格式串来自密文解码。
 * 输出写入调用方提供的缓冲区 out（容量 out_size）。
 * 返回写入的字符数（不含终止符），截断时返回 < 0 表示空间不足。
 */
int db_kw_format(int idx, char *out, size_t out_size, ...) {
    if (!out || out_size == 0) return -1;
    const char *fmt = db_kw_decode(idx);
    if (!fmt || !*fmt) { out[0] = '\0'; return 0; }

    va_list ap;
    va_start(ap, out_size);
    int n = vsnprintf(out, out_size, fmt, ap);
    va_end(ap);

    if (n < 0 || n >= (int)out_size) return -1;  /* 截断或错误 */
    return n;
}

/* 清理缓存（进程退出时调用，可选） */
void db_kw_cleanup(void) {
    for (int i = 0; i < DB_SQL_KW_COUNT; i++) {
        if (db_kw_cache[i]) {
            free(db_kw_cache[i]);
            db_kw_cache[i] = NULL;
        }
    }
    db_kw_initialized = 0;
}
