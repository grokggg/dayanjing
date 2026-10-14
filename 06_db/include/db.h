#ifndef DB_H
#define DB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DB_VERSION   "0.1.0"
#define DB_MAX_PATH  1024
#define DB_MAX_SQL   4096
#define DB_MAX_ERRMSG 512
#define DB_MAX_BIND  64
#define DB_POOL_MAX  16
#define DB_DEFAULT_TIMEOUT_MS 5000

/* 符号导出：默认隐藏，显式标记公开 API */
#if defined(_WIN32) || defined(__CYGWIN__)
#  ifdef DB_BUILD_SHARED
#    define DB_API __declspec(dllexport)
#  else
#    define DB_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#  define DB_API __attribute__((visibility("default")))
#else
#  define DB_API
#endif

/* ============ 错误码 ============ */
typedef enum {
    DB_OK          = 0,
    DB_ERR         = -1,
    DB_BUSY        = -2,
    DB_LOCKED      = -3,
    DB_CONSTRAINT  = -4,
    DB_NOTFOUND    = -5,
    DB_NOMEM       = -6,
    DB_TIMEOUT     = -7,
    DB_NOTSUP      = -8,
    DB_DONE        = -9,    /* 迭代结束（非错误） */
} db_err_t;

DB_API const char *db_strerror(db_err_t e);

/* ============ 数据类型 ============ */
typedef enum {
    DB_NULL  = 0,
    DB_INT   = 1,    /* 32-bit */
    DB_INT64 = 2,    /* 64-bit */
    DB_FLOAT = 3,
    DB_TEXT  = 4,
    DB_BLOB  = 5,
} db_type_t;

struct db_value {
    db_type_t type;
    union {
        int         i32;
        int64_t     i64;
        double      f;
        const char *text;
        struct {
            const void *data;
            size_t      len;
        } blob;
    } u;
};

/* ============ 前置声明 ============ */
struct db;
struct db_stmt;
struct db_pool;
typedef struct db db_t;
typedef struct db_stmt db_stmt_t;
typedef struct db_pool db_pool_t;

/* ============ 预编译语句 ============ */
DB_API db_err_t db_prepare   (db_t *db, const char *sql, db_stmt_t **out);
DB_API db_err_t db_bind_int  (db_stmt_t *s, int idx, int v);
DB_API db_err_t db_bind_int64(db_stmt_t *s, int idx, int64_t v);
DB_API db_err_t db_bind_double(db_stmt_t *s, int idx, double v);
DB_API db_err_t db_bind_text (db_stmt_t *s, int idx, const char *text, int n);
DB_API db_err_t db_bind_blob (db_stmt_t *s, int idx, const void *data, size_t len);
DB_API db_err_t db_bind_null (db_stmt_t *s, int idx);
DB_API db_err_t db_step      (db_stmt_t *s);
DB_API db_err_t db_reset     (db_stmt_t *s);
DB_API void     db_finalize  (db_stmt_t *s);

/* 列取值。db_col_text 返回的指针指向 sqlite3 内部临时缓冲区，
 * 仅在下次对该 stmt 调用 db_step/db_reset/db_finalize 之前有效。
 * 同一行多列读取时 sqlite3 会复用内部 scratch 缓冲区，故须逐列
 * 立即使用（拷贝到本地缓冲区或 db_col_text_dup()）。 */
DB_API db_type_t    db_col_type  (db_stmt_t *s, int col);
DB_API int          db_col_int   (db_stmt_t *s, int col);
DB_API int64_t      db_col_int64 (db_stmt_t *s, int col);
DB_API double       db_col_float (db_stmt_t *s, int col);
DB_API const char  *db_col_text  (db_stmt_t *s, int col);
DB_API char        *db_col_text_dup(db_stmt_t *s, int col); /* 持久拷贝，调用方 free */
DB_API const void  *db_col_blob  (db_stmt_t *s, int col, size_t *out_len);
DB_API int          db_col_count (db_stmt_t *s);
DB_API const char  *db_col_name  (db_stmt_t *s, int col);

/* ============ 便捷接口 ============ */
DB_API db_err_t db_exec(db_t *db, const char *sql);
DB_API db_err_t db_query_row(db_t *db, const char *sql,
                      struct db_value *cols, size_t ncols);

/* ============ 事务 ============ */
DB_API db_err_t db_tx_begin   (db_t *db);
DB_API db_err_t db_tx_commit  (db_t *db);
DB_API db_err_t db_tx_rollback(db_t *db);

/* ============ 连接池 ============ */
DB_API db_err_t db_pool_create (db_pool_t **out, const char *uri, size_t max_conn);
DB_API db_err_t db_pool_acquire(db_pool_t *p, db_t **out, uint32_t timeout_ms);
DB_API db_err_t db_pool_release(db_pool_t *p, db_t *db);
DB_API void     db_pool_destroy(db_pool_t *p);

/* ============ 主句柄 ============ */
typedef enum { DB_ENGINE_SQLITE = 1, DB_ENGINE_PG = 2 } db_engine_t;

struct db_config {
    db_engine_t engine;
    const char *path_or_dbname;
    const char *host;
    uint16_t    port;
    const char *user;
    const char *password;
    bool        read_only;
    bool        create_if_missing;
    size_t      busy_timeout_ms;
};

DB_API db_err_t db_open (const struct db_config *cfg, db_t **out);
DB_API void     db_close(db_t *db);
DB_API db_engine_t db_engine(const db_t *db);
DB_API const char *db_errmsg(const db_t *db);
DB_API uint64_t db_last_insert_id(const db_t *db);
DB_API int      db_changes(const db_t *db);

/* ============ 反取证接口 ============ */
DB_API db_err_t db_backup      (const db_t *src, const char *dst_path);
DB_API db_err_t db_secure_wipe (db_t *db, const char *path);
DB_API db_err_t db_vacuum_into (db_t *db, const char *dst_path);

/* ============ XOR 解码器接口 ============ */
#include <stdarg.h>

DB_API const char *db_kw_get(int idx);
DB_API const char *db_kw_decode(int idx);
DB_API int  db_kw_format(int idx, char *out, size_t out_size, ...);
DB_API void db_kw_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* DB_H */
