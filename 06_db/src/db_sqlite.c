/*
 * db_sqlite.c -- SQLite 引擎实现（dlsym 运行时解析 + XOR 密文 SQL）
 *
 * 设计要点：
 *   1. 所有 SQLite 符号通过 dlsym 运行时解析，规避手写头文件 ABI 偏差
 *   2. 所有 SQL 关键字以 XOR(0x5A) 密文存储，运行时解码
 *   3. 动态加载 libsqlite3.so，缺失时优雅降级
 */

/* 前置声明（避免依赖系统头文件，所有符号通过 dlsym 运行时解析） */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef struct sqlite3_backup sqlite3_backup;
typedef long long sqlite3_int64;

#include "db.h"
#include "db_sql_kw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <pthread.h>

/* ==================== dlsym 函数指针 ==================== */

typedef int  (*fn_sqlite3_open_v2)(const char*, sqlite3**, int, const char*);
typedef int  (*fn_sqlite3_close)(sqlite3*);
typedef const char* (*fn_sqlite3_errmsg)(sqlite3*);
typedef int  (*fn_sqlite3_busy_timeout)(sqlite3*, int);
typedef int  (*fn_sqlite3_exec)(sqlite3*, const char*,
                                int(*)(void*,int,char**,char**), void*, char**);
typedef int  (*fn_sqlite3_prepare_v2)(sqlite3*, const char*, int,
                                      sqlite3_stmt**, const char**);
typedef int  (*fn_sqlite3_finalize)(sqlite3_stmt*);
typedef int  (*fn_sqlite3_reset)(sqlite3_stmt*);
typedef int  (*fn_sqlite3_bind_int)(sqlite3_stmt*, int, int);
typedef int  (*fn_sqlite3_bind_int64)(sqlite3_stmt*, int, sqlite3_int64);
typedef int  (*fn_sqlite3_bind_double)(sqlite3_stmt*, int, double);
typedef int  (*fn_sqlite3_bind_text)(sqlite3_stmt*, int, const char*, int,
                                     void(*)(void*));
typedef int  (*fn_sqlite3_bind_blob)(sqlite3_stmt*, int, const void*, int,
                                     void(*)(void*));
typedef int  (*fn_sqlite3_bind_null)(sqlite3_stmt*, int);
typedef int  (*fn_sqlite3_step)(sqlite3_stmt*);
typedef int  (*fn_sqlite3_column_count)(sqlite3_stmt*);
typedef int  (*fn_sqlite3_column_type)(sqlite3_stmt*, int);
typedef int  (*fn_sqlite3_column_int)(sqlite3_stmt*, int);
typedef sqlite3_int64 (*fn_sqlite3_column_int64)(sqlite3_stmt*, int);
typedef double (*fn_sqlite3_column_double)(sqlite3_stmt*, int);
typedef const char* (*fn_sqlite3_column_text)(sqlite3_stmt*, int);
typedef const void* (*fn_sqlite3_column_blob)(sqlite3_stmt*, int);
typedef int  (*fn_sqlite3_column_bytes)(sqlite3_stmt*, int);
typedef sqlite3_int64 (*fn_sqlite3_last_insert_rowid)(sqlite3*);
typedef int  (*fn_sqlite3_changes)(sqlite3*);
typedef int  (*fn_sqlite3_column_count)(sqlite3_stmt*);
typedef const char* (*fn_sqlite3_column_name)(sqlite3_stmt*, int);
typedef int  (*fn_sqlite3_wal_checkpoint)(sqlite3*, const char*);
typedef sqlite3_backup* (*fn_sqlite3_backup_init)(sqlite3*, const char*,
                                                  sqlite3*, const char*);
typedef int  (*fn_sqlite3_backup_step)(sqlite3_backup*, int);
typedef int  (*fn_sqlite3_backup_finish)(sqlite3_backup*);
typedef void (*fn_sqlite3_free)(void*);

static struct {
    void *handle;
    fn_sqlite3_open_v2           open_v2;
    fn_sqlite3_close             close;
    fn_sqlite3_errmsg            errmsg;
    fn_sqlite3_busy_timeout      busy_timeout;
    fn_sqlite3_exec              exec;
    fn_sqlite3_prepare_v2        prepare_v2;
    fn_sqlite3_finalize          finalize;
    fn_sqlite3_reset             reset;
    fn_sqlite3_bind_int          bind_int;
    fn_sqlite3_bind_int64        bind_int64;
    fn_sqlite3_bind_double       bind_double;
    fn_sqlite3_bind_text         bind_text;
    fn_sqlite3_bind_blob         bind_blob;
    fn_sqlite3_bind_null         bind_null;
    fn_sqlite3_step              step;
    fn_sqlite3_column_count      column_count;
    fn_sqlite3_column_type       column_type;
    fn_sqlite3_column_int        column_int;
    fn_sqlite3_column_int64      column_int64;
    fn_sqlite3_column_double     column_double;
    fn_sqlite3_column_text       column_text;
    fn_sqlite3_column_blob       column_blob;
    fn_sqlite3_column_bytes      column_bytes;
    fn_sqlite3_last_insert_rowid last_insert_rowid;
    fn_sqlite3_changes           changes;
    fn_sqlite3_wal_checkpoint    wal_checkpoint;
    fn_sqlite3_backup_init       backup_init;
    fn_sqlite3_backup_step       backup_step;
    fn_sqlite3_backup_finish     backup_finish;
    fn_sqlite3_free              free;
    fn_sqlite3_column_count      column_count_fn;
    fn_sqlite3_column_name       column_name;
    int loaded;
} g_sqlite;

static pthread_once_t g_sqlite_once = PTHREAD_ONCE_INIT;

static void db_sqlite_dlsym_or_die(const char *name, void *out_fn) {
    void *sym = dlsym(g_sqlite.handle, name);
    if (!sym) {
        fprintf(stderr, "[db] dlsym(%s) failed: %s\n", name, dlerror());
        abort();
    }
    /* ISO C 不允许直接把 void* 强转为函数指针，用 union 做位级重解释 */
    union { void *p; void (*fp)(void); } u;
    u.p = sym;
    *(void (**)(void))out_fn = u.fp;
}

static void db_sqlite_load(void) {
    const char *candidates[] = {
        "libsqlite3.so.0",
        "libsqlite3.so",
        "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/usr/lib64/libsqlite3.so.0",
        NULL
    };

    for (const char **p = candidates; *p; p++) {
        g_sqlite.handle = dlopen(*p, RTLD_NOW | RTLD_LOCAL);
        if (g_sqlite.handle) break;
    }

    if (!g_sqlite.handle) {
        fprintf(stderr, "[db] dlopen libsqlite3 failed: %s\n", dlerror());
        return;
    }

    db_sqlite_dlsym_or_die("sqlite3_open_v2", &g_sqlite.open_v2);
    db_sqlite_dlsym_or_die("sqlite3_close", &g_sqlite.close);
    db_sqlite_dlsym_or_die("sqlite3_errmsg", &g_sqlite.errmsg);
    db_sqlite_dlsym_or_die("sqlite3_busy_timeout", &g_sqlite.busy_timeout);
    db_sqlite_dlsym_or_die("sqlite3_exec", &g_sqlite.exec);
    db_sqlite_dlsym_or_die("sqlite3_prepare_v2", &g_sqlite.prepare_v2);
    db_sqlite_dlsym_or_die("sqlite3_finalize", &g_sqlite.finalize);
    db_sqlite_dlsym_or_die("sqlite3_reset", &g_sqlite.reset);
    db_sqlite_dlsym_or_die("sqlite3_bind_int", &g_sqlite.bind_int);
    db_sqlite_dlsym_or_die("sqlite3_bind_int64", &g_sqlite.bind_int64);
    db_sqlite_dlsym_or_die("sqlite3_bind_double", &g_sqlite.bind_double);
    db_sqlite_dlsym_or_die("sqlite3_bind_text", &g_sqlite.bind_text);
    db_sqlite_dlsym_or_die("sqlite3_bind_blob", &g_sqlite.bind_blob);
    db_sqlite_dlsym_or_die("sqlite3_bind_null", &g_sqlite.bind_null);
    db_sqlite_dlsym_or_die("sqlite3_step", &g_sqlite.step);
    db_sqlite_dlsym_or_die("sqlite3_column_count", &g_sqlite.column_count);
    db_sqlite_dlsym_or_die("sqlite3_column_type", &g_sqlite.column_type);
    db_sqlite_dlsym_or_die("sqlite3_column_int", &g_sqlite.column_int);
    db_sqlite_dlsym_or_die("sqlite3_column_int64", &g_sqlite.column_int64);
    db_sqlite_dlsym_or_die("sqlite3_column_double", &g_sqlite.column_double);
    db_sqlite_dlsym_or_die("sqlite3_column_text", &g_sqlite.column_text);
    db_sqlite_dlsym_or_die("sqlite3_column_blob", &g_sqlite.column_blob);
    db_sqlite_dlsym_or_die("sqlite3_column_bytes", &g_sqlite.column_bytes);
    db_sqlite_dlsym_or_die("sqlite3_last_insert_rowid", &g_sqlite.last_insert_rowid);
    db_sqlite_dlsym_or_die("sqlite3_changes", &g_sqlite.changes);
    db_sqlite_dlsym_or_die("sqlite3_wal_checkpoint", &g_sqlite.wal_checkpoint);
    db_sqlite_dlsym_or_die("sqlite3_backup_init", &g_sqlite.backup_init);
    db_sqlite_dlsym_or_die("sqlite3_backup_step", &g_sqlite.backup_step);
    db_sqlite_dlsym_or_die("sqlite3_backup_finish", &g_sqlite.backup_finish);
    db_sqlite_dlsym_or_die("sqlite3_free", &g_sqlite.free);
    db_sqlite_dlsym_or_die("sqlite3_column_count", &g_sqlite.column_count_fn);
    db_sqlite_dlsym_or_die("sqlite3_column_name", &g_sqlite.column_name);

    g_sqlite.loaded = 1;
}

static void db_sqlite_ensure_loaded(void) {
    pthread_once(&g_sqlite_once, db_sqlite_load);
}

/* ==================== 错误码映射 ==================== */

const char *db_strerror(db_err_t e) {
    switch (e) {
        case DB_OK:         return "success";
        case DB_ERR:        return "generic error";
        case DB_BUSY:       return "database busy";
        case DB_LOCKED:     return "locked";
        case DB_CONSTRAINT: return "constraint violation";
        case DB_NOTFOUND:   return "not found";
        case DB_NOMEM:      return "out of memory";
        case DB_TIMEOUT:    return "timeout";
        case DB_NOTSUP:     return "not supported";
        case DB_DONE:       return "done";
    }
    return "unknown";
}

static db_err_t db_rc_to_err(int rc) {
    switch (rc) {
        case 0:   return DB_OK;
        case 5:   return DB_BUSY;
        case 6:   return DB_LOCKED;
        case 19:  return DB_CONSTRAINT;
        default:  return DB_ERR;
    }
}

/* ==================== 句柄结构 ==================== */

struct db {
    db_engine_t     engine;
    struct db_config cfg;
    sqlite3         *sqlite;
    char            errmsg[DB_MAX_ERRMSG];
    int             tx_depth;
};

db_engine_t db_engine(const struct db *db) {
    return db ? db->engine : DB_ENGINE_SQLITE;
}

const char *db_errmsg(const struct db *db) {
    if (!db) return "";
    if (db->sqlite && g_sqlite.loaded) {
        const char *m = g_sqlite.errmsg(db->sqlite);
        if (m) return m;
        return "";
    }
    return db->errmsg[0] ? db->errmsg : "";
}

uint64_t db_last_insert_id(const struct db *db) {
    if (!db || !db->sqlite || !g_sqlite.loaded) return 0;
    return (uint64_t)g_sqlite.last_insert_rowid(db->sqlite);
}

int db_changes(const struct db *db) {
    if (!db || !db->sqlite || !g_sqlite.loaded) return 0;
    return g_sqlite.changes(db->sqlite);
}

/* ==================== 打开 / 关闭 ==================== */

db_err_t db_open(const struct db_config *cfg, struct db **out) {
    if (!cfg || !out) return DB_ERR;
    if (cfg->engine != DB_ENGINE_SQLITE) return DB_NOTSUP;

    db_sqlite_ensure_loaded();
    if (!g_sqlite.loaded) {
        return DB_ERR;
    }

    struct db *db = calloc(1, sizeof(*db));
    if (!db) return DB_NOMEM;
    db->engine = DB_ENGINE_SQLITE;
    db->cfg = *cfg;

    int flags = 0x00008000; /* SQLITE_OPEN_NOMUTEX */
    if (cfg->read_only) {
        flags |= 0x00000001; /* SQLITE_OPEN_READONLY */
    } else {
        flags |= 0x00000002; /* SQLITE_OPEN_READWRITE */
        if (cfg->create_if_missing) flags |= 0x00000004; /* SQLITE_OPEN_CREATE */
    }

    int rc = g_sqlite.open_v2(cfg->path_or_dbname, &db->sqlite, flags, NULL);
    if (rc != 0) {
        snprintf(db->errmsg, sizeof(db->errmsg), "open: %s",
                 db->sqlite ? g_sqlite.errmsg(db->sqlite) : "oom");
        if (db->sqlite) g_sqlite.close(db->sqlite);
        free(db);
        return DB_ERR;
    }

    /* WAL 模式 + 性能调优 */
    if (!cfg->read_only) {
        char *err = NULL;
        const char *pragmas[] = {
            db_kw_get(DB_KW_00),
            db_kw_get(DB_KW_01),
            db_kw_get(DB_KW_02),
            db_kw_get(DB_KW_03),
            NULL
        };
        for (const char **p = pragmas; *p; p++) {
            g_sqlite.exec(db->sqlite, *p, NULL, NULL, &err);
            if (err) { g_sqlite.free(err); err = NULL; }
        }
    }

    if (cfg->busy_timeout_ms > 0) {
        g_sqlite.busy_timeout(db->sqlite, (int)cfg->busy_timeout_ms);
    }

    *out = db;
    return DB_OK;
}

void db_close(struct db *db) {
    if (!db) return;
    if (db->sqlite && g_sqlite.loaded) {
        g_sqlite.wal_checkpoint(db->sqlite, NULL);
        g_sqlite.close(db->sqlite);
        db->sqlite = NULL;
    }
    free(db);
}

/* ==================== 预编译语句 ==================== */

struct db_stmt {
    sqlite3_stmt *stmt;
    struct db    *db;
};

db_err_t db_prepare(struct db *db, const char *sql, db_stmt_t **out) {
    if (!db || !db->sqlite || !sql || !out || !g_sqlite.loaded) return DB_ERR;
    struct db_stmt *s = calloc(1, sizeof(*s));
    if (!s) return DB_NOMEM;

    int rc = g_sqlite.prepare_v2(db->sqlite, sql, -1, &s->stmt, NULL);
    if (rc != 0) {
        free(s);
        return db_rc_to_err(rc);
    }
    s->db = db;
    *out = s;
    return DB_OK;
}

db_err_t db_bind_int(db_stmt_t *s, int idx, int v) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_ERR;
    return db_rc_to_err(g_sqlite.bind_int(s->stmt, idx, v));
}

db_err_t db_bind_int64(db_stmt_t *s, int idx, int64_t v) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_ERR;
    return db_rc_to_err(g_sqlite.bind_int64(s->stmt, idx, (sqlite3_int64)v));
}

db_err_t db_bind_text(db_stmt_t *s, int idx, const char *text, int n) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_ERR;
    if (!text) return db_rc_to_err(g_sqlite.bind_null(s->stmt, idx));
    if (n < 0) n = (int)strlen(text);
    return db_rc_to_err(g_sqlite.bind_text(s->stmt, idx, text, n,
                                          (void(*)(void*))(-1)));
}

db_err_t db_bind_blob(db_stmt_t *s, int idx, const void *data, size_t len) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_ERR;
    if (!data) return db_rc_to_err(g_sqlite.bind_null(s->stmt, idx));
    return db_rc_to_err(g_sqlite.bind_blob(s->stmt, idx, data, (int)len,
                                          (void(*)(void*))(-1)));
}

db_err_t db_bind_null(db_stmt_t *s, int idx) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_ERR;
    return db_rc_to_err(g_sqlite.bind_null(s->stmt, idx));
}

db_err_t db_step(db_stmt_t *s) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_ERR;
    int rc = g_sqlite.step(s->stmt);
    switch (rc) {
        case 100: return DB_OK;        /* SQLITE_ROW */
        case 101: return DB_DONE;      /* SQLITE_DONE */
        case 5:   return DB_BUSY;
        case 6:   return DB_LOCKED;
        case 19:  return DB_CONSTRAINT;
        default:  return DB_ERR;
    }
}

db_err_t db_reset(db_stmt_t *s) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_ERR;
    return db_rc_to_err(g_sqlite.reset(s->stmt));
}

void db_finalize(db_stmt_t *s) {
    if (!s) return;
    if (s->stmt && g_sqlite.loaded) g_sqlite.finalize(s->stmt);
    free(s);
}

/* ==================== 列取值 ==================== */

db_type_t db_col_type(db_stmt_t *s, int col) {
    if (!s || !s->stmt || !g_sqlite.loaded) return DB_NULL;
    switch (g_sqlite.column_type(s->stmt, col)) {
        case 1:  return DB_INT64;
        case 2:  return DB_FLOAT;
        case 3:  return DB_TEXT;
        case 4:  return DB_BLOB;
        default: return DB_NULL;
    }
}

int db_col_int(db_stmt_t *s, int col) {
    if (!s || !s->stmt || !g_sqlite.loaded) return 0;
    return g_sqlite.column_int(s->stmt, col);
}

int64_t db_col_int64(db_stmt_t *s, int col) {
    if (!s || !s->stmt || !g_sqlite.loaded) return 0;
    return (int64_t)g_sqlite.column_int64(s->stmt, col);
}

double db_col_float(db_stmt_t *s, int col) {
    if (!s || !s->stmt || !g_sqlite.loaded) return 0.0;
    return g_sqlite.column_double(s->stmt, col);
}

const char *db_col_text(db_stmt_t *s, int col) {
    if (!s || !s->stmt || !g_sqlite.loaded) return NULL;
    /* 返回 sqlite3 内部临时缓冲区的指针。
     * 生命周期：仅在下次对该 stmt 调用 db_step/db_reset/db_finalize 之前有效。
     * 同一行多列读取时，SQLite 会复用内部 scratch 缓冲区，
     * 因此必须逐列立即使用（拷贝到本地缓冲区或 strdup），
     * 不能在读取完所有列之后才去引用前面的列。
     * 需要持久引用请用 db_col_text_dup()。 */
    return g_sqlite.column_text(s->stmt, col);
}

/* 返回持久拷贝，调用方负责 free() */
char *db_col_text_dup(db_stmt_t *s, int col) {
    if (!s || !s->stmt || !g_sqlite.loaded) return NULL;
    const char *raw = g_sqlite.column_text(s->stmt, col);
    if (!raw) return NULL;
    return strdup(raw);
}

const void *db_col_blob(db_stmt_t *s, int col, size_t *out_len) {
    if (!s || !s->stmt || !g_sqlite.loaded) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = (size_t)g_sqlite.column_bytes(s->stmt, col);
    return g_sqlite.column_blob(s->stmt, col);
}

int db_col_count(db_stmt_t *s) {
    if (!s || !s->stmt || !g_sqlite.loaded) return 0;
    return g_sqlite.column_count_fn(s->stmt);
}

const char *db_col_name(db_stmt_t *s, int col) {
    if (!s || !s->stmt || !g_sqlite.loaded) return NULL;
    return g_sqlite.column_name(s->stmt, col);
}

/* ==================== 便捷接口 ==================== */

db_err_t db_exec(struct db *db, const char *sql) {
    if (!db || !db->sqlite || !sql || !g_sqlite.loaded) return DB_ERR;
    char *err = NULL;
    int rc = g_sqlite.exec(db->sqlite, sql, NULL, NULL, &err);
    if (err) {
        snprintf(db->errmsg, sizeof(db->errmsg), "%s", err);
        g_sqlite.free(err);
    }
    return db_rc_to_err(rc);
}

db_err_t db_query_row(struct db *db, const char *sql,
                      struct db_value *cols, size_t ncols) {
    db_stmt_t *s = NULL;
    db_err_t rc = db_prepare(db, sql, &s);
    if (rc != DB_OK) return rc;
    rc = db_step(s);
    if (rc != DB_OK) {
        db_finalize(s);
        return rc == DB_DONE ? DB_NOTFOUND : rc;
    }
    for (size_t i = 0; i < ncols; i++) {
        cols[i].type = db_col_type(s, (int)i);
        switch (cols[i].type) {
            case DB_INT64:
                cols[i].u.i64 = db_col_int64(s, (int)i);
                break;
            case DB_INT:
                cols[i].u.i32 = db_col_int(s, (int)i);
                break;
            case DB_FLOAT:
                cols[i].u.f = db_col_float(s, (int)i);
                break;
            case DB_TEXT:
                cols[i].u.text = db_col_text(s, (int)i);
                break;
            case DB_BLOB: {
                size_t blen = 0;
                cols[i].u.blob.data = db_col_blob(s, (int)i, &blen);
                cols[i].u.blob.len = blen;
                break;
            }
            default:
                cols[i].u.i64 = 0;
                break;
        }
    }
    db_finalize(s);
    return DB_OK;
}

/* ==================== 事务 ==================== */

db_err_t db_tx_begin(struct db *db) {
    if (!db || !g_sqlite.loaded) return DB_ERR;
    if (db->tx_depth > 0) {
        /* 嵌套：SAVEPOINT */
        char buf[64];
        int n = snprintf(buf, sizeof(buf),
                         db_kw_get(DB_KW_07), db->tx_depth);
        if (n < 0 || n >= (int)sizeof(buf)) return DB_ERR;
        db->tx_depth++;
        return db_exec(db, buf);
    }
    db->tx_depth = 1;
    return db_exec(db, db_kw_get(DB_KW_04));
}

db_err_t db_tx_commit(struct db *db) {
    if (!db || db->tx_depth == 0 || !g_sqlite.loaded) return DB_ERR;
    if (db->tx_depth > 1) {
        char buf[64];
        int n = snprintf(buf, sizeof(buf),
                         db_kw_get(DB_KW_08), db->tx_depth - 1);
        if (n < 0 || n >= (int)sizeof(buf)) return DB_ERR;
        db->tx_depth--;
        return db_exec(db, buf);
    }
    db->tx_depth = 0;
    return db_exec(db, db_kw_get(DB_KW_05));
}

db_err_t db_tx_rollback(struct db *db) {
    if (!db || db->tx_depth == 0 || !g_sqlite.loaded) return DB_ERR;
    if (db->tx_depth > 1) {
        char buf[64];
        int n = snprintf(buf, sizeof(buf),
                         db_kw_get(DB_KW_09), db->tx_depth - 1);
        if (n < 0 || n >= (int)sizeof(buf)) return DB_ERR;
        db->tx_depth--;
        return db_exec(db, buf);
    }
    db->tx_depth = 0;
    return db_exec(db, db_kw_get(DB_KW_06));
}

/* ==================== 热备份 ==================== */

db_err_t db_backup(const struct db *src, const char *dst_path) {
    if (!src || !src->sqlite || !dst_path || !g_sqlite.loaded) return DB_ERR;

    sqlite3 *dst = NULL;
    int rc = g_sqlite.open_v2(dst_path, &dst,
                              0x00000002 | 0x00000004, /* RW | CREATE */
                              NULL);
    if (rc != 0) return DB_ERR;

    sqlite3_backup *b = g_sqlite.backup_init(dst, "main", src->sqlite, "main");
    if (!b) { g_sqlite.close(dst); return DB_ERR; }

    int step_rc;
    do {
        step_rc = g_sqlite.backup_step(b, 100);
    } while (step_rc == 0 || step_rc == 5); /* SQLITE_OK=0, BUSY=5 */

    int finish_rc = g_sqlite.backup_finish(b);
    g_sqlite.close(dst);
    return (step_rc == 101 && finish_rc == 0) ? DB_OK : DB_ERR; /* DONE=101 */
}

/* ==================== 安全擦除 ==================== */

static db_err_t db_overwrite_file(const char *path, size_t passes) {
    int fd = open(path, O_WRONLY | O_SYNC);
    if (fd < 0) return DB_ERR;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return DB_ERR; }
    if (st.st_size <= 0) { close(fd); return DB_OK; }

    size_t bufsz = st.st_size > 65536 ? 65536 : (size_t)st.st_size;
    uint8_t *buf = malloc(bufsz);
    if (!buf) { close(fd); return DB_NOMEM; }

    for (size_t p = 0; p < passes; p++) {
        lseek(fd, 0, SEEK_SET);
        uint8_t pat = (uint8_t)(p * 0x55 + 0xAA);
        memset(buf, pat, bufsz);
        size_t left = (size_t)st.st_size;
        while (left > 0) {
            size_t w = left > bufsz ? bufsz : left;
            if (write(fd, buf, w) != (ssize_t)w) break;
            left -= w;
        }
        fsync(fd);
    }
    free(buf);
    close(fd);
    return DB_OK;
}

db_err_t db_secure_wipe(struct db *db, const char *path) {
    if (!path) return DB_ERR;
    if (db && db->sqlite && g_sqlite.loaded) {
        db_exec(db, db_kw_get(DB_KW_10));
        g_sqlite.wal_checkpoint(db->sqlite, NULL);
    }
    static const char *suffixes[] = {"", "-journal", "-wal", "-shm"};
    for (size_t i = 0; i < 4; i++) {
        char p[DB_MAX_PATH * 2];
        int n = snprintf(p, sizeof(p), "%s%s", path, suffixes[i]);
        if (n < 0 || n >= (int)sizeof(p)) continue;
        if (access(p, F_OK) == 0) {
            db_overwrite_file(p, 3);
            unlink(p);
        }
    }
    return DB_OK;
}

db_err_t db_vacuum_into(struct db *db, const char *dst_path) {
    if (!db || !db->sqlite || !dst_path || !g_sqlite.loaded) return DB_ERR;
    /* 手动转义单引号：' -> '' */
    size_t dstlen = strlen(dst_path);
    size_t esc_cap = dstlen * 2 + 1;
    char *esc = malloc(esc_cap);
    if (!esc) return DB_NOMEM;
    char *q = esc;
    for (const char *c = dst_path; *c; c++) {
        if (*c == '\'') *q++ = '\'';
        *q++ = *c;
    }
    *q = '\0';

    size_t sql_cap = strlen(db_kw_get(DB_KW_11)) + strlen(esc) + 1;
    char *sql = malloc(sql_cap);
    if (!sql) { free(esc); return DB_NOMEM; }
    int n = snprintf(sql, sql_cap, db_kw_get(DB_KW_11), esc);
    free(esc);
    if (n < 0 || n >= (int)sql_cap) { free(sql); return DB_ERR; }

    db_err_t rc = db_exec(db, sql);
    free(sql);
    return rc;
}
