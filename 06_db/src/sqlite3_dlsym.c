/*
 * sqlite3_dlsym.c —— 运行时解析 libsqlite3 符号
 *
 * 设计：dlopen 加载 libsqlite3.so.0，dlsym 解析全部 API 函数指针。
 * 调用约定由编译器按本文件的精确函数原型生成，规避手写头文件与系统库 ABI 偏差。
 */
#include "sqlite3_min.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *g_handle = NULL;
static char  g_dl_err[256] = {0};

/* ---- 函数指针类型定义（合法 C） ---- */
typedef int    (*fn_sqlite3_open_v2_t)(const char*, sqlite3**, int, const char*);
typedef int    (*fn_sqlite3_close_t)(sqlite3*);
typedef const char *(*fn_sqlite3_errmsg_t)(sqlite3*);
typedef int    (*fn_sqlite3_busy_timeout_t)(sqlite3*, int);
typedef int    (*fn_sqlite3_exec_t)(sqlite3*, const char*,
                                    int(*)(void*,int,char**,char**), void*, char**);
typedef int    (*fn_sqlite3_prepare_v2_t)(sqlite3*, const char*, int,
                                          sqlite3_stmt**, const char**);
typedef int    (*fn_sqlite3_finalize_t)(sqlite3_stmt*);
typedef int    (*fn_sqlite3_reset_t)(sqlite3_stmt*);
typedef int    (*fn_sqlite3_clear_bindings_t)(sqlite3_stmt*);
typedef int    (*fn_sqlite3_bind_int_t)(sqlite3_stmt*, int, int);
typedef int    (*fn_sqlite3_bind_int64_t)(sqlite3_stmt*, int, sqlite3_int64);
typedef int    (*fn_sqlite3_bind_double_t)(sqlite3_stmt*, int, double);
typedef int    (*fn_sqlite3_bind_text_t)(sqlite3_stmt*, int, const char*, int,
                                         void(*)(void*));
typedef int    (*fn_sqlite3_bind_blob_t)(sqlite3_stmt*, int, const void*, int,
                                         void(*)(void*));
typedef int    (*fn_sqlite3_bind_null_t)(sqlite3_stmt*, int);
typedef int    (*fn_sqlite3_step_t)(sqlite3_stmt*);
typedef int    (*fn_sqlite3_column_count_t)(sqlite3_stmt*);
typedef int    (*fn_sqlite3_column_type_t)(sqlite3_stmt*, int);
typedef int    (*fn_sqlite3_column_int_t)(sqlite3_stmt*, int);
typedef sqlite3_int64 (*fn_sqlite3_column_int64_t)(sqlite3_stmt*, int);
typedef double (*fn_sqlite3_column_double_t)(sqlite3_stmt*, int);
typedef const char *(*fn_sqlite3_column_text_t)(sqlite3_stmt*, int);
typedef const void *(*fn_sqlite3_column_blob_t)(sqlite3_stmt*, int);
typedef int    (*fn_sqlite3_column_bytes_t)(sqlite3_stmt*, int);
typedef const char *(*fn_sqlite3_column_name_t)(sqlite3_stmt*, int);
typedef sqlite3_int64 (*fn_sqlite3_last_insert_rowid_t)(sqlite3*);
typedef int    (*fn_sqlite3_changes_t)(sqlite3*);
typedef int    (*fn_sqlite3_total_changes_t)(sqlite3*);
typedef int    (*fn_sqlite3_get_autocommit_t)(sqlite3*);
typedef void   (*fn_sqlite3_free_t)(void*);
typedef int    (*fn_sqlite3_wal_checkpoint_t)(sqlite3*, const char*);
typedef sqlite3_backup *(*fn_sqlite3_backup_init_t)(sqlite3*, const char*,
                                                    sqlite3*, const char*);
typedef int    (*fn_sqlite3_backup_step_t)(sqlite3_backup*, int);
typedef int    (*fn_sqlite3_backup_finish_t)(sqlite3_backup*);
typedef int    (*fn_sqlite3_backup_remaining_t)(sqlite3_backup*);
typedef int    (*fn_sqlite3_backup_pagecount_t)(sqlite3_backup*);
typedef int    (*fn_sqlite3_errcode_t)(sqlite3*);
typedef int    (*fn_sqlite3_extended_errcode_t)(sqlite3*);
typedef const char *(*fn_sqlite3_system_errmsg_t)(sqlite3*);
typedef int    (*fn_sqlite3_threadsafe_t)(void);

/* ---- 全局函数指针 ---- */
static fn_sqlite3_open_v2_t         pfn_sqlite3_open_v2 = NULL;
static fn_sqlite3_close_t           pfn_sqlite3_close = NULL;
static fn_sqlite3_errmsg_t          pfn_sqlite3_errmsg = NULL;
static fn_sqlite3_busy_timeout_t    pfn_sqlite3_busy_timeout = NULL;
static fn_sqlite3_exec_t            pfn_sqlite3_exec = NULL;
static fn_sqlite3_prepare_v2_t      pfn_sqlite3_prepare_v2 = NULL;
static fn_sqlite3_finalize_t        pfn_sqlite3_finalize = NULL;
static fn_sqlite3_reset_t           pfn_sqlite3_reset = NULL;
static fn_sqlite3_clear_bindings_t  pfn_sqlite3_clear_bindings = NULL;
static fn_sqlite3_bind_int_t        pfn_sqlite3_bind_int = NULL;
static fn_sqlite3_bind_int64_t      pfn_sqlite3_bind_int64 = NULL;
static fn_sqlite3_bind_double_t     pfn_sqlite3_bind_double = NULL;
static fn_sqlite3_bind_text_t       pfn_sqlite3_bind_text = NULL;
static fn_sqlite3_bind_blob_t       pfn_sqlite3_bind_blob = NULL;
static fn_sqlite3_bind_null_t       pfn_sqlite3_bind_null = NULL;
static fn_sqlite3_step_t            pfn_sqlite3_step = NULL;
static fn_sqlite3_column_count_t    pfn_sqlite3_column_count = NULL;
static fn_sqlite3_column_type_t     pfn_sqlite3_column_type = NULL;
static fn_sqlite3_column_int_t      pfn_sqlite3_column_int = NULL;
static fn_sqlite3_column_int64_t    pfn_sqlite3_column_int64 = NULL;
static fn_sqlite3_column_double_t   pfn_sqlite3_column_double = NULL;
static fn_sqlite3_column_text_t     pfn_sqlite3_column_text = NULL;
static fn_sqlite3_column_blob_t     pfn_sqlite3_column_blob = NULL;
static fn_sqlite3_column_bytes_t    pfn_sqlite3_column_bytes = NULL;
static fn_sqlite3_column_name_t     pfn_sqlite3_column_name = NULL;
static fn_sqlite3_last_insert_rowid_t pfn_sqlite3_last_insert_rowid = NULL;
static fn_sqlite3_changes_t         pfn_sqlite3_changes = NULL;
static fn_sqlite3_total_changes_t   pfn_sqlite3_total_changes = NULL;
static fn_sqlite3_get_autocommit_t  pfn_sqlite3_get_autocommit = NULL;
static fn_sqlite3_free_t            pfn_sqlite3_free = NULL;
static fn_sqlite3_wal_checkpoint_t  pfn_sqlite3_wal_checkpoint = NULL;
static fn_sqlite3_backup_init_t     pfn_sqlite3_backup_init = NULL;
static fn_sqlite3_backup_step_t     pfn_sqlite3_backup_step = NULL;
static fn_sqlite3_backup_finish_t   pfn_sqlite3_backup_finish = NULL;
static fn_sqlite3_backup_remaining_t pfn_sqlite3_backup_remaining = NULL;
static fn_sqlite3_backup_pagecount_t pfn_sqlite3_backup_pagecount = NULL;
static fn_sqlite3_errcode_t         pfn_sqlite3_errcode = NULL;
static fn_sqlite3_extended_errcode_t pfn_sqlite3_extended_errcode = NULL;
static fn_sqlite3_system_errmsg_t   pfn_sqlite3_system_errmsg = NULL;
static fn_sqlite3_threadsafe_t      pfn_sqlite3_threadsafe = NULL;

#define RESOLVE(handle, name, type) do { \
    void *sym = dlsym((handle), #name); \
    pfn_##name = (type)(uintptr_t)sym; \
    if (!pfn_##name) { \
        snprintf(g_dl_err, sizeof(g_dl_err), "dlsym %s unavailable: %s", \
                 #name, dlerror()); \
    } \
} while (0)

int sqlite3_dlsym_init(void) {
    if (g_handle) return 0;

    g_handle = dlopen("libsqlite3.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!g_handle) {
        snprintf(g_dl_err, sizeof(g_dl_err), "dlopen libsqlite3.so.0 failed: %s",
                 dlerror());
        return -1;
    }
    dlerror();

    RESOLVE(g_handle, sqlite3_open_v2, fn_sqlite3_open_v2_t);
    RESOLVE(g_handle, sqlite3_close, fn_sqlite3_close_t);
    RESOLVE(g_handle, sqlite3_errmsg, fn_sqlite3_errmsg_t);
    RESOLVE(g_handle, sqlite3_busy_timeout, fn_sqlite3_busy_timeout_t);
    RESOLVE(g_handle, sqlite3_exec, fn_sqlite3_exec_t);
    RESOLVE(g_handle, sqlite3_prepare_v2, fn_sqlite3_prepare_v2_t);
    RESOLVE(g_handle, sqlite3_finalize, fn_sqlite3_finalize_t);
    RESOLVE(g_handle, sqlite3_reset, fn_sqlite3_reset_t);
    RESOLVE(g_handle, sqlite3_clear_bindings, fn_sqlite3_clear_bindings_t);
    RESOLVE(g_handle, sqlite3_bind_int, fn_sqlite3_bind_int_t);
    RESOLVE(g_handle, sqlite3_bind_int64, fn_sqlite3_bind_int64_t);
    RESOLVE(g_handle, sqlite3_bind_double, fn_sqlite3_bind_double_t);
    RESOLVE(g_handle, sqlite3_bind_text, fn_sqlite3_bind_text_t);
    RESOLVE(g_handle, sqlite3_bind_blob, fn_sqlite3_bind_blob_t);
    RESOLVE(g_handle, sqlite3_bind_null, fn_sqlite3_bind_null_t);
    RESOLVE(g_handle, sqlite3_step, fn_sqlite3_step_t);
    RESOLVE(g_handle, sqlite3_column_count, fn_sqlite3_column_count_t);
    RESOLVE(g_handle, sqlite3_column_type, fn_sqlite3_column_type_t);
    RESOLVE(g_handle, sqlite3_column_int, fn_sqlite3_column_int_t);
    RESOLVE(g_handle, sqlite3_column_int64, fn_sqlite3_column_int64_t);
    RESOLVE(g_handle, sqlite3_column_double, fn_sqlite3_column_double_t);
    RESOLVE(g_handle, sqlite3_column_text, fn_sqlite3_column_text_t);
    RESOLVE(g_handle, sqlite3_column_blob, fn_sqlite3_column_blob_t);
    RESOLVE(g_handle, sqlite3_column_bytes, fn_sqlite3_column_bytes_t);
    RESOLVE(g_handle, sqlite3_column_name, fn_sqlite3_column_name_t);
    RESOLVE(g_handle, sqlite3_last_insert_rowid, fn_sqlite3_last_insert_rowid_t);
    RESOLVE(g_handle, sqlite3_changes, fn_sqlite3_changes_t);
    RESOLVE(g_handle, sqlite3_total_changes, fn_sqlite3_total_changes_t);
    RESOLVE(g_handle, sqlite3_get_autocommit, fn_sqlite3_get_autocommit_t);
    RESOLVE(g_handle, sqlite3_free, fn_sqlite3_free_t);
    RESOLVE(g_handle, sqlite3_wal_checkpoint, fn_sqlite3_wal_checkpoint_t);
    RESOLVE(g_handle, sqlite3_backup_init, fn_sqlite3_backup_init_t);
    RESOLVE(g_handle, sqlite3_backup_step, fn_sqlite3_backup_step_t);
    RESOLVE(g_handle, sqlite3_backup_finish, fn_sqlite3_backup_finish_t);
    RESOLVE(g_handle, sqlite3_backup_remaining, fn_sqlite3_backup_remaining_t);
    RESOLVE(g_handle, sqlite3_backup_pagecount, fn_sqlite3_backup_pagecount_t);
    RESOLVE(g_handle, sqlite3_errcode, fn_sqlite3_errcode_t);
    RESOLVE(g_handle, sqlite3_extended_errcode, fn_sqlite3_extended_errcode_t);
    RESOLVE(g_handle, sqlite3_system_errmsg, fn_sqlite3_system_errmsg_t);
    RESOLVE(g_handle, sqlite3_threadsafe, fn_sqlite3_threadsafe_t);

    return 0;
}

const char *sqlite3_dlsym_error(void) {
    return g_dl_err[0] ? g_dl_err : NULL;
}

/* ---- 转发函数：API 名 -> 真实函数指针 ---- */
int sqlite3_open_v2(const char *f, sqlite3 **pp, int fl, const char *v) {
    return pfn_sqlite3_open_v2(f, pp, fl, v);
}
int sqlite3_close(sqlite3 *db) { return pfn_sqlite3_close(db); }
const char *sqlite3_errmsg(sqlite3 *db) { return pfn_sqlite3_errmsg(db); }
int sqlite3_busy_timeout(sqlite3 *db, int ms) { return pfn_sqlite3_busy_timeout(db, ms); }
int sqlite3_exec(sqlite3 *db, const char *sql,
                 int (*cb)(void*,int,char**,char**), void *a, char **e) {
    return pfn_sqlite3_exec(db, sql, cb, a, e);
}
int sqlite3_prepare_v2(sqlite3 *db, const char *s, int n, sqlite3_stmt **st, const char **t) {
    return pfn_sqlite3_prepare_v2(db, s, n, st, t);
}
int sqlite3_finalize(sqlite3_stmt *st) { return pfn_sqlite3_finalize(st); }
int sqlite3_reset(sqlite3_stmt *st) { return pfn_sqlite3_reset(st); }
int sqlite3_clear_bindings(sqlite3_stmt *st) { return pfn_sqlite3_clear_bindings(st); }
int sqlite3_bind_int(sqlite3_stmt *st, int i, int v) { return pfn_sqlite3_bind_int(st, i, v); }
int sqlite3_bind_int64(sqlite3_stmt *st, int i, sqlite3_int64 v) { return pfn_sqlite3_bind_int64(st, i, v); }
int sqlite3_bind_double(sqlite3_stmt *st, int i, double v) { return pfn_sqlite3_bind_double(st, i, v); }
int sqlite3_bind_text(sqlite3_stmt *st, int i, const char *d, int n, void(*x)(void*)) {
    return pfn_sqlite3_bind_text(st, i, d, n, x);
}
int sqlite3_bind_blob(sqlite3_stmt *st, int i, const void *d, int n, void(*x)(void*)) {
    return pfn_sqlite3_bind_blob(st, i, d, n, x);
}
int sqlite3_bind_null(sqlite3_stmt *st, int i) { return pfn_sqlite3_bind_null(st, i); }
int sqlite3_step(sqlite3_stmt *st) { return pfn_sqlite3_step(st); }
int sqlite3_column_count(sqlite3_stmt *st) { return pfn_sqlite3_column_count(st); }
int sqlite3_column_type(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_type(st, i); }
int sqlite3_column_int(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_int(st, i); }
sqlite3_int64 sqlite3_column_int64(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_int64(st, i); }
double sqlite3_column_double(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_double(st, i); }
const char *sqlite3_column_text(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_text(st, i); }
const void *sqlite3_column_blob(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_blob(st, i); }
int sqlite3_column_bytes(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_bytes(st, i); }
const char *sqlite3_column_name(sqlite3_stmt *st, int i) { return pfn_sqlite3_column_name(st, i); }
sqlite3_int64 sqlite3_last_insert_rowid(sqlite3 *db) { return pfn_sqlite3_last_insert_rowid(db); }
int sqlite3_changes(sqlite3 *db) { return pfn_sqlite3_changes(db); }
int sqlite3_total_changes(sqlite3 *db) { return pfn_sqlite3_total_changes(db); }
int sqlite3_get_autocommit(sqlite3 *db) { return pfn_sqlite3_get_autocommit(db); }
void sqlite3_free(void *p) { pfn_sqlite3_free(p); }
int sqlite3_wal_checkpoint(sqlite3 *db, const char *z) { return pfn_sqlite3_wal_checkpoint(db, z); }
sqlite3_backup *sqlite3_backup_init(sqlite3 *d, const char *dn, sqlite3 *s, const char *sn) {
    return pfn_sqlite3_backup_init(d, dn, s, sn);
}
int sqlite3_backup_step(sqlite3_backup *b, int n) { return pfn_sqlite3_backup_step(b, n); }
int sqlite3_backup_finish(sqlite3_backup *b) { return pfn_sqlite3_backup_finish(b); }
int sqlite3_backup_remaining(sqlite3_backup *b) { return pfn_sqlite3_backup_remaining(b); }
int sqlite3_backup_pagecount(sqlite3_backup *b) { return pfn_sqlite3_backup_pagecount(b); }
int sqlite3_errcode(sqlite3 *db) { return pfn_sqlite3_errcode(db); }
int sqlite3_extended_errcode(sqlite3 *db) { return pfn_sqlite3_extended_errcode(db); }
const char *sqlite3_system_errmsg(sqlite3 *db) { return pfn_sqlite3_system_errmsg(db); }
int sqlite3_threadsafe(void) { return pfn_sqlite3_threadsafe(); }
