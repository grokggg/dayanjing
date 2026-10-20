#ifndef DB_H
#define DB_H
#include <stdint.h>
#include <stdio.h>

typedef struct { FILE *f; } db_t;

int db_open_rw(db_t *db, const char *path);   /* 写打开：不存在则创建并清空 */
int db_open_ro(db_t *db, const char *path);   /* 只读打开 */
int db_close(db_t *db);

/* 追加一条记录；len 可为 0。成功 0 */
int db_append(db_t *db, uint8_t type, const uint8_t *data, uint16_t len);

/* 读下一条：1=读到, 0=EOF, -1=错误/损坏。data 缓冲区由调用方保证 >= len */
int db_next(db_t *db, uint8_t *type, uint8_t *data, uint16_t *len);


/* ---- 索引 / 完整性 / 崩溃恢复（不改动原有记录格式） ---- */

typedef struct { uint8_t type; long offset; uint16_t len; } db_entry_t;

typedef struct {
    db_entry_t *v;
    size_t      n, cap;
} db_index_t;

/* 扫描全库建索引；成功 0。索引条目按文件顺序 */
int    db_index_build(db_t *db, db_index_t *ix);
void   db_index_free(db_index_t *ix);
size_t db_index_count(const db_index_t *ix, uint8_t type);
const db_entry_t *db_index_find(const db_index_t *ix, uint8_t type, size_t nth);

/* 按索引条目随机读取一条记录；成功 0 */
int    db_seek_read(db_t *db, const db_entry_t *e,
                    uint8_t *type, uint8_t *data, uint16_t *len);

/* 校验：返回 0 表示全库完好；>0 返回首个损坏记录的字节偏移；-1 打不开。
 * *good 回填损坏前完好记录数 */
long   db_scan_verify(const char *path, size_t *good);

/* 崩溃恢复：把文件截断到 offset（丢弃损坏尾部）。成功 0 */
int    db_truncate_at(const char *path, long offset);

#endif
