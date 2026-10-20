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

#endif
