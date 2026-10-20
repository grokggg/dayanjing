#ifndef SESSION_H
#define SESSION_H
#include <stdint.h>
#include <stddef.h>

#define SESSION_ID_LEN 6

typedef struct session {
    uint8_t id[SESSION_ID_LEN];
    int     fd;
    struct session *hnext;          /* 哈希链 */
    struct session *lprev, *lnext;  /* LRU 双向链表 */
} session_t;

typedef struct {
    session_t *buckets[256];
    session_t *head, *tail;         /* head=最近使用, tail=最久未用 */
    size_t     count;
} session_table_t;

void       st_init(session_table_t *t);
int        st_insert(session_table_t *t, const uint8_t *id, int fd);
session_t *st_lookup(session_table_t *t, const uint8_t *id);
int        st_remove(session_table_t *t, const uint8_t *id);
void       st_touch(session_table_t *t, session_t *s);
session_t *st_lru(session_table_t *t);   /* 返回最久未用（tail） */

#endif
