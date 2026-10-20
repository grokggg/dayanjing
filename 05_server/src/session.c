#include "session.h"
#include <stdlib.h>
#include <string.h>

static unsigned hash_id(const uint8_t *id) {
    unsigned h = 0;
    for (int i = 0; i < SESSION_ID_LEN; i++) h = h * 31u + id[i];
    return h % 256u;
}

void st_init(session_table_t *t) {
    if (!t) return;
    memset(t, 0, sizeof *t);
}

static void lru_unlink(session_table_t *t, session_t *s) {
    if (s->lprev) s->lprev->lnext = s->lnext; else t->head = s->lnext;
    if (s->lnext) s->lnext->lprev = s->lprev; else t->tail = s->lprev;
    s->lprev = s->lnext = NULL;
}

static void lru_push_front(session_table_t *t, session_t *s) {
    s->lprev = NULL;
    s->lnext = t->head;
    if (t->head) t->head->lprev = s;
    t->head = s;
    if (!t->tail) t->tail = s;
}

int st_insert(session_table_t *t, const uint8_t *id, int fd) {
    if (!t || !id) return -1;
    if (st_lookup(t, id)) return -1;          /* 已存在 */
    session_t *s = calloc(1, sizeof *s);
    if (!s) return -1;
    memcpy(s->id, id, SESSION_ID_LEN);
    s->fd = fd;
    unsigned h = hash_id(id);
    s->hnext = t->buckets[h];
    t->buckets[h] = s;
    lru_push_front(t, s);
    t->count++;
    return 0;
}

session_t *st_lookup(session_table_t *t, const uint8_t *id) {
    if (!t || !id) return NULL;
    session_t *s = t->buckets[hash_id(id)];
    while (s) {
        if (memcmp(s->id, id, SESSION_ID_LEN) == 0) return s;
        s = s->hnext;
    }
    return NULL;
}

int st_remove(session_table_t *t, const uint8_t *id) {
    if (!t || !id) return -1;
    unsigned h = hash_id(id);
    session_t **pp = &t->buckets[h];
    while (*pp) {
        if (memcmp((*pp)->id, id, SESSION_ID_LEN) == 0) {
            session_t *s = *pp;
            *pp = s->hnext;
            lru_unlink(t, s);
            free(s);
            t->count--;
            return 0;
        }
        pp = &(*pp)->hnext;
    }
    return -1;
}

void st_touch(session_table_t *t, session_t *s) {
    if (!t || !s) return;
    if (t->head == s) return;                 /* 已在头部 */
    lru_unlink(t, s);
    lru_push_front(t, s);
}

session_t *st_lru(session_table_t *t) {
    return t ? t->tail : NULL;
}
