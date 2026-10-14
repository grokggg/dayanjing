/*
 * db_pool.c -- 连接池（票据式借还）
 */

#include "db.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

struct pool_slot {
    struct db *db;
    bool       in_use;
    time_t     borrowed_at;
};

struct db_pool {
    struct db_config cfg;
    struct pool_slot slots[DB_POOL_MAX];
    size_t           capacity;
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
};

db_err_t db_pool_create(struct db_pool **out, const char *uri, size_t max_conn) {
    if (!out || max_conn == 0 || max_conn > DB_POOL_MAX) return DB_ERR;

    struct db_pool *p = calloc(1, sizeof(*p));
    if (!p) return DB_NOMEM;

    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
    p->capacity = max_conn;

    /* uri 解析: sqlite://path */
    if (strncmp(uri, "sqlite://", 9) == 0) {
        p->cfg.engine = DB_ENGINE_SQLITE;
        p->cfg.path_or_dbname = strdup(uri + 9);
        p->cfg.create_if_missing = true;
        p->cfg.busy_timeout_ms = 3000;
    } else {
        pthread_mutex_destroy(&p->mu);
        pthread_cond_destroy(&p->cv);
        free(p);
        return DB_NOTSUP;
    }

    *out = p;
    return DB_OK;
}

db_err_t db_pool_acquire(struct db_pool *p, struct db **out, uint32_t timeout_ms) {
    if (!p || !out) return DB_ERR;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }

    pthread_mutex_lock(&p->mu);

    db_err_t rc;
    while (1) {
        /* 先尝试找到一个空闲槽 */
        rc = DB_TIMEOUT;
        for (size_t i = 0; i < p->capacity; i++) {
            if (!p->slots[i].in_use) {
                if (!p->slots[i].db) {
                    /* 惰性创建 */
                    if (db_open(&p->cfg, &p->slots[i].db) != DB_OK) {
                        rc = DB_ERR;
                        break;
                    }
                }
                p->slots[i].in_use = true;
                p->slots[i].borrowed_at = time(NULL);
                *out = p->slots[i].db;
                rc = DB_OK;
                goto done;
            }
        }
        if (rc == DB_ERR) break;   /* db_open 失败，不重试 */

        /* 全部繁忙：等待或超时 */
        if (timeout_ms == 0) break;
        if (pthread_cond_timedwait(&p->cv, &p->mu, &ts) == ETIMEDOUT) break;
        /* 被唤醒后重新遍历 */
    }

done:
    pthread_mutex_unlock(&p->mu);
    return rc;
}

db_err_t db_pool_release(struct db_pool *p, struct db *db) {
    if (!p || !db) return DB_ERR;
    pthread_mutex_lock(&p->mu);
    db_err_t rc = DB_NOTFOUND;
    for (size_t i = 0; i < p->capacity; i++) {
        if (p->slots[i].db == db && p->slots[i].in_use) {
            p->slots[i].in_use = false;
            rc = DB_OK;
            break;
        }
    }
    pthread_cond_signal(&p->cv);
    pthread_mutex_unlock(&p->mu);
    return rc;
}

void db_pool_destroy(struct db_pool *p) {
    if (!p) return;
    pthread_mutex_lock(&p->mu);
    for (size_t i = 0; i < p->capacity; i++) {
        if (p->slots[i].db) db_close(p->slots[i].db);
    }
    pthread_mutex_unlock(&p->mu);
    pthread_mutex_destroy(&p->mu);
    pthread_cond_destroy(&p->cv);
    free((void *)p->cfg.path_or_dbname);
    free(p);
}
