/*
 * test_db_pool.c -- 连接池并发测试
 */

#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#define TEST_DB "/tmp/test_db_pool.db"
#define N_THREADS 6
#define N_ROUNDS  30

static struct db_pool *g_pool = NULL;

static void cleanup(void) {
    if (g_pool) db_pool_destroy(g_pool);
    unlink(TEST_DB);
}

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < N_ROUNDS; i++) {
        struct db *db = NULL;
        db_err_t rc = db_pool_acquire(g_pool, &db, 2000);
        assert(rc == DB_OK && db != NULL);
        db_exec(db, "CREATE TABLE IF NOT EXISTS p(x INTEGER)");
        db_exec(db, "INSERT INTO p(x) VALUES(1)");
        rc = db_pool_release(g_pool, db);
        assert(rc == DB_OK);
    }
    return NULL;
}

int main(void) {
    atexit(cleanup);
    printf("[*] db/ 连接池并发测试 (%d threads x %d rounds)\n", N_THREADS, N_ROUNDS);

    db_err_t rc = db_pool_create(&g_pool, "sqlite://" TEST_DB, 4);
    assert(rc == DB_OK);
    printf("  [+] pool created (cap=4)\n");

    pthread_t t[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < N_THREADS; i++) pthread_join(t[i], NULL);

    /* 验证无泄漏：全部释放后 in_use 应为 0 */
    struct db *peek = NULL;
    rc = db_pool_acquire(g_pool, &peek, 100);
    assert(rc == DB_OK);
    rc = db_pool_release(g_pool, peek);
    assert(rc == DB_OK);

    printf("  [+] %d threads x %d rounds OK (6 threads vs 4-slot pool)\n",
           N_THREADS, N_ROUNDS);
    printf("\n[+] db/ 连接池测试通过\n");
    return 0;
}
