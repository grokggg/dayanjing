#include "session.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    session_table_t t;
    st_init(&t);
    CHECK(t.count == 0);

    uint8_t a[6] = {1,2,3,4,5,6};
    uint8_t b[6] = {6,5,4,3,2,1};
    uint8_t c[6] = {9,9,9,9,9,9};

    CHECK(st_insert(&t, a, 10) == 0);
    CHECK(st_insert(&t, b, 20) == 0);
    CHECK(st_insert(&t, c, 30) == 0);
    CHECK(t.count == 3);

    /* 重复插入应失败 */
    CHECK(st_insert(&t, a, 99) != 0);
    CHECK(t.count == 3);

    /* 查找 */
    session_t *sa = st_lookup(&t, a);
    CHECK(sa && sa->fd == 10);
    CHECK(st_lookup(&t, b) && st_lookup(&t, b)->fd == 20);
    CHECK(st_lookup(&t, c) && st_lookup(&t, c)->fd == 30);

    /* LRU: 插入顺序 a,b,c -> head=c(最新), tail=a(最久) */
    CHECK(t.head == st_lookup(&t, c));
    CHECK(st_lru(&t) == sa);

    /* touch a 后，a 变最新，最久变成 b */
    st_touch(&t, sa);
    CHECK(t.head == sa);
    CHECK(st_lru(&t) == st_lookup(&t, b));

    /* 删除 b */
    CHECK(st_remove(&t, b) == 0);
    CHECK(t.count == 2);
    CHECK(st_lookup(&t, b) == NULL);
    CHECK(st_remove(&t, b) != 0);   /* 重复删除失败 */

    /* 删除不存在的 */
    uint8_t z[6] = {0,0,0,0,0,0};
    CHECK(st_remove(&t, z) != 0);

    printf("05_server session tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
