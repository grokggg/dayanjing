#include "db.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    const char *path = "/tmp/dayanjing_test_db.bin";
    db_t w;
    CHECK(db_open_rw(&w, path) == 0);
    CHECK(db_append(&w, 1, (const uint8_t *)"abc", 3) == 0);
    CHECK(db_append(&w, 2, (const uint8_t *)"de", 2) == 0);
    CHECK(db_append(&w, 3, (const uint8_t *)"", 0) == 0);   /* 空记录 */
    CHECK(db_close(&w) == 0);

    db_t r;
    CHECK(db_open_ro(&r, path) == 0);
    uint8_t buf[256];
    uint8_t type;
    uint16_t len;

    CHECK(db_next(&r, &type, buf, &len) == 1);
    CHECK(type == 1 && len == 3 && memcmp(buf, "abc", 3) == 0);

    CHECK(db_next(&r, &type, buf, &len) == 1);
    CHECK(type == 2 && len == 2 && memcmp(buf, "de", 2) == 0);

    CHECK(db_next(&r, &type, buf, &len) == 1);
    CHECK(type == 3 && len == 0);

    CHECK(db_next(&r, &type, buf, &len) == 0);   /* EOF */
    CHECK(db_close(&r) == 0);

    printf("06_db tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
