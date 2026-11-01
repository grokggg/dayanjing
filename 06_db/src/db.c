#include "db.h"

#define DB_MAGIC0 0xDA
#define DB_MAGIC1 0x7A

static int write_header(FILE *f, uint8_t type, uint16_t len) {
    if (fputc(DB_MAGIC0, f) == EOF) return -1;
    if (fputc(DB_MAGIC1, f) == EOF) return -1;
    if (fputc((int)type, f) == EOF) return -1;
    if (fputc((int)(len & 0xFFu), f) == EOF) return -1;
    if (fputc((int)((len >> 8) & 0xFFu), f) == EOF) return -1;
    return 0;
}

static int read_header(FILE *f, uint8_t *type, uint16_t *len, int *eof) {
    int c = fgetc(f);
    if (c == EOF) { *eof = 1; return 0; }
    if (c != DB_MAGIC0) return -1;
    c = fgetc(f);
    if (c != DB_MAGIC1) return -1;
    int t = fgetc(f);
    int lo = fgetc(f);
    int hi = fgetc(f);
    if (t == EOF || lo == EOF || hi == EOF) return -1;
    *type = (uint8_t)t;
    *len = (uint16_t)((uint16_t)lo | (uint16_t)((uint16_t)hi << 8));
    return 0;
}

int db_open_rw(db_t *db, const char *path) {
    if (!db || !path) return -1;
    db->f = fopen(path, "w+b");
    return db->f ? 0 : -1;
}

int db_open_ro(db_t *db, const char *path) {
    if (!db || !path) return -1;
    db->f = fopen(path, "rb");
    return db->f ? 0 : -1;
}

int db_close(db_t *db) {
    if (!db || !db->f) return -1;
    int r = fclose(db->f);
    db->f = NULL;
    return r;
}

int db_append(db_t *db, uint8_t type, const uint8_t *data, uint16_t len) {
    if (!db || !db->f) return -1;
    if (len && !data) return -1;
    if (write_header(db->f, type, len) != 0) return -1;
    if (len && fwrite(data, 1, len, db->f) != (size_t)len) return -1;
    return 0;
}

int db_next(db_t *db, uint8_t *type, uint8_t *data, uint16_t *len) {
    if (!db || !db->f || !type || !data || !len) return -1;
    int eof = 0;
    if (read_header(db->f, type, len, &eof) != 0) return -1;
    if (eof) return 0;
    if (*len == 0) return 1;
    if (fread(data, 1, *len, db->f) != (size_t)*len) return -1;
    return 1;
}
