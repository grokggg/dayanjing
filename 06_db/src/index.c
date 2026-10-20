#define _DEFAULT_SOURCE
#include "db.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define DB_MAGIC0 0xDA
#define DB_MAGIC1 0x7A

int db_index_build(db_t *db, db_index_t *ix){
    if(!db || !db->f || !ix) return -1;
    memset(ix, 0, sizeof *ix);
    rewind(db->f);
    for(;;){
        long off = ftell(db->f);
        int c0 = fgetc(db->f);
        if(c0 == EOF) break;
        if(c0 != DB_MAGIC0) break;
        int c1 = fgetc(db->f);
        if(c1 != DB_MAGIC1) break;
        int t = fgetc(db->f);
        int lo = fgetc(db->f);
        int hi = fgetc(db->f);
        if(t == EOF || lo == EOF || hi == EOF) break;
        uint16_t len = (uint16_t)((uint16_t)lo | (uint16_t)((uint16_t)hi << 8));
        if(len){
            uint8_t tmp[65536];
            if(fread(tmp, 1, len, db->f) != len) break;   /* fseek 可越 EOF，必须实读 */
        }
        if(ix->n + 1 > ix->cap){
            size_t nc = ix->cap ? ix->cap * 2 : 32;
            db_entry_t *nv = realloc(ix->v, nc * sizeof *nv);
            if(!nv) return -1;
            ix->v = nv; ix->cap = nc;
        }
        ix->v[ix->n].type = (uint8_t)t;
        ix->v[ix->n].offset = off;
        ix->v[ix->n].len = len;
        ix->n++;
    }
    rewind(db->f);
    return 0;
}

void db_index_free(db_index_t *ix){
    if(!ix) return;
    free(ix->v); memset(ix, 0, sizeof *ix);
}

size_t db_index_count(const db_index_t *ix, uint8_t type){
    size_t n = 0;
    if(!ix) return 0;
    for(size_t i = 0; i < ix->n; i++) if(ix->v[i].type == type) n++;
    return n;
}

const db_entry_t *db_index_find(const db_index_t *ix, uint8_t type, size_t nth){
    if(!ix) return NULL;
    size_t seen = 0;
    for(size_t i = 0; i < ix->n; i++)
        if(ix->v[i].type == type){
            if(seen == nth) return &ix->v[i];
            seen++;
        }
    return NULL;
}

int db_seek_read(db_t *db, const db_entry_t *e,
                 uint8_t *type, uint8_t *data, uint16_t *len){
    if(!db || !db->f || !e || !type || !len) return -1;
    if(fseek(db->f, e->offset, SEEK_SET) != 0) return -1;
    if(fgetc(db->f) != DB_MAGIC0) return -1;
    if(fgetc(db->f) != DB_MAGIC1) return -1;
    int t = fgetc(db->f);
    int lo = fgetc(db->f);
    int hi = fgetc(db->f);
    if(t == EOF || lo == EOF || hi == EOF) return -1;
    uint16_t l = (uint16_t)((uint16_t)lo | (uint16_t)((uint16_t)hi << 8));
    if(l > e->len) return -1;
    if(l && data){
        if(fread(data, 1, l, db->f) != l) return -1;
    }
    *type = (uint8_t)t; *len = l;
    return 0;
}

long db_scan_verify(const char *path, size_t *good){
    if(good) *good = 0;
    if(!path) return -1;
    FILE *f = fopen(path, "rb");
    if(!f) return -1;
    long off = 0;
    for(;;){
        long rec = ftell(f);
        int c0 = fgetc(f);
        if(c0 == EOF){ fclose(f); return 0; }      /* 干净结尾 */
        if(c0 != DB_MAGIC0){ fclose(f); return rec; }
        int c1 = fgetc(f);
        if(c1 != DB_MAGIC1){ fclose(f); return rec; }
        int t = fgetc(f), lo = fgetc(f), hi = fgetc(f);
        if(t == EOF || lo == EOF || hi == EOF){ fclose(f); return rec; }
        uint16_t len = (uint16_t)((uint16_t)lo | (uint16_t)((uint16_t)hi << 8));
        if(len){
            uint8_t tmp[65536];
            if(fread(tmp, 1, len, f) != len){ fclose(f); return rec; }  /* 尾部截断在此现形 */
        }
        long after = ftell(f);
        if(after < 0){ fclose(f); return rec; }
        if(good) (*good)++;
        off = after; (void)off;
    }
}

int db_truncate_at(const char *path, long offset){
    if(!path || offset < 0) return -1;
    int r = truncate(path, (off_t)offset);
    return r == 0 ? 0 : -1;
}
