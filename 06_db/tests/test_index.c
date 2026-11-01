#include "db.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
static int pass=0, fail=0;
#define CK(c,m) do{ if(c){pass++;printf("[PASS] %s\n",m);} else{fail++;printf("[FAIL] %s\n",m);} }while(0)

int main(void){
    printf("=== 06_db 索引/校验/恢复测试 ===\n");
    const char *p = "/tmp/t_db.idx";
    unlink(p);
    db_t db;
    CK(db_open_rw(&db, p) == 0, "db_open_rw 成功");

    uint8_t d1[16]; for(int i=0;i<16;i++) d1[i]=(uint8_t)i;
    CK(db_append(&db, 1, d1, 16) == 0, "append type=1");
    CK(db_append(&db, 2, d1, 8)  == 0, "append type=2");
    CK(db_append(&db, 1, d1, 4)  == 0, "append type=1 第二条");
    db_close(&db);

    db_t rd;
    CK(db_open_ro(&rd, p) == 0, "db_open_ro 成功");
    db_index_t ix;
    CK(db_index_build(&rd, &ix) == 0, "索引构建成功");
    CK(ix.n == 3, "索引共 3 条记录");
    CK(db_index_count(&ix, 1) == 2, "type=1 有 2 条");
    CK(db_index_count(&ix, 2) == 1, "type=2 有 1 条");

    const db_entry_t *e = db_index_find(&ix, 1, 1);
    CK(e != NULL && e->len == 4, "按 type+序号定位到第 2 条 type=1(len=4)");
    uint8_t t=0, out[64]; uint16_t ol=0;
    CK(e && db_seek_read(&rd, e, &t, out, &ol) == 0, "随机读取成功");
    CK(t == 1 && ol == 4 && memcmp(out, d1, 4) == 0, "随机读取内容一致");

    const db_entry_t *e2 = db_index_find(&ix, 2, 0);
    CK(e2 && db_seek_read(&rd, e2, &t, out, &ol) == 0 && t == 2 && ol == 8,
       "type=2 随机读取一致");
    CK(db_index_find(&ix, 2, 5) == NULL, "越界序号返回 NULL");
    db_index_free(&ix);
    db_close(&rd);

    /* 完整性校验：干净库 */
    size_t good = 0;
    long bad = db_scan_verify(p, &good);
    CK(bad == 0 && good == 3, "干净库校验通过(3 条完好)");

    /* 人为截断尾部 → 应检出损坏偏移并恢复 */
    long fsz = 0;
    { FILE *f = fopen(p,"rb"); fseek(f,0,SEEK_END); fsz = ftell(f); fclose(f); }
    CK(db_truncate_at(p, fsz - 3) == 0, "截断文件尾部");
    size_t good2 = 0;
    long bad2 = db_scan_verify(p, &good2);
    CK(bad2 > 0, "截断后校验检出损坏偏移");
    printf("  [INFO] 完好=%zu 损坏偏移=%ld 原大小=%ld\n", good2, bad2, fsz);
    CK(bad2 == 34, "损坏偏移定位到第三条记录起点(34)");
    CK(good2 == 2, "损坏前完好记录为 2 条");
    CK(db_truncate_at(p, bad2) == 0, "按损坏偏移截断恢复");
    CK(db_scan_verify(p, &good2) == 0 && good2 == 2, "恢复后校验干净且保留 2 条");

    unlink(p);
    printf("total=%d pass=%d fail=%d\n", pass+fail, pass, fail);
    return fail ? 1 : 0;
}
