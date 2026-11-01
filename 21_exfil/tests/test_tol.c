/*
 * test_tol.c —— 验签失败容忍层
 *
 * 结构：operator 先写进一条 scratch 管道，测试读出这 512 字节，
 *       可原样转发 / 篡改 / 额外塞一个伪造信元，再写进 implant 的读端。
 *       这样能精确控制线上字节，而不必真的去改网络。
 */
#include "exfil_tol.h"
#include "exfil_task_link.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

static int total = 0, pass = 0, fail = 0;
static void check(int cond, const char *what) {
    total++;
    if (cond) { pass++; printf("[PASS] %s\n", what); }
    else      { fail++; printf("[FAIL] %s\n", what); }
}

static uint8_t KS[16], KR[16], PFX[8];

/* 用 operator 生成一条命令信元，取回线上字节 */
static int make_cmd_cell(exfil_task_chan_t *op, int scratch_w, uint64_t seq,
                         uint8_t opcode, uint8_t cell[P2P_CELL_WIRE]) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    (void)scratch_w;
    exfil_task_cmd_t c; memset(&c, 0, sizeof c);
    c.opcode = opcode; c.task_id = seq;
    int r = exfil_task_chan_cmd(op, sp[0], seq, &c);
    ssize_t n = read(sp[1], cell, P2P_CELL_WIRE);
    close(sp[0]); close(sp[1]);
    return (r == EXF_TASK_OK && n == P2P_CELL_WIRE) ? 0 : -1;
}

static void wr(int fd, const uint8_t *b) {
    size_t off = 0;
    while (off < P2P_CELL_WIRE) {
        ssize_t n = write(fd, b + off, P2P_CELL_WIRE - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
}

int main(void) {
    for (int i = 0; i < 16; i++) { KS[i] = (uint8_t)(0x10 + i); KR[i] = (uint8_t)(0x80 + i); }
    for (int i = 0; i < 8;  i++) PFX[i] = (uint8_t)(0xA0 + i);

    exfil_task_chan_t op, im;
    check(exfil_task_chan_init(&op, KS, KR, PFX) == EXF_TASK_OK, "operator chan 初始化");
    check(exfil_task_chan_init(&im, KR, KS, PFX) == EXF_TASK_OK, "implant chan 初始化（方向相反）");

    int up[2];   /* 测试写 up[1]，implant 读 up[0] */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, up) != 0) { printf("socketpair 失败\n"); return 1; }

    exfil_tol_t t;
    check(exfil_tol_init(&t, 8) == EXF_TOL_OK, "tol 初始化 (max=8)");
    check(t.max_consec == 8, "max_consec 生效");

    uint8_t cell[P2P_CELL_WIRE];
    uint64_t seq = 0;
    exfil_task_cmd_t c;

    /* ---- 1. 正常命令 ---- */
    check(make_cmd_cell(&op, 0, 1, EXF_TASK_OP_START, cell) == 0, "生成命令信元 #1");
    wr(up[1], cell);
    check(exfil_tol_recv_cmd(&t, &im, up[0], &seq, &c) == EXF_TOL_OK, "正常命令 -> OK");
    check(seq == 1 && c.opcode == EXF_TASK_OP_START, "seq 与 opcode 正确");

    /* ---- 2. 单个被篡改的信元：容忍 + 之后恢复 ---- */
    uint8_t bad[P2P_CELL_WIRE];
    check(make_cmd_cell(&op, 0, 2, EXF_TASK_OP_STOP, bad) == 0, "生成命令信元 #2");
    bad[P2P_CELL_WIRE - 1] ^= 0x01;          /* 就地篡改一个比特 */
    wr(up[1], bad);
    check(exfil_tol_recv_cmd(&t, &im, up[0], &seq, &c) == EXF_TOL_SKIP,
          "★ 单个坏信元 -> SKIP（不杀链路）");
    check(t.n_fail == 1 && t.consec == 1, "失败计数正确");

    check(make_cmd_cell(&op, 0, 3, EXF_TASK_OP_START, cell) == 0, "生成命令信元 #3");
    wr(up[1], cell);
    check(exfil_tol_recv_cmd(&t, &im, up[0], &seq, &c) == EXF_TOL_OK,
          "★ 坏信元之后下一条正常恢复");
    check(t.consec == 0, "成功后连续失败计数清零");
    check(seq == 3, "恢复后 seq 正确（未跳号错乱）");

    /* ---- 3. 通过验签的 PAD 会清零连续失败（对齐的正证据） ---- */
    uint8_t pad[P2P_CELL_WIRE];
    check(p2p_cell_pack_cover(&op.cell, pad) == P2P_CELL_OK, "生成覆盖信元");
    wr(up[1], pad);
    check(exfil_tol_recv_cmd(&t, &im, up[0], &seq, &c) == EXF_TOL_PAD, "覆盖信元 -> PAD");
    check(t.n_pad == 1, "PAD 计数正确");

    /* ---- 4. 注入（多塞一个整信元）-> 永久失步 -> 超上限后 FATAL ---- */
    exfil_task_chan_t op2, im2;
    exfil_task_chan_init(&op2, KS, KR, PFX);
    exfil_task_chan_init(&im2, KR, KS, PFX);
    int up2[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, up2);

    exfil_tol_t t2;
    exfil_tol_init(&t2, 4);

    /* 先正常送一条，保证对齐 */
    make_cmd_cell(&op2, 0, 10, EXF_TASK_OP_START, cell);
    wr(up2[1], cell);
    check(exfil_tol_recv_cmd(&t2, &im2, up2[0], &seq, &c) == EXF_TOL_OK, "注入前基线正常");

    /* 注入一个伪造的整信元 —— 流整体偏移一格 */
    uint8_t junk[P2P_CELL_WIRE];
    memset(junk, 0xCD, sizeof junk);
    wr(up2[1], junk);
    check(exfil_tol_recv_cmd(&t2, &im2, up2[0], &seq, &c) == EXF_TOL_SKIP, "伪造信元 -> SKIP");

    /* 此后即使 operator 发真命令也全部对不上位置 */
    int saw_fatal = 0, steps = 0;
    for (int i = 0; i < 10 && !saw_fatal; i++) {
        make_cmd_cell(&op2, 0, 20 + (uint64_t)i, EXF_TASK_OP_START, cell);
        wr(up2[1], cell);
        int r = exfil_tol_recv_cmd(&t2, &im2, up2[0], &seq, &c);
        steps++;
        if (r == EXF_TOL_FATAL) saw_fatal = 1;
    }
    check(saw_fatal, "★ 注入导致失步 -> 最终 FATAL（不静默黑洞）");
    check(steps <= 6, "在容忍上限附近即判定失步（未无限重试）");
    printf("[INFO] 注入后 %d 步内判定失步；累计失败=%llu\n",
           steps, (unsigned long long)t2.n_fail);

    /* ---- 5. max_consec=0：不容忍，第一次失败即 FATAL ---- */
    exfil_task_chan_t op3, im3;
    exfil_task_chan_init(&op3, KS, KR, PFX);
    exfil_task_chan_init(&im3, KR, KS, PFX);
    int up3[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, up3);
    exfil_tol_t t3;
    exfil_tol_init(&t3, 0);
    check(t3.max_consec == 8, "max_consec=0 时回落内置默认 8");

    make_cmd_cell(&op3, 0, 30, EXF_TASK_OP_STOP, bad);
    bad[5] ^= 0xFF;
    wr(up3[1], bad);
    check(exfil_tol_recv_cmd(&t3, &im3, up3[0], &seq, &c) == EXF_TOL_SKIP, "默认容忍下首次失败仍 SKIP");

    /* ---- 6. 参数校验 ---- */
    check(exfil_tol_recv_cmd(NULL, &im, up[0], &seq, &c) == EXF_TOL_ARG, "NULL tol -> ARG");
    check(exfil_tol_recv_cmd(&t, NULL, up[0], &seq, &c) == EXF_TOL_ARG, "NULL chan -> ARG");
    check(exfil_tol_recv_cmd(&t, &im, up[0], &seq, NULL) == EXF_TOL_ARG, "NULL cmd -> ARG");
    check(exfil_tol_init(NULL, 4) == EXF_TOL_ARG, "tol_init(NULL) -> ARG");

    /* ---- 7. 遥测：累计计数反映"有人在动链路" ---- */
    check(t.n_fail >= 1 && t.n_ok >= 2 && t.n_pad >= 1, "遥测三项计数均已累积");
    printf("[INFO] 遥测: fail=%llu ok=%llu pad=%llu\n",
           (unsigned long long)t.n_fail, (unsigned long long)t.n_ok,
           (unsigned long long)t.n_pad);

    close(up[0]); close(up[1]);
    close(up2[0]); close(up2[1]);
    close(up3[0]); close(up3[1]);
    exfil_task_chan_wipe(&op); exfil_task_chan_wipe(&im);
    exfil_task_chan_wipe(&op2); exfil_task_chan_wipe(&im2);
    exfil_task_chan_wipe(&op3); exfil_task_chan_wipe(&im3);

    printf("\ntotal=%d pass=%d fail=%d\n", total, pass, fail);
    return fail ? 1 : 0;
}
