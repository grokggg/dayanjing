/*
 * DAYANJING v4 — 21_exfil/tests/test_link_cover.c
 *
 * 自适应覆盖流量接入真实发送循环的验证。
 *
 * 为什么用 fork + socketpair 而不是纯内存：
 *   覆盖流量的关键性质（"空闲时链路仍在流动"、"数据不被覆盖挤掉"）
 *   只有在**真实 fd 上有真实读写**时才成立。纯内存调用 flush 也能得到
 *   正确的 n_real/n_cover，但那不证明字节真的到达了、也不证明接收端的
 *   计数器被覆盖信元推进后仍能解出后续数据 —— 后者是"覆盖开旁路会全线
 *   AUTH"这个真实缺陷的唯一检测手段。
 *
 * 子进程做接收端，通过 pipe 把结果回传父进程，父进程断言。
 */

#include "exfil.h"
#include "exfil_link.h"
#include "exfil_link_cover.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <fcntl.h>

static int g_pass = 0, g_fail = 0;

static void check(const char *name, int cond) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

static void info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[INFO] ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

/* 固定密钥材料（测试用常量，非真随机） */
static const uint8_t KS[16] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};
static const uint8_t KR[16] = {
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};
static const uint8_t PFX[8] = { 'a','b','c','d','e','f','g','h' };

#define PAYLOAD_TAG  0xA5

static void mkrec(exfil_rec_t *r, const uint8_t *pl, size_t n, uint32_t type) {
    memset(r, 0, sizeof(*r));
    r->type = type;
    r->seq = 1;
    r->ts_us = 1700000000000000ull;
    r->width = 320;
    r->height = 240;
    r->flags = 0;
    snprintf(r->name, EXF_NAME_BUF, "cam0");
    r->payload = pl;
    r->plen = n;
}

int main(void) {
    /* ---------------- 用例1：参数校验 ---------------- */
    {
        exfil_link_cover_t lc;
        exfil_chan_t ch;
        exfil_rec_t r;
        uint8_t pl[64];
        size_t n = 0;

        memset(pl, PAYLOAD_TAG, sizeof pl);
        mkrec(&r, pl, sizeof pl, 1);

        check("用例1 lc 为空 init 被拒",
              exfil_link_cover_init(NULL, 1, 50, 32, P2P_COVER_PROFILE_DIRECT,
                                    100000, 0) == EXF_LC_ERR_ARG);
        check("用例1 正常 init 成功",
              exfil_link_cover_init(&lc, 1, 50, 32, P2P_COVER_PROFILE_DIRECT,
                                    100000, 0) == EXF_LC_OK);
        check("用例1 ch 为空 enqueue 被拒",
              exfil_link_cover_submit(NULL, &lc, &r, 1, &n) == EXF_LC_ERR_ARG);
        check("用例1 lc 为空 enqueue 被拒",
              exfil_link_cover_submit(&ch, NULL, &r, 1, &n) == EXF_LC_ERR_ARG);
        check("用例1 r 为空 enqueue 被拒",
              exfil_link_cover_submit(&ch, &lc, NULL, 1, &n) == EXF_LC_ERR_ARG);
        check("用例1 无效 fd flush 被拒",
              exfil_link_cover_pump(&ch, &lc, -1, 0, NULL, NULL)
                  == EXF_LC_ERR_ARG);
        check("用例1 pending 初始为 0", exfil_link_cover_pending(&lc) == 0);
        check("用例1 rate 在合理区间", exfil_link_cover_rate(&lc) > 0 && exfil_link_cover_rate(&lc) <= 600);
    }

    /* ---------------- 用例2：小产物端到端（真实进程） ---------------- */
    {
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
            check("用例2 socketpair", 0);
            return 1;
        }
        pid_t pid = fork();
        if (pid < 0) { check("用例2 fork", 0); return 1; }

        if (pid == 0) {
            /* 子进程：接收端 */
            close(sp[0]);
            exfil_chan_t ch;
            if (exfil_chan_init(&ch, KR, KS, PFX, 0) != EXF_OK) _exit(2);
            uint8_t out[4096];
            exfil_rec_t rr;
            size_t plen = 0;
            int rc = exfil_link_recv(&ch, sp[1], &rr, out, sizeof out, &plen);
            int ok = (rc == EXF_DONE) && plen == 100;
            if (ok) {
                for (size_t i = 0; i < plen; i++)
                    if (out[i] != PAYLOAD_TAG) { ok = 0; break; }
            }
            exfil_chan_wipe(&ch);
            close(sp[1]);
            _exit(ok ? 0 : 3);
        }

        /* 父进程：发送端 */
        close(sp[1]);
        exfil_chan_t ch;
        exfil_link_cover_t lc;
        if (exfil_chan_init(&ch, KS, KR, PFX, 0) != EXF_OK) { check("用例2 chan init", 0); return 1; }
        if (exfil_link_cover_init(&lc, 7, 50, 32, P2P_COVER_PROFILE_DIRECT,
                                  100000, 0) != EXF_LC_OK) {
            check("用例2 cover init", 0); return 1;
        }

        uint8_t pl[100];
        memset(pl, PAYLOAD_TAG, sizeof pl);
        exfil_rec_t r;
        mkrec(&r, pl, sizeof pl, 1);

        size_t nr = 0, nc = 0;
        int rc = exfil_link_send_adaptive(&ch, &lc, &r, sp[0], 0, 1, &nr, &nc);
        check("用例2 send_adaptive 成功", rc == EXF_LC_OK);
        check("用例2 确有数据信元发出", nr >= 1);
        check("用例2 队列已排空", exfil_link_cover_pending(&lc) == 0);
        info("用例2 数据信元=%zu 覆盖信元=%zu 线上字节=%llu",
             nr, nc, (unsigned long long)lc.bytes_sent);

        int st = 0;
        waitpid(pid, &st, 0);
        check("用例2 子进程解出且字节一致", WIFEXITED(st) && WEXITSTATUS(st) == 0);

        exfil_link_cover_set_budget(&lc, 0);   /* 收尾：关覆盖（不影响断言） */
        exfil_chan_wipe(&ch);
        close(sp[0]);
    }

    /* ---------------- 用例3：空闲期确有覆盖信元在线上流动 ---------------- */
    /*
     * 必须 fork 出接收端：socketpair 是有限缓冲的字节流，单进程自写自读
     * 会在缓冲写满后阻塞（首版正是如此，40 片 × 上千覆盖信元直接死锁）。
     * 覆盖流量的"在线上流动"只有在对端真实读取时才成立。
     */
    {
        int sp[2];
        int rp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
            check("用例3 socketpair", 0); return 1;
        }
        if (pipe(rp) != 0) { check("用例3 pipe", 0); return 1; }

        pid_t pid = fork();
        if (pid < 0) { check("用例3 fork", 0); return 1; }

        if (pid == 0) {
            /* 子进程：接收端，把吃掉的 PAD 数回传 */
            close(sp[0]); close(rp[0]);
            exfil_chan_t chr;
            if (exfil_chan_init(&chr, KR, KS, PFX, 0) != EXF_OK) _exit(2);
            size_t eaten = 0;
            int first_rc = 0;   /* 首个非 EXF_OK 的返回值，0 表示全部 OK */
            for (;;) {
                uint8_t cell[P2P_CELL_WIRE];
                if (exfil_link_read_exact(sp[1], cell, P2P_CELL_WIRE)
                        != P2P_CELL_WIRE) break;   /* 对端关闭 -> EOF */
                exfil_rec_t rr; memset(&rr, 0, sizeof rr);
                size_t dummy_plen = 0;   /* feed 要求 plen 非 NULL */
                int rc = exfil_chan_feed(&chr, cell, &rr, NULL, 0, &dummy_plen);
                if (rc != EXF_OK) { first_rc = rc; break; }  /* PAD -> EXF_OK */
                eaten++;
            }
            exfil_chan_wipe(&chr);
            uint64_t msg[2];
            msg[0] = (uint64_t)eaten;
            msg[1] = (uint64_t)(int64_t)first_rc;
            (void)!write(rp[1], msg, sizeof msg);
            close(rp[1]); close(sp[1]);
            _exit(0);
        }

        /* 父进程：发送端，只发空闲覆盖 */
        close(sp[1]); close(rp[1]);
        exfil_chan_t ch;
        exfil_link_cover_t lc;
        if (exfil_chan_init(&ch, KS, KR, PFX, 0) != EXF_OK) { check("用例3 chan", 0); return 1; }
        if (exfil_link_cover_init(&lc, 3, 1000, 32, P2P_COVER_PROFILE_DIRECT,
                                  1024u * 1024u, 0) != EXF_LC_OK) {
            check("用例3 cover init", 0); return 1;
        }
        exfil_link_cover_set_bounds(&lc, 2, 600);

        size_t total_cover = 0;
        uint32_t t = 0;
        for (int i = 0; i < 10; i++) {
            size_t nc = 0;
            int irc = exfil_link_cover_idle(&ch, &lc, sp[0], t, &nc);
            if (irc != EXF_LC_OK) { info("用例3 idle rc=%d (%s) i=%d", irc, exfil_link_cover_errstr(irc), i); break; }
            total_cover += nc;
            t += 1000;   /* 每片推进 1 秒虚拟时间 */
        }
        check("用例3 空闲期产出了覆盖信元", total_cover > 0);
        info("用例3 10 次 idle 覆盖信元合计=%zu 线上字节=%llu",
             total_cover, (unsigned long long)lc.bytes_sent);

        close(sp[0]);   /* EOF，让子进程收尾 */

        uint64_t msg[2] = {0, 0};
        size_t got = 0;
        while (got < sizeof msg) {
            ssize_t r = read(rp[0], (uint8_t *)msg + got, sizeof msg - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
        int st = 0;
        waitpid(pid, &st, 0);
        close(rp[0]);

        size_t eaten = (size_t)msg[0];
        int bad = (int)msg[1];
        info("用例3 子进程首个非 OK 返回码 = %d", bad);
        check("用例3 覆盖信元全被识别为 PAD（无一处解包失败）", bad == 0);
        check("用例3 吃掉的信元数等于发出的信元数", eaten == lc.cells_sent);
        check("用例3 吃掉的均为覆盖信元（等于覆盖计数）", eaten == lc.cover_sent);
        info("用例3 接收端吃掉 %zu 个信元（覆盖 %llu）",
             eaten, (unsigned long long)lc.cover_sent);

        exfil_chan_wipe(&ch);
    }

    /* ---------------- 用例4：大载荷多片出队，覆盖不吃掉数据 ---------------- */
    {
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
            check("用例4 socketpair", 0); return 1;
        }
        pid_t pid = fork();
        if (pid < 0) { check("用例4 fork", 0); return 1; }

        if (pid == 0) {
            close(sp[0]);
            exfil_chan_t ch;
            if (exfil_chan_init(&ch, KR, KS, PFX, 0) != EXF_OK) _exit(2);
            uint8_t *out = (uint8_t *)malloc(200000);
            if (!out) _exit(2);
            exfil_rec_t rr;
            size_t plen = 0;
            int rc = exfil_link_recv(&ch, sp[1], &rr, out, 200000, &plen);
            int ok = (rc == EXF_DONE) && plen == 100000;
            if (ok) {
                for (size_t i = 0; i < plen; i++)
                    if (out[i] != PAYLOAD_TAG) { ok = 0; break; }
            }
            free(out);
            exfil_chan_wipe(&ch);
            close(sp[1]);
            _exit(ok ? 0 : 3);
        }

        close(sp[1]);
        exfil_chan_t ch;
        exfil_link_cover_t lc;
        if (exfil_chan_init(&ch, KS, KR, PFX, 0) != EXF_OK) { check("用例4 chan", 0); return 1; }
        if (exfil_link_cover_init(&lc, 11, 50, 32, P2P_COVER_PROFILE_DIRECT,
                                  100000, 0) != EXF_LC_OK) {
            check("用例4 cover init", 0); return 1;
        }

        uint8_t *pl = (uint8_t *)malloc(100000);
        if (!pl) { check("用例4 malloc", 0); return 1; }
        memset(pl, PAYLOAD_TAG, 100000);
        exfil_rec_t r;
        mkrec(&r, pl, 100000, 2);

        size_t nr = 0, nc = 0;
        int rc = exfil_link_send_adaptive(&ch, &lc, &r, sp[0], 0, 1, &nr, &nc);
        check("用例4 大载荷发送成功", rc == EXF_LC_OK);
        check("用例4 数据信元数符合预期（100000B -> 204 信元）", nr == 204);
        info("用例4 数据=%zu 覆盖=%zu 线上字节=%llu", nr, nc,
             (unsigned long long)lc.bytes_sent);

        int st = 0;
        waitpid(pid, &st, 0);
        check("用例4 子进程解出 100000B 且字节一致",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);

        free(pl);
        exfil_chan_wipe(&ch);
        close(sp[0]);
    }

    /* ---------------- 用例5：budget=0 关闭覆盖 ---------------- */
    {
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
            check("用例5 socketpair", 0); return 1;
        }
        exfil_chan_t ch;
        exfil_link_cover_t lc;
        if (exfil_chan_init(&ch, KS, KR, PFX, 0) != EXF_OK) { check("用例5 chan", 0); return 1; }
        if (exfil_link_cover_init(&lc, 5, 50, 32, P2P_COVER_PROFILE_DIRECT,
                                  0, 0) != EXF_LC_OK) {
            check("用例5 cover init", 0); return 1;
        }
        size_t nc = 0;
        uint32_t t = 0;
        size_t sum = 0;
        for (int i = 0; i < 10; i++) {
            int irc = exfil_link_cover_idle(&ch, &lc, sp[0], t, &nc);
            if (irc != EXF_LC_OK) { info("用例3 idle rc=%d (%s) i=%d", irc, exfil_link_cover_errstr(irc), i); break; }
            sum += nc;
            t += 1000;
        }
        check("用例5 预算为 0 时不发覆盖信元", sum == 0);
        check("用例5 预算为 0 时线上无字节", lc.cells_sent == 0);

        exfil_chan_wipe(&ch);
        close(sp[0]); close(sp[1]);
    }

    /* ---------------- 用例6：换信道覆盖自动缩放 ---------------- */
    {
        exfil_link_cover_t lc1, lc2;
        if (exfil_link_cover_init(&lc1, 9, 50, 32, P2P_COVER_PROFILE_DIRECT,
                                  1024u * 1024u, 0) != EXF_LC_OK) {
            check("用例6 init direct", 0); return 1;
        }
        if (exfil_link_cover_init(&lc2, 9, 50, 32, P2P_COVER_PROFILE_DNS,
                                  1024u * 1024u, 0) != EXF_LC_OK) {
            check("用例6 init dns", 0); return 1;
        }
        uint32_t r1 = exfil_link_cover_rate(&lc1);
        uint32_t r2 = exfil_link_cover_rate(&lc2);
        check("用例6 同样预算下 DNS 信道的覆盖速率低于直连", r2 < r1);
        check("用例6 直连覆盖速率为正", r1 > 0);
        info("用例6 覆盖速率 direct=%u dns=%u (信元/分钟)", r1, r2);

        /* 用实测成本覆盖画像后，速率应随之变化 */
        uint32_t before = exfil_link_cover_rate(&lc2);
        exfil_link_cover_set_cost(&lc2, 2854);   /* 实测 DNS 成本 */
        uint32_t after = exfil_link_cover_rate(&lc2);
        check("用例6 回填实测成本后覆盖速率下降", after < before);
        info("用例6 DNS 画像 2040 -> 实测 2854：覆盖速率 %u -> %u", before, after);
    }

    /* ---------------- 用例7：背压（队列满） ---------------- */
    {
        exfil_chan_t ch;
        exfil_link_cover_t lc;
        if (exfil_chan_init(&ch, KS, KR, PFX, 0) != EXF_OK) { check("用例7 chan", 0); return 1; }
        if (exfil_link_cover_init(&lc, 13, 50, 32, P2P_COVER_PROFILE_DIRECT,
                                  100000, 0) != EXF_LC_OK) {
            check("用例7 cover init", 0); return 1;
        }
        uint8_t *pl = (uint8_t *)malloc(100000);
        if (!pl) { check("用例7 malloc", 0); return 1; }
        memset(pl, PAYLOAD_TAG, 100000);

        exfil_rec_t r;
        mkrec(&r, pl, 100000, 3);

        /*
         * 接收端用 socketpair + 子进程丢弃读：exfil_link_write_all 走 send()，
         * 对普通文件（/dev/null）无效 —— 首版正是因此拿到 io failure。
         */
        int sp7[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp7) != 0) {
            check("用例7 socketpair", 0); return 1;
        }
        pid_t pid7 = fork();
        if (pid7 == 0) {
            close(sp7[0]);
            uint8_t sinkbuf[P2P_CELL_WIRE];
            for (;;) {
                if (exfil_link_read_exact(sp7[1], sinkbuf, P2P_CELL_WIRE)
                        != P2P_CELL_WIRE) break;
            }
            close(sp7[1]);
            _exit(0);
        }
        close(sp7[1]);
        int sink = sp7[0];

        size_t n1 = 0;
        int rc1 = exfil_link_cover_submit(&ch, &lc, &r, 1, &n1);
        check("用例7 提交 204 信元成功（不再因队列容量被拒）",
              rc1 == EXF_LC_OK && n1 == 204);

        /* 首次 pump：受 P2P_MIX_MAXQ=64 背压，不可能一次全部入队 */
        size_t r2 = 0, c2 = 0;
        int rc = exfil_link_cover_pump(&ch, &lc, sink, 0, &r2, &c2);
        info("用例7 pump rc=%d (%s)", rc, exfil_link_cover_errstr(rc));
        check("用例7 首次 pump 成功", rc == EXF_LC_OK);
        check("用例7 单批入队受队列容量约束（<=64）", lc.enc_i <= 64);
        info("用例7 首次 pump 后已入队 %zu/204，本片发出数据=%zu 覆盖=%zu",
             lc.enc_i, r2, c2);

        /* 反复 pump 直到排空：验证背压不丢信元、一批能完整发完 */
        uint32_t t = 0;
        int ticks = 0;
        while (exfil_link_cover_pending(&lc) > 0 && ticks < 2000) {
            t += 50;
            if (exfil_link_cover_pump(&ch, &lc, sink, t, NULL, NULL)
                    != EXF_LC_OK) break;
            ticks++;
        }
        check("用例7 反复 pump 后缓冲排空", lc.enc_i == lc.enc_n);
        check("用例7 反复 pump 后队列排空", lc.mx.n == 0);
        check("用例7 pending 归零", exfil_link_cover_pending(&lc) == 0);
        info("用例7 共 %d 片发完 204 信元，累计信元=%llu",
             ticks + 1, (unsigned long long)lc.cells_sent);

        close(sink);   /* EOF -> 子进程收尾 */
        int st7 = 0; waitpid(pid7, &st7, 0);
        free(pl);
        exfil_link_cover_wipe(&lc);
        exfil_chan_wipe(&ch);
    }

    /* ---------------- 用例8：errstr 覆盖 ---------------- */
    {
        check("用例8 errstr OK", strcmp(exfil_link_cover_errstr(EXF_LC_OK), "ok") == 0);
        check("用例8 errstr FULL 含 backpressure",
              strstr(exfil_link_cover_errstr(EXF_LC_ERR_FULL), "backpressure") != NULL);
        check("用例8 errstr 未知码不崩",
              exfil_link_cover_errstr(-999) != NULL);
    }

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
