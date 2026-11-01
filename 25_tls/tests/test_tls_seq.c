/* test_tls_seq.c — 协议时序攻击健壮性（丢弃 / 重放 / 重排 / 注入）
 *
 * 与 test_tls_hs.c 的分工：
 *   那个改的是「字节」——某个字段错了，解析器会不会越界。
 *   这个改的是「顺序与存在性」——每条记录本身都合法、字节一个没动，
 *   只是把其中一条丢掉、重复一遍、换个位置，或者在中间插一条格式正确的
 *   记录。字节级变异碰不到这类问题，因为它不改变任何字节。
 *
 * 为什么这是比"没崩"更硬的判据：
 *   一个把什么都接受的实现同样不会崩。只断言"崩溃=0"会放过真正的缺陷：
 *   状态机跳步、握手未完成就收应用数据、CCS 被吃掉后仍按密文解 Finished。
 *   所以本文件除了"不得崩溃/挂死"，还有一组语义断言——
 *   该拒绝的，必须拒绝。那一组才是这个测试存在的理由。
 *
 * 变异单位是记录，不是字节：
 *   代理必须先按 TLS 记录头（5 字节）把流切成一条条完整记录，才能谈
 *   "丢掉第 N 条"。所以转发循环是"攒够一条完整记录再决策"，而不是
 *   "读到多少转多少"。
 *
 * 正向对照（缺了它们，整份报告就是恒绿的）：
 *   1. 基线必须完整成功且回显一致 —— 证明代理真的在传数据。
 *   2. 每轮变异必须有若干例改变了握手结果 —— 证明变异真的生效了。
 *   3. 语义断言里"必须失败"的那些，若实测居然成功，就是真缺陷，
 *      不是断言写错 —— 判据在写代码之前就定好了（见 main 中的注释）。
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "tls.h"
#include "tls_server.h"
#include "x509.h"
#include "rsa.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>

/* 单条记录上限。与实现的接收上限一致（明文 2^14 / 密文 2^14+8+16），
 * 取大者再留余量。超过它的声明长度不是"要分配更多"，而是非法输入。 */
#define REC_CAP  18432
#define ACC_CAP  (REC_CAP + 8192)
#define IO_CHUNK 8192
#define MAXREC   64

static int pass = 0, fail = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) { pass++; printf("[PASS] "); }                \
        else      { fail++; printf("[FAIL] "); }                \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

/* ---------- IO 回调：EINTR 必须重试 ---------- */
static int snd_cb(void *arg, const uint8_t *d, size_t n) {
    int fd = *(int *)arg;
    for (;;) {
        ssize_t r = write(fd, d, n);
        if (r < 0 && errno == EINTR) continue;
        return (int)r;
    }
}

static int rcv_cb(void *arg, uint8_t *b, size_t cap) {
    int fd = *(int *)arg;
    for (;;) {
        ssize_t r = read(fd, b, cap);
        if (r < 0 && errno == EINTR) continue;
        return (int)r;
    }
}

static void stage(int fd, int s) {
    unsigned char c = (unsigned char)s;
    ssize_t r = write(fd, &c, 1);
    (void)r;
}

static int write_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = write(fd, b + off, n - off);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* ---------- 两端子进程：完整握手 + 回显 ---------- */
static int run_client(int fd, int stfd, const char *sni, const char *ca) {
    stage(stfd, 1);
    tls_config tc;
    memset(&tc, 0, sizeof(tc));
    tc.sni     = sni;
    tc.alpn    = "h2";
    tc.ca_path = ca;
    tc.verify  = 1;

    tls_ctx *c = NULL;
    tls_err e  = tls_client_init(&c, &tc, snd_cb, rcv_cb, &fd);
    if (e != TLS_OK) return 10 + (int)e;

    stage(stfd, 2);
    e = tls_handshake(c);
    if (e != TLS_OK) { tls_free(c); return 20 + (int)e; }

    stage(stfd, 3);
    const char *msg = "PING-HELLO";
    e = tls_write(c, (const uint8_t *)msg, strlen(msg));
    if (e != TLS_OK) { tls_free(c); return 30 + (int)e; }

    stage(stfd, 4);
    uint8_t b[512];
    size_t  n = 0;
    e = tls_read(c, b, sizeof(b), &n);
    if (e != TLS_OK) { tls_free(c); return 40 + (int)e; }
    if (n != strlen(msg) || memcmp(b, msg, n) != 0) { tls_free(c); return 41; }

    stage(stfd, 5);
    e = tls_close(c);
    if (e != TLS_OK) { tls_free(c); return 50 + (int)e; }

    stage(stfd, 6);
    tls_free(c);
    stage(stfd, 7);
    return 0;
}

static int run_server(int fd, int stfd, const rsa_privkey *key,
                      const uint8_t *der, size_t der_len) {
    stage(stfd, 1);
    tls_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.chain[0]     = der;
    cfg.chain_len[0] = der_len;
    cfg.chain_n      = 1;
    cfg.key          = key;
    cfg.alpn         = "h2";

    tls_server_ctx *s = NULL;
    tls_err e = tls_server_init(&s, &cfg, snd_cb, rcv_cb, &fd);
    if (e != TLS_OK) return 10 + (int)e;

    stage(stfd, 2);
    e = tls_server_accept(s);
    if (e != TLS_OK) { tls_server_free(s); return 20 + (int)e; }

    stage(stfd, 3);
    uint8_t b[512];
    size_t  n = 0;
    e = tls_server_read(s, b, sizeof(b), &n);
    if (e != TLS_OK) { tls_server_free(s); return 30 + (int)e; }

    stage(stfd, 4);
    e = tls_server_write(s, b, n);
    if (e != TLS_OK) { tls_server_free(s); return 40 + (int)e; }

    stage(stfd, 5);
    e = tls_server_close(s);
    if (e != TLS_OK) { tls_server_free(s); return 50 + (int)e; }

    stage(stfd, 6);
    tls_server_free(s);
    stage(stfd, 7);
    return 0;
}

/* ---------- 记录边界 ---------- */
typedef struct {
    size_t  off;
    size_t  len;   /* 含 5 字节头 */
    uint8_t type;
} recinfo;

/* 从一条完整的流里切出记录表。记录头永远是明文，所以密文阶段同样可切。 */
static size_t parse_recs(const uint8_t *buf, size_t len, recinfo *out, size_t cap) {
    size_t n = 0, p = 0;
    while (n < cap && p + 5 <= len) {
        uint8_t t  = buf[p];
        size_t  rl = ((size_t)buf[p + 3] << 8) | (size_t)buf[p + 4];
        if (p + 5 + rl > len) break;   /* 最后一条不完整（被截断） */
        out[n].off = p;
        out[n].len = 5 + rl;
        out[n].type = t;
        n++;
        p += 5 + rl;
    }
    return n;
}

static const char *rec_type_name(uint8_t t) {
    switch (t) {
    case 0x14: return "CCS";
    case 0x15: return "alert";
    case 0x16: return "handshake";
    case 0x17: return "appdata";
    default:   return "other";
    }
}

/* ---------- 变异描述：作用于记录，不是字节 ---------- */
enum {
    SEQ_NONE = 0,
    SEQ_DROP,            /* 丢掉第 rec_idx 条 */
    SEQ_DUP,             /* 第 rec_idx 条连发两次（重放） */
    SEQ_SWAP,            /* 交换第 rec_idx 与 rec_idx+1 条（重排） */
    SEQ_INJ_BEFORE,      /* 在第 rec_idx 条之前注入一条合成记录 */
};

enum {
    INJ_APPDATA = 0,     /* 17 03 03 00 05 "HELLO" —— 握手未完成就发应用数据 */
    INJ_EMPTY_HS,        /* 16 03 03 00 00 —— 空握手记录 */
    INJ_ALERT_CLOSE,     /* 15 03 03 00 02 01 00 —— warning close_notify */
    INJ_ALERT_FATAL,     /* 15 03 03 00 02 02 28 —— fatal handshake_failure */
    INJ_UNKNOWN_TYPE,    /* FF 03 03 00 00 —— 未知记录类型 */
};

typedef struct {
    int    dir;      /* 0 = C->S，1 = S->C */
    int    op;
    size_t rec_idx;
    int    inj;      /* SEQ_INJ_BEFORE 时指定注入内容 */
} seqspec;

static const uint8_t INJECTS[][16] = {
    {0x17, 0x03, 0x03, 0x00, 0x05, 'H','E','L','L','O'},           /* 10 */
    {0x16, 0x03, 0x03, 0x00, 0x00},                                 /* 5  */
    {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},                     /* 7  */
    {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},                     /* 7  */
    {0xFF, 0x03, 0x03, 0x00, 0x00},                                 /* 5  */
};
static const size_t INJECTS_LEN[] = {10, 5, 7, 7, 5};
static const char *INJECTS_NAME[] = {
    "应用数据", "空握手记录", "warning close_notify", "fatal handshake_failure", "未知记录类型",
};

/* ---------- 累积器：攒够一条完整记录才决策 ---------- */
typedef struct {
    uint8_t buf[ACC_CAP];
    size_t  len;
    int     broken;   /* 解析不下去（声明长度越界），此后原样转发 */
} acc_t;

/* 取出第一条完整记录。1 = 取到，0 = 还不完整，-1 = 非法长度 */
static int pull_rec(acc_t *a, uint8_t *out, size_t *out_len) {
    if (a->len < 5) return 0;
    size_t rl = ((size_t)a->buf[3] << 8) | (size_t)a->buf[4];
    if (rl > REC_CAP - 5) return -1;
    if (a->len < 5 + rl) return 0;
    memcpy(out, a->buf, 5 + rl);
    *out_len = 5 + rl;
    memmove(a->buf, a->buf + 5 + rl, a->len - (5 + rl));
    a->len -= 5 + rl;
    return 1;
}

typedef struct {
    int    cli_rc, srv_rc;
    int    cli_sig, srv_sig;
    int    cli_stage, srv_stage;
    int    hang;
    int    stalled;
    size_t cs_len, sc_len;
} case_out;

static int last_stage(int fd) {
    int last = 0;
    unsigned char c = 0;
    while (read(fd, &c, 1) == 1) last = (int)c;
    return last;
}

/* ---------- MITM：按记录转发并施加时序变异 ---------- */
static int run_seq_case(const seqspec *m, uint8_t *cs_out, size_t *cs_out_len,
                        uint8_t *sc_out, size_t *sc_out_len, case_out *o) {
    memset(o, 0, sizeof(*o));
    o->cli_rc = o->srv_rc = -1;
    if (cs_out_len) *cs_out_len = 0;
    if (sc_out_len) *sc_out_len = 0;

    int sv_c[2], sv_s[2], st_c[2], st_s[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv_c) != 0) return -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv_s) != 0) return -1;
    if (pipe(st_c) != 0) return -1;
    if (pipe(st_s) != 0) return -1;

    pid_t pc = fork();
    if (pc == 0) {
        close(sv_c[0]); close(sv_s[0]); close(sv_s[1]);
        close(st_c[0]); close(st_s[0]); close(st_s[1]);
        int rc = run_client(sv_c[1], st_c[1], "front.test", TLS_TESTDATA "/ca.pem");
        _exit(rc);
    }
    pid_t ps = fork();
    if (ps == 0) {
        close(sv_s[0]); close(sv_c[0]); close(sv_c[1]);
        close(st_s[0]); close(st_c[0]); close(st_c[1]);
        int rc = 90;
        rsa_privkey k;
        x509_store   xs;
        memset(&k, 0, sizeof(k));
        memset(&xs, 0, sizeof(xs));
        if (rsa_privkey_load_pem(TLS_TESTDATA "/leaf.key", &k) == RSA_OK &&
            x509_store_load_pem(&xs, TLS_TESTDATA "/leaf.pem") == X509_OK && xs.n > 0) {
            rc = run_server(sv_s[1], st_s[1], &k, xs.e[0].der, xs.e[0].der_len);
        }
        rsa_privkey_clear(&k);
        x509_store_free(&xs);
        _exit(rc);
    }
    close(sv_c[1]); close(sv_s[1]);
    close(st_c[1]); close(st_s[1]);

    acc_t acs, asc;
    memset(&acs, 0, sizeof(acs));
    memset(&asc, 0, sizeof(asc));
    size_t idx_cs = 0, idx_sc = 0;

    /* 重排用的暂存：第 rec_idx 条先扣下，等第 rec_idx+1 条到了再逆序发出 */
    uint8_t held[REC_CAP];
    size_t  held_len = 0;
    int     held_valid = 0;

    size_t rec_cs = 0, rec_sc = 0;   /* 记录表（仅基线统计用） */
    int cli_read = 1, srv_read = 1;
    int cs_fwd = 1, sc_fwd = 1;
    int grace = 0;

    while (cli_read || srv_read) {
        struct pollfd p[2];
        int np = 0;
        if (cli_read) { p[np].fd = sv_c[0]; p[np].events = POLLIN; p[np].revents = 0; np++; }
        if (srv_read) { p[np].fd = sv_s[0]; p[np].events = POLLIN; p[np].revents = 0; np++; }

        int r = poll(p, (unsigned long)np, 3000);
        if (r == 0) {
            /* 与 test_tls_hs.c 同一套判据：停滞不等于缺陷。丢掉一条记录后，
             * 对端就是在等一个永远不来的字节 —— 任何阻塞式 TLS 实现都如此。
             * 第一次停滞时由夹具扮演调用方的接收超时：双向 shutdown 关连接，
             * 再给一次收尾机会；仍退不出才是真死循环。 */
            if (!grace) {
                grace = 1;
                o->stalled = 1;
                cs_fwd = 0; sc_fwd = 0;
                shutdown(sv_c[0], SHUT_WR);
                shutdown(sv_s[0], SHUT_WR);
                continue;
            }
            o->hang = 1;
            break;
        }
        if (r < 0) { if (errno == EINTR) continue; break; }

        int idx = 0;
        if (cli_read) {
            if (p[idx].revents & (POLLIN | POLLHUP | POLLERR)) {
                uint8_t b[IO_CHUNK];
                ssize_t n = read(sv_c[0], b, sizeof(b));
                if (n <= 0) {
                    cli_read = 0;
                    /* 连接断前把扣下的那条发出去，避免"交换"退化成"丢弃两条" */
                    if (held_valid && sc_fwd) { write_all(sv_s[0], held, held_len); held_valid = 0; }
                    if (cs_fwd) { cs_fwd = 0; shutdown(sv_s[0], SHUT_WR); }
                } else {
                    if (cs_out && o->cs_len + (size_t)n <= 65536) {
                        memcpy(cs_out + o->cs_len, b, (size_t)n);
                        *cs_out_len = o->cs_len + (size_t)n;
                    }
                    o->cs_len += (size_t)n;
                    if (acs.len + (size_t)n <= ACC_CAP) {
                        memcpy(acs.buf + acs.len, b, (size_t)n);
                        acs.len += (size_t)n;
                    }
                    for (;;) {
                        uint8_t rec[REC_CAP];
                        size_t  rl = 0;
                        int pr = pull_rec(&acs, rec, &rl);
                        if (pr <= 0) break;
                        if (cs_fwd) rec_cs++;
                        size_t my = idx_cs++;
                        int emit_cur = 1, emit_held = 0;

                        if (m->dir == 0 && cs_fwd) {
                            switch (m->op) {
                            case SEQ_DROP:
                                if (my == m->rec_idx) emit_cur = 0;
                                break;
                            case SEQ_DUP:
                                if (my == m->rec_idx) {
                                    write_all(sv_s[0], rec, rl);
                                }
                                break;
                            case SEQ_SWAP:
                                if (my == m->rec_idx) {
                                    memcpy(held, rec, rl); held_len = rl; held_valid = 1;
                                    emit_cur = 0;
                                } else if (my == m->rec_idx + 1 && held_valid) {
                                    emit_held = 1;
                                }
                                break;
                            case SEQ_INJ_BEFORE:
                                if (my == m->rec_idx)
                                    write_all(sv_s[0], INJECTS[m->inj], INJECTS_LEN[m->inj]);
                                break;
                            default: break;
                            }
                        }
                        if (cs_fwd) {
                            if (emit_cur) write_all(sv_s[0], rec, rl);
                            if (emit_held) { write_all(sv_s[0], held, held_len); held_valid = 0; }
                        }
                    }
                }
            }
            idx++;
        }
        if (srv_read) {
            if (p[idx].revents & (POLLIN | POLLHUP | POLLERR)) {
                uint8_t b[IO_CHUNK];
                ssize_t n = read(sv_s[0], b, sizeof(b));
                if (n <= 0) {
                    srv_read = 0;
                    if (sc_fwd) { sc_fwd = 0; shutdown(sv_c[0], SHUT_WR); }
                } else {
                    if (sc_out && o->sc_len + (size_t)n <= 65536) {
                        memcpy(sc_out + o->sc_len, b, (size_t)n);
                        *sc_out_len = o->sc_len + (size_t)n;
                    }
                    o->sc_len += (size_t)n;
                    if (asc.len + (size_t)n <= ACC_CAP) {
                        memcpy(asc.buf + asc.len, b, (size_t)n);
                        asc.len += (size_t)n;
                    }
                    for (;;) {
                        uint8_t rec[REC_CAP];
                        size_t  rl = 0;
                        int pr = pull_rec(&asc, rec, &rl);
                        if (pr <= 0) break;
                        if (sc_fwd) rec_sc++;
                        size_t my = idx_sc++;
                        int emit_cur = 1, emit_held = 0;

                        if (m->dir == 1 && sc_fwd) {
                            switch (m->op) {
                            case SEQ_DROP:
                                if (my == m->rec_idx) emit_cur = 0;
                                break;
                            case SEQ_DUP:
                                if (my == m->rec_idx) write_all(sv_c[0], rec, rl);
                                break;
                            case SEQ_SWAP:
                                if (my == m->rec_idx) {
                                    memcpy(held, rec, rl); held_len = rl; held_valid = 1;
                                    emit_cur = 0;
                                } else if (my == m->rec_idx + 1 && held_valid) {
                                    emit_held = 1;
                                }
                                break;
                            case SEQ_INJ_BEFORE:
                                if (my == m->rec_idx)
                                    write_all(sv_c[0], INJECTS[m->inj], INJECTS_LEN[m->inj]);
                                break;
                            default: break;
                            }
                        }
                        if (sc_fwd) {
                            if (emit_cur) write_all(sv_c[0], rec, rl);
                            if (emit_held) { write_all(sv_c[0], held, held_len); held_valid = 0; }
                        }
                    }
                }
            }
            idx++;
        }
    }

    int st1 = 0, st2 = 0;
    if (o->hang) { kill(pc, SIGKILL); kill(ps, SIGKILL); }
    waitpid(pc, &st1, 0);
    waitpid(ps, &st2, 0);

    o->cli_sig   = WIFSIGNALED(st1) ? WTERMSIG(st1) : 0;
    o->cli_rc    = WIFEXITED(st1) ? WEXITSTATUS(st1) : -1;
    o->srv_sig   = WIFSIGNALED(st2) ? WTERMSIG(st2) : 0;
    o->srv_rc    = WIFEXITED(st2) ? WEXITSTATUS(st2) : -1;
    o->cli_stage = last_stage(st_c[0]);
    o->srv_stage = last_stage(st_s[0]);

    close(sv_c[0]); close(sv_s[0]);
    close(st_c[0]); close(st_s[0]);
    (void)rec_cs; (void)rec_sc;
    return 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    {
        rsa_privkey k;
        memset(&k, 0, sizeof(k));
        rsa_err re = rsa_privkey_load_pem(TLS_TESTDATA "/leaf.key", &k);
        rsa_privkey_clear(&k);
        if (re != RSA_OK) {
            fprintf(stderr, "[FATAL] 缺 leaf.key，先跑 make testdata\n");
            return 77;
        }
    }

    /* ---- 0. 基线：正向对照 + 记录序列取证 ---- */
    static uint8_t cs[65536], sc[65536];
    size_t cs_len = 0, sc_len = 0;
    case_out base;
    seqspec none;
    memset(&none, 0, sizeof(none));

    if (run_seq_case(&none, cs, &cs_len, sc, &sc_len, &base) != 0) {
        printf("[FAIL] 基线用例无法运行\n");
        return 1;
    }
    CHECK(!base.hang && !base.cli_sig && !base.srv_sig &&
          base.cli_rc == 0 && base.srv_rc == 0,
          "基线：完整握手+回显成功（cli_rc=%d srv_rc=%d cli_sig=%d srv_sig=%d hang=%d）",
          base.cli_rc, base.srv_rc, base.cli_sig, base.srv_sig, base.hang);

    recinfo rc[MAXREC], rs[MAXREC];
    size_t nrc = parse_recs(cs, cs_len, rc, MAXREC);
    size_t nrs = parse_recs(sc, sc_len, rs, MAXREC);
    CHECK(nrc >= 4 && nrs >= 3, "基线记录序列：C->S %zu 条，S->C %zu 条", nrc, nrs);

    printf("[INFO] C->S 记录序列：");
    for (size_t i = 0; i < nrc; i++) printf("%zu:%s ", i, rec_type_name(rc[i].type));
    printf("\n[INFO] S->C 记录序列：");
    for (size_t i = 0; i < nrs; i++) printf("%zu:%s ", i, rec_type_name(rs[i].type));
    printf("\n");

    if (base.cli_rc != 0 || base.srv_rc != 0 || nrc < 4 || nrs < 3) {
        printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
        return fail ? 1 : 0;
    }

    /* 定位关键记录。不硬编码索引——握手实现若合并/拆分记录，索引会变，
     * 硬编码的断言会在某次改动后悄悄指向错误的记录（那才是假通过）。 */
    size_t cs_ccs = (size_t)-1, cs_fin = (size_t)-1, sc_ccs = (size_t)-1, sc_fin = (size_t)-1;
    for (size_t i = 0; i < nrc; i++) if (rc[i].type == 0x14 && cs_ccs == (size_t)-1) cs_ccs = i;
    for (size_t i = cs_ccs + 1; i < nrc; i++) if (rc[i].type == 0x16) { cs_fin = i; break; }
    for (size_t i = 0; i < nrs; i++) if (rs[i].type == 0x14 && sc_ccs == (size_t)-1) sc_ccs = i;
    for (size_t i = sc_ccs + 1; i < nrs; i++) if (rs[i].type == 0x16) { sc_fin = i; break; }

    CHECK(cs_ccs != (size_t)-1 && cs_fin != (size_t)-1,
          "C->S 定位到 CCS@%zu 与其后的 Finished@%zu", cs_ccs, cs_fin);
    CHECK(sc_ccs != (size_t)-1 && sc_fin != (size_t)-1,
          "S->C 定位到 CCS@%zu 与其后的 Finished@%zu", sc_ccs, sc_fin);

    /* ---- 1. 丢弃：每条记录逐个丢一遍 ---- */
    {
        int cr = 0, hg = 0, nc = 0, ch = 0;
        for (size_t i = 0; i < nrc; i++) {
            seqspec m; memset(&m, 0, sizeof(m));
            m.dir = 0; m.op = SEQ_DROP; m.rec_idx = i;
            case_out o;
            if (run_seq_case(&m, NULL, NULL, NULL, NULL, &o) != 0) { cr++; continue; }
            nc++;
            if (o.hang) { hg++; printf("[HANG] 丢弃 C->S 第 %zu 条(%s)\n", i, rec_type_name(rc[i].type)); continue; }
            if (o.cli_sig || o.srv_sig) {
                cr++;
                printf("[FAIL] 丢弃 C->S 第 %zu 条(%s) 崩溃 srv_sig=%d(stage=%d)\n",
                       i, rec_type_name(rc[i].type), o.srv_sig, o.srv_stage);
                continue;
            }
            if (o.cli_rc != 0 || o.srv_rc != 0) ch++;
        }
        CHECK(cr == 0 && hg == 0, "C->S 逐条丢弃 %d 例：崩溃=%d 真挂死=%d", nc, cr, hg);
        CHECK(ch > 0, "C->S 丢弃确实改变了握手结果（%d/%d 例 rc 非 0）——变异生效的对照", ch, nc);
    }

    /* ---- 2. 重放：每条记录连发两次 ---- */
    {
        int cr = 0, hg = 0, nc = 0, ch = 0;
        for (size_t i = 0; i < nrc; i++) {
            seqspec m; memset(&m, 0, sizeof(m));
            m.dir = 0; m.op = SEQ_DUP; m.rec_idx = i;
            case_out o;
            if (run_seq_case(&m, NULL, NULL, NULL, NULL, &o) != 0) { cr++; continue; }
            nc++;
            if (o.hang) { hg++; printf("[HANG] 重放 C->S 第 %zu 条(%s)\n", i, rec_type_name(rc[i].type)); continue; }
            if (o.cli_sig || o.srv_sig) {
                cr++;
                printf("[FAIL] 重放 C->S 第 %zu 条(%s) 崩溃 srv_sig=%d(stage=%d)\n",
                       i, rec_type_name(rc[i].type), o.srv_sig, o.srv_stage);
                continue;
            }
            if (o.cli_rc != 0 || o.srv_rc != 0) ch++;
        }
        CHECK(cr == 0 && hg == 0, "C->S 逐条重放 %d 例：崩溃=%d 真挂死=%d", nc, cr, hg);
        CHECK(ch > 0, "C->S 重放确实改变了握手结果（%d/%d 例 rc 非 0）", ch, nc);
    }

    /* ---- 3. 重排：交换相邻两条 ---- */
    {
        int cr = 0, hg = 0, nc = 0, ch = 0;
        for (size_t i = 0; i + 1 < nrc; i++) {
            seqspec m; memset(&m, 0, sizeof(m));
            m.dir = 0; m.op = SEQ_SWAP; m.rec_idx = i;
            case_out o;
            if (run_seq_case(&m, NULL, NULL, NULL, NULL, &o) != 0) { cr++; continue; }
            nc++;
            if (o.hang) { hg++; printf("[HANG] 重排 C->S 第 %zu/%zu 条\n", i, i + 1); continue; }
            if (o.cli_sig || o.srv_sig) {
                cr++;
                printf("[FAIL] 重排 C->S 第 %zu/%zu 条 崩溃 srv_sig=%d(stage=%d)\n",
                       i, i + 1, o.srv_sig, o.srv_stage);
                continue;
            }
            if (o.cli_rc != 0 || o.srv_rc != 0) ch++;
        }
        CHECK(cr == 0 && hg == 0, "C->S 相邻重排 %d 例：崩溃=%d 真挂死=%d", nc, cr, hg);
        CHECK(ch > 0, "C->S 重排确实改变了握手结果（%d/%d 例 rc 非 0）", ch, nc);
    }

    /* ---- 4. 注入：在每一条之前插一条格式正确的合成记录 ---- */
    for (int inj = 0; inj < 5; inj++) {
        int cr = 0, hg = 0, nc = 0, ch = 0;
        for (size_t i = 0; i < nrc; i++) {
            seqspec m; memset(&m, 0, sizeof(m));
            m.dir = 0; m.op = SEQ_INJ_BEFORE; m.rec_idx = i; m.inj = inj;
            case_out o;
            if (run_seq_case(&m, NULL, NULL, NULL, NULL, &o) != 0) { cr++; continue; }
            nc++;
            if (o.hang) { hg++; continue; }
            if (o.cli_sig || o.srv_sig) {
                cr++;
                printf("[FAIL] 注入%s @%zu 前 崩溃 srv_sig=%d(stage=%d)\n",
                       INJECTS_NAME[inj], i, o.srv_sig, o.srv_stage);
                continue;
            }
            if (o.cli_rc != 0 || o.srv_rc != 0) ch++;
        }
        CHECK(cr == 0 && hg == 0, "C->S 注入%s %d 例：崩溃=%d 真挂死=%d",
              INJECTS_NAME[inj], nc, cr, hg);
        CHECK(ch > 0, "C->S 注入%s 确实改变了握手结果（%d/%d 例 rc 非 0）",
              INJECTS_NAME[inj], ch, nc);
    }

    /* ---- 5. 反向：S->C 也要扛住（客户端解析器同样在被攻击） ---- */
    {
        int cr = 0, hg = 0, nc = 0, ch = 0;
        for (size_t i = 0; i < nrs; i++) {
            for (int op = SEQ_DROP; op <= SEQ_SWAP; op++) {
                seqspec m; memset(&m, 0, sizeof(m));
                m.dir = 1; m.op = op; m.rec_idx = i;
                case_out o;
                if (run_seq_case(&m, NULL, NULL, NULL, NULL, &o) != 0) { cr++; continue; }
                nc++;
                if (o.hang) { hg++; continue; }
                if (o.cli_sig || o.srv_sig) {
                    cr++;
                    printf("[FAIL] S->C op=%d @%zu 崩溃 cli_sig=%d(stage=%d)\n",
                           op, i, o.cli_sig, o.cli_stage);
                    continue;
                }
                if (o.cli_rc != 0 || o.srv_rc != 0) ch++;
            }
        }
        CHECK(cr == 0 && hg == 0, "S->C 丢弃/重放/重排 %d 例：崩溃=%d 真挂死=%d", nc, cr, hg);
        CHECK(ch > 0, "S->C 时序变异确实改变了握手结果（%d/%d 例 rc 非 0）", ch, nc);
    }

    /* ---- 6. 语义断言：该拒绝的，必须拒绝 ----
     * 判据在写代码之前就定好，不是看着结果写断言。
     * 这些若实测"居然成功"，是服务端状态机的真缺陷，不是断言写错。 */
    {
        /* 6.1 吃掉 CCS：Finished 是密文，没收过 CCS 就不该按密文去解它。
         *     若服务端照样收下，等于把明文当密文解还能过——那是真缺陷。 */
        seqspec m; memset(&m, 0, sizeof(m));
        m.dir = 0; m.op = SEQ_DROP; m.rec_idx = cs_ccs;
        case_out o;
        run_seq_case(&m, NULL, NULL, NULL, NULL, &o);
        CHECK(!o.hang && !o.cli_sig && !o.srv_sig && (o.cli_rc != 0 || o.srv_rc != 0),
              "吃掉 CCS：握手必须失败（cli_rc=%d srv_rc=%d stage=%d）——明文/密文分界不可跳过",
              o.cli_rc, o.srv_rc, o.srv_stage);

        /* 6.2 吃掉 Finished：对端没完成握手，就不得进入应用数据阶段 */
        memset(&m, 0, sizeof(m));
        m.dir = 0; m.op = SEQ_DROP; m.rec_idx = cs_fin;
        run_seq_case(&m, NULL, NULL, NULL, NULL, &o);
        CHECK(!o.hang && !o.cli_sig && !o.srv_sig && (o.cli_rc != 0 || o.srv_rc != 0),
              "吃掉 Finished：握手必须失败（cli_rc=%d srv_rc=%d stage=%d）",
              o.cli_rc, o.srv_rc, o.srv_stage);

        /* 6.3 握手第一条之前就发应用数据：未完成握手不得收应用数据 */
        memset(&m, 0, sizeof(m));
        m.dir = 0; m.op = SEQ_INJ_BEFORE; m.rec_idx = 0; m.inj = INJ_APPDATA;
        run_seq_case(&m, NULL, NULL, NULL, NULL, &o);
        CHECK(!o.hang && !o.cli_sig && !o.srv_sig && (o.cli_rc != 0 || o.srv_rc != 0),
              "ClientHello 之前注入应用数据：必须被拒绝（cli_rc=%d srv_rc=%d stage=%d）",
              o.cli_rc, o.srv_rc, o.srv_stage);

        /* 6.4 重放 ClientHello：握手已在进行中，不得当成重新开始 */
        memset(&m, 0, sizeof(m));
        m.dir = 0; m.op = SEQ_DUP; m.rec_idx = 0;
        run_seq_case(&m, NULL, NULL, NULL, NULL, &o);
        CHECK(!o.hang && !o.cli_sig && !o.srv_sig && (o.cli_rc != 0 || o.srv_rc != 0),
              "重放 ClientHello：必须被拒绝或不得静默续跑（cli_rc=%d srv_rc=%d stage=%d）",
              o.cli_rc, o.srv_rc, o.srv_stage);

        /* 6.5 把 Finished 挪到 CCS 前面：顺序即状态，不可跳步 */
        memset(&m, 0, sizeof(m));
        m.dir = 0; m.op = SEQ_SWAP; m.rec_idx = cs_ccs;
        run_seq_case(&m, NULL, NULL, NULL, NULL, &o);
        CHECK(!o.hang && !o.cli_sig && !o.srv_sig && (o.cli_rc != 0 || o.srv_rc != 0),
              "CCS 与 Finished 调换顺序：必须失败（cli_rc=%d srv_rc=%d stage=%d）",
              o.cli_rc, o.srv_rc, o.srv_stage);

        /* 6.6 反向：吃掉服务端的 CCS，客户端不得照样收 Finished */
        memset(&m, 0, sizeof(m));
        m.dir = 1; m.op = SEQ_DROP; m.rec_idx = sc_ccs;
        run_seq_case(&m, NULL, NULL, NULL, NULL, &o);
        CHECK(!o.hang && !o.cli_sig && !o.srv_sig && (o.cli_rc != 0 || o.srv_rc != 0),
              "吃掉服务端 CCS：客户端必须失败（cli_rc=%d srv_rc=%d stage=%d）",
              o.cli_rc, o.srv_rc, o.cli_stage);

        /* 6.7 客户端侧的同源缺陷：ServerHello 之前先收到应用数据。
         *     客户端若也静默跳过，等于把"是否安全"交给恶意服务端决定——
         *     它可以在握手中间夹带数据，客户端照样报握手成功。 */
        memset(&m, 0, sizeof(m));
        m.dir = 1; m.op = SEQ_INJ_BEFORE; m.rec_idx = 0; m.inj = INJ_APPDATA;
        run_seq_case(&m, NULL, NULL, NULL, NULL, &o);
        CHECK(!o.hang && !o.cli_sig && !o.srv_sig && (o.cli_rc != 0 || o.srv_rc != 0),
              "ServerHello 之前注入应用数据：客户端必须拒绝（cli_rc=%d srv_rc=%d stage=%d）",
              o.cli_rc, o.srv_rc, o.cli_stage);
    }

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
