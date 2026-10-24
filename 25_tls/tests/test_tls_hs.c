/* test_tls_hs.c — 完整握手序列上的变异健壮性（MITM 代理）
 *
 * 为什么不能沿用"录一段流再重放"：
 *   服务端的 ServerRandom 与临时 X25519 私钥每次握手都重新生成，握手摘要
 *   （transcript）必然不同。把上一次抓到的客户端字节原样喂回去，客户端
 *   那份 Finished 的 MAC 一定对不上——重放跑通不了完整握手，于是"没崩"
 *   只是因为服务端在第一条消息之后就没再往前走。那样的用例是假覆盖。
 *
 *   所以这里做 MITM：父进程是代理，真实的客户端与真实的服务端各自在
 *   子进程里跑完整握手（ClientHello / ClientKeyExchange / CCS / Finished /
 *   应用数据全部走到），代理在中途按用例注入变异。
 *
 * 正向对照（本文件最重要的断言）：
 *   1. 基线（无变异）必须完整成功且回显一致。代理本身写错没人会发现，
 *      只有基线成功才能证明后续"变异后没崩"是代理真的在传数据。
 *   2. 每一轮变异必须至少有一例改变了握手结果（rc 非 0）。若一例都没变，
 *      说明变异根本没生效，整轮"无崩溃"就是恒绿。
 *
 * 崩溃与挂死必须分开判定：
 *   段错误和死循环在 waitpid 里都表现为"子进程没正常退出"。所以两端都
 *   放子进程，父进程用 WIFSIGNALED 判崩溃、用 poll 超时判挂死，并用阶段
 *   管道记录崩溃时走到了哪一步——只有崩溃点可定位，缺陷才可修。
 */
/* -std=c11 会定义 __STRICT_ANSI__，fork/waitpid/socketpair/kill 等 POSIX
 * 声明随之不可见（隐式声明在 64 位下会把返回值截断成 int，指针直接错位）。
 * 必须显式打开 POSIX 源，不能靠"编译没报错"蒙过去。 */
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
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define STREAM_CAP 65536
#define IO_CHUNK   8192

static int pass = 0, fail = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) { pass++; printf("[PASS] "); }                \
        else      { fail++; printf("[FAIL] "); }                \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

/* ---- IO 回调：EINTR 必须重试 ----
 * 被信号打断的一次 read 若当成连接断开，表现为偶发握手失败，且与信号
 * 时机相关，极难复现。 */
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

/* ---- 客户端子进程：完整握手 + 回显校验 ---- */
static int run_client(int fd, int stfd, const char *sni, const char *ca) {
    stage(stfd, 1);
    tls_config tc;
    memset(&tc, 0, sizeof(tc));
    tc.sni      = sni;
    tc.alpn     = "h2";
    tc.ca_path  = ca;
    tc.verify   = 1;

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

/* ---- 服务端子进程：完整握手 + 回显 ---- */
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

/* ---- 变异描述 ---- */
typedef struct {
    int    dir;    /* 0 = 客户端->服务端，1 = 服务端->客户端 */
    int    mode;   /* 0 无 / 1 单字节异或 / 2 截断 / 3 置值 */
    size_t off;
    uint8_t val;
} mutspec;

typedef struct {
    uint8_t buf[STREAM_CAP];
    size_t  len;
} stream_rec;

typedef struct {
    int    cli_rc, srv_rc;      /* -1 = 被信号杀死 */
    int    cli_sig, srv_sig;    /* 0 = 正常退出 */
    int    cli_stage, srv_stage;
    int    hang;      /* 关掉连接后仍退不出 = 真死循环 */
    int    stalled;   /* 出现过停滞（等一个永远不完整的记录） */
    size_t cs_len, sc_len;
} case_out;

static int last_stage(int fd) {
    int last = 0;
    unsigned char c = 0;
    while (read(fd, &c, 1) == 1) last = (int)c;
    return last;
}

static int run_case(const mutspec *m, stream_rec *rcs, stream_rec *rsc, case_out *o) {
    memset(o, 0, sizeof(*o));
    o->cli_rc = o->srv_rc = -1;

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
        close(sv_c[1]); close(st_c[1]);
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
        close(sv_s[1]); close(st_s[1]);
        _exit(rc);
    }

    /* 父进程必须关掉子进程持有的四个写端，否则 EOF 永远传不到对端，
     * 表现为"两端都在等"，与被测代码无关。 */
    close(sv_c[1]); close(sv_s[1]);
    close(st_c[1]); close(st_s[1]);

    size_t off_cs = 0, off_sc = 0;
    int cli_read = 1, srv_read = 1;
    int cs_fwd = 1, sc_fwd = 1;
    int grace = 0;   /* 已关掉连接、给过一次收尾机会 */

    while (cli_read || srv_read) {
        struct pollfd p[2];
        int np = 0;
        if (cli_read) { p[np].fd = sv_c[0]; p[np].events = POLLIN; p[np].revents = 0; np++; }
        if (srv_read) { p[np].fd = sv_s[0]; p[np].events = POLLIN; p[np].revents = 0; np++; }

        int r = poll(p, (unsigned long)np, 3000);
        if (r == 0) {
            /* 停滞不等于缺陷：把某个记录的长度字段改大（但仍在合法上限内）后，
             * 两端都会等那些永远不会到的字节 —— 任何阻塞式 TLS 实现都如此，
             * OpenSSL 也一样，真正的兜底是调用方的接收超时。
             *
             * 所以第一次停滞时由夹具扮演那个超时：双向 shutdown 关掉连接，
             * 再给一次机会。此时若仍退不出，就是真的死循环/不可中断等待 ——
             * 那才是缺陷。这样"hang == 0"才是一条有意义的断言，而不是
             * 把"跑得快"当成"没问题"。 */
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
                    if (cs_fwd) { cs_fwd = 0; shutdown(sv_s[0], SHUT_WR); }
                } else {
                    if (rcs && off_cs + (size_t)n <= STREAM_CAP)
                        memcpy(rcs->buf + off_cs, b, (size_t)n);
                    size_t keep = (size_t)n;
                    if (m->dir == 0 && m->mode == 2) {
                        if (off_cs >= m->off) keep = 0;
                        else if (off_cs + (size_t)n > m->off) keep = m->off - off_cs;
                    } else if (m->dir == 0 && (m->mode == 1 || m->mode == 3)) {
                        for (size_t i = 0; i < (size_t)n; i++) {
                            if (off_cs + i == m->off)
                                b[i] = (m->mode == 1) ? (uint8_t)(b[i] ^ m->val) : m->val;
                        }
                    }
                    if (keep > 0 && cs_fwd) write_all(sv_s[0], b, keep);
                    if (keep < (size_t)n && cs_fwd) {
                        cs_fwd = 0;
                        shutdown(sv_s[0], SHUT_WR);
                    }
                    off_cs += (size_t)n;
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
                    if (rsc && off_sc + (size_t)n <= STREAM_CAP)
                        memcpy(rsc->buf + off_sc, b, (size_t)n);
                    size_t keep = (size_t)n;
                    if (m->dir == 1 && m->mode == 2) {
                        if (off_sc >= m->off) keep = 0;
                        else if (off_sc + (size_t)n > m->off) keep = m->off - off_sc;
                    } else if (m->dir == 1 && (m->mode == 1 || m->mode == 3)) {
                        for (size_t i = 0; i < (size_t)n; i++) {
                            if (off_sc + i == m->off)
                                b[i] = (m->mode == 1) ? (uint8_t)(b[i] ^ m->val) : m->val;
                        }
                    }
                    if (keep > 0 && sc_fwd) write_all(sv_c[0], b, keep);
                    if (keep < (size_t)n && sc_fwd) {
                        sc_fwd = 0;
                        shutdown(sv_c[0], SHUT_WR);
                    }
                    off_sc += (size_t)n;
                }
            }
            idx++;
        }
    }

    o->cs_len = off_cs;
    o->sc_len = off_sc;

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

    if (rcs) rcs->len = off_cs;
    if (rsc) rsc->len = off_sc;

    close(sv_c[0]); close(sv_s[0]);
    close(st_c[0]); close(st_s[0]);
    return 0;
}

/* 把一个方向的字节流按 TLS 记录头切成边界表（用于结构化变异） */
static size_t find_records(const stream_rec *s, size_t *offs, size_t cap) {
    size_t n = 0, p = 0;
    while (n < cap && p + 5 <= s->len) {
        size_t rl = ((size_t)s->buf[p + 3] << 8) | (size_t)s->buf[p + 4];
        offs[n++] = p;
        if (rl == 0 || p + 5 + rl > s->len) break;
        p += 5 + rl;
    }
    return n;
}

/* 一轮变异：返回崩溃/挂死计数，*changed 累计"结果被改变"的用例数 */
static void run_pass(const char *name, int dir, int mode, size_t step,
                     uint8_t val, size_t len, int *crash, int *hang,
                     int *ncase, int *changed, int *stalled) {
    *crash = 0; *hang = 0; *ncase = 0; *changed = 0; *stalled = 0;
    for (size_t off = 0; off < len; off += step) {
        mutspec m;
        memset(&m, 0, sizeof(m));
        m.dir = dir; m.mode = mode; m.off = off; m.val = val;
        case_out o;
        if (run_case(&m, NULL, NULL, &o) != 0) { (*crash)++; continue; }
        (*ncase)++;
        if (o.stalled) (*stalled)++;
        if (o.hang) {
            (*hang)++;
            printf("[HANG] %s 偏移 %zu：c->s=%zu s->c=%zu cli_stage=%d srv_stage=%d\n",
                   name, off, o.cs_len, o.sc_len, o.cli_stage, o.srv_stage);
            continue;
        }
        if (o.cli_sig || o.srv_sig) {
            (*crash)++;
            printf("[FAIL] %s 偏移 %zu 崩溃：cli_sig=%d(stage=%d) srv_sig=%d(stage=%d)\n",
                   name, off, o.cli_sig, o.cli_stage, o.srv_sig, o.srv_stage);
            continue;
        }
        if (o.cli_rc != 0 || o.srv_rc != 0) (*changed)++;
    }
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    /* 素材存在性：缺失时返回 77（跳过），绝不冒充通过 */
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

    /* ---- 0. 基线：正向对照。代理写错没人会发现，只有它成功才算数 ---- */
    stream_rec rcs, rsc;
    memset(&rcs, 0, sizeof(rcs));
    memset(&rsc, 0, sizeof(rsc));
    case_out base;
    mutspec none;
    memset(&none, 0, sizeof(none));

    if (run_case(&none, &rcs, &rsc, &base) != 0) {
        printf("[FAIL] 基线用例无法运行\n");
        return 1;
    }
    CHECK(!base.hang && !base.cli_sig && !base.srv_sig && base.cli_rc == 0 && base.srv_rc == 0,
          "基线：完整握手+回显成功（cli_rc=%d srv_rc=%d cli_sig=%d srv_sig=%d hang=%d）",
          base.cli_rc, base.srv_rc, base.cli_sig, base.srv_sig, base.hang);
    CHECK(rcs.len > 0 && rsc.len > 0,
          "基线：双向流量已记录 c->s=%zu s->c=%zu（后续变异按此定位）", rcs.len, rsc.len);
    printf("[INFO] 基线到达阶段：客户端 stage=%d，服务端 stage=%d（7 = 全程走完）\n",
           base.cli_stage, base.srv_stage);

    if (base.cli_rc != 0 || base.srv_rc != 0 || rcs.len == 0 || rsc.len == 0) {
        printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
        return fail ? 1 : 0;
    }

    /* ---- 1. 客户端->服务端：单字节翻转 ---- */
    {
        int cr = 0, hg = 0, nc = 0, ch = 0, sl = 0;
        run_pass("C->S 翻转", 0, 1, 8, 0xFF, rcs.len, &cr, &hg, &nc, &ch, &sl);
        CHECK(cr == 0 && hg == 0, "C->S 单字节翻转 %d 例：崩溃=%d 真挂死=%d（停滞 %d 例，已关连接验证可收尾）", nc, cr, hg, sl);
        CHECK(ch > 0, "C->S 翻转确实改变了握手结果（%d/%d 例 rc 非 0）——变异生效的对照",
              ch, nc);
    }

    /* ---- 2. 客户端->服务端：截断 ---- */
    {
        int cr = 0, hg = 0, nc = 0, ch = 0, sl = 0;
        run_pass("C->S 截断", 0, 2, 16, 0, rcs.len, &cr, &hg, &nc, &ch, &sl);
        CHECK(cr == 0 && hg == 0, "C->S 截断 %d 例：崩溃=%d 真挂死=%d（停滞 %d 例）", nc, cr, hg, sl);
        CHECK(ch > 0, "C->S 截断确实改变了握手结果（%d/%d 例 rc 非 0）", ch, nc);
    }

    /* ---- 3. 服务端->客户端：单字节翻转（客户端解析器同样要扛住） ---- */
    {
        int cr = 0, hg = 0, nc = 0, ch = 0, sl = 0;
        size_t step = (rsc.len > 4096) ? 64 : 32;
        run_pass("S->C 翻转", 1, 1, step, 0xFF, rsc.len, &cr, &hg, &nc, &ch, &sl);
        CHECK(cr == 0 && hg == 0, "S->C 单字节翻转 %d 例（步长 %zu）：崩溃=%d 真挂死=%d（停滞 %d 例）",
              nc, step, cr, hg, sl);
        CHECK(ch > 0, "S->C 翻转确实改变了握手结果（%d/%d 例 rc 非 0）", ch, nc);
    }

    /* ---- 4. 结构化变异：记录层头部字段 ----
     * 单字节翻转碰不到"长度字段整体非法""类型字段未知"这类组合，
     * 而解析器最容易在长度字段上越界。按记录边界逐个改 type 与 length。 */
    {
        size_t offs[64];
        size_t nr = find_records(&rcs, offs, 64);
        CHECK(nr >= 3, "C->S 流中解析出 %zu 条 TLS 记录（>=3 才说明握手各阶段都走到了）", nr);

        int cr = 0, hg = 0, nc = 0, ch = 0, sl = 0;
        for (size_t i = 0; i < nr; i++) {
            static const uint8_t vals[] = {0xFF, 0x00};
            for (int vi = 0; vi < 2; vi++) {
                /* 类型字段：未知类型必须被干净拒绝 */
                mutspec m; memset(&m, 0, sizeof(m));
                m.dir = 0; m.mode = 3; m.off = offs[i]; m.val = vals[vi];
                case_out o;
                if (run_case(&m, NULL, NULL, &o) != 0) { cr++; continue; }
                nc++;
                if (o.stalled) sl++;
                if (o.hang) { hg++; continue; }
                if (o.cli_sig || o.srv_sig) {
                    cr++;
                    printf("[FAIL] 记录类型置 0x%02X @%zu 崩溃 srv_sig=%d(stage=%d)\n",
                           vals[vi], offs[i], o.srv_sig, o.srv_stage);
                    continue;
                }
                if (o.cli_rc != 0 || o.srv_rc != 0) ch++;
                /* 长度字段高字节置 0xFF：声明一个远大于实际的记录 */
                memset(&m, 0, sizeof(m));
                m.dir = 0; m.mode = 3; m.off = offs[i] + 3; m.val = 0xFF;
                if (run_case(&m, NULL, NULL, &o) != 0) { cr++; continue; }
                nc++;
                if (o.stalled) sl++;
                if (o.hang) { hg++; continue; }
                if (o.cli_sig || o.srv_sig) {
                    cr++;
                    printf("[FAIL] 记录长度置 0xFF @%zu 崩溃 srv_sig=%d(stage=%d)\n",
                           offs[i] + 3, o.srv_sig, o.srv_stage);
                    continue;
                }
                if (o.cli_rc != 0 || o.srv_rc != 0) ch++;
            }
        }
        CHECK(cr == 0 && hg == 0, "记录层头部结构化变异 %d 例：崩溃=%d 真挂死=%d（停滞 %d 例）", nc, cr, hg, sl);
        CHECK(ch > 0, "结构化变异确实改变了握手结果（%d/%d 例 rc 非 0）", ch, nc);
    }

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
