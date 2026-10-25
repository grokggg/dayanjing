/* test_tls_cke_struct.c —— ClientKeyExchange 结构化变异下的服务端健壮性
 *
 * 与 test_tls_hs.c 的分工：
 *   那个做「字节级」变异（截断、单字节翻转），这个做「结构化」变异。
 *   字节翻转有个先天盲区：长度字段一翻转就先被长度检查挡下，根本到不了
 *   解析器。而解析器真正会出事的地方正是「格式自洽、但语义刁钻」的报文：
 *
 *     * point 长度声明 33 而实际只有 32 字节（经典的一字节越界读）
 *     * point 长度声明 31 而实际留了 32 字节（尾部残留未消费）
 *     * 一条握手消息被拆成两个记录（TLS 允许，实现常常不允许）
 *     * 同一条 CKE 出现两次
 *
 * 用例与期望值全部来自 scripts/gen_cke_struct.py，期望值不是拍的 ——
 * 由同一脚本连真实 OpenSSL s_server 逐例实测取得。凭 RFC 推断「未知握手
 * 类型该忽略还是拒绝」很容易推错，而推错的代价是把我们调成和真实世界
 * 不一致：探测者只需发一个畸形报文就能把我们和真实服务端区分开。
 *
 * 为什么判据是「输出流里有没有告警记录」而不是「accept 的返回值」：
 *   只喂 CH+CKE 时，服务端即使在 CKE 阶段出错，也可能因为随后读不到
 *   CCS 而以别的错误码返回 —— 返回值分不清「CKE 解析失败」和「EOF」。
 *   而「有没有主动发出告警」是服务端自己对该报文的表态，不掺 EOF 的因素。
 *
 * 三条断言，缺一不可：
 *   1. 任何用例都不许崩、不许挂死（fork + alarm 检测）
 *   2. 标 TOLERATE 的：不得发出告警 —— 分片、合法公钥变异被拒，等于
 *      在真实互联网上握不上手
 *   3. 标 REJECT 的：必须发出告警 —— 结构非法却继续握手，往往意味着它
 *      按错误长度读过去了
 */
#include "tls.h"
#include "tls_server.h"
#include "x509.h"
#include "rsa.h"
#include "hs_msgs_real.h"
#include "cke_struct.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

static int pass = 0, fail = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) { pass++; printf("[PASS] "); }                \
        else      { fail++; printf("[FAIL] "); }                \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

#define OUT_CAP 8192

typedef struct {
    const uint8_t *in;
    size_t         in_len, in_off;
    uint8_t        out[OUT_CAP];
    size_t         out_len;
} io_st;

static int snd_cb(void *arg, const uint8_t *d, size_t n) {
    io_st *io = (io_st *)arg;
    if (io->out_len + n <= OUT_CAP)
        memcpy(io->out + io->out_len, d, n);
    io->out_len += n;          /* 计数照走，哪怕缓冲放不下 */
    return (int)n;
}

static int rcv_cb(void *arg, uint8_t *b, size_t cap) {
    io_st *io = (io_st *)arg;
    if (io->in_off >= io->in_len) return 0;   /* EOF */
    size_t n = io->in_len - io->in_off;
    if (n > cap) n = cap;
    memcpy(b, io->in + io->in_off, n);
    io->in_off += n;
    return (int)n;
}

/* 输出流里是否出现了告警记录（ct == 21）*/
static int sent_alert(const uint8_t *b, size_t len) {
    size_t off = 0;
    while (off + 5 <= len) {
        uint8_t ct = b[off];
        size_t  ln = ((size_t)b[off + 3] << 8) | b[off + 4];
        if (ct == 21) return 1;
        off += 5 + ln;
        if (ln == 0) break;    /* 防止零长记录导致死循环 */
    }
    return 0;
}

static void on_alarm(int s) { (void)s; _exit(99); }

static void child_run(const uint8_t *in, size_t in_len,
                      const rsa_privkey *key,
                      const uint8_t *der, size_t der_len, int fd) {
    signal(SIGALRM, on_alarm);
    alarm(5);

    io_st io;
    memset(&io, 0, sizeof(io));
    io.in = in; io.in_len = in_len;

    tls_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.chain[0]     = der;
    cfg.chain_len[0] = der_len;
    cfg.chain_n      = 1;
    cfg.key          = key;
    cfg.alpn         = "h2";

    int      err   = -1;
    int      alert = 0;
    uint64_t sent  = 0;

    tls_server_ctx *c = NULL;
    tls_err e = tls_server_init(&c, &cfg, snd_cb, rcv_cb, &io);
    if (e == TLS_OK) {
        e = tls_server_accept(c);
        err = (int)e;
    } else {
        err = (int)e;
    }
    sent  = (uint64_t)io.out_len;
    alert = sent_alert(io.out, io.out_len);

    {
        ssize_t w1 = write(fd, &sent,  sizeof(sent));
        ssize_t w2 = write(fd, &err,   sizeof(err));
        ssize_t w3 = write(fd, &alert, sizeof(alert));
        (void)w1; (void)w2; (void)w3;
    }
    _exit(0);
}

/* 返回：0 = 正常返回；-99 = 挂死；其他 <0 = 被信号杀死（崩溃）*/
static int run_case(const uint8_t *in, size_t in_len,
                    const rsa_privkey *key,
                    const uint8_t *der, size_t der_len,
                    uint64_t *out_sent, int *out_err, int *out_alert) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        child_run(in, in_len, key, der, der_len, pfd[1]);
        _exit(127);
    }
    close(pfd[1]);

    uint64_t sent = 0;
    int      err = -1, alert = 0;
    if (read(pfd[0], &sent, sizeof(sent)) == (ssize_t)sizeof(sent)) {
        if (read(pfd[0], &err, sizeof(err)) == (ssize_t)sizeof(err)) {
            ssize_t ra = read(pfd[0], &alert, sizeof(alert));
            (void)ra;
        }
    }
    close(pfd[0]);

    int st = 0;
    waitpid(pid, &st, 0);

    *out_sent = sent; *out_err = err; *out_alert = alert;
    if (WIFSIGNALED(st)) return -2 - WTERMSIG(st);
    int ec = WEXITSTATUS(st);
    if (ec == 99) return -99;
    return ec;
}

int main(void) {
    rsa_privkey key;
    x509_store  st;
    memset(&st, 0, sizeof(st));

    if (rsa_privkey_load_pem(TLS_TESTDATA "/leaf.key", &key) != RSA_OK) {
        fprintf(stderr, "[FATAL] 缺 leaf.key，先跑 make testdata\n");
        return 77;
    }
    if (x509_store_load_pem(&st, TLS_TESTDATA "/leaf.pem") != X509_OK || st.n < 1) {
        fprintf(stderr, "[FATAL] 缺 leaf.pem，先跑 make testdata\n");
        rsa_privkey_clear(&key);
        return 77;
    }
    const uint8_t *der     = st.e[0].der;
    size_t         der_len = st.e[0].der_len;

    /* ---- 0. 基底自检：BASE 用例必须就是「真实 CH + 真实 CKE」原样拼接 ----
     * 这条不成立，说明生成器抓取/固化环节有问题，后面所有用例测的都不
     * 是真实报文的变体，结论全部作废。 */
    {
        const cke_case_t *b = NULL;
        for (size_t i = 0; i < CKE_NCASES; i++)
            if (strcmp(CKE_CASES[i].name, "BASE") == 0) b = &CKE_CASES[i];
        CHECK(b != NULL, "存在 BASE 基底用例");
        if (b) {
            size_t ch_len = sizeof(CH_REAL_REC), cke_len = sizeof(CKE_REAL_REC);
            CHECK(b->len == ch_len + cke_len &&
                  memcmp(b->stream, CH_REAL_REC, ch_len) == 0 &&
                  memcmp(b->stream + ch_len, CKE_REAL_REC, cke_len) == 0,
                  "基底自检：BASE == 真实 CH + 真实 CKE（%zu = %zu+%zu）",
                  b->len, ch_len, cke_len);
        }
    }

    /* ---- 1. 逐用例：不崩不挂 + 按 OpenSSL 实测的期望接受/拒绝 ---- */
    int crash = 0, hang = 0, wrong_tol = 0, wrong_rej = 0;
    int n_tol = 0, n_rej = 0, n_any = 0;

    for (size_t i = 0; i < CKE_NCASES; i++) {
        const cke_case_t *c = &CKE_CASES[i];
        uint64_t sent = 0;
        int err = -1, alert = 0;
        int rc = run_case(c->stream, c->len, &key, der, der_len, &sent, &err, &alert);

        if (rc == -99) { hang++; printf("[HANG] %s\n", c->name); }
        else if (rc < 0) { crash++; printf("[CRASH] %s sig=%d\n", c->name, -rc - 2); }

        if (c->expect == EXPECT_TOLERATE) {
            n_tol++;
            if (alert) {
                wrong_tol++;
                printf("[FAIL] %s 应被容忍却发出告警（sent=%llu err=%d）—— %s\n",
                       c->name, (unsigned long long)sent, err, c->note);
            }
        } else if (c->expect == EXPECT_REJECT) {
            n_rej++;
            if (!alert) {
                wrong_rej++;
                printf("[FAIL] %s 应被拒绝却未发告警（sent=%llu err=%d）—— %s\n",
                       c->name, (unsigned long long)sent, err, c->note);
            }
        } else {
            n_any++;
        }
    }

    CHECK(crash == 0, "%zu 例结构化 CKE：崩溃 %d 例", CKE_NCASES, crash);
    CHECK(hang == 0,  "%zu 例结构化 CKE：挂死 %d 例", CKE_NCASES, hang);
    CHECK(wrong_tol == 0, "%d 例应容忍：%d 例被错拒（与 OpenSSL 不一致）", n_tol, wrong_tol);
    CHECK(wrong_rej == 0, "%d 例应拒绝：%d 例被错收（与 OpenSSL 不一致）", n_rej, wrong_rej);
    printf("[INFO] 用例构成：容忍 %d / 拒绝 %d / 待定 %d\n", n_tol, n_rej, n_any);

    rsa_privkey_clear(&key);
    printf("=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
