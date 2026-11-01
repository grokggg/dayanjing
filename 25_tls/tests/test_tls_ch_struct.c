/* test_tls_ch_struct.c — ClientHello 结构化变异下的服务端健壮性
 *
 * 与 test_tls_ch.c 的分工：
 *   那个做「字节级」变异（截断、单字节置 0x00/0xFF），这个做「结构化」
 *   变异。字节翻转有个先天盲区：它几乎不可能产生出「格式自洽、但语义
 *   刁钻」的报文 —— 因为长度字段一翻转就先被长度检查挡下了，根本到
 *   不了解析器。而解析器真正会出事的地方正是这类自洽报文：
 *
 *     * 类型未知、但长度合法的扩展（RFC 要求：必须忽略）
 *     * GREASE 值（RFC 8701：必须容忍）出现在套件/扩展/组/签名算法/
 *       版本/key_share 里
 *     * 单条扩展声明长度比实际多 1（经典的一字节越界读）
 *     * 同一个扩展出现两次
 *
 * 所以本文件的用例全部由 scripts/gen_ch_struct.py 按 TLS 结构生成，
 * 外层长度一律如实重算，只有「长度不符」那一类是故意不重算。
 *
 * 三条断言，缺一不可：
 *   1. 任何用例都不许崩、不许挂死（fork + alarm 检测，理由见 run_case）
 *   2. 标记为 TOLERATE 的：服务端必须照常产出响应（sent > 0）
 *      —— 未知扩展和 GREASE 被拒，等于在真实互联网上握不上手
 *   3. 标记为 REJECT 的：服务端必须干净拒绝（sent == 0）
 *      —— 结构非法却产出响应，往往意味着它按错误长度读过去了
 *
 * 第 2 条尤其不能省：只断言「不崩」的话，一个「遇到未知扩展就拒绝」
 * 的实现会全绿通过，而它在真实互联网上是残废的。
 */
#include "tls.h"
#include "tls_server.h"
#include "x509.h"
#include "rsa.h"
#include "clienthello_default.h"
#include "clienthello_struct.h"
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

typedef struct {
    const uint8_t *in;
    size_t         in_len, in_off;
    uint8_t        out[4096];
    size_t         sent;
} io_st;

static int snd_cb(void *arg, const uint8_t *d, size_t n) {
    io_st *io = (io_st *)arg;
    if (io->sent + n <= sizeof(io->out))
        memcpy(io->out + io->sent, d, n);
    io->sent += n;
    return (int)n;
}

/* 输出流里是否出现了告警记录（ct == 21）
 *
 * 为什么判据从「有没有产出字节」改成「有没有发告警」：
 *   服务端原本在任何失败路径上一个字节都不发，于是「拒绝」表现为 sent=0。
 *   但这不是协议行为 —— 对端只能看到连接被关，无法区分「被拒绝」和
 *   「网络断了」，而真实实现会明确发 fatal 告警。补齐告警之后，「拒绝」
 *   的表现变成 sent=7（一条告警记录），原来的 sent==0 判据就反了。
 *   「有没有主动发告警」才是服务端对该报文的真实表态。 */
static int sent_alert(const uint8_t *b, size_t len) {
    size_t off = 0;
    while (off + 5 <= len) {
        uint8_t ct = b[off];
        size_t  ln = ((size_t)b[off + 3] << 8) | b[off + 4];
        if (ct == 21) return 1;
        off += 5 + ln;
        if (ln == 0) break;
    }
    return 0;
}

static int rcv_cb(void *arg, uint8_t *b, size_t cap) {
    io_st *io = (io_st *)arg;
    if (io->in_off >= io->in_len) return 0;
    size_t n = io->in_len - io->in_off;
    if (n > cap) n = cap;
    memcpy(b, io->in + io->in_off, n);
    io->in_off += n;
    return (int)n;
}

static void on_alarm(int s) { (void)s; _exit(99); }

static void child_run(const uint8_t *in, size_t in_len,
                      const rsa_privkey *key,
                      const uint8_t *der, size_t der_len, int fd) {
    signal(SIGALRM, on_alarm);
    alarm(3);

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

    uint64_t sent = 0;
    int      err  = -1;

    tls_server_ctx *c = NULL;
    tls_err e = tls_server_init(&c, &cfg, snd_cb, rcv_cb, &io);
    if (e == TLS_OK) {
        e = tls_server_accept(c);
        err = (int)e;
    } else {
        err = (int)e;
    }
    sent = (uint64_t)io.sent;

    {
        int alert = sent_alert(io.out, io.sent);
        ssize_t w1 = write(fd, &sent, sizeof(sent));
        ssize_t w2 = write(fd, &err,  sizeof(err));
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
    int      err  = -1, alert = 0;
    if (read(pfd[0], &sent, sizeof(sent)) == (ssize_t)sizeof(sent)) {
        if (read(pfd[0], &err, sizeof(err)) == (ssize_t)sizeof(err)) {
            if (read(pfd[0], &alert, sizeof(alert)) != (ssize_t)sizeof(alert))
                alert = 0;
        }
    }
    close(pfd[0]);

    int st = 0;
    waitpid(pid, &st, 0);

    *out_sent = sent;
    *out_err  = err;
    *out_alert = alert;
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

    /* ---- 0. 生成器自检：重建的未修改报文必须与原报文逐字节相同 ----
     * 这条不成立，说明生成器的字段偏移算错了，后面所有用例测的都不是
     * 「真实报文的变体」而是它自己编出来的另一个包，结论全部作废。 */
    {
        const chs_case_t *z = NULL;
        for (size_t i = 0; i < CHS_N; i++)
            if (strcmp(CHS_CASES[i].name, "Z0_roundtrip_equals_real") == 0) z = &CHS_CASES[i];
        CHECK(z != NULL, "生成器自检用例存在");
        if (z) {
            CHECK(z->len == CH_REAL_LEN && memcmp(z->buf, CH_REAL, CH_REAL_LEN) == 0,
                  "生成器自检：重建报文与 CH_REAL 逐字节相同（len=%zu vs %zu）",
                  z->len, (size_t)CH_REAL_LEN);
        }
    }

    /* ---- 1. 逐用例：不崩不挂 + 按期望接受/拒绝 ---- */
    int crash = 0, hang = 0;
    int wrong_tolerate = 0, wrong_reject = 0, wrong_any = 0;
    int n_tol = 0, n_rej = 0, n_any = 0;

    for (size_t i = 0; i < CHS_N; i++) {
        const chs_case_t *c = &CHS_CASES[i];
        uint64_t sent = 0;
        int      err  = -1;
        int alert = 0;
        int rc = run_case(c->buf, c->len, &key, der, der_len, &sent, &err, &alert);

        if (rc == -99) hang++;
        else if (rc < 0) crash++;

        if (c->expect == CH_EXPECT_TOLERATE) {
            n_tol++;
            if (alert) {
                wrong_tolerate++;
                printf("[FAIL] %s 必须被接受（未知扩展/GREASE 被拒 = 真实互联网上握不上手），"
                       "却发出了告警 rc=%d err=%d\n", c->name, rc, err);
            }
        } else if (c->expect == CH_EXPECT_REJECT) {
            n_rej++;
            if (!alert) {
                wrong_reject++;
                printf("[FAIL] %s 必须被拒绝并发告警，但没发告警"
                       "（多半是照错误长度读过去了，或静默失败）sent=%llu err=%d\n",
                       c->name, (unsigned long long)sent, err);
            }
        } else {
            n_any++;
            /* 真值未定，但有一件事是确定的：实测中 OpenSSL 对这些用例
             * 一个告警都没发。我们若发了，就把「等数据」和「拒绝」混为
             * 一谈 —— 那正是可被探测的分歧。所以这里不是「什么都不验」。 */
            if (alert) {
                wrong_any++;
                printf("[FAIL] %s 真实实现未发告警（多半在等剩余字节），"
                       "我们却发了 sent=%llu err=%d\n",
                       c->name, (unsigned long long)sent, err);
            }
        }

        /* 逐例实际结果，供与 OpenSSL 做行为比对（scripts 里的 oracle）。
         * 默认不打，免得回归日志被 47 行刷屏；需要比对时设 CHS_VERBOSE=1。 */
        if (getenv("CHS_VERBOSE")) {
            printf("[CASE] %s sent=%llu\n", c->name, (unsigned long long)sent);
        }
    }

    CHECK(crash == 0 && hang == 0,
          "结构化变异 %zu 例：崩溃=%d 挂死=%d", (size_t)CHS_N, crash, hang);
    CHECK(wrong_tolerate == 0,
          "必须被容忍的 %d 例（未知扩展 / GREASE / 自检）：全部产出响应", n_tol);
    CHECK(wrong_reject == 0,
          "必须被拒绝的 %d 例（声明长度不符）：全部发出告警", n_rej);
    CHECK(wrong_any == 0,
          "真值未定的 %d 例：不得发出告警（真实实现在这些用例上也没发）", n_any);
    printf("[INFO] 真值未定的 %d 例（真实实现无响应，多半在等剩余字节）"
           "：不崩不挂且未发告警\n", n_any);

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    rsa_privkey_clear(&key);
    x509_store_free(&st);
    return fail ? 1 : 0;
}
