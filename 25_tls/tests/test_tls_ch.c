/* test_tls_ch.c — 真实 ClientHello 下的服务端解析器健壮性
 *
 * 为什么必须有它：
 *   上一个"下一步"识别出：我们只对强制 -tls1_2 的 OpenSSL 客户端验过。
 *   真实世界的客户端（默认 openssl、浏览器）发的是另一种 ClientHello：
 *   legacy_version 仍是 0x0303，但带 TLS 1.3 的 supported_versions、
 *   几十个扩展、完整套件列表。解析器会不会在这种报文上崩掉，此前无人把关。
 *
 *   本文件不做"握手成功"的断言 —— 那只喂一个 ClientHello，后续必然 EOF。
 *   它断言的是三件更硬的事：
 *     1. 真实报文被吃下去了（服务端产出响应字节，而不是在版本检查处就拒了）
 *     2. 任何截断都不崩、不挂死
 *     3. 任何单字节变异都不崩、不挂死
 *
 * 崩溃/挂死必须在子进程里检测：
 *   段错误和死循环都会让父进程的 waitpid 变成"永远等下去"。所以每个用例
 *   fork 一个子进程，子进程自带 alarm 兜底（挂死 -> _exit(99)），父进程
 *   用 WIFSIGNALED 判定崩溃。这是唯一能把"解析器崩了"和"握手失败"
 *   区分开的办法 —— 两者在返回值上都只是"accept 没成功"。
 *
 * 为什么嵌真实报文而不是手写：
 *   手写的 ClientHello 只会包含我们想到的扩展，而解析器真正会崩在
 *   没想到的扩展上。CH_REAL 是从 OpenSSL 3.0.2 默认 s_client 抓下来的。
 */
#include "tls.h"
#include "tls_server.h"
#include "x509.h"
#include "rsa.h"
#include "clienthello_default.h"
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

/* send/recv 共用一个 arg：recv 从 in 取字节（取完返回 0 = EOF），
 * send 只累加计数。服务端写出多少字节是本文件最关心的观测量 ——
 * "产出了响应"才是"解析成功"的证据，accept 的返回值不是。 */
typedef struct {
    const uint8_t *in;
    size_t         in_len, in_off;
    size_t         sent;
} io_st;

static int snd_cb(void *arg, const uint8_t *d, size_t n) {
    io_st *io = (io_st *)arg;
    (void)d;
    io->sent += n;
    return (int)n;                      /* 假装全部写出成功 */
}

static int rcv_cb(void *arg, uint8_t *b, size_t cap) {
    io_st *io = (io_st *)arg;
    if (io->in_off >= io->in_len) return 0;         /* EOF */
    size_t n = io->in_len - io->in_off;
    if (n > cap) n = cap;
    memcpy(b, io->in + io->in_off, n);
    io->in_off += n;
    return (int)n;
}

/* 挂死兜底：3 秒还没返回就 _exit(99)。没有它，"死循环"会和
   "正常返回"混在一起，父进程只能一直等。 */
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
        sent = (uint64_t)io.sent;
        e = tls_server_accept(c);
        err = (int)e;
    } else {
        err = (int)e;
    }
    sent = (uint64_t)io.sent;

    /* 结果经管道回传父进程；写完立即 _exit，绝不跑父进程的循环 */
    {
        ssize_t w1 = write(fd, &sent, sizeof(sent));
        ssize_t w2 = write(fd, &err,  sizeof(err));
        (void)w1; (void)w2;
    }
    _exit(0);
}

/* 返回：0 = 子进程正常返回；-99 = 挂死；<0 其他 = 被信号杀死（崩溃）；
 *       -1 = fork/pipe 失败。*out_sent / *out_err 为子进程回传值。 */
static int run_case(const uint8_t *in, size_t in_len,
                    const rsa_privkey *key,
                    const uint8_t *der, size_t der_len,
                    uint64_t *out_sent, int *out_err) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        child_run(in, in_len, key, der, der_len, pfd[1]);
        _exit(127);                     /* 不会到这里 */
    }
    close(pfd[1]);

    uint64_t sent = 0;
    int      err  = -1;
    if (read(pfd[0], &sent, sizeof(sent)) == (ssize_t)sizeof(sent)) {
        ssize_t r2 = read(pfd[0], &err, sizeof(err));
        (void)r2;          /* 短读说明子进程中途就死了，err 保持 -1 即可 */
    }
    close(pfd[0]);

    int st = 0;
    waitpid(pid, &st, 0);

    *out_sent = sent;
    *out_err  = err;
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

    /* ---- 1. 真实 ClientHello：必须被解析并产出响应 ---- */
    uint64_t sent = 0;
    int      err  = -1;
    int rc = run_case(CH_REAL, CH_REAL_LEN, &key, der, der_len, &sent, &err);
    CHECK(rc == 0,
          "真实 ClientHello：服务端未崩溃未挂死，正常返回（rc=%d）", rc);
    CHECK(sent > 0,
          "真实 ClientHello：服务端产出响应字节 sent=%llu（解析器吃下了真实报文，不是在版本检查处就拒）",
          (unsigned long long)sent);
    printf("[INFO] 只喂 ClientHello，后续 EOF，故 accept 返回 err=%d（属预期）\n", err);

    /* ---- 2. 逐段截断 ---- */
    int crash_tr = 0, hang_tr = 0, n_tr = 0;
    for (size_t cut = 1; cut < CH_REAL_LEN; cut += 13) {
        uint8_t tmp[CH_REAL_LEN];
        memcpy(tmp, CH_REAL, cut);
        uint64_t s2 = 0; int e2 = -1;
        int r2 = run_case(tmp, cut, &key, der, der_len, &s2, &e2);
        n_tr++;
        if (r2 == -99) hang_tr++;
        else if (r2 < 0) crash_tr++;
    }
    CHECK(crash_tr == 0 && hang_tr == 0,
          "截断 %d 例（每 13 字节一刀）：崩溃=%d 挂死=%d", n_tr, crash_tr, hang_tr);

    /* ---- 3. 单字节置 0x00 / 0xFF ---- */
    int crash_bf = 0, hang_bf = 0, n_bf = 0;
    for (size_t off = 0; off < CH_REAL_LEN; off += 8) {
        for (int vi = 0; vi < 2; vi++) {
            uint8_t tmp[CH_REAL_LEN];
            memcpy(tmp, CH_REAL, CH_REAL_LEN);
            tmp[off] = (vi == 0) ? 0x00u : 0xFFu;
            uint64_t s3 = 0; int e3 = -1;
            int r3 = run_case(tmp, CH_REAL_LEN, &key, der, der_len, &s3, &e3);
            n_bf++;
            if (r3 == -99) hang_bf++;
            else if (r3 < 0) crash_bf++;
        }
    }
    CHECK(crash_bf == 0 && hang_bf == 0,
          "单字节变异 %d 例（每 8 字节一处，置 0x00/0xFF）：崩溃=%d 挂死=%d",
          n_bf, crash_bf, hang_bf);

    /* ---- 4. legacy_version 改成 0x0304 ----
     * TLS 1.3 客户端发的 ClientHello，legacy_version 字段仍是 0x0303，
     * 真正的版本在 supported_versions 里。把 legacy 直接写成 0x0304
     * 是在试探：服务端若只看 legacy_version，会把它当成 1.3 并应当
     * 干净拒绝（我们只支持 1.2）；无论拒绝还是忽略，都不许崩。 */
    {
        uint8_t tmp[CH_REAL_LEN];
        memcpy(tmp, CH_REAL, CH_REAL_LEN);
        tmp[9]  = 0x03;                 /* 记录头 5 字节 + 握手头 4 字节 = 偏移 9 */
        tmp[10] = 0x04;
        uint64_t s4 = 0; int e4 = -1;
        int r4 = run_case(tmp, CH_REAL_LEN, &key, der, der_len, &s4, &e4);
        CHECK(r4 == 0,
              "legacy_version=0x0304（TLS1.3 客户端形态）：未崩溃未挂死（rc=%d, sent=%llu）",
              r4, (unsigned long long)s4);
    }

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    rsa_privkey_clear(&key);
    x509_store_free(&st);
    return fail ? 1 : 0;
}
