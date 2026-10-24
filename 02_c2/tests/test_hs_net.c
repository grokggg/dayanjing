/*
 * DAYANJING v3 — test_hs_net.c
 *
 * 02_c2 握手报文层的真实网络协商验证。
 *
 * 与旧"两端本地喂相同字节"的本质区别：
 *   - cnonce / snonce / server_static_id / generation 全部经 loopback TCP 交换
 *   - WELCOME 的 server_mac、FINISHED 的 client_mac 由对端用 k_identity 校验
 *   - 双方各自独立推导 transcript 与会话密钥，再用 AEAD 双向验通证明一致
 *
 * 覆盖：
 *   [离线] 报文编解码往返 / 长度异常 / MAC 篡改 / 错误 k_identity / 类型识别
 *   [在线] fork 服务端+客户端，完整三次握手 + k_c2s/k_s2c 双向 AEAD 验通
 */

#define _POSIX_C_SOURCE 200809L
#include "c2.h"
#include "c2_hsmsg.h"
#include "c2_frame.h"
#include "crypto_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

/* ---- 固定向量（两端共享，模拟预置 PSK 与注册盐） ---- */
static const uint8_t PSK[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t SALT_REG[C2_SALT_REG_LEN] = {
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
    0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
};
static const uint8_t SERVER_ID[C2_SERVER_ID_LEN] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
};
static const char *IMPLANT_ID = "implant-01";
static const uint64_t GENERATION = 7;

/* ---- 网络辅助 ---- */
static int listen_auto(int *out_port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    if (listen(s, 8) < 0) { close(s); return -1; }
    struct sockaddr_in got; socklen_t gl = sizeof got;
    if (getsockname(s, (struct sockaddr *)&got, &gl) < 0) { close(s); return -1; }
    *out_port = ntohs(got.sin_port);
    return s;
}

static int connect_to(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    return s;
}

static int send_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, b + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static ssize_t recv_exact(int fd, uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, b + off, n - off, 0);
        if (r <= 0) break;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

/* ---- 离线：报文编解码与认证 ---- */
static void test_offline(void) {
    c2_keymat_t km;
    CK(c2_derive_pair(PSK, sizeof PSK, SALT_REG, &km) == C2_OK, "注册派生 c2_derive_pair");

    uint8_t cnonce[C2_HS_NONCE_LEN], snonce[C2_HS_NONCE_LEN];
    for (int i = 0; i < C2_HS_NONCE_LEN; i++) {
        cnonce[i] = (uint8_t)(0xC0 + i);
        snonce[i] = (uint8_t)(0x5A + i);
    }

    /* HELLO 往返 */
    uint8_t hello[256]; size_t hello_len = 0;
    CK(c2_hsmsg_encode_hello(NULL, 0, &hello_len, C2_HS_VERSION, C2_HS_SUITE,
                             IMPLANT_ID, cnonce) == C2_OK, "HELLO 探测长度");
    CK(hello_len == 10 + strlen(IMPLANT_ID) + C2_HS_NONCE_LEN, "HELLO 长度正确");
    CK(c2_hsmsg_encode_hello(hello, sizeof hello, &hello_len, C2_HS_VERSION,
                             C2_HS_SUITE, IMPLANT_ID, cnonce) == C2_OK, "HELLO 编码");
    CK(c2_hsmsg_type(hello, hello_len) == C2_HSMSG_HELLO, "HELLO 类型识别");

    char got_id[64]; uint8_t got_cn[C2_HS_NONCE_LEN]; uint32_t v=0, s=0;
    CK(c2_hsmsg_decode_hello(hello, hello_len, &v, &s, got_id, sizeof got_id,
                             got_cn) == C2_OK, "HELLO 解码");
    CK(v == C2_HS_VERSION && s == C2_HS_SUITE, "HELLO version/suite 一致");
    CK(strcmp(got_id, IMPLANT_ID) == 0, "HELLO implant_id 一致");
    CK(memcmp(got_cn, cnonce, C2_HS_NONCE_LEN) == 0, "HELLO cnonce 一致");
    CK(c2_hsmsg_decode_hello(hello, hello_len - 1, &v, &s, got_id, sizeof got_id,
                             got_cn) == C2_ERR_LEN, "HELLO 截断被拒");

    /* WELCOME 往返（服务端 MAC） */
    uint8_t welcome[256]; size_t wl = 0;
    CK(c2_hsmsg_encode_welcome(welcome, sizeof welcome, &wl, C2_HS_VERSION,
                               C2_HS_SUITE, snonce, SERVER_ID, GENERATION,
                               km.k_identity, hello, hello_len) == C2_OK, "WELCOME 编码");
    CK(wl == C2_HS_WELCOME_PREFIX + C2_HS_MAC_LEN, "WELCOME 长度 97");
    CK(c2_hsmsg_type(welcome, wl) == C2_HSMSG_WELCOME, "WELCOME 类型识别");

    /* 参数校验：任一必填指针为 NULL 必须返回 ARG，不得静默解引用。
       这四条是变异审计逼出来的——把整行校验删掉后本文件曾全绿，
       即"这层防护从未被任何断言覆盖"。out=NULL 是合法的（仅查询长度），
       故不在此列，另有 cap 边界用例单独覆盖。 */
    {
        size_t dwl = 0;
        CK(c2_hsmsg_encode_welcome(welcome, sizeof welcome, NULL, C2_HS_VERSION,
                                   C2_HS_SUITE, snonce, SERVER_ID, GENERATION,
                                   km.k_identity, hello, hello_len) == C2_ERR_ARG,
           "WELCOME 编码 len=NULL 被拒 ARG");
        CK(c2_hsmsg_encode_welcome(welcome, sizeof welcome, &dwl, C2_HS_VERSION,
                                   C2_HS_SUITE, NULL, SERVER_ID, GENERATION,
                                   km.k_identity, hello, hello_len) == C2_ERR_ARG,
           "WELCOME 编码 snonce=NULL 被拒 ARG");
        CK(c2_hsmsg_encode_welcome(welcome, sizeof welcome, &dwl, C2_HS_VERSION,
                                   C2_HS_SUITE, snonce, NULL, GENERATION,
                                   km.k_identity, hello, hello_len) == C2_ERR_ARG,
           "WELCOME 编码 server_static_id=NULL 被拒 ARG");
        CK(c2_hsmsg_encode_welcome(welcome, sizeof welcome, &dwl, C2_HS_VERSION,
                                   C2_HS_SUITE, snonce, SERVER_ID, GENERATION,
                                   NULL, hello, hello_len) == C2_ERR_ARG,
           "WELCOME 编码 k_identity=NULL 被拒 ARG");
    }

    uint8_t g_sn[C2_HS_NONCE_LEN], g_sid[C2_SERVER_ID_LEN]; uint64_t g_gen = 0;
    CK(c2_hsmsg_decode_welcome(welcome, wl, &v, &s, g_sn, g_sid, &g_gen,
                               km.k_identity, hello, hello_len) == C2_OK,
       "WELCOME 解码且 server_mac 校验通过");
    CK(memcmp(g_sn, snonce, C2_HS_NONCE_LEN) == 0, "WELCOME snonce 一致");
    CK(memcmp(g_sid, SERVER_ID, C2_SERVER_ID_LEN) == 0, "WELCOME server_static_id 一致");
    CK(g_gen == GENERATION, "WELCOME generation 一致");

    /* 篡改 WELCOME 的 MAC -> AUTH */
    uint8_t bad[256]; memcpy(bad, welcome, wl);
    bad[C2_HS_WELCOME_PREFIX] ^= 0x01;
    CK(c2_hsmsg_decode_welcome(bad, wl, &v, &s, g_sn, g_sid, &g_gen,
                               km.k_identity, hello, hello_len) == C2_ERR_AUTH,
       "WELCOME MAC 篡改被拒 AUTH");
    /* 用错误 k_identity 校验 -> AUTH */
    uint8_t wrongkey[C2_KEY_LEN]; memset(wrongkey, 0x77, sizeof wrongkey);
    CK(c2_hsmsg_decode_welcome(welcome, wl, &v, &s, g_sn, g_sid, &g_gen,
                               wrongkey, hello, hello_len) == C2_ERR_AUTH,
       "WELCOME 错误 k_identity 被拒 AUTH");
    /* 绑定 HELLO：换一个 hello 再验 -> AUTH（证明 MAC 覆盖 HELLO，非仅 prefix） */
    uint8_t hello2[256]; size_t h2len = 0;
    c2_hsmsg_encode_hello(hello2, sizeof hello2, &h2len, C2_HS_VERSION,
                          C2_HS_SUITE, "other-implant", cnonce);
    CK(c2_hsmsg_decode_welcome(welcome, wl, &v, &s, g_sn, g_sid, &g_gen,
                               km.k_identity, hello2, h2len) == C2_ERR_AUTH,
       "WELCOME 绑定到 HELLO（换 HELLO 即 AUTH 失败）");

    /* FINISHED 往返（客户端 MAC） */
    uint8_t fin[128]; size_t fl = 0;
    CK(c2_hsmsg_encode_finished(fin, sizeof fin, &fl, C2_HS_VERSION, C2_HS_SUITE,
                                km.k_identity, hello, hello_len, welcome, wl) == C2_OK,
       "FINISHED 编码");
    CK(fl == C2_HS_FINISHED_PREFIX + C2_HS_MAC_LEN, "FINISHED 长度 41");
    CK(c2_hsmsg_decode_finished(fin, fl, &v, &s, km.k_identity, hello,
                                hello_len, welcome, wl) == C2_OK,
       "FINISHED 解码且 client_mac 校验通过");
    uint8_t badf[128]; memcpy(badf, fin, fl);
    badf[C2_HS_FINISHED_PREFIX] ^= 0x02;
    CK(c2_hsmsg_decode_finished(badf, fl, &v, &s, km.k_identity, hello,
                                hello_len, welcome, wl) == C2_ERR_AUTH,
       "FINISHED MAC 篡改被拒 AUTH");

    /* transcript 三段拼接 */
    uint8_t tr[C2_TRANSCRIPT_LEN];
    c2_hsmsg_transcript(hello, hello_len, welcome, wl, fin, C2_HS_FINISHED_PREFIX, tr);
    uint8_t tr2[C2_TRANSCRIPT_LEN];
    c2_hsmsg_transcript(hello, hello_len, welcome, wl, fin, C2_HS_FINISHED_PREFIX, tr2);
    CK(memcmp(tr, tr2, C2_TRANSCRIPT_LEN) == 0, "transcript 计算确定性");
    uint8_t tr3[C2_TRANSCRIPT_LEN];
    c2_hsmsg_transcript(hello2, h2len, welcome, wl, fin, C2_HS_FINISHED_PREFIX, tr3);
    CK(memcmp(tr, tr3, C2_TRANSCRIPT_LEN) != 0, "transcript 随 HELLO 变化（绑定生效）");
}

/* ---- 在线：fork 服务端 + 客户端，真实 TCP 协商 ---- */

/* 服务端子进程：ls 为已在监听的 fd（由调用方创建并上报端口），返回 0 表示成功 */
static int server_child(int ls) {
    c2_keymat_t km;
    if (c2_derive_pair(PSK, sizeof PSK, SALT_REG, &km) != C2_OK) return 1;

    int cfd = accept(ls, NULL, NULL);
    if (cfd < 0) return 3;

    /* 1) 收 HELLO：先 9 字节拿 id_len，再收剩余 */
    uint8_t hdr[10];
    if (recv_exact(cfd, hdr, sizeof hdr) != (ssize_t)sizeof hdr) { close(cfd); return 4; }
    size_t id_len = hdr[9];
    size_t hello_len = 10 + id_len + C2_HS_NONCE_LEN;
    uint8_t *hello = calloc(hello_len, 1);
    if (!hello) { close(cfd); return 5; }
    memcpy(hello, hdr, sizeof hdr);
    if (recv_exact(cfd, hello + sizeof hdr, hello_len - sizeof hdr) !=
        (ssize_t)(hello_len - sizeof hdr)) { free(hello); close(cfd); return 6; }

    uint32_t v = 0, s = 0; char cid[64]; uint8_t cn[C2_HS_NONCE_LEN];
    if (c2_hsmsg_decode_hello(hello, hello_len, &v, &s, cid, sizeof cid, cn) != C2_OK) {
        free(hello); close(cfd); return 7;
    }

    /* 2) 发 WELCOME（snonce 由服务端产生，不经本地常量） */
    uint8_t snonce[C2_HS_NONCE_LEN];
    for (int i = 0; i < C2_HS_NONCE_LEN; i++) snonce[i] = (uint8_t)(0x5A + i);
    uint8_t welcome[256]; size_t wl = 0;
    if (c2_hsmsg_encode_welcome(welcome, sizeof welcome, &wl, C2_HS_VERSION,
                                C2_HS_SUITE, snonce, SERVER_ID, GENERATION,
                                km.k_identity, hello, hello_len) != C2_OK) {
        free(hello); close(cfd); return 8;
    }
    if (send_all(cfd, welcome, wl) != 0) { free(hello); close(cfd); return 9; }

    /* 3) 收 FINISHED 并校验 client_mac */
    uint8_t fin[128];
    ssize_t got = recv_exact(cfd, fin, C2_HS_FINISHED_PREFIX + C2_HS_MAC_LEN);
    if (got != (ssize_t)(C2_HS_FINISHED_PREFIX + C2_HS_MAC_LEN)) { free(hello); close(cfd); return 10; }
    if (c2_hsmsg_decode_finished(fin, (size_t)got, &v, &s, km.k_identity,
                                 hello, hello_len, welcome, wl) != C2_OK) {
        free(hello); close(cfd); return 11;   /* 伪造客户端 -> 直接失败 */
    }

    /* 4) 推导会话密钥 */
    uint8_t tr[C2_TRANSCRIPT_LEN];
    c2_hsmsg_transcript(hello, hello_len, welcome, wl, fin, C2_HS_FINISHED_PREFIX, tr);
    c2_session_keys_t sk;
    if (c2_derive_session(km.k_server_hold, tr, SERVER_ID, cid, GENERATION, &sk) != C2_OK) {
        free(hello); close(cfd); return 12;
    }

    /* 5) 收客户端用 k_c2s 密封的帧 -> 证明客户端 k_c2s 与服务端一致 */
    uint8_t ibuf[1024];
    ssize_t igot = recv(cfd, ibuf, sizeof ibuf, 0);
    if (igot <= 0) { free(hello); close(cfd); return 13; }
    uint64_t seq = 0; uint32_t mt = 0; uint8_t pl[256]; size_t plen = 0;
    if (c2_frame_open(sk.k_c2s, ibuf, (size_t)igot, &seq, &mt, pl, sizeof pl, &plen) != C2_FRAME_OK) {
        free(hello); close(cfd); return 14;   /* 密钥不一致或篡改 */
    }
    if (plen != 5 || memcmp(pl, "READY", 5) != 0) { free(hello); close(cfd); return 15; }

    /* 6) 回一帧用 k_s2c 密封的响应 */
    uint8_t obuf[512]; size_t olen = 0;
    uint8_t np[8]; memcpy(np, snonce, 8);
    if (c2_frame_seal(sk.k_s2c, np, 0, 1, 0x31, (const uint8_t *)"OK", 2,
                      obuf, sizeof obuf, &olen) != C2_FRAME_OK) {
        free(hello); close(cfd); return 16;
    }
    if (send_all(cfd, obuf, olen) != 0) { free(hello); close(cfd); return 17; }

    free(hello);
    close(cfd);
    return 0;
}

static void test_online(void) {
    int pfd[2];
    if (pipe(pfd) < 0) { CK(0, "pipe 创建"); return; }
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); CK(0, "fork 服务端"); return; }

    if (pid == 0) {
        /* 服务端子进程 */
        close(pfd[0]);
        int lp = 0, ls = listen_auto(&lp);
        if (ls < 0) { (void)!write(pfd[1], &lp, sizeof lp); _exit(2); }
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);
        close(pfd[1]);
        int rc = server_child(ls);
        close(ls);
        _exit(rc == 0 ? 0 : 20 + rc);
    }

    close(pfd[1]);
    int port = 0;
    if (read(pfd[0], &port, sizeof port) != (ssize_t)sizeof port || port == 0) {
        close(pfd[0]); CK(0, "服务端端口回传"); return;
    }
    close(pfd[0]);

    /* ---- 客户端 ---- */
    c2_keymat_t km;
    if (c2_derive_pair(PSK, sizeof PSK, SALT_REG, &km) != C2_OK) {
        CK(0, "客户端注册派生"); waitpid(pid, NULL, 0); return;
    }
    int s = connect_to(port);
    if (s < 0) { CK(0, "客户端连接服务端"); waitpid(pid, NULL, 0); return; }

    uint8_t cnonce[C2_HS_NONCE_LEN];
    for (int i = 0; i < C2_HS_NONCE_LEN; i++) cnonce[i] = (uint8_t)(0xC0 + i);

    uint8_t hello[256]; size_t hello_len = 0;
    c2_hsmsg_encode_hello(hello, sizeof hello, &hello_len, C2_HS_VERSION,
                          C2_HS_SUITE, IMPLANT_ID, cnonce);
    if (send_all(s, hello, hello_len) != 0) { CK(0,"发送 HELLO"); close(s); waitpid(pid,NULL,0); return; }

    uint8_t welcome[256];
    ssize_t wg = recv_exact(s, welcome, C2_HS_WELCOME_PREFIX + C2_HS_MAC_LEN);
    if (wg != (ssize_t)(C2_HS_WELCOME_PREFIX + C2_HS_MAC_LEN)) {
        CK(0, "接收 WELCOME"); close(s); waitpid(pid, NULL, 0); return;
    }
    uint32_t v=0,su=0; uint8_t g_sn[C2_HS_NONCE_LEN], g_sid[C2_SERVER_ID_LEN];
    uint64_t g_gen = 0;
    if (c2_hsmsg_decode_welcome(welcome, (size_t)wg, &v, &su, g_sn, g_sid, &g_gen,
                                km.k_identity, hello, hello_len) != C2_OK) {
        CK(0, "WELCOME server_mac 校验（线上）"); close(s); waitpid(pid,NULL,0); return;
    }
    CK(memcmp(g_sid, SERVER_ID, C2_SERVER_ID_LEN) == 0, "线上收到 server_static_id");
    CK(g_gen == GENERATION, "线上收到 generation");

    uint8_t fin[128]; size_t fl = 0;
    c2_hsmsg_encode_finished(fin, sizeof fin, &fl, C2_HS_VERSION, C2_HS_SUITE,
                             km.k_identity, hello, hello_len, welcome, (size_t)wg);
    if (send_all(s, fin, fl) != 0) { CK(0,"发送 FINISHED"); close(s); waitpid(pid,NULL,0); return; }

    uint8_t tr[C2_TRANSCRIPT_LEN];
    c2_hsmsg_transcript(hello, hello_len, welcome, (size_t)wg, fin, C2_HS_FINISHED_PREFIX, tr);
    c2_session_keys_t sk;
    if (c2_derive_session(km.k_server_hold, tr, g_sid, IMPLANT_ID, g_gen, &sk) != C2_OK) {
        CK(0, "客户端会话密钥派生"); close(s); waitpid(pid,NULL,0); return;
    }
    CK(memcmp(sk.k_c2s, sk.k_s2c, C2_KEY_LEN) != 0, "k_c2s != k_s2c（单向密钥分离）");

    /* 用 k_c2s 发 READY */
    uint8_t obuf[512]; size_t olen = 0;
    uint8_t np[8]; memcpy(np, cnonce, 8);
    if (c2_frame_seal(sk.k_c2s, np, 0, 1, 0x30, (const uint8_t *)"READY", 5,
                      obuf, sizeof obuf, &olen) != C2_FRAME_OK) {
        CK(0, "客户端 k_c2s 密封"); close(s); waitpid(pid,NULL,0); return;
    }
    if (send_all(s, obuf, olen) != 0) { CK(0,"发送 READY"); close(s); waitpid(pid,NULL,0); return; }

    /* 收服务端 k_s2c 响应 */
    uint8_t ibuf[512];
    ssize_t ig = recv(s, ibuf, sizeof ibuf, 0);
    if (ig <= 0) { CK(0, "接收服务端响应"); close(s); waitpid(pid,NULL,0); return; }
    uint64_t sq=0; uint32_t mt=0; uint8_t pl[256]; size_t plen=0;
    int rc = c2_frame_open(sk.k_s2c, ibuf, (size_t)ig, &sq, &mt, pl, sizeof pl, &plen);
    CK(rc == C2_FRAME_OK, "服务端响应用 k_s2c 验签通过（双向密钥一致）");
    if (rc == C2_FRAME_OK)
        CK(plen == 2 && memcmp(pl, "OK", 2) == 0, "服务端响应载荷为 OK");

    close(s);
    int st = 0;
    waitpid(pid, &st, 0);
    CK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "服务端子进程正常完成（0）");
}

int main(void) {
    printf("=== 02_c2 握手报文层：真实网络协商 ===\n");
    signal(SIGPIPE, SIG_IGN);
    test_offline();
    test_online();
    printf("total=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
