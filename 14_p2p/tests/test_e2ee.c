/*
 * DAYANJING v4 — 14_p2p/tests/test_e2ee.c
 *
 * 验证两件事：
 *   A. 隧道语义：封装/解封往返、探测长度、密钥错误、篡改、重放、乱序、过旧
 *   B. 真实多跳链路：端点封装 -> edge0 -> edge1 -> core -> 对端解封
 *      · 中间跳只转发密文，且在 edge0 上做旁路抓包（tap）
 *      · 抓到的字节用错误密钥解不开（AUTH），用端点密钥才能解开
 *      · 中间跳对密文做单字节篡改 -> 端点侧验签失败
 *
 * 全部用真实 socket + fork 进程，不做模拟。
 */

#define _POSIX_C_SOURCE 200809L
#include "p2p.h"
#include "p2p_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

/* ---- 固定密钥材料（仅测试用，生产环境来自 02_c2 会话派生） ---- */
static const uint8_t K_CS[16] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                  0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10 };
static const uint8_t K_SC[16] = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
                                  0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0 };
static const uint8_t K_X[16]  = { 0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
                                  0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef };
static const uint8_t PFX[8]   = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };

#define MSG_REQ 0x21u
#define MSG_RSP 0x22u
#define BIGBUF  70000

/* 子串查找：不用 memmem（GNU 扩展，会被 _POSIX_C_SOURCE 屏蔽） */
static const uint8_t *find_bytes(const uint8_t *hay, size_t hlen,
                                 const uint8_t *needle, size_t nlen) {
    if (!hay || !needle || nlen == 0 || nlen > hlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

/* 客户端视角：send=K_CS, recv=K_SC */
static void mk_client(p2p_tunnel_t *t) {
    p2p_tunnel_init(t, K_CS, K_SC, PFX);
}
/* 对端视角：方向相反 */
static void mk_peer(p2p_tunnel_t *t) {
    p2p_tunnel_init(t, K_SC, K_CS, PFX);
}

/* ===================== 网络辅助 ===================== */

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
    if (listen(s, 16) < 0) { close(s); return -1; }
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
        if (w <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int recv_exact(int fd, uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, b + off, n - off, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;              /* EOF */
        off += (size_t)r;
    }
    return 0;
}

/* 按 wire 自带的长度前缀读一整帧 */
static int recv_frame(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t hdr[4];
    if (recv_exact(fd, hdr, 4) < 0) return -1;
    size_t total = (size_t)hdr[0] | ((size_t)hdr[1] << 8)
                 | ((size_t)hdr[2] << 16) | ((size_t)hdr[3] << 24);
    if (total < 52 || total + 4 > cap) return -1;
    memcpy(buf, hdr, 4);
    if (recv_exact(fd, buf + 4, total) < 0) return -1;
    *out_len = total + 4;
    return 0;
}

/* 双工中继，并把流经的字节旁路写入 tapfd（抓包用） */
static void relay_tap(int a, int b, int tapfd) {
    struct pollfd fds[2];
    uint8_t buf[4096];
    for (;;) {
        fds[0].fd = a; fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = b; fds[1].events = POLLIN; fds[1].revents = 0;
        int r = poll(fds, 2, 5000);
        if (r < 0) { if (errno == EINTR) continue; return; }
        if (r == 0) return;
        for (int i = 0; i < 2; i++) {
            if (!(fds[i].revents & POLLIN)) continue;
            ssize_t n = recv(fds[i].fd, buf, sizeof buf, 0);
            if (n <= 0) return;
            if (tapfd >= 0) {
                ssize_t w = write(tapfd, buf, (size_t)n);
                (void)w;
            }
            int dst = (i == 0) ? b : a;
            if (send_all(dst, buf, (size_t)n) < 0) return;
        }
    }
}

/* ===================== A. 隧道语义 ===================== */

static void test_units(void) {
    printf("\n--- A. 隧道语义 ---\n");
    p2p_tunnel_t c, p;

    p2p_tunnel_t bad;
    CK(p2p_tunnel_init(&bad, K_CS, K_CS, PFX) == P2P_C_ERR_ARG,
       "k_send == k_recv 被拒（单向密钥分离）");
    CK(p2p_tunnel_init(NULL, K_CS, K_SC, PFX) == P2P_C_ERR_ARG, "NULL 隧道返回 ARG");
    CK(p2p_tunnel_init(&bad, K_CS, K_SC, NULL) == P2P_C_ERR_ARG, "NULL nonce 前缀返回 ARG");

    /* 往返 */
    mk_client(&c); mk_peer(&p);
    const char *msg = "P2P-E2EE-PAYLOAD-0123456789";
    size_t mlen = strlen(msg);
    uint8_t wire[BIGBUF]; size_t wlen = 0;
    CK(p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)msg, mlen, wire, sizeof wire, &wlen) == P2P_C_OK,
       "wrap 成功");
    CK(wlen == p2p_tunnel_wire_len(mlen), "wire 长度与 wire_len() 一致");

    uint8_t out[BIGBUF]; size_t olen = 0; uint64_t seq = 0; uint32_t mt = 0;
    CK(p2p_tunnel_unwrap(&p, wire, wlen, &seq, &mt, out, sizeof out, &olen) == P2P_C_OK,
       "unwrap 成功");
    CK(olen == mlen && memcmp(out, msg, mlen) == 0, "载荷字节级一致");
    CK(seq == 0, "seq 回传正确");
    CK(mt == MSG_REQ, "msg_type 回传正确");

    size_t dummy = 0;   /* 探针调用：plen 不可为 NULL */

    /* 探测长度不得推进状态 */
    size_t probe = 0;
    CK(p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)msg, mlen, NULL, 0, &probe) == P2P_C_OK,
       "wrap(NULL) 探测成功");
    CK(probe == wlen, "探测长度与实际一致");
    size_t wlen2 = 0;
    p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)msg, mlen, wire, sizeof wire, &wlen2);
    CK(p2p_tunnel_unwrap(&p, wire, wlen2, &seq, NULL, NULL, 0, &olen) == P2P_C_OK,
       "探测后再次 wrap 的帧仍可解");
    CK(seq == 1, "探测调用未污染 seq（仍为 1）");

    /* 错误密钥 */
    p2p_tunnel_t wrong;
    p2p_tunnel_init(&wrong, K_X, K_SC, PFX);
    CK(p2p_tunnel_unwrap(&wrong, wire, wlen2, NULL, NULL, out, sizeof out, &olen) == P2P_C_ERR_AUTH,
       "错误密钥解封返回 AUTH");

    /* 篡改：翻转密文中间一字节 */
    uint8_t tw[BIGBUF];
    memcpy(tw, wire, wlen2);
    tw[wlen2 / 2] ^= 0x01;
    p2p_tunnel_t fresh;
    mk_peer(&fresh);
    CK(p2p_tunnel_unwrap(&fresh, tw, wlen2, NULL, NULL, out, sizeof out, &olen) == P2P_C_ERR_AUTH,
       "密文单字节篡改被拒绝");

    /* 篡改帧头 msg_type（参与 AAD） */
    memcpy(tw, wire, wlen2);
    tw[4] ^= 0x01;
    mk_peer(&fresh);
    CK(p2p_tunnel_unwrap(&fresh, tw, wlen2, NULL, NULL, out, sizeof out, &olen) == P2P_C_ERR_AUTH,
       "帧头 msg_type 篡改被拒绝");

    /* 探测模式也必须验签：伪造帧在仅探测路径上不得被当成合法帧 */
    memcpy(tw, wire, wlen2);
    tw[wlen2 / 2] ^= 0x01;
    mk_peer(&fresh);
    CK(p2p_tunnel_unwrap(&fresh, tw, wlen2, NULL, NULL, NULL, 0, &dummy) == P2P_C_ERR_AUTH,
       "探测模式对篡改帧也返回 AUTH（不接受伪造帧）");

    /* 重放 */
    mk_client(&c); mk_peer(&p);
    uint8_t w1[BIGBUF]; size_t l1 = 0;
    p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)"A", 1, w1, sizeof w1, &l1);
    CK(p2p_tunnel_unwrap(&p, w1, l1, NULL, NULL, out, sizeof out, &olen) == P2P_C_OK, "首帧接受");
    CK(p2p_tunnel_unwrap(&p, w1, l1, NULL, NULL, out, sizeof out, &olen) == P2P_C_ERR_REPLAY,
       "重放同一帧被拒绝");

    /* 乱序：先 seq=1 再 seq=0，窗口内可接受 */
    mk_client(&c); mk_peer(&p);
    uint8_t f0[BIGBUF], f1[BIGBUF]; size_t l0 = 0, l1b = 0;
    p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)"zero", 4, f0, sizeof f0, &l0);
    p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)"one",  3, f1, sizeof f1, &l1b);
    CK(p2p_tunnel_unwrap(&p, f1, l1b, NULL, NULL, out, sizeof out, &olen) == P2P_C_OK, "乱序先收 seq=1");
    CK(p2p_tunnel_unwrap(&p, f0, l0, NULL, NULL, out, sizeof out, &olen) == P2P_C_OK, "乱序后收 seq=0 仍接受");
    CK(p2p_tunnel_unwrap(&p, f0, l0, NULL, NULL, out, sizeof out, &olen) == P2P_C_ERR_REPLAY,
       "窗口内重复帧被拒绝");

    /* 过旧：滑出 64 窗口 */
    mk_client(&c); mk_peer(&p);
    uint8_t old[BIGBUF]; size_t oldl = 0;
    p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)"old", 3, old, sizeof old, &oldl);
    uint8_t cur[BIGBUF]; size_t curl = 0;
    for (int i = 0; i < 70; i++) {
        curl = 0;
        p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)"x", 1, cur, sizeof cur, &curl);
        p2p_tunnel_unwrap(&p, cur, curl, NULL, NULL, NULL, 0, &dummy);
    }
    CK(p2p_tunnel_unwrap(&p, old, oldl, NULL, NULL, out, sizeof out, &olen) == P2P_C_ERR_REPLAY,
       "滑出窗口的过旧帧被拒绝");

    /* 格式 */
    CK(p2p_tunnel_unwrap(&p, wire, 3, NULL, NULL, NULL, 0, &dummy) == P2P_C_ERR_FMT, "不足 4 字节返回 FMT");
    uint8_t trunc[BIGBUF];
    memcpy(trunc, cur, curl);
    CK(p2p_tunnel_unwrap(&p, trunc, curl - 1, NULL, NULL, NULL, 0, &dummy) == P2P_C_ERR_FMT,
       "截断帧返回 FMT（长度前缀不符）");
    size_t fl = 0;
    CK(p2p_tunnel_frame_len(cur, curl, &fl) == P2P_C_OK && fl == curl, "frame_len 解析正确");

    /* 大载荷 */
    mk_client(&c); mk_peer(&p);
    static uint8_t big[60000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 7 + 3);
    uint8_t bw[BIGBUF]; size_t bl = 0;
    CK(p2p_tunnel_wrap(&c, MSG_REQ, big, sizeof big, bw, sizeof bw, &bl) == P2P_C_OK, "大载荷 wrap 成功");
    static uint8_t bout[BIGBUF]; size_t bol = 0;
    CK(p2p_tunnel_unwrap(&p, bw, bl, NULL, NULL, bout, sizeof bout, &bol) == P2P_C_OK, "大载荷 unwrap 成功");
    CK(bol == sizeof big && memcmp(bout, big, sizeof big) == 0, "大载荷字节级一致");
}

/* ===================== B. 真实多跳链路 ===================== */

/* 对端进程：解封请求 -> 封装响应 */
static void peer_child(int lfd) {
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) _exit(1);
    p2p_tunnel_t t; mk_peer(&t);
    uint8_t buf[BIGBUF];
    /* 循环服务：每个请求解封后回一个响应，直到对端关闭 */
    for (;;) {
        size_t fl = 0;
        if (recv_frame(cfd, buf, sizeof buf, &fl) < 0) break;
        uint8_t out[BIGBUF]; size_t olen = 0;
        if (p2p_tunnel_unwrap(&t, buf, fl, NULL, NULL, out, sizeof out, &olen) != P2P_C_OK)
            continue;                       /* 非法帧静默丢弃，不暴露原因 */
        size_t rl = olen + 4;
        uint8_t *rsp = malloc(rl);
        if (!rsp) break;
        memcpy(rsp, out, olen);
        memcpy(rsp + olen, "_RSP", 4);
        uint8_t w[BIGBUF]; size_t wl = 0;
        if (p2p_tunnel_wrap(&t, MSG_RSP, rsp, rl, w, sizeof w, &wl) == P2P_C_OK) {
            if (send_all(cfd, w, wl) < 0) { free(rsp); break; }
        }
        free(rsp);
    }
    close(cfd);
    _exit(0);
}

/* 中继子进程：accept 一连接 -> 连下一跳 -> 双工转发（可带抓包） */
static pid_t spawn_relay(int lfd, int next_port, int tapfd) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        close(0);
        signal(SIGPIPE, SIG_IGN);
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) _exit(1);
        int sfd = connect_to(next_port);
        if (sfd < 0) { close(cfd); _exit(1); }
        relay_tap(cfd, sfd, tapfd);
        close(cfd); close(sfd);
        _exit(0);
    }
    return pid;
}

static void test_chain_e2ee(void) {
    printf("\n--- B. 真实多跳链路（endpoint -> edge0 -> edge1 -> core -> peer） ---\n");

    int p_peer = 0, p_core = 0, p_edge1 = 0, p_edge0 = 0;
    int l_peer = listen_auto(&p_peer);
    int l_core = listen_auto(&p_core);
    int l_edge1 = listen_auto(&p_edge1);
    int l_edge0 = listen_auto(&p_edge0);
    if (l_peer < 0 || l_core < 0 || l_edge1 < 0 || l_edge0 < 0) {
        printf("[FAIL] 监听失败\n"); fail++; return;
    }

    /* edge0 上做旁路抓包 */
    char tap_path[] = "/tmp/p2p_tapXXXXXX";
    int tapfd = mkstemp(tap_path);
    if (tapfd < 0) { printf("[FAIL] 抓包文件创建失败\n"); fail++; return; }

    pid_t pid_peer = fork();
    if (pid_peer == 0) { signal(SIGPIPE, SIG_IGN); peer_child(l_peer); _exit(0); }

    pid_t r_core  = spawn_relay(l_core,  p_peer, -1);
    pid_t r_edge1 = spawn_relay(l_edge1, p_core, -1);
    pid_t r_edge0 = spawn_relay(l_edge0, p_edge1, tapfd);

    int cfd = connect_to(p_edge0);
    if (cfd < 0) { printf("[FAIL] 连接 edge0 失败\n"); fail++; return; }

    p2p_tunnel_t c; mk_client(&c);
    const char *req = "HELLO-P2P-E2EE-over-4-hops";
    size_t rlen = strlen(req);
    uint8_t wire[BIGBUF]; size_t wl = 0;
    CK(p2p_tunnel_wrap(&c, MSG_REQ, (const uint8_t *)req, rlen, wire, sizeof wire, &wl) == P2P_C_OK,
       "端点封装请求");

    CK(send_all(cfd, wire, wl) == 0, "请求经四级链路发出");

    uint8_t rsp[BIGBUF]; size_t rl = 0;
    if (recv_frame(cfd, rsp, sizeof rsp, &rl) == 0) {
        uint8_t out[BIGBUF]; size_t olen = 0; uint64_t seq = 0; uint32_t mt = 0;
        CK(p2p_tunnel_unwrap(&c, rsp, rl, &seq, &mt, out, sizeof out, &olen) == P2P_C_OK,
           "响应解封成功（四级链路往返）");
        CK(mt == MSG_RSP, "响应 msg_type 正确");
        CK(olen == rlen + 4 && memcmp(out, req, rlen) == 0 &&
           memcmp(out + rlen, "_RSP", 4) == 0, "响应载荷为请求 + _RSP");
    } else {
        CK(0, "收到响应帧");
    }

    /* 大载荷穿越多跳 */
    static uint8_t big[40000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i ^ 0x5a);
    uint8_t bwire[BIGBUF]; size_t bwl = 0;
    p2p_tunnel_wrap(&c, MSG_REQ, big, sizeof big, bwire, sizeof bwire, &bwl);
    CK(send_all(cfd, bwire, bwl) == 0, "大载荷经四级链路发出");
    uint8_t brsp[BIGBUF]; size_t brl = 0;
    if (recv_frame(cfd, brsp, sizeof brsp, &brl) == 0) {
        static uint8_t bout[BIGBUF]; size_t bol = 0;
        CK(p2p_tunnel_unwrap(&c, brsp, brl, NULL, NULL, bout, sizeof bout, &bol) == P2P_C_OK,
           "大载荷响应解封成功");
        CK(bol == sizeof big + 4 && memcmp(bout, big, sizeof big) == 0, "大载荷经四跳字节级一致");
    } else {
        CK(0, "大载荷响应帧到达");
    }

    close(cfd);
    close(l_edge0); close(l_edge1); close(l_core); close(l_peer);

    /* ---- 抓包取证：中间跳看到的是密文 ---- */
    off_t tsz = lseek(tapfd, 0, SEEK_END);
    lseek(tapfd, 0, SEEK_SET);
    uint8_t *tap = NULL;
    if (tsz > 0) {
        tap = malloc((size_t)tsz);
        if (tap) {
            size_t got = 0;
            while (got < (size_t)tsz) {
                ssize_t r = read(tapfd, tap + got, (size_t)tsz - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
        }
    }
    close(tapfd);

    if (tap && tsz > 0) {
        size_t fl = 0;
        CK(p2p_tunnel_frame_len(tap, (size_t)tsz, &fl) == P2P_C_OK, "抓包首帧可解析出长度");
        if (fl <= (size_t)tsz) {
            /* 明文不应出现在抓包里 */
            CK(find_bytes(tap, fl, (const uint8_t *)req, rlen) == NULL,
               "抓包中不含明文载荷（中间跳看不到内容）");

            p2p_tunnel_t sniffer_wrong, sniffer_right;
            p2p_tunnel_init(&sniffer_wrong, K_X, K_SC, PFX);
            uint8_t so[BIGBUF]; size_t sol = 0;
            CK(p2p_tunnel_unwrap(&sniffer_wrong, tap, fl, NULL, NULL, so, sizeof so, &sol) == P2P_C_ERR_AUTH,
               "抓包用错误密钥解不开 AUTH");

            p2p_tunnel_init(&sniffer_right, K_SC, K_CS, PFX);   /* recv = K_CS */
            CK(p2p_tunnel_unwrap(&sniffer_right, tap, fl, NULL, NULL, so, sizeof so, &sol) == P2P_C_OK &&
               sol == rlen && memcmp(so, req, rlen) == 0, "抓包用端点密钥可还原（证明转发的确是该帧）");

            /* 中间跳篡改抓到的密文 -> 端点侧验签失败 */
            uint8_t *tw = malloc(fl);
            if (tw) {
                memcpy(tw, tap, fl);
                tw[fl / 2] ^= 0x01;
                p2p_tunnel_t victim;
                mk_peer(&victim);
                CK(p2p_tunnel_unwrap(&victim, tw, fl, NULL, NULL, so, sizeof so, &sol) == P2P_C_ERR_AUTH,
                   "中间跳篡改密文后端点验签失败");
                free(tw);
            }
        }
    } else {
        CK(0, "抓包捕获到字节");
    }
    free(tap);
    unlink(tap_path);

    int st;
    if (pid_peer > 0) waitpid(pid_peer, &st, 0);
    if (r_edge0 > 0) waitpid(r_edge0, &st, 0);
    if (r_edge1 > 0) waitpid(r_edge1, &st, 0);
    if (r_core  > 0) waitpid(r_core,  &st, 0);
}

int main(void) {
    printf("=== 14_p2p E2EE 测试 ===\n");
    signal(SIGPIPE, SIG_IGN);
    test_units();
    test_chain_e2ee();
    printf("\ntotal=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
