/*
 * DAYANJING v4 — p2p_cell.h
 *
 * 定长信元层（cell）—— 解除"电路建好后数据面可被流量分析"的限制。
 *
 * ====================================================================
 * 解决的问题
 * ====================================================================
 * 电路建立后，数据面原本是"一帧一个长度"：
 *     wire = 4 字节长度前缀 || AEAD 密文
 * 于是线上每个报文的长度 == 载荷长度 + 常数。
 * 攻击者即使读不懂内容，也能通过**包长序列与时序**推断链路行为
 * （命令下发短、回传截图长、心跳周期固定 —— 这是可识别的行为指纹）。
 *
 * 定长信元后：
 *   - 无论载荷 1 字节还是 493 字节，线上**恒为 512 字节**
 *   - 不足部分用随机填充补足（不是补零 —— 补零会在密文外留下可识别模式，
 *     填充在 AEAD **内部**，加密后才上线）
 *   - 大载荷切成多个信元，小载荷填成一个信元
 *   - 覆盖信元（PAD）在空闲期按抖动节奏发出，打破"无流量=空闲"的对应
 *   - 发送间隔加抖动，打破固定心跳周期
 *
 * ====================================================================
 * 线上格式（恒 512 字节）
 * ====================================================================
 *     ct(496) || tag(16)
 *   其中 ct = AES-128-GCM( pt(496) )
 *     pt = cmd(1) || len(2 LE) || data[len] || pad(随机)
 *   IV  = nonce_pfx(8) || counter(4 LE)      （不在线上传输，两端各自计数）
 *   AAD = nonce_pfx(8) || counter(4 LE)      （把信元绑定到位置，防重排）
 *
 * cmd: 1=DATA  2=PAD(覆盖)  3=FIN(本批结束)
 *
 * ====================================================================
 * 密码学复用（不自研第二套）
 * ====================================================================
 * 原语仍是 00_crypto 的 AES-128-GCM；密钥材料来自 14_p2p 隧道（p2p_crypto.h），
 * 与端点 E2EE 同一套密钥 —— 本层只定义**定长封包格式**，不重新实现任何算法。
 */

#ifndef DAYANJING_P2P_CELL_H
#define DAYANJING_P2P_CELL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_CELL_KEY_LEN     16
#define P2P_CELL_PFX_LEN      8
#define P2P_CELL_WIRE       512   /* 线上恒定长度 */
#define P2P_CELL_TAG_LEN     16
#define P2P_CELL_PT_LEN     496   /* = WIRE - TAG */
#define P2P_CELL_HDR_LEN      3   /* cmd(1) || len(2) */
#define P2P_CELL_DATA_MAX   493   /* = PT - HDR */

/* 信元命令字 */
#define P2P_CELL_CMD_DATA     1
#define P2P_CELL_CMD_PAD      2
#define P2P_CELL_CMD_FIN      3

/* ---- 返回值（与 p2p_crypto.h 对齐） ---- */
#define P2P_CELL_OK        0
#define P2P_CELL_ERR_ARG  -1
#define P2P_CELL_ERR_LEN  -2
#define P2P_CELL_ERR_AUTH -3
#define P2P_CELL_ERR_FMT  -4
#define P2P_CELL_ERR_REPLAY -5

typedef struct {
    uint8_t  k_send[P2P_CELL_KEY_LEN];
    uint8_t  k_recv[P2P_CELL_KEY_LEN];
    uint8_t  pfx[P2P_CELL_PFX_LEN];
    uint32_t send_counter;
    uint32_t recv_counter;      /* 已接受的最大 counter；严格递增，防重排/重放 */
    int      recv_init;
} p2p_cell_ctx_t;

/* 初始化。k_send/k_recv 必须不同（方向分离）；两端方向相反。 */
int p2p_cell_init(p2p_cell_ctx_t *c,
                  const uint8_t k_send[P2P_CELL_KEY_LEN],
                  const uint8_t k_recv[P2P_CELL_KEY_LEN],
                  const uint8_t pfx[P2P_CELL_PFX_LEN]);
void p2p_cell_wipe(p2p_cell_ctx_t *c);

/*
 * 封装一个信元：无论 len 多小，out 恒写 P2P_CELL_WIRE 字节。
 * len > P2P_CELL_DATA_MAX 返回 P2P_CELL_ERR_LEN（应改用 pack_stream 分片）。
 */
int p2p_cell_pack(p2p_cell_ctx_t *c, uint8_t cmd,
                  const uint8_t *data, size_t len,
                  uint8_t out[P2P_CELL_WIRE]);

/* 解封一个信元。counter 回退或重复 -> P2P_CELL_ERR_REPLAY。 */
int p2p_cell_unpack(p2p_cell_ctx_t *c, const uint8_t in[P2P_CELL_WIRE],
                    uint8_t *cmd, uint8_t *data, size_t cap, size_t *len);

/* 生成一个覆盖信元（cmd=PAD，内容为随机填充），线上同样 512 字节 */
int p2p_cell_pack_cover(p2p_cell_ctx_t *c, uint8_t out[P2P_CELL_WIRE]);

/*
 * 流式分片：把任意长度的数据切成若干定长信元。
 * out 需要 n_cells * 512 字节；out_cells 返回实际信元数。
 * 最后一片 cmd=FIN；空数据也产生 1 个 FIN 信元（避免"空消息不发信元"的侧信道）。
 */
int p2p_cell_fragment(size_t len, size_t *n_cells);
int p2p_cell_pack_stream(p2p_cell_ctx_t *c,
                         const uint8_t *data, size_t len,
                         uint8_t *out, size_t cap, size_t *out_cells);
int p2p_cell_unpack_stream(p2p_cell_ctx_t *c,
                           const uint8_t *in, size_t n_cells,
                           uint8_t *data, size_t cap, size_t *len);

/* ---- 发送调度：抖动 + 覆盖流量 ---- */
typedef struct { uint32_t s; } p2p_cell_sched_t;

void p2p_cell_sched_seed(p2p_cell_sched_t *sc, uint32_t seed);

/* 下一次发送的延迟（ms），均匀取自 [min_ms, max_ms]；min==max 时返回该值 */
uint32_t p2p_cell_next_delay_ms(p2p_cell_sched_t *sc,
                                uint32_t min_ms, uint32_t max_ms);

/*
 * 覆盖流量判决：给定空闲时长 idle_ms 与目标速率 rate_per_min（每分钟覆盖信元数），
 * 返回 1 表示此刻应发一个覆盖信元；*out_delay 给出建议延迟。
 * 判决含随机性 —— 同样的空闲时长不总得出同样结论，避免节奏可被建模。
 */
int  p2p_cell_cover_due(p2p_cell_sched_t *sc, uint32_t idle_ms,
                        uint32_t rate_per_min, uint32_t *out_delay);

const char *p2p_cell_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_CELL_H */
