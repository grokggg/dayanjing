#ifndef FRAME_H
#define FRAME_H

#include <stddef.h>
#include <stdint.h>

/* 帧格式（小端序）：
 *   offset  size   field
 *   0       4      magic  (0xDAYA)
 *   4       1      version
 *   5       1      flags
 *   6       2      reserved
 *   8       4      payload_len
 *   12      N      payload
 *   12+N    4      crc32  (IEEE 802.3, 覆盖 header + payload)
 *
 * 最小合法帧长度 = 16 字节（header 12 + crc 4，payload 可为空）
 */

#define FRAME_MAGIC      0x44415941u   /* 'D' 'A' 'Y' 'A' */
#define FRAME_VERSION     0x01
#define FRAME_HDR_SIZE    12u
#define FRAME_CRC_SIZE    4u
#define FRAME_MIN_SIZE    (FRAME_HDR_SIZE + FRAME_CRC_SIZE)   /* 16 */
#define FRAME_MAX_PAYLOAD 0x100000u                           /* 1 MiB */

#define FRAME_OK          0
#define FRAME_ERR_NOMEM   -1
#define FRAME_ERR_FORMAT  -2   /* magic 不匹配 / 长度非法 */
#define FRAME_ERR_TRUNC   -3   /* 数据不足最小帧 / 长度字段超过输入 */
#define FRAME_ERR_TOOBIG  -4
#define FRAME_ERR_CRC     -5

struct frame_hdr {
    uint32_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint16_t reserved;
    uint32_t payload_len;
};

struct frame {
    struct frame_hdr hdr;
    uint8_t *payload;
    size_t   payload_cap;   /* 分配容量，内部使用 */
    uint32_t crc;           /* 解码时记录读到的 crc，编码时由 pack 计算 */
};

/* 生命周期 */
void     frame_init(struct frame *f);
void     frame_reset(struct frame *f);   /* 释放 payload，清零（保留可复用） */
void     frame_fini(struct frame *f);    /* 完全释放 */

/* 编码：把 hdr + payload 序列化为连续缓冲区
 * 返回写入字节数（>= FRAME_MIN_SIZE），失败返回负值错误码
 * out 由调用者管理生命周期；建议容量 FRAME_MIN_SIZE + payload_len */
int      frame_pack(const struct frame *f, uint8_t *out, size_t out_cap);

/* 解码：从 buf 中解析一帧，返回消耗的字节数
 * 返回正值：成功，值为该帧占用字节数（= FRAME_MIN_SIZE + hdr.payload_len）
 * 返回负值：错误码
 * 注意：若 buf 长度不足以容纳声明的 payload_len+尾部，返回 FRAME_ERR_TRUNC
 *       表示“需要更多数据”，调用者可继续缓冲后重试 */
int      frame_unpack(struct frame *f, const uint8_t *buf, size_t buf_len);

/* 计算当前帧的 CRC32（覆盖 header + payload），写入 f->crc */
uint32_t frame_calc_crc(const struct frame *f);

/* 校验 CRC：重新计算并与 f->crc 比较，匹配返回 FRAME_OK */
int      frame_verify_crc(const struct frame *f);

/* 设置 payload（深拷贝 len 字节），同时设置 hdr.payload_len
 * 返回 FRAME_OK 或 FRAME_ERR_NOMEM / FRAME_ERR_TOOBIG */
int      frame_set_payload(struct frame *f, const uint8_t *data, size_t len);

#endif /* FRAME_H */
