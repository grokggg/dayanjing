#include "frame.h"

#include <stdlib.h>
#include <string.h>

/* ---------- 字节序工具（小端序） ---------- */

static uint16_t
u16_le(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t
u32_le(const uint8_t *p)
{
    return (uint32_t)(p[0]        | ((uint32_t)p[1] << 8)
                    | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static void
put_u16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

static void
put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* ---------- CRC32 (IEEE 802.3, 多项式 0xEDB88320) ---------- */

static uint32_t crc32_table[256];
static int      crc32_table_initialized;

static void
crc32_init(void)
{
    if (crc32_table_initialized) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int b = 0; b < 8; b++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_initialized = 1;
}

static uint32_t
crc32_buf(const uint8_t *buf, size_t len)
{
    crc32_init();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

/* ---------- 生命周期 ---------- */

void
frame_init(struct frame *f)
{
    memset(f, 0, sizeof(*f));
    f->hdr.magic   = FRAME_MAGIC;
    f->hdr.version = FRAME_VERSION;
    f->hdr.flags   = 0;
    f->hdr.reserved = 0;
    f->hdr.payload_len = 0;
}

void
frame_reset(struct frame *f)
{
    free(f->payload);
    f->payload = NULL;
    f->payload_cap = 0;
    f->hdr.payload_len = 0;
    f->hdr.flags = 0;
    f->crc = 0;
}

void
frame_fini(struct frame *f)
{
    frame_reset(f);
    memset(f, 0, sizeof(*f));
}

/* ---------- payload 深拷贝 ---------- */

int
frame_set_payload(struct frame *f, const uint8_t *data, size_t len)
{
    if (len > FRAME_MAX_PAYLOAD) return FRAME_ERR_TOOBIG;

    uint8_t *p = NULL;
    if (len > 0) {
        p = malloc(len);
        if (!p) return FRAME_ERR_NOMEM;
        memcpy(p, data, len);
    }
    free(f->payload);
    f->payload = p;
    f->payload_cap = len;
    f->hdr.payload_len = (uint32_t)len;
    return FRAME_OK;
}

/* ---------- CRC 计算 ---------- */

uint32_t
frame_calc_crc(const struct frame *f)
{
    /* 拼一份 header（不含尾部 crc 字段），与 payload 拼接后一次计算 */
    size_t plen = (size_t)f->hdr.payload_len;
    size_t n = (size_t)FRAME_HDR_SIZE + plen;
    uint8_t *tmp = malloc(n);
    if (!tmp) return 0;   /* 极端情况：分配失败返回 0，等价于校验失败 */

    put_u32_le(tmp + 0, f->hdr.magic);
    tmp[4] = f->hdr.version;
    tmp[5] = f->hdr.flags;
    put_u16_le(tmp + 6, f->hdr.reserved);
    put_u32_le(tmp + 8, f->hdr.payload_len);
    if (plen > 0 && f->payload) {
        memcpy(tmp + FRAME_HDR_SIZE, f->payload, plen);
    }

    uint32_t c = crc32_buf(tmp, n);
    free(tmp);
    return c;
}

int
frame_verify_crc(const struct frame *f)
{
    return (frame_calc_crc(f) == f->crc) ? FRAME_OK : FRAME_ERR_CRC;
}

/* ---------- 编码 ---------- */

int
frame_pack(const struct frame *f, uint8_t *out, size_t out_cap)
{
    if (!out) return FRAME_ERR_FORMAT;
    if (f->hdr.magic != FRAME_MAGIC) return FRAME_ERR_FORMAT;

    uint32_t plen = f->hdr.payload_len;
    if (plen > FRAME_MAX_PAYLOAD) return FRAME_ERR_TOOBIG;

    size_t total = (size_t)FRAME_MIN_SIZE + (size_t)plen;
    if (out_cap < total) return FRAME_ERR_NOMEM;

    uint8_t *p = out;
    put_u32_le(p + 0,  f->hdr.magic);
    p[4] = f->hdr.version;
    p[5] = f->hdr.flags;
    put_u16_le(p + 6, f->hdr.reserved);
    put_u32_le(p + 8, plen);
    p += FRAME_HDR_SIZE;

    if (plen > 0) {
        memcpy(p, f->payload, plen);
        p += plen;
    }

    uint32_t crc = frame_calc_crc(f);
    put_u32_le(p, crc);
    /* 注意：调用方若需要 f->crc 反映，可自行读取尾部；此处不修改 const 输入 */

    return (int)total;
}

/* ---------- 解码 ---------- */

int
frame_unpack(struct frame *f, const uint8_t *buf, size_t buf_len)
{
    if (!f || !buf) return FRAME_ERR_FORMAT;
    if (buf_len < FRAME_MIN_SIZE) return FRAME_ERR_TRUNC;

    uint32_t magic = u32_le(buf + 0);
    if (magic != FRAME_MAGIC) return FRAME_ERR_FORMAT;

    uint8_t  version = buf[4];
    uint8_t  flags   = buf[5];
    uint16_t reserved = u16_le(buf + 6);
    uint32_t plen     = u32_le(buf + 8);

    if (plen > FRAME_MAX_PAYLOAD) return FRAME_ERR_TOOBIG;

    size_t total = (size_t)FRAME_MIN_SIZE + (size_t)plen;
    if (buf_len < total) return FRAME_ERR_TRUNC;   /* 需要更多数据 */

    uint32_t crc_in = u32_le(buf + FRAME_HDR_SIZE + plen);

    uint8_t *payload = NULL;
    if (plen > 0) {
        payload = malloc(plen);
        if (!payload) return FRAME_ERR_NOMEM;
        memcpy(payload, buf + FRAME_HDR_SIZE, plen);
    }

    /* 全部就绪，填充 frame */
    frame_reset(f);
    f->hdr.magic        = magic;
    f->hdr.version      = version;
    f->hdr.flags        = flags;
    f->hdr.reserved     = reserved;
    f->hdr.payload_len  = plen;
    f->payload          = payload;
    f->payload_cap      = plen;
    f->crc              = crc_in;

    if (frame_verify_crc(f) != FRAME_OK) {
        /* 校验失败：回滚 payload 分配，保持空帧 */
        free(f->payload);
        f->payload = NULL;
        f->payload_cap = 0;
        f->hdr.payload_len = 0;
        return FRAME_ERR_CRC;
    }

    return (int)total;
}
