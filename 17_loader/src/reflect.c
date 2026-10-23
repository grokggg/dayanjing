/*
 * DAYANJING v4 — 17_loader/src/reflect.c
 *
 * 反射加载（无文件执行）：
 *   头拷贝 -> 节区拷贝 -> 基址重定位 -> IAT 绑定 -> TLS 回调收集
 *
 * 本层在调用方提供的内存区域上构造一个完整的 PE 内存映像。
 * Windows 上的后续步骤（权限切换、TLS 回调调用、入口点跳转）依赖目标平台；
 * Linux 上可验证到"内存映像与加载器语义一致"这一层。
 */

#include "loader.h"

#include <string.h>
#include <stdint.h>

/* RVA 写入 region：边界检查后按 is64 写 4 或 8 字节 */
static int region_wr(const pe_image_t *img, uint8_t *region, size_t region_size,
                     uint32_t rva, uint64_t val)
{
    size_t need = img->is64 ? 8u : 4u;
    if ((size_t)rva > region_size) return LD_ERR_NOSPACE;
    if (need > region_size - (size_t)rva) return LD_ERR_NOSPACE;
    if (img->is64) ld_wr64(region + rva, val);
    else           ld_wr32(region + rva, (uint32_t)val);
    return LD_OK;
}

int reflect_map_sections(const pe_image_t *img, uint8_t *region, size_t region_size)
{
    uint32_t hdr;
    uint16_t i;

    if (!img || !region || !img->buf) return LD_ERR_ARG;
    if (region_size < pe_virtual_size(img)) return LD_ERR_NOSPACE;

    memset(region, 0, region_size);

    /* 1) 头部 */
    hdr = img->size_headers;
    if (hdr > img->len) hdr = (uint32_t)img->len;
    if (hdr > region_size) hdr = (uint32_t)region_size;
    memcpy(region, img->buf, hdr);

    /* 2) 节区 */
    for (i = 0; i < img->sec_count; i++) {
        const pe_sec_t *s = &img->secs[i];
        uint32_t copy = s->vsize < s->raw_size ? s->vsize : s->raw_size;
        uint32_t avail;

        if (s->vaddr == 0) continue;
        if (copy == 0) continue;
        if ((size_t)s->vaddr >= region_size) return LD_ERR_NOSPACE;
        avail = (uint32_t)(region_size - (size_t)s->vaddr);
        if (copy > avail) copy = avail;

        if (s->raw_ptr >= img->len) continue;
        {
            uint32_t srcavail = (uint32_t)(img->len - (size_t)s->raw_ptr);
            if (copy > srcavail) copy = srcavail;
        }
        memcpy(region + s->vaddr, img->buf + s->raw_ptr, copy);
    }
    return LD_OK;
}

int reflect_relocate(const pe_image_t *img, uint8_t *region, size_t region_size,
                     int64_t delta, uint32_t *nfixed)
{
    uint32_t dir_rva, dir_size, off;
    uint32_t consumed = 0;
    uint32_t count = 0;
    int r;

    if (!img || !region || !img->buf) return LD_ERR_ARG;
    if (nfixed) *nfixed = 0;
    if (delta == 0) return LD_OK;   /* 按 ImageBase 加载，无需重定位 */

    dir_rva  = img->dir[PE_DIR_RELOC].rva;
    dir_size = img->dir[PE_DIR_RELOC].size;
    if (dir_rva == 0 || dir_size == 0) return LD_OK;

    r = pe_rva_to_file(img, dir_rva, &off);
    if (r != LD_OK) return r;

    while (consumed + 8u <= dir_size) {
        uint32_t boff = off + consumed;
        uint32_t page, bsize;
        uint32_t nent, e;

        if ((size_t)boff + 8u > img->len) return LD_ERR_TRUNC;

        page  = ld_rd32(img->buf + boff);
        bsize = ld_rd32(img->buf + boff + 4u);
        if (bsize < 8u || bsize > dir_size - consumed) return LD_ERR_FORMAT;
        if ((size_t)boff + bsize > img->len) return LD_ERR_TRUNC;

        nent = (bsize - 8u) / 2u;
        for (e = 0; e < nent; e++) {
            uint16_t raw = (uint16_t)((uint16_t)img->buf[boff + 8u + e * 2u]
                                    | ((uint16_t)img->buf[boff + 8u + e * 2u + 1u] << 8));
            uint16_t type = (uint16_t)((raw >> 12) & 0x0Fu);
            uint32_t low  = (uint32_t)(raw & 0x0FFFu);
            uint32_t rva  = page + low;
            uint64_t cur;

            if (type == 0) continue;                    /* ABSOLUTE：跳过 */
            if (rva >= region_size) return LD_ERR_NOSPACE;

            if (type == 3u) {                            /* HIGHLOW：32 位 */
                if (rva + 4u > region_size) return LD_ERR_NOSPACE;
                cur = ld_rd32(region + rva);
                cur = (uint32_t)(cur + (uint32_t)(int32_t)delta);
                ld_wr32(region + rva, (uint32_t)cur);
                count++;
            } else if (type == 10u) {                    /* DIR64：64 位 */
                if (rva + 8u > region_size) return LD_ERR_NOSPACE;
                cur = ld_rd64(region + rva);
                cur = (uint64_t)((int64_t)cur + delta);
                ld_wr64(region + rva, cur);
                count++;
            } else {
                /* 其余类型（HIGH/LOW/HIGHADJ 等）在 PE32+ 上是无效/不支持的；
                   静默跳过会让映像静默损坏，故显式报错。 */
                return LD_ERR_FORMAT;
            }
        }

        consumed += bsize;
        if (bsize == 0) break;    /* 防御：避免死循环 */
    }

    if (nfixed) *nfixed = count;
    return LD_OK;
}

int reflect_bind_imports(const pe_image_t *img, uint8_t *region, size_t region_size,
                         reflect_resolve_fn res, void *ud, uint32_t *n)
{
    pe_import_iter_t it;
    int r;
    uint32_t cnt = 0;

    if (!img || !region) return LD_ERR_ARG;
    if (n) *n = 0;
    if (img->dir[PE_DIR_IMPORT].rva == 0) return LD_OK;

    r = pe_import_begin(img, &it);
    if (r != LD_OK) return r;

    for (;;) {
        uint64_t addr = 0;
        r = pe_import_next(&it);
        if (r < 0) return r;
        if (r == 0) break;

        if (res) {
            r = res(it.dll, it.func, it.ordinal, it.by_ordinal, ud, &addr);
            if (r != LD_OK) return r;
        } else {
            /* 无解析器：填 0，调用方自行判断 */
            addr = 0;
        }

        {
            uint32_t slot_rva = it.iat_rva
                              + (uint32_t)(it.iat_slot - it.iat_off);
            r = region_wr(img, region, region_size, slot_rva, addr);
            if (r != LD_OK) return r;
        }
        cnt++;
    }
    if (n) *n = cnt;
    return LD_OK;
}

int reflect_collect_tls(const pe_image_t *img, uint8_t *region, size_t region_size,
                        uint64_t *cbs, size_t cap, size_t *n)
{
    uint32_t dir_rva, off;
    uint64_t cb_va;        /* VA，不是 RVA：ImageBase 常 >= 4GiB，必须 64 位 */
    size_t   i;
    int r;

    if (!img || !img->buf) return LD_ERR_ARG;
    if (n) *n = 0;
    if (img->dir[PE_DIR_TLS].rva == 0) return LD_OK;

    dir_rva = img->dir[PE_DIR_TLS].rva;
    r = pe_rva_to_file(img, dir_rva, &off);
    if (r != LD_OK) return r;
    if ((size_t)off + (img->is64 ? 40u : 24u) > img->len) return LD_ERR_TRUNC;

    /*
     * AddressOfCallBacks：IMAGE_TLS_DIRECTORY64 @ +24，IMAGE_TLS_DIRECTORY32
     * @ +12。存的是 VA，不是 RVA。
     *
     * 修正：PE32+ 下该字段是 8 字节 ULONGLONG。此前按 +20 偏移、4 字节读取：
     *   - 偏移 +20 在 64 位目录里是 SizeOfZeroFill，恒为 0，于是"无 TLS 回调"
     *     被静默判定，reflect_load 照样返回 OK；
     *   - 即便偏移对了，4 字节读取会把 ImageBase >= 4GiB（MSVC 默认
     *     0x140000000）的 VA 截断，得到 < ImageBase 的值而报 FORMAT。
     * 两者都导致 PE32+ 的 TLS 回调从未被真正收集，且都不报错。
     */
    if (img->is64) {
        if ((size_t)off + 32u > img->len) return LD_ERR_TRUNC;
        cb_va = ld_rd64(img->buf + off + 24u);
    } else {
        cb_va = ld_rd32(img->buf + off + 12u);
    }
    if (cb_va == 0) return LD_OK;

    for (i = 0; i < cap; i++) {
        uint32_t rva = (uint32_t)(cb_va - img->image_base);
        uint32_t fo;
        uint64_t va;

        if (cb_va < img->image_base) return LD_ERR_FORMAT;

        r = pe_rva_to_file(img, rva, &fo);
        if (r != LD_OK) return r;

        if (img->is64) {
            if ((size_t)fo + 8u > img->len) return LD_ERR_TRUNC;
            va = ld_rd64(img->buf + fo);
        } else {
            if ((size_t)fo + 4u > img->len) return LD_ERR_TRUNC;
            va = ld_rd32(img->buf + fo);
        }
        if (va == 0) break;   /* 以 NULL 结尾 */

        if (va < img->image_base) return LD_ERR_FORMAT;
        rva = (uint32_t)(va - img->image_base);
        if ((size_t)rva >= region_size) return LD_ERR_NOSPACE;

        cbs[i] = (uint64_t)(uintptr_t)(region + rva);
        cb_va += img->is64 ? 8u : 4u;
    }
    if (n) *n = i;
    return LD_OK;
}

int reflect_load(const uint8_t *pe_buf, size_t pe_len,
                 uint8_t *region, size_t region_size,
                 reflect_resolve_fn res, void *ud,
                 reflect_image_t *out)
{
    pe_image_t img;
    int64_t delta;
    uint32_t vsz;
    int r;

    if (!pe_buf || !region || !out) return LD_ERR_ARG;

    r = pe_parse(pe_buf, pe_len, &img);
    if (r != LD_OK) return r;

    vsz = pe_virtual_size(&img);
    if (region_size < vsz) return LD_ERR_NOSPACE;

    delta = (int64_t)((uintptr_t)region) - (int64_t)img.image_base;

    memset(out, 0, sizeof(*out));
    out->base = region;
    out->region_size = region_size;
    out->delta = delta;

    r = reflect_map_sections(&img, region, region_size);
    if (r != LD_OK) return r;

    r = reflect_relocate(&img, region, region_size, delta, &out->n_reloc);
    if (r != LD_OK) return r;

    r = reflect_bind_imports(&img, region, region_size, res, ud, &out->n_import);
    if (r != LD_OK) return r;

    r = reflect_collect_tls(&img, region, region_size,
                            out->tls_cb, REFLECT_MAX_TLS, &out->n_tls);
    if (r != LD_OK) return r;

    out->entry_va = img.entry_rva
                  ? (uint64_t)(uintptr_t)(region + img.entry_rva)
                  : 0;
    return LD_OK;
}
