/*
 * DAYANJING v4 — 17_loader/src/pe.c
 *
 * PE/PE32+ 解析：DOS -> COFF -> Optional -> Sections -> DataDirectory
 * 以及导入表迭代、导出表查询。
 *
 * 全部读取走小端助手，不直接对结构体做指针强转，避免对齐与严格别名问题。
 */

#include "loader.h"

#include <string.h>

uint32_t ld_rd32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

uint64_t ld_rd64(const uint8_t *p)
{
    return (uint64_t)ld_rd32(p) | ((uint64_t)ld_rd32(p + 4) << 32);
}

void ld_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

void ld_wr64(uint8_t *p, uint64_t v)
{
    ld_wr32(p, (uint32_t)(v & 0xFFFFFFFFu));
    ld_wr32(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* 安全读取：确认 [off, off+need) 落在缓冲区内 */
static int in_bounds(const pe_image_t *img, uint32_t off, size_t need)
{
    if (!img || !img->buf) return 0;
    if ((size_t)off > img->len) return 0;
    if (need > img->len - (size_t)off) return 0;
    return 1;
}

int pe_parse(const uint8_t *buf, size_t len, pe_image_t *img)
{
    uint32_t lfanew;
    const uint8_t *coff;
    const uint8_t *opt;
    const uint8_t *dd;
    const uint8_t *sh;
    uint16_t magic;
    size_t   need;
    uint32_t nrva;
    uint16_t i;
    size_t   n;

    if (!buf || !img) return LD_ERR_ARG;
    if (len < 64) return LD_ERR_TRUNC;

    memset(img, 0, sizeof(*img));
    img->buf = buf;
    img->len = len;

    if (rd16(buf) != (uint16_t)PE_DOS_MAGIC) return LD_ERR_FORMAT;

    lfanew = ld_rd32(buf + 0x3C);
    if ((size_t)lfanew > len) return LD_ERR_TRUNC;
    if ((size_t)lfanew + 24u > len) return LD_ERR_TRUNC;
    if (ld_rd32(buf + lfanew) != PE_NT_SIG) return LD_ERR_FORMAT;

    coff = buf + lfanew + 4;
    img->machine  = rd16(coff + 0);
    img->nsec     = rd16(coff + 2);
    img->opt_size = rd16(coff + 16);
    img->chars    = rd16(coff + 18);

    opt = coff + 20;
    if ((size_t)(opt - buf) + 2u > len) return LD_ERR_TRUNC;

    magic = rd16(opt);
    if (magic == (uint16_t)PE_OPT_MAGIC64) {
        img->is64 = 1;
        need = 240;
    } else if (magic == (uint16_t)PE_OPT_MAGIC32) {
        img->is64 = 0;
        need = 224;
    } else {
        return LD_ERR_FORMAT;
    }
    if ((size_t)(opt - buf) + need > len) return LD_ERR_TRUNC;

    img->entry_rva = ld_rd32(opt + 16);
    if (img->is64) {
        img->image_base = ld_rd64(opt + 24);
        nrva = ld_rd32(opt + 108);
        dd = opt + 112;
    } else {
        img->image_base = ld_rd32(opt + 28);
        nrva = ld_rd32(opt + 92);
        dd = opt + 96;
    }
    img->sect_align   = ld_rd32(opt + 32);
    img->file_align   = ld_rd32(opt + 36);
    img->size_image   = ld_rd32(opt + 56);
    img->size_headers = ld_rd32(opt + 60);

    img->nrva = (uint16_t)(nrva > PE_NUM_DIRS ? PE_NUM_DIRS : nrva);
    for (i = 0; i < img->nrva; i++) {
        img->dir[i].rva  = ld_rd32(dd + (size_t)i * 8u);
        img->dir[i].size = ld_rd32(dd + (size_t)i * 8u + 4u);
    }

    /* 节表紧跟 Optional Header。COFF 的 opt_size 含数据目录，优先使用它；
       若为 0 则退化为按 magic 推算。 */
    {
        size_t opt_real = img->opt_size ? (size_t)img->opt_size : need;
        sh = opt + opt_real;
    }
    if (img->nsec > PE_MAX_SEC) return LD_ERR_FORMAT;
    if ((size_t)(sh - buf) > len) return LD_ERR_TRUNC;

    n = (size_t)img->nsec;
    if ((size_t)(sh - buf) + n * 40u > len) return LD_ERR_TRUNC;

    for (i = 0; i < n; i++) {
        const uint8_t *e = sh + (size_t)i * 40u;
        memcpy(img->secs[i].name, e, PE_SEC_NAME_LEN);
        img->secs[i].vsize    = ld_rd32(e + 8);
        img->secs[i].vaddr    = ld_rd32(e + 12);
        img->secs[i].raw_size = ld_rd32(e + 16);
        img->secs[i].raw_ptr  = ld_rd32(e + 20);
        img->secs[i].chars    = ld_rd32(e + 36);
    }
    img->sec_count = img->nsec;
    return LD_OK;
}

int pe_rva_to_file(const pe_image_t *img, uint32_t rva, uint32_t *off)
{
    uint16_t i;

    if (!img || !off || !img->buf) return LD_ERR_ARG;

    /* 头部区域：文件偏移 == RVA */
    if (img->size_headers && rva < img->size_headers) {
        if (!in_bounds(img, rva, 1)) return LD_ERR_TRUNC;
        *off = rva;
        return LD_OK;
    }

    for (i = 0; i < img->sec_count; i++) {
        const pe_sec_t *s = &img->secs[i];
        uint32_t vs = s->vsize ? s->vsize : s->raw_size;
        if (rva >= s->vaddr && rva < s->vaddr + vs) {
            uint32_t d = rva - s->vaddr;
            if (d >= s->raw_size) return LD_ERR_TRUNC;  /* 未初始化数据，无文件映像 */
            if (s->raw_ptr + d < s->raw_ptr) return LD_ERR_TRUNC; /* 溢出 */
            if (!in_bounds(img, s->raw_ptr + d, 1)) return LD_ERR_TRUNC;
            *off = s->raw_ptr + d;
            return LD_OK;
        }
    }
    return LD_ERR_NOTFOUND;
}

const pe_sec_t *pe_sec_by_rva(const pe_image_t *img, uint32_t rva)
{
    uint16_t i;
    if (!img) return NULL;
    for (i = 0; i < img->sec_count; i++) {
        const pe_sec_t *s = &img->secs[i];
        uint32_t vs = s->vsize ? s->vsize : s->raw_size;
        if (rva >= s->vaddr && rva < s->vaddr + vs) return s;
    }
    return NULL;
}

uint32_t pe_virtual_size(const pe_image_t *img)
{
    uint32_t mx = 0;
    uint16_t i;

    if (!img) return 0;
    if (img->size_image) return img->size_image;

    mx = img->size_headers;
    for (i = 0; i < img->sec_count; i++) {
        const pe_sec_t *s = &img->secs[i];
        uint32_t vs = s->vsize ? s->vsize : s->raw_size;
        if (s->vaddr + vs > mx) mx = s->vaddr + vs;
    }
    if (img->sect_align) {
        uint32_t a = img->sect_align;
        mx = (mx + a - 1u) / a * a;
    }
    return mx;
}

/* ---------------- 导入表 ---------------- */

int pe_import_begin(const pe_image_t *img, pe_import_iter_t *it)
{
    uint32_t off;
    int r;

    if (!img || !it) return LD_ERR_ARG;
    memset(it, 0, sizeof(*it));
    it->img = img;

    if (img->dir[PE_DIR_IMPORT].rva == 0) return LD_OK;  /* 无导入 */

    r = pe_rva_to_file(img, img->dir[PE_DIR_IMPORT].rva, &off);
    if (r != LD_OK) return r;
    if (!in_bounds(img, off, 20)) return LD_ERR_TRUNC;
    it->desc_off = off;
    return LD_OK;
}

/* 从 RVA 读一个以 NUL 结尾的字符串到 dst */
static int read_str(const pe_image_t *img, uint32_t rva, char *dst, size_t cap)
{
    uint32_t off;
    int r;
    size_t i;

    r = pe_rva_to_file(img, rva, &off);
    if (r != LD_OK) return r;
    if (!in_bounds(img, off, 1)) return LD_ERR_TRUNC;

    for (i = 0; i + 1u < cap; i++) {
        size_t pos = (size_t)off + i;
        if (pos >= img->len) return LD_ERR_TRUNC;
        dst[i] = (char)img->buf[pos];
        if (dst[i] == '\0') return LD_OK;
    }
    dst[cap - 1u] = '\0';
    return LD_OK;
}

int pe_import_next(pe_import_iter_t *it)
{
    const pe_image_t *img;
    size_t esz;

    if (!it || !it->img) return LD_ERR_ARG;
    img = it->img;
    if (it->desc_off == 0) return 0;   /* 无导入表 */
    esz = img->is64 ? 8u : 4u;

    for (;;) {
        const uint8_t *d;
        uint32_t oft, name_rva, ft, ilt_rva, o;
        uint32_t toff;
        uint64_t val;
        int r;

        if (it->ilt_off == 0) {
            if (!in_bounds(img, it->desc_off, 20)) return LD_ERR_TRUNC;
            d = img->buf + it->desc_off;
            oft      = ld_rd32(d + 0);
            name_rva = ld_rd32(d + 12);
            ft       = ld_rd32(d + 16);
            if (oft == 0 && name_rva == 0 && ft == 0) return 0;  /* 描述符终止 */

            r = read_str(img, name_rva, it->dll, sizeof(it->dll));
            if (r != LD_OK) return r;

            ilt_rva = oft ? oft : ft;
            r = pe_rva_to_file(img, ilt_rva, &o);
            if (r != LD_OK) return r;
            if (!in_bounds(img, o, esz)) return LD_ERR_TRUNC;
            it->ilt_off = o;

            r = pe_rva_to_file(img, ft, &o);
            if (r != LD_OK) return r;
            if (!in_bounds(img, o, esz)) return LD_ERR_TRUNC;
            it->iat_off = o;
            it->iat_rva = ft;

            it->idx = 0;
        }

        toff = it->ilt_off + (uint32_t)(it->idx * esz);
        if (!in_bounds(img, toff, esz)) return LD_ERR_TRUNC;

        val = img->is64 ? ld_rd64(img->buf + toff) : (uint64_t)ld_rd32(img->buf + toff);
        if (val == 0) {
            /* 本描述符结束，进入下一个 */
            it->desc_off += 20;
            it->ilt_off = 0;
            it->idx = 0;
            it->iat_off = 0;
            if (!in_bounds(img, it->desc_off, 20)) return LD_ERR_TRUNC;
            continue;
        }

        it->iat_slot = it->iat_off + (uint32_t)(it->idx * esz);
        if (!in_bounds(img, it->iat_slot, esz)) return LD_ERR_TRUNC;

        it->hint = 0;
        it->ordinal = 0;
        it->by_ordinal = 0;
        it->func[0] = '\0';

        if (img->is64) {
            if (val & 0x8000000000000000ULL) {
                it->by_ordinal = 1;
                it->ordinal = (uint16_t)(val & 0xFFFFULL);
            } else {
                uint32_t hn = (uint32_t)(val & 0xFFFFFFFFULL);
                uint32_t fo;
                r = pe_rva_to_file(img, hn, &fo);
                if (r != LD_OK) return r;
                if (!in_bounds(img, fo, 2)) return LD_ERR_TRUNC;
                it->hint = (uint16_t)((uint16_t)img->buf[fo]
                                    | ((uint16_t)img->buf[fo + 1] << 8));
                r = read_str(img, hn + 2u, it->func, sizeof(it->func));
                if (r != LD_OK) return r;
            }
        } else {
            uint32_t v32 = (uint32_t)val;
            if (v32 & 0x80000000u) {
                it->by_ordinal = 1;
                it->ordinal = (uint16_t)(v32 & 0xFFFFu);
            } else {
                uint32_t fo;
                r = pe_rva_to_file(img, v32, &fo);
                if (r != LD_OK) return r;
                if (!in_bounds(img, fo, 2)) return LD_ERR_TRUNC;
                it->hint = (uint16_t)((uint16_t)img->buf[fo]
                                    | ((uint16_t)img->buf[fo + 1] << 8));
                r = read_str(img, v32 + 2u, it->func, sizeof(it->func));
                if (r != LD_OK) return r;
            }
        }

        it->idx++;
        return 1;
    }
}

/* ---------------- 导出表 ---------------- */

int pe_export_count(const pe_image_t *img, uint32_t *nfunc, uint32_t *nnames)
{
    uint32_t off;
    int r;

    if (!img || !nfunc || !nnames) return LD_ERR_ARG;
    *nfunc = 0;
    *nnames = 0;
    if (img->dir[PE_DIR_EXPORT].rva == 0) return LD_OK;

    r = pe_rva_to_file(img, img->dir[PE_DIR_EXPORT].rva, &off);
    if (r != LD_OK) return r;
    if (!in_bounds(img, off, 40)) return LD_ERR_TRUNC;

    *nfunc  = ld_rd32(img->buf + off + 20);
    *nnames = ld_rd32(img->buf + off + 24);
    return LD_OK;
}

int pe_export_rva_by_index(const pe_image_t *img, uint32_t idx, uint32_t *rva)
{
    uint32_t off, eat, fo;
    int r;

    if (!img || !rva) return LD_ERR_ARG;
    if (img->dir[PE_DIR_EXPORT].rva == 0) return LD_ERR_NOTFOUND;

    r = pe_rva_to_file(img, img->dir[PE_DIR_EXPORT].rva, &off);
    if (r != LD_OK) return r;
    if (!in_bounds(img, off, 40)) return LD_ERR_TRUNC;

    if (idx >= ld_rd32(img->buf + off + 20)) return LD_ERR_NOTFOUND;

    eat = ld_rd32(img->buf + off + 28);
    r = pe_rva_to_file(img, eat + idx * 4u, &fo);
    if (r != LD_OK) return r;
    if (!in_bounds(img, fo, 4)) return LD_ERR_TRUNC;

    *rva = ld_rd32(img->buf + fo);
    return LD_OK;
}

int pe_export_name_by_index(const pe_image_t *img, uint32_t idx,
                            char *name, size_t cap, uint32_t *ordinal)
{
    uint32_t off, ent, eot, fo, nrva;
    int r;

    if (!img || !name || cap == 0) return LD_ERR_ARG;
    name[0] = '\0';
    if (img->dir[PE_DIR_EXPORT].rva == 0) return LD_ERR_NOTFOUND;

    r = pe_rva_to_file(img, img->dir[PE_DIR_EXPORT].rva, &off);
    if (r != LD_OK) return r;
    if (!in_bounds(img, off, 40)) return LD_ERR_TRUNC;

    if (idx >= ld_rd32(img->buf + off + 24)) return LD_ERR_NOTFOUND;

    ent = ld_rd32(img->buf + off + 32);
    eot = ld_rd32(img->buf + off + 36);

    r = pe_rva_to_file(img, ent + idx * 4u, &fo);
    if (r != LD_OK) return r;
    if (!in_bounds(img, fo, 4)) return LD_ERR_TRUNC;
    nrva = ld_rd32(img->buf + fo);

    r = read_str(img, nrva, name, cap);
    if (r != LD_OK) return r;

    if (ordinal) {
        uint32_t oo;
        r = pe_rva_to_file(img, eot + idx * 2u, &oo);
        if (r != LD_OK) return r;
        if (!in_bounds(img, oo, 2)) return LD_ERR_TRUNC;
        *ordinal = (uint32_t)((uint16_t)img->buf[oo]
                            | ((uint16_t)img->buf[oo + 1] << 8));
    }
    return LD_OK;
}

int pe_export_by_name(const pe_image_t *img, const char *name, uint32_t *rva)
{
    uint32_t nfunc, nnames, i;
    int r;

    if (!img || !name || !rva) return LD_ERR_ARG;

    r = pe_export_count(img, &nfunc, &nnames);
    if (r != LD_OK) return r;

    for (i = 0; i < nnames; i++) {
        char nm[PE_IMPORT_FUNC_MAX];
        uint32_t ord = 0;
        r = pe_export_name_by_index(img, i, nm, sizeof(nm), &ord);
        if (r != LD_OK) continue;
        if (strcmp(nm, name) == 0) {
            uint32_t frva;
            r = pe_export_rva_by_index(img, ord, &frva);
            if (r != LD_OK) return r;
            *rva = frva;
            return LD_OK;
        }
    }
    return LD_ERR_NOTFOUND;
}
