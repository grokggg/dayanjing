#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include "pe_image.h"

uint32_t pe_rva_to_fileoff(uint32_t rva,
                           const struct pe_sec_hdr *secs,
                           uint16_t nsec,
                           size_t fsize)
{
    if (secs == NULL || nsec == 0 || fsize == 0)
        return 0;
    if (rva >= fsize)
        return 0;

    for (uint16_t i = 0; i < nsec; i++) {
        uint32_t va  = secs[i].VirtualAddress;
        uint32_t vsz = secs[i].VirtualSize;
        if (vsz == 0)
            vsz = secs[i].SizeOfRawData;
        if (vsz == 0)
            continue;

        if (rva >= va && rva < va + vsz) {
            uint32_t off = secs[i].PointerToRawData + (rva - va);
            if (off < fsize)
                return off;
            return 0;
        }
    }

    /* RVA falls outside any section: header area. Return as-is with bounds check. */
    return (rva < fsize) ? rva : 0;
}
