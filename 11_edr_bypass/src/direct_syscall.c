#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "direct_syscall.h"
#include "pe_image.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

hash_t ds_hash(const char *s)
{
    hash_t h = 5381;
    int c;
    if (s == NULL)
        return 0;
    while ((c = (unsigned char)*s++) != '\0')
        h = ((h << 5) + h) + (hash_t)(uint8_t)c;
    return h;
}

static uint32_t scan_mov_eax_imm32(const uint8_t *code, size_t maxlen, int *found)
{
    *found = 0;
    if (code == NULL || maxlen < 5)
        return 0;

    for (size_t k = 0; k + 5 <= maxlen; k++) {
        if (code[k] == 0xB8) {
            *found = 1;
            return (uint32_t)code[k + 1]
                 | ((uint32_t)code[k + 2] << 8)
                 | ((uint32_t)code[k + 3] << 16)
                 | ((uint32_t)code[k + 4] << 24);
        }
    }
    return 0;
}

int ds_resolve(const char *module_path,
               struct syscall_entry *out,
               size_t out_cap,
               int mode)
{
    if (module_path == NULL || out == NULL || out_cap == 0)
        return -1;

    void *base = NULL;
    size_t fsize = 0;
    int rc = 0;

#ifdef _WIN32
    HMODULE h = GetModuleHandleA(module_path);
    if (h == NULL)
        h = LoadLibraryA(module_path);
    if (h == NULL)
        return -2;
    base = (void *)h;
    fsize = 0;   /* in-memory mapping, no file size */
#else
    int fd = open(module_path, O_RDONLY);
    if (fd < 0)
        return -2;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz <= 0) {
        close(fd);
        return -3;
    }
    fsize = (size_t)sz;
    base = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED)
        return -4;
#endif

    if (fsize < sizeof(struct pe_dos_hdr)) {
        rc = -5;
        goto cleanup;
    }

    struct pe_dos_hdr *dos = (struct pe_dos_hdr *)base;
    if (dos->e_magic != 0x5A4D) {   /* "MZ" */
        rc = -5;
        goto cleanup;
    }

    uint32_t pe_off = dos->e_lfanew;
    if (pe_off + sizeof(uint32_t) + sizeof(struct pe_file_hdr) > fsize) {
        rc = -6;
        goto cleanup;
    }

    struct pe_file_hdr *fh = (struct pe_file_hdr *)((uint8_t *)base + pe_off + sizeof(uint32_t));
    if (fh->Machine != PE_MACHINE_AMD64) {
        rc = -7;   /* only x86-64 supported */
        goto cleanup;
    }
    if (fh->Machine != PE_MACHINE_AMD64) {
        rc = -7;   /* only x86-64 supported */
        goto cleanup;
    }

    struct pe_opt_hdr *oh = (struct pe_opt_hdr *)((uint8_t *)fh + sizeof(*fh));
    uint16_t opt_size = fh->SizeOfOptionalHeader;
    if (opt_size != sizeof(*oh)) {
        rc = -8;
        goto cleanup;
    }

    struct pe_data_dir *dd = oh->DataDirectory;
    struct pe_sec_hdr *secs = (struct pe_sec_hdr *)((uint8_t *)oh + opt_size);

    uint32_t exp_off = pe_rva_to_fileoff(dd[0].VirtualAddress, secs, fh->NumberOfSections, fsize);
    if (exp_off == 0 || exp_off + sizeof(struct pe_export_dir) > fsize) {
        rc = -9;
        goto cleanup;
    }

    struct pe_export_dir *exp = (struct pe_export_dir *)((uint8_t *)base + exp_off);
    if (exp->NumberOfFunctions == 0) {
        rc = -10;
        goto cleanup;
    }

    uint32_t off_af = pe_rva_to_fileoff(exp->AddressOfFunctions, secs, fh->NumberOfSections, fsize);
    uint32_t off_an = pe_rva_to_fileoff(exp->AddressOfNames,     secs, fh->NumberOfSections, fsize);
    uint32_t off_ao = pe_rva_to_fileoff(exp->AddressOfNameOrdinals, secs, fh->NumberOfSections, fsize);
    if (off_af == 0 || off_an == 0 || off_ao == 0) {
        rc = -11;
        goto cleanup;
    }

    const uint32_t *af = (const uint32_t *)((uint8_t *)base + off_af);
    const uint32_t *an = (const uint32_t *)((uint8_t *)base + off_an);
    const uint16_t *ao = (const uint16_t *)((uint8_t *)base + off_ao);

    size_t idx = 0;

    if (mode == DS_RESOLVE_PROLOGUE) {
        for (uint32_t i = 0; i < exp->NumberOfNames && idx < out_cap; i++) {
            uint32_t name_off = pe_rva_to_fileoff(an[i], secs, fh->NumberOfSections, fsize);
            if (name_off == 0 || name_off >= fsize)
                continue;

            const char *fname = (const char *)((uint8_t *)base + name_off);
            size_t maxlen = fsize - name_off;
            size_t nlen = strnlen(fname, maxlen);
            if (nlen < 3 || strncmp(fname, "Zw", 2) != 0)
                continue;

            uint16_t ord = ao[i];
            if ((uint32_t)ord >= exp->NumberOfFunctions)
                continue;

            uint32_t proc_rva = af[ord];
            uint32_t proc_off = pe_rva_to_fileoff(proc_rva, secs, fh->NumberOfSections, fsize);
            if (proc_off == 0 || proc_off + 5 > fsize)
                continue;

            const uint8_t *code = (const uint8_t *)base + proc_off;
            int found = 0;
            uint32_t ssn = scan_mov_eax_imm32(code, 16, &found);
            if (!found)
                continue;
            if (ssn > 0x1000)
                continue;

            out[idx].name_hash = ds_hash(fname);
            out[idx].ssn       = ssn;
            out[idx].addr      = (uintptr_t)code;
            idx++;
        }
    } else {
        for (uint32_t i = 0; i < exp->NumberOfFunctions && idx < out_cap; i++) {
            uint32_t proc_rva = af[i];
            if (proc_rva == 0)
                continue;

            uint32_t proc_off = pe_rva_to_fileoff(proc_rva, secs, fh->NumberOfSections, fsize);
            if (proc_off == 0 || proc_off + 5 > fsize)
                continue;

            const uint8_t *code = (const uint8_t *)base + proc_off;
            size_t head = 0;
            while (head < 8 && (code[head] == 0xCC || code[head] == 0x90))
                head++;

            int found = 0;
            uint32_t ssn = scan_mov_eax_imm32(code + head, 16 - head, &found);
            if (!found || ssn > 0x1000)
                continue;

            out[idx].ssn  = ssn;
            out[idx].addr = (uintptr_t)code;
            idx++;
        }
    }

    rc = (int)idx;

cleanup:
#ifndef _WIN32
    if (base != NULL && base != MAP_FAILED)
        munmap(base, fsize);
#endif
    return rc;
}

uintptr_t ds_stub(uintptr_t a1, uintptr_t a2,
                  uintptr_t a3, uintptr_t a4, uint32_t ssn)
{
#if defined(__x86_64__) && !defined(_WIN32)
    (void)a1; (void)a2; (void)a3; (void)a4;
    return (uintptr_t)ssn;
#elif defined(_WIN64)
    extern uintptr_t ds_asm_stub(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uint32_t);
    return ds_asm_stub(a1, a2, a3, a4, ssn);
#else
    (void)a1; (void)a2; (void)a3; (void)a4;
    return (uintptr_t)ssn;
#endif
}

uintptr_t ds_invoke(struct syscall_entry *table, size_t count,
                    hash_t name_hash,
                    uintptr_t a1, uintptr_t a2,
                    uintptr_t a3, uintptr_t a4)
{
    if (table == NULL || count == 0)
        return (uintptr_t)-1;

    for (size_t i = 0; i < count; i++) {
        if (table[i].name_hash == name_hash)
            return ds_stub(a1, a2, a3, a4, table[i].ssn);
    }
    return (uintptr_t)-2;
}

int ds_anti_debug(void)
{
#ifdef _WIN32
    if (IsDebuggerPresent())
        return 1;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote)
        return 1;
#else
    FILE *f = fopen("/proc/self/status", "r");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = 0;
                sscanf(line + 10, "%d", &pid);
                fclose(f);
                return (pid != 0) ? 1 : 0;
            }
        }
        fclose(f);
    }
#endif
    return 0;
}
