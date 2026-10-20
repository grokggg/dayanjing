#ifndef DIRECT_SYSCALL_H
#define DIRECT_SYSCALL_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
typedef DWORD hash_t;
#else
typedef uint32_t hash_t;
#endif

hash_t ds_hash(const char *s);

struct syscall_entry {
    hash_t    name_hash;
    uint32_t  ssn;
    uintptr_t addr;
};

#define DS_RESOLVE_PROLOGUE  0
#define DS_RESOLVE_TABLE     1

int ds_resolve(const char *module_path,
               struct syscall_entry *out,
               size_t out_cap,
               int mode);

uintptr_t ds_stub(uintptr_t a1, uintptr_t a2,
                  uintptr_t a3, uintptr_t a4, uint32_t ssn);

uintptr_t ds_invoke(struct syscall_entry *table, size_t count,
                    hash_t name_hash,
                    uintptr_t a1, uintptr_t a2,
                    uintptr_t a3, uintptr_t a4);

int ds_anti_debug(void);

#endif
