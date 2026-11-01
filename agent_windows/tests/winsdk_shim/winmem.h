/* winsdk_shim/winmem.h — 虚拟内存 API 最小等价声明
 *
 * 真实 Windows 上这些来自 memoryapi.h（经 windows.h）。shim 里单独成文件，
 * 是为了不改动既有 windows.h 的结构，避免影响 cam_mf / persist_win 的
 * 既有构建。
 */
#ifndef WSDK_SHIM_WINMEM_H
#define WSDK_SHIM_WINMEM_H

/* 同 winsock2.h：不 include windows.h，保持 C/C++ 双可用。
   LPVOID/BOOL 的定义必须与 shim 的 windows.h 逐字一致，否则 shim_winsock.cpp
   里的实现与这里的声明会被当成不同类型（C 链接不做检查，但实参与形参
   的解释会不一致）。 */
#include <stddef.h>
#include <stdint.h>

#ifndef LPVOID_DEFINED_SHIM
#define LPVOID_DEFINED_SHIM
typedef void *LPVOID;
#endif
#ifndef BOOL_DEFINED_SHIM
#define BOOL_DEFINED_SHIM
typedef int BOOL;
#endif

#define MEM_COMMIT     0x00001000u
#define MEM_RESERVE    0x00002000u
#define MEM_RESET      0x00080000u
#define MEM_RELEASE    0x00008000u

#define PAGE_NOACCESS          0x01u
#define PAGE_READONLY          0x02u
#define PAGE_READWRITE         0x04u
#define PAGE_WRITECOPY         0x08u
#define PAGE_EXECUTE           0x10u
#define PAGE_EXECUTE_READ      0x20u
#define PAGE_EXECUTE_READWRITE 0x40u

#ifdef __cplusplus
extern "C" {
#endif

LPVOID VirtualAlloc(LPVOID addr, size_t size, unsigned long type,
                    unsigned long protect);
BOOL   VirtualProtect(LPVOID addr, size_t size, unsigned long new_prot,
                      unsigned long *old);
BOOL   VirtualFree(LPVOID addr, size_t size, unsigned long type);

#ifdef __cplusplus
}
#endif

#endif /* WSDK_SHIM_WINMEM_H */
