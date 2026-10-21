/* winsdk_shim/wsdk_test.h — 测试注入接口（shim 与测试共用） */
#ifndef WSDK_SHIM_TEST_H
#define WSDK_SHIM_TEST_H
#include <windows.h>
struct NativeFmt { GUID subtype; UINT32 w, h; };
void   wsdk_set_native_formats(const NativeFmt *list, size_t n);
bool   wsdk_mf_started(void);
GUID   wsdk_last_set_subtype(void);
UINT64 wsdk_last_set_framesize(void);
#endif
