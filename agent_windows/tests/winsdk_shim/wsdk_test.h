/* winsdk_shim/wsdk_test.h — 测试注入接口（shim 与测试共用） */
#ifndef WSDK_SHIM_TEST_H
#define WSDK_SHIM_TEST_H
#include <windows.h>
struct NativeFmt { GUID subtype; UINT32 w, h; };
void   wsdk_set_native_formats(const NativeFmt *list, size_t n);
bool   wsdk_mf_started(void);
GUID   wsdk_last_set_subtype(void);
UINT64 wsdk_last_set_framesize(void);

/* 有状态注册表 mock 的测试注入接口。
 * path 形如 "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"。
 * 用途：验证安装是否真的写入了内容——无状态 mock 会让 install 后 query
 * 恒成功，测试通过但实际什么都没装，这是最危险的假阳性。 */
bool   wsdk_reg_has(const char *path, const char *name);
bool   wsdk_reg_get(const char *path, const char *name, char *out, size_t cap);
void   wsdk_reg_reset(void);
#endif
