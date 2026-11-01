/*
 * winsdk_shim/windows.h
 *
 * 用途：仅供在 Linux 下对 cam_mf.cpp 做「真实编译验证」的最小 shim。
 * 不是产品代码，不参与任何部署。它提供 Windows SDK 的类型/宏/函数声明，
 * 使 g++ 能对 Windows 专用源码做语法、类型、调用契约层面的真实检查。
 *
 * 已知与真机的差异（仅影响运行语义，不影响编译检查）：
 *   - WCHAR 用 wchar_t（Linux 4 字节）而非 UTF-16（2 字节）
 *   - 注册表/字符串转换函数在 shim 中不提供真实行为
 */
#ifndef WSDK_SHIM_WINDOWS_H
#define WSDK_SHIM_WINDOWS_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <type_traits>

typedef unsigned long  DWORD;
typedef long           LONG;
typedef int32_t        HRESULT;  /* 真机 Windows: 32 位，负值表示失败 */
typedef unsigned char  BYTE;
typedef BYTE          *LPBYTE;
typedef wchar_t        WCHAR;
typedef unsigned int   UINT;
typedef uint32_t       UINT32;
typedef uint64_t       UINT64;
typedef int64_t        LONGLONG;
typedef int            BOOL;
typedef void          *HKEY;
typedef HKEY          *PHKEY;
typedef const wchar_t *LPCWSTR;
typedef wchar_t       *LPWSTR;
typedef unsigned long  ULONG;
typedef unsigned short USHORT;
typedef void          *LPVOID;

#ifndef NULL
#define NULL nullptr
#endif
#define TRUE  1
#define FALSE 0

#define S_OK            ((HRESULT)0)
#define S_FALSE         ((HRESULT)1)
#define E_FAIL          ((HRESULT)0x80004005)
#define E_INVALIDARG    ((HRESULT)0x80070057)
#define E_OUTOFMEMORY   ((HRESULT)0x8007000E)
#define E_POINTER       ((HRESULT)0x80004003)
#define E_NOINTERFACE   ((HRESULT)0x80004002)

#define FAILED(hr)    (((HRESULT)(hr)) < 0)
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)

#define ERROR_SUCCESS       0L
#define KEY_READ            0x20019L
#define HKEY_CURRENT_USER   ((HKEY)(uintptr_t)0x80000001u)

#define CP_UTF8 65001

#define ZeroMemory(dst, len) (std::memset((dst), 0, (len)))

/* GUID ---------------------------------------------------------------- */
struct GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
};
inline bool operator==(const GUID &a, const GUID &b) {
    return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}
inline bool operator!=(const GUID &a, const GUID &b) { return !(a == b); }
typedef GUID  IID;
typedef const GUID &REFGUID;
typedef const IID  &REFIID;
#define DEFINE_SHIM_GUID(name, d1, d2, d3, d4_0, d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7) \
    static const GUID name = { (uint32_t)(d1), (uint16_t)(d2), (uint16_t)(d3), \
        { (uint8_t)(d4_0), (uint8_t)(d4_1), (uint8_t)(d4_2), (uint8_t)(d4_3), \
          (uint8_t)(d4_4), (uint8_t)(d4_5), (uint8_t)(d4_6), (uint8_t)(d4_7) } }

/* IUnknown ------------------------------------------------------------ */
struct IUnknown {
    virtual ~IUnknown() {}
    virtual HRESULT QueryInterface(REFIID riid, void **ppv) = 0;
    virtual ULONG   AddRef(void) = 0;
    virtual ULONG   Release(void) = 0;
    static const GUID &GetIid();
};

/* IID_PPV_ARGS -------------------------------------------------------- */
namespace wsdk {
template <typename T> struct Deref2                 { typedef T type; };
template <typename T> struct Deref2<T **>           { typedef T type; };
template <typename T> const GUID &IidOf() { return T::GetIid(); }
}
#define IID_PPV_ARGS(pp) \
    wsdk::IidOf< wsdk::Deref2< decltype(pp) >::type >(), (void **)(pp)

/* 注册表 -------------------------------------------------------------- */
#define KEY_QUERY_VALUE      0x0001L
#define KEY_SET_VALUE        0x0002L
#define KEY_WRITE            0x20006L
#define REG_SZ               1L
#define ERROR_FILE_NOT_FOUND 2L
#define ERROR_NO_MORE_ITEMS  259L
#define ERROR_INVALID_PARAMETER 87L

LONG RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
                   DWORD samDesired, PHKEY phkResult);
LONG RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved,
                     LPWSTR lpClass, DWORD dwOptions, DWORD samDesired,
                     void *lpSecurityAttributes, PHKEY phkResult,
                     DWORD *lpdwDisposition);
LONG RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD *lpcchName,
                   DWORD *lpReserved, LPWSTR lpClass, DWORD *lpcchClass,
                   void *lpftLastWriteTime);
LONG RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD *lpReserved,
                      DWORD *lpType, LPBYTE lpData, DWORD *lpcbData);
LONG RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
                    DWORD dwType, const BYTE *lpData, DWORD cbData);
LONG RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName);
LONG RegCloseKey(HKEY hKey);

int  MultiByteToWideChar(UINT CodePage, DWORD dwFlags, const char *lpMultiByteStr,
                         int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

/* 字符串 / 内存 -------------------------------------------------------- */
int  WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr,
                         int cchWideChar, char *lpMultiByteStr, int cbMultiByte,
                         const char *lpDefaultChar, BOOL *lpUsedDefaultChar);
void *CoTaskMemAlloc(size_t cb);
void  CoTaskMemFree(void *pv);

int  _stricmp(const char *a, const char *b);
int  _wcsicmp(const wchar_t *a, const wchar_t *b);

#endif /* WSDK_SHIM_WINDOWS_H */
