/*
 * winsdk_shim/shim_impl.cpp
 *
 * Media Foundation 的可运行 mock 实现。目的是让 cam_mf.cpp 在 Linux 下
 * 不仅能编译，还能「真跑」——用受控的假设备验证其逻辑行为。
 *
 * 关键保真点：
 *   - MF_MT_FRAME_SIZE 按真机语义存为 UINT64（packed），
 *     因此 GetUINT32 对它必须失败。这一条是暴露真实缺陷的关键。
 *   - GetNativeMediaType 越界返回 MF_E_NO_MORE_TYPES。
 */
#include <windows.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfreadwrite.h>
#include <string>
#include <vector>
#include <map>
#include <cwctype>
#include <cctype>
#include "../../include/camera.h"
#include "wsdk_test.h"

/* GUID 排序（供 std::map） */
namespace std {
template <> struct less<GUID> {
    bool operator()(const GUID &a, const GUID &b) const {
        int r = memcmp(&a, &b, sizeof(GUID));
        return r < 0;
    }
};
}

/* ---- 接口 IID ---- */
static const GUID IID_IUnknown_ = {0x00000000,0x0000,0x0000,{0xC0,0,0,0,0,0,0,0x46}};
const GUID &IUnknown::GetIid()      { return IID_IUnknown_; }
const GUID &IMFAttributes::GetIid() { static GUID g = {0x2CD2D921,0x0000,0x0000,{0,0,0,0,0,0,0,1}}; return g; }
const GUID &IMFMediaType::GetIid()  { static GUID g = {0x2CD2D921,0x0000,0x0000,{0,0,0,0,0,0,0,2}}; return g; }
const GUID &IMFActivate::GetIid()   { static GUID g = {0x2CD2D921,0x0000,0x0000,{0,0,0,0,0,0,0,3}}; return g; }
const GUID &IMFMediaSource::GetIid(){ static GUID g = {0x2CD2D921,0x0000,0x0000,{0,0,0,0,0,0,0,4}}; return g; }
const GUID &IMFMediaBuffer::GetIid(){ static GUID g = {0x2CD2D921,0x0000,0x0000,{0,0,0,0,0,0,0,5}}; return g; }
const GUID &IMFSample::GetIid()     { static GUID g = {0x2CD2D921,0x0000,0x0000,{0,0,0,0,0,0,0,6}}; return g; }
const GUID &IMFSourceReader::GetIid(){static GUID g = {0x2CD2D921,0x0000,0x0000,{0,0,0,0,0,0,0,7}}; return g; }

/* ---- 属性键 ---- */
const GUID MF_MT_MAJOR_TYPE  = {0x48EBE18A,0x0000,0x0000,{0,0,0,0,0,0,0,1}};
const GUID MF_MT_SUBTYPE     = {0xF7E34C9A,0x42E8,0x4714,{0xB7,0x4B,0xCB,0x29,0xD7,0x2C,0x28,0x3E}};
const GUID MF_MT_FRAME_SIZE  = {0x1652C33D,0xD6B2,0x4012,{0xB8,0x34,0x72,0x03,0x08,0x49,0xA3,0x7D}};
const GUID MF_MT_FRAME_RATE  = {0xC459A2E8,0x3D2C,0x4E44,{0xB1,0x32,0xFE,0xE5,0x15,0x6C,0x7B,0xB0}};
const GUID MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE =
    {0xC60AC5FE,0x252A,0x478F,{0xA0,0xEF,0xBC,0x8F,0xA5,0xF7,0xCA,0xD3}};
const GUID MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID =
    {0x8AC3587A,0x4AE7,0x42D8,{0x99,0xE0,0x0A,0x60,0x13,0xEE,0xF9,0x0F}};
const GUID MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK =
    {0x58F0AAD8,0x22BF,0x4F8A,{0xBB,0x3D,0xD2,0xC4,0x97,0x8C,0x6E,0x2F}};
const GUID MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME =
    {0x60D0E559,0x52F8,0x4FA2,{0xB4,0x3C,0x85,0xA3,0x8A,0x57,0x84,0x44}};

/* ---- 注册表（mock：模拟已授权） ---- */
LONG RegOpenKeyExW(HKEY, LPCWSTR, DWORD, DWORD, PHKEY phk) { *phk = (HKEY)1; return ERROR_SUCCESS; }
LONG RegCloseKey(HKEY) { return ERROR_SUCCESS; }
LONG RegEnumKeyExW(HKEY, DWORD dwIndex, LPWSTR lpName, DWORD *lpcchName,
                              DWORD *, LPWSTR, DWORD *, void *) {
    if (dwIndex == 0) {
        const wchar_t *sid = L"S-1-5-21-TEST";
        wcscpy(lpName, sid);
        *lpcchName = (DWORD)wcslen(sid);
        return ERROR_SUCCESS;
    }
    return 259; /* ERROR_NO_MORE_ITEMS */
}
LONG RegQueryValueExW(HKEY, LPCWSTR, DWORD *, DWORD *, LPBYTE lpData, DWORD *lpcbData) {
    const wchar_t *v = L"Allow";
    size_t n = (wcslen(v) + 1) * sizeof(wchar_t);
    if (*lpcbData < (DWORD)n) { *lpcbData = (DWORD)n; return 234; }
    memcpy(lpData, v, n); *lpcbData = (DWORD)n;
    return ERROR_SUCCESS;
}

/* ---- 字符串 / 内存 ---- */
int WideCharToMultiByte(UINT, DWORD, LPCWSTR src, int cch,
                                   char *dst, int cb, const char *, BOOL *) {
    if (!src || !dst || cb <= 0) return 0;
    int i = 0;
    for (; i < cb - 1; i++) {
        if (cch >= 0 && i >= cch) break;
        wchar_t c = src[i];
        if (c == 0) break;
        dst[i] = (c < 128) ? (char)c : '?';
    }
    dst[i] = 0;
    return i + 1;
}
void *CoTaskMemAlloc(size_t cb) { return malloc(cb); }
void  CoTaskMemFree(void *pv)   { free(pv); }
int _stricmp(const char *a, const char *b) {
    if (!a || !b) return a ? 1 : (b ? -1 : 0);
    for (; *a && *b; a++, b++) {
        int ca = tolower((unsigned char)*a), cb2 = tolower((unsigned char)*b);
        if (ca != cb2) return ca - cb2;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}
int _wcsicmp(const wchar_t *a, const wchar_t *b) {
    if (!a || !b) return a ? 1 : (b ? -1 : 0);
    for (; *a && *b; a++, b++) {
        int ca = towlower(*a), cb2 = towlower(*b);
        if (ca != cb2) return ca - cb2;
    }
    return towlower(*a) - towlower(*b);
}

/* ---- Mock COM 对象 ---- */
struct MockAttributes : public IMFAttributes {
    ULONG ref = 1;
    std::map<GUID, GUID>        m_guid;
    std::map<GUID, UINT32>      m_u32;
    std::map<GUID, UINT64>      m_u64;
    std::map<GUID, std::wstring> m_str;

    HRESULT QueryInterface(REFIID, void **ppv) override { *ppv = nullptr; return E_NOINTERFACE; }
    ULONG AddRef() override  { return ++ref; }
    ULONG Release() override { if (--ref == 0) { delete this; return 0; } return ref; }

    HRESULT SetGUID(REFGUID k, REFGUID v) override { m_guid[k] = v; return S_OK; }
    HRESULT SetUINT32(REFGUID k, UINT32 v) override { m_u32[k] = v; return S_OK; }
    HRESULT SetUINT64(REFGUID k, UINT64 v) override { m_u64[k] = v; return S_OK; }
    HRESULT GetGUID(REFGUID k, GUID *v) override {
        auto it = m_guid.find(k); if (it == m_guid.end()) return E_FAIL; *v = it->second; return S_OK;
    }
    HRESULT GetUINT32(REFGUID k, UINT32 *v) override {
        auto it = m_u32.find(k); if (it == m_u32.end()) return E_FAIL; *v = it->second; return S_OK;
    }
    HRESULT GetUINT64(REFGUID k, UINT64 *v) override {
        auto it = m_u64.find(k); if (it == m_u64.end()) return E_FAIL; *v = it->second; return S_OK;
    }
    HRESULT GetStringLength(REFGUID k, UINT32 *n) override {
        auto it = m_str.find(k); if (it == m_str.end()) return E_FAIL;
        *n = (UINT32)it->second.size(); return S_OK;
    }
    HRESULT GetString(REFGUID k, LPWSTR buf, UINT32 cch, UINT32 *n) override {
        auto it = m_str.find(k); if (it == m_str.end()) return E_FAIL;
        UINT32 need = (UINT32)it->second.size() + 1;
        if (n) *n = need - 1;
        if (!buf) return S_OK;
        if (cch < need) return E_FAIL;
        memcpy(buf, it->second.c_str(), need * sizeof(WCHAR));
        return S_OK;
    }
};

struct MockMediaType : public IMFMediaType {
    /* 复用 MockAttributes 的存储：以组合方式 */
    MockAttributes attr;
    ULONG ref = 1;
    HRESULT QueryInterface(REFIID, void **ppv) override { *ppv = nullptr; return E_NOINTERFACE; }
    ULONG AddRef() override  { return ++ref; }
    ULONG Release() override { if (--ref == 0) { delete this; return 0; } return ref; }
    HRESULT SetGUID(REFGUID k, REFGUID v) override { return attr.SetGUID(k, v); }
    HRESULT SetUINT32(REFGUID k, UINT32 v) override { return attr.SetUINT32(k, v); }
    HRESULT SetUINT64(REFGUID k, UINT64 v) override { return attr.SetUINT64(k, v); }
    HRESULT GetGUID(REFGUID k, GUID *v) override { return attr.GetGUID(k, v); }
    HRESULT GetUINT32(REFGUID k, UINT32 *v) override { return attr.GetUINT32(k, v); }
    HRESULT GetUINT64(REFGUID k, UINT64 *v) override { return attr.GetUINT64(k, v); }
    HRESULT GetStringLength(REFGUID k, UINT32 *n) override { return attr.GetStringLength(k, n); }
    HRESULT GetString(REFGUID k, LPWSTR b, UINT32 c, UINT32 *n) override { return attr.GetString(k, b, c, n); }
};

/* 供测试注入的原生格式表 */
static std::vector<NativeFmt> &native_list() { static std::vector<NativeFmt> v; return v; }
static bool &mf_started() { static bool b = false; return b; }
static GUID &last_set_subtype() { static GUID g = {0,0,0,{0,0,0,0,0,0,0,0}}; return g; }
static UINT64 &last_set_framesize() { static UINT64 u = 0; return u; }

struct MockSourceReader : public IMFSourceReader {
    ULONG ref = 1;
    HRESULT QueryInterface(REFIID, void **ppv) override { *ppv = nullptr; return E_NOINTERFACE; }
    ULONG AddRef() override  { return ++ref; }
    ULONG Release() override { if (--ref == 0) { delete this; return 0; } return ref; }

    HRESULT GetNativeMediaType(DWORD, DWORD idx, IMFMediaType **pp) override {
        if (idx >= native_list().size()) return MF_E_NO_MORE_TYPES;
        MockMediaType *m = new MockMediaType();
        m->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        m->SetGUID(MF_MT_SUBTYPE, native_list()[idx].subtype);
        UINT64 packed = ((UINT64)native_list()[idx].w << 32) | native_list()[idx].h;
        m->SetUINT64(MF_MT_FRAME_SIZE, packed);   /* 真机语义：UINT64 */
        *pp = m;
        return S_OK;
    }
    HRESULT SetCurrentMediaType(DWORD, DWORD *, IMFMediaType *p) override {
        if (!p) return E_POINTER;
        p->GetGUID(MF_MT_SUBTYPE, &last_set_subtype());
        p->GetUINT64(MF_MT_FRAME_SIZE, &last_set_framesize());
        return S_OK;
    }
    HRESULT ReadSample(DWORD, DWORD, DWORD *, DWORD *flags,
                       LONGLONG *ts, IMFSample **pp) override;
};

struct MockMediaBuffer : public IMFMediaBuffer {
    ULONG ref = 1; std::vector<BYTE> data;
    HRESULT QueryInterface(REFIID, void **ppv) override { *ppv = nullptr; return E_NOINTERFACE; }
    ULONG AddRef() override  { return ++ref; }
    ULONG Release() override { if (--ref == 0) { delete this; return 0; } return ref; }
    HRESULT Lock(BYTE **pb, DWORD *mx, DWORD *cur) override {
        *pb = data.data(); *mx = (DWORD)data.size(); *cur = (DWORD)data.size(); return S_OK;
    }
    HRESULT Unlock() override { return S_OK; }
};
struct MockSample : public IMFSample {
    ULONG ref = 1; MockMediaBuffer *buf;
    MockSample() { buf = new MockMediaBuffer(); buf->data.assign(64, 0x41); }
    HRESULT QueryInterface(REFIID, void **ppv) override { *ppv = nullptr; return E_NOINTERFACE; }
    ULONG AddRef() override  { return ++ref; }
    ULONG Release() override { if (--ref == 0) { buf->Release(); delete this; return 0; } return ref; }
    HRESULT ConvertToContiguousBuffer(IMFMediaBuffer **pp) override { *pp = buf; buf->AddRef(); return S_OK; }
};
HRESULT MockSourceReader::ReadSample(DWORD, DWORD, DWORD *, DWORD *flags,
                                     LONGLONG *ts, IMFSample **pp) {
    if (flags) *flags = 0;
    if (ts) *ts = 1234567;   /* 100ns 单位 */
    *pp = new MockSample();
    return S_OK;
}

struct MockMediaSource : public IMFMediaSource {
    ULONG ref = 1;
    HRESULT QueryInterface(REFIID, void **ppv) override { *ppv = nullptr; return E_NOINTERFACE; }
    ULONG AddRef() override  { return ++ref; }
    ULONG Release() override { if (--ref == 0) { delete this; return 0; } return ref; }
};
struct MockActivate : public IMFActivate {
    MockAttributes attr; ULONG ref = 1;
    HRESULT QueryInterface(REFIID, void **ppv) override { *ppv = nullptr; return E_NOINTERFACE; }
    ULONG AddRef() override  { return ++ref; }
    ULONG Release() override { if (--ref == 0) { delete this; return 0; } return ref; }
    HRESULT SetGUID(REFGUID k, REFGUID v) override { return attr.SetGUID(k, v); }
    HRESULT SetUINT32(REFGUID k, UINT32 v) override { return attr.SetUINT32(k, v); }
    HRESULT SetUINT64(REFGUID k, UINT64 v) override { return attr.SetUINT64(k, v); }
    HRESULT GetGUID(REFGUID k, GUID *v) override { return attr.GetGUID(k, v); }
    HRESULT GetUINT32(REFGUID k, UINT32 *v) override { return attr.GetUINT32(k, v); }
    HRESULT GetUINT64(REFGUID k, UINT64 *v) override { return attr.GetUINT64(k, v); }
    HRESULT GetStringLength(REFGUID k, UINT32 *n) override { return attr.GetStringLength(k, n); }
    HRESULT GetString(REFGUID k, LPWSTR b, UINT32 c, UINT32 *n) override { return attr.GetString(k, b, c, n); }
    HRESULT ActivateObject(REFIID, void **ppv) override { *ppv = new MockMediaSource(); return S_OK; }
};

/* ---- MF 函数 ---- */
HRESULT MFStartup(ULONG, DWORD) { mf_started() = true; return S_OK; }
HRESULT MFShutdown(void) { mf_started() = false; return S_OK; }
HRESULT MFCreateAttributes(IMFAttributes **pp, UINT32) { *pp = new MockAttributes(); return S_OK; }
HRESULT MFCreateMediaType(IMFMediaType **pp) { *pp = new MockMediaType(); return S_OK; }
HRESULT MFEnumDeviceSources(IMFAttributes *, IMFActivate ***ppp, UINT32 *pc) {
    *pc = 1;
    *ppp = (IMFActivate **)CoTaskMemAlloc(sizeof(IMFActivate *));
    MockActivate *a = new MockActivate();
    a->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
               MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    a->attr.m_str[MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK] = L"\\\\?\\usb#vid_0000";
    a->attr.m_str[MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME] = L"Integrated Camera";
    (*ppp)[0] = a;
    return S_OK;
}
HRESULT MFCreateSourceReaderFromMediaSource(IMFMediaSource *, IMFAttributes *,
                                                       IMFSourceReader **pp) {
    *pp = new MockSourceReader(); return S_OK;
}

/* 测试注入接口 */
void wsdk_set_native_formats(const NativeFmt *list, size_t n) {
    native_list().assign(list, list + n);
}
bool wsdk_mf_started(void) { return mf_started(); }
GUID wsdk_last_set_subtype(void) { return last_set_subtype(); }
UINT64 wsdk_last_set_framesize(void) { return last_set_framesize(); }

/* cam_errstr 由 shim 提供，避免链接 cam_mock.c（后者也定义了 cam_source_create） */
extern "C" const char *cam_errstr(cam_err_t e)
{
    switch (e) {
    case CAM_OK:                  return "ok";
    case CAM_ERR_GENERIC:         return "generic error";
    case CAM_ERR_NO_DEVICE:       return "no device";
    case CAM_ERR_NO_PERMISSION:   return "no permission";
    case CAM_ERR_FORMAT_NEGOTIATE:return "format negotiate failed";
    case CAM_ERR_TRANSFORM:       return "transform failed";
    case CAM_ERR_TIMEOUT:         return "timeout";
    case CAM_ERR_NOT_OPEN:        return "not open";
    case CAM_ERR_INVALID_ARG:     return "invalid argument";
    default:                      return "unknown";
    }
}
