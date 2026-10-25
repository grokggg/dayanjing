/*
 * agent_windows/src/cam_mf.cpp
 *
 * Media Foundation 后端（Windows 真机专用）。
 *
 * 职责：
 *   - 枚举视频采集设备（MFEnumDeviceSources）
 *   - 格式协商：按 width×height 优先 + 格式优先级链
 *     (MFVideoFormat_MJPG -> YUY2 -> NV12 -> RGB24) 遍历
 *     IMFSourceReader::GetNativeMediaType，禁止裸设容器格式
 *   - 通过 IMFSourceReader 取帧，处理 ENDOFSTREAM / ENDOFMEDIA 流控
 *   - 从 IMFMediaBuffer 正确取帧数据与步幅
 *   - 采集完立即释放设备句柄，缩短指示灯点亮窗口
 *
 * 编译（Windows SDK / MSVC）：
 *   cl /EHsc /I.. /I../../00_crypto cam_mf.cpp /link mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib
 * 或 Clang-cl：
 *   clang-cl /EHsc /I.. /I../../00_crypto cam_mf.cpp mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib
 *
 * 运行时依赖：Windows 10 及以上，Media Foundation。进程需已初始化 COM（STA）。
 *
 * 本文件仅实现后端，接口契约见 camera.h。
 */

#ifdef _WIN32

#include "camera.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mfobjects.h>
#include <mfcaptureengine.h>
#include <mferror.h>
#include <shlwapi.h>
#include <wrl/client.h>
#include <string>
#include <vector>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "ole32.lib")

using Microsoft::WRL::ComPtr;

/* ------------------------------------------------------------------ */
/* 私有数据                                                           */
/* ------------------------------------------------------------------ */

struct mf_priv {
    ComPtr<IMFAttributes>         pDevices;
    ComPtr<IMFMediaSource>        pSource;
    ComPtr<IMFSourceReader>       pReader;
    ComPtr<IMFMediaType>          pCurrentType;
    IMFActivate                  **ppActivates;   /* MFEnumDeviceSources 返回的数组 */
    UINT                          cActivates;
    cam_config_t                  cfg;
    cam_frame_t                   last_frame;     /* 最近一帧（内部缓冲区） */
    std::vector<uint8_t>          frame_buf;      /* 帧数据持有者 */
    bool                          com_inited;     /* 本实例是否初始化了 COM */
    bool                          need_transform; /* 原生格式非压缩 -> 交付前须转码 */
    bool                          mf_started;     /* 本实例是否调用过 MFStartup */
};

#define PRIV(s) ((mf_priv *)(s)->priv)

/* ------------------------------------------------------------------ */
/* GUID <-> FourCC 转换                                               */
/* ------------------------------------------------------------------ */

static uint32_t FourCCFromGUID(const GUID &g)
{
    /* MF 视频子类型 GUID 的低 4 字节即 FourCC，小端布局 */
    return (uint32_t)g.Data1;
}

/*
 * FourCC 以小端 uint32 存放于 GUID.Data1。
 *
 * 用显式十六进制常量，不用多字符字面量（'MJPG'）：多字符字面量的取值是
 * 实现定义的，换编译器会静默变成另一个值，且 GCC/MSVC 均会告警。
 *
 * 注意 MFVideoFormat_RGB24 的 Data1 是 20（D3DFMT 值），不是 FourCC。
 * 原实现按 'RGB ' 匹配，导致 RGB24 设备永远被判为 UNKNOWN 而无法采集。
 */
#define FCC_MJPG  0x47504A4Du   /* 'MJPG' */
#define FCC_MEPG  0x4750454Du   /* 'MEPG'，部分编码器上报 */
#define FCC_YUY2  0x32595559u   /* 'YUY2' */
#define FCC_NV12  0x3231564Eu   /* 'NV12' */
#define FCC_RGB24 20u           /* MFVideoFormat_RGB24 */

static cam_pixel_fmt_t FmtFromGUID(const GUID &subtype)
{
    uint32_t fcc = FourCCFromGUID(subtype);
    switch (fcc) {
    case FCC_MJPG:
    case FCC_MEPG:
        return CAM_FMT_MJPEG;
    case FCC_YUY2:
        return CAM_FMT_YUYV422;
    case FCC_NV12:
        return CAM_FMT_NV12;
    case FCC_RGB24:
        return CAM_FMT_RGB24;
    default:
        return CAM_FMT_UNKNOWN;
    }
}

/* 压缩格式无需转码即可当 JPEG 交付；未压缩格式必须经 cam_frame_to_jpeg */
static bool IsCompressedFmt(uint32_t fcc)
{
    return (fcc == FCC_MJPG || fcc == FCC_MEPG);
}

/* ------------------------------------------------------------------ */
/* 权限检测                                                           */
/* ------------------------------------------------------------------ */

bool mf_check_permission(void)
{
    /*
     * 读取 CapabilityAccessManager 注册表，判定当前进程是否被授权访问摄像头。
     * 路径：HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\
     *         ConsentStore\webcam\{current-user-sid}\NonWin32ChildProcess
     * 键 "Value" = "Allow" 表示已授权。
     *
     * 这是权限前提 A（admin / 已有摄像头权限）的检测手段。
     * 若返回 false，说明当前进程无授权，需要引导用户授权或换用已授权进程（前提 B）。
     */
    HKEY hKey = NULL;
    bool allowed = false;

    /* 构造当前用户 SID 路径（简化：读 ConsentStore\webcam 的 LastUsedTimeStart 是否存在） */
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\"
                      L"CapabilityAccessManager\\ConsentStore\\webcam",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        /* 遍历子键找当前用户 SID */
        DWORD idx = 0;
        wchar_t sub[256];
        DWORD sub_sz = sizeof(sub);
        while (RegEnumKeyExW(hKey, idx, sub, &sub_sz, NULL, NULL, NULL, NULL)
               == ERROR_SUCCESS) {
            /* SID 子键形如 S-1-5-21-...，跳过 NonWin32* 与 LastUsedTime* */
            if (wcsncmp(sub, L"S-1-5", 5) == 0) {
                std::wstring path = L"Software\\Microsoft\\Windows\\CurrentVersion\\"
                                    L"CapabilityAccessManager\\ConsentStore\\webcam\\";
                path += sub;
                HKEY hSid = NULL;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0,
                                  KEY_READ, &hSid) == ERROR_SUCCESS) {
                    wchar_t val[32];
                    DWORD v_sz = sizeof(val);
                    DWORD ty = 0;
                    if (RegQueryValueExW(hSid, L"Value", NULL, &ty,
                                         (LPBYTE)val, &v_sz) == ERROR_SUCCESS) {
                        if (_wcsicmp(val, L"Allow") == 0)
                            allowed = true;
                    }
                    RegCloseKey(hSid);
                }
            }
            sub_sz = sizeof(sub);
            idx++;
        }
        RegCloseKey(hKey);
    }
    return allowed;
}

/* ------------------------------------------------------------------ */
/* 设备枚举                                                           */
/* ------------------------------------------------------------------ */

int mf_enumerate(cam_device_info_t *info, int count)
{
    if (!info || count <= 0)
        return 0;

    ComPtr<IMFAttributes> pAttr;
    if (FAILED(MFCreateAttributes(&pAttr, 1)))
        return 0;

    pAttr->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                   MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

    IMFActivate **ppAct = NULL;
    UINT cAct = 0;
    if (FAILED(MFEnumDeviceSources(pAttr.Get(), &ppAct, &cAct)))
        return 0;

    int n = 0;
    for (UINT i = 0; i < cAct && n < count; i++) {
        UINT32 len = 0;
        if (SUCCEEDED(ppAct[i]->GetStringLength(
                MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                &len))) {
            std::vector<WCHAR> sym(len + 1);
            ppAct[i]->GetString(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                                sym.data(), len + 1, &len);
            WideCharToMultiByte(CP_UTF8, 0, sym.data(), -1,
                                info[n].device_id, sizeof(info[n].device_id),
                                NULL, NULL);

            UINT32 nlen = 0;
            if (SUCCEEDED(ppAct[i]->GetStringLength(
                    MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &nlen))) {
                std::vector<WCHAR> fn(nlen + 1);
                ppAct[i]->GetString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME,
                                    fn.data(), nlen + 1, &nlen);
                WideCharToMultiByte(CP_UTF8, 0, fn.data(), -1,
                                    info[n].friendly_name,
                                    sizeof(info[n].friendly_name),
                                    NULL, NULL);
            }
            info[n].has_permission = mf_check_permission();
            n++;
        }
    }

    for (UINT i = 0; i < cAct; i++)
        ppAct[i]->Release();
    CoTaskMemFree(ppAct);

    return n;
}

/* ------------------------------------------------------------------ */
/* 格式协商                                                           */
/* ------------------------------------------------------------------ */

static HRESULT NegotiateFormat(IMFSourceReader *reader, const cam_config_t *cfg,
                               GUID *outSubtype, UINT32 *outW, UINT32 *outH)
{
    HRESULT hr = S_OK;
    bool prefer_mjpeg = cfg->prefer_mjpeg;

    /*
     * 格式优先级链：MJPG 优先（免转码），其次 YUY2 / NV12 / RGB24。
     * 遍历 GetNativeMediaType 的全部 (index, media_type_index) 组合，
     * 筛选满足 width×height 要求的最高优先级格式。
     */
    struct Cand { GUID subtype; UINT32 w, h; cam_pixel_fmt_t fmt; };
    std::vector<Cand> candidates;

    for (DWORD i = 0; ; i++) {
        ComPtr<IMFMediaType> pType;
        hr = reader->GetNativeMediaType((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM,
                                        i, &pType);
        if (hr == MF_E_NO_MORE_TYPES)
            break;
        if (FAILED(hr))
            continue;

        GUID major = {}, subtype = {};
        pType->GetGUID(MF_MT_MAJOR_TYPE, &major);
        if (major != MFMediaType_Video)
            continue;
        pType->GetGUID(MF_MT_SUBTYPE, &subtype);

        /*
         * MF_MT_FRAME_SIZE 是 packed UINT64：高 32 位为宽，低 32 位为高。
         *
         * 必须用 GetUINT64。此前用 GetUINT32 读该属性会返回失败
         * （属性类型不匹配），宽高保持 0，后果是：
         *   - 指定了分辨率时，所有候选都被过滤掉 -> 协商永远失败，
         *     摄像头根本打不开；
         *   - 未指定分辨率时，把 0x0 写进 SetCurrentMediaType，
         *     open 却返回成功（假成功）。
         */
        UINT64 packed = 0;
        if (FAILED(pType->GetUINT64(MF_MT_FRAME_SIZE, &packed)))
            continue;
        UINT32 w = (UINT32)(packed >> 32);
        UINT32 h = (UINT32)(packed & 0xFFFFFFFFu);
        if (w == 0 || h == 0)
            continue;

        cam_pixel_fmt_t fmt = FmtFromGUID(subtype);
        if (fmt == CAM_FMT_UNKNOWN)
            continue;

        /* 若指定了尺寸，只保留匹配的 */
        if (cfg->width != 0 && w != cfg->width)
            continue;
        if (cfg->height != 0 && h != cfg->height)
            continue;

        candidates.push_back({subtype, w, h, fmt});
    }

    if (candidates.empty())
        return MF_E_NO_MORE_TYPES;

    /* 按优先级排序 */
    auto prio = [prefer_mjpeg](cam_pixel_fmt_t f) -> int {
        if (f == CAM_FMT_MJPEG) return prefer_mjpeg ? 0 : 3;
        if (f == CAM_FMT_YUYV422) return 1;
        if (f == CAM_FMT_NV12) return 2;
        if (f == CAM_FMT_RGB24) return 4;
        return 5;
    };

    size_t best = 0;
    for (size_t i = 1; i < candidates.size(); i++) {
        if (prio(candidates[i].fmt) < prio(candidates[best].fmt))
            best = i;
    }

    /* 设置选中的媒体类型 */
    ComPtr<IMFMediaType> pSet;
    if (FAILED(MFCreateMediaType(&pSet)))
        return E_FAIL;

    pSet->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    pSet->SetGUID(MF_MT_SUBTYPE, candidates[best].subtype);
    /*
     * 与读取端严格对称：UINT64 packed，高 32 位宽、低 32 位高。
     * 原实现用 SetUINT32 且按 16+16 打包，写入的分辨率是错误的。
     */
    pSet->SetUINT64(MF_MT_FRAME_SIZE,
                    ((UINT64)candidates[best].w << 32) | (UINT64)candidates[best].h);
    if (cfg->fps != 0) {
        UINT64 fps = ((UINT64)cfg->fps << 32) | 1;
        pSet->SetUINT64(MF_MT_FRAME_RATE, fps);
    }

    hr = reader->SetCurrentMediaType(
        (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, NULL, pSet.Get());
    if (FAILED(hr))
        return hr;

    *outSubtype = candidates[best].subtype;
    *outW = candidates[best].w;
    *outH = candidates[best].h;
    return S_OK;
}

/* ------------------------------------------------------------------ */
/* 打开设备                                                           */
/* ------------------------------------------------------------------ */

static cam_err_t mf_open(cam_source_t *self, const cam_config_t *cfg)
{
    if (!self || !cfg || !self->priv)
        return CAM_ERR_INVALID_ARG;

    mf_priv *p = PRIV(self);
    p->cfg = *cfg;

    if (!mf_check_permission())
        return CAM_ERR_NO_PERMISSION;

    if (FAILED(MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET)))
        return CAM_ERR_GENERIC;
    p->mf_started = true;

    /* 枚举设备 */
    ComPtr<IMFAttributes> pAttr;
    if (FAILED(MFCreateAttributes(&pAttr, 1)))
        return CAM_ERR_GENERIC;
    pAttr->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                   MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

    if (FAILED(MFEnumDeviceSources(pAttr.Get(), &p->ppActivates, &p->cActivates)))
        return CAM_ERR_NO_DEVICE;
    if (p->cActivates == 0)
        return CAM_ERR_NO_DEVICE;

    /* 取第一个设备（如需指定 device_id，按 symbolic link 匹配） */
    if (FAILED(p->ppActivates[0]->ActivateObject(
            IID_PPV_ARGS(&p->pSource))))
        return CAM_ERR_NO_DEVICE;

    if (FAILED(MFCreateSourceReaderFromMediaSource(
            p->pSource.Get(), NULL, &p->pReader)))
        return CAM_ERR_GENERIC;

    GUID subtype = {};
    UINT32 w = 0, h = 0;
    HRESULT hr = NegotiateFormat(p->pReader.Get(), cfg, &subtype, &w, &h);
    if (FAILED(hr))
        return CAM_ERR_FORMAT_NEGOTIATE;

    p->last_frame.width = w;
    p->last_frame.height = h;
    p->last_frame.fmt = FmtFromGUID(subtype);
    /* 压缩格式（MJPEG）可直接当 JPEG 交付；未压缩格式必须经 cam_frame_to_jpeg */
    p->need_transform = !IsCompressedFmt(FourCCFromGUID(subtype));

    return CAM_OK;
}

/* ------------------------------------------------------------------ */
/* 采集一帧                                                           */
/* ------------------------------------------------------------------ */

static cam_err_t mf_capture(cam_source_t *self, cam_frame_t *frame)
{
    if (!self || !frame || !self->priv)
        return CAM_ERR_INVALID_ARG;
    if (!PRIV(self)->pReader)
        return CAM_ERR_NOT_OPEN;

    mf_priv *p = PRIV(self);
    DWORD flags = 0;
    LONGLONG llTimeStamp = 0;
    ComPtr<IMFSample> pSample;
    ComPtr<IMFMediaBuffer> pBuffer;

    /* 循环读取，处理 ENDOFSTREAM / ENDOFMEDIA 标志 */
    HRESULT hr = p->pReader->ReadSample(
        (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM,
        0, NULL, &flags, &llTimeStamp, &pSample);
    if (FAILED(hr))
        return CAM_ERR_GENERIC;

    if ((flags & MF_SOURCE_READERF_ENDOFSTREAM) ||
        (flags & MF_SOURCE_READERF_ENDOFMEDIA)) {
        return CAM_ERR_TIMEOUT;
    }
    if (pSample == NULL)
        return CAM_ERR_TIMEOUT;

    if (FAILED(pSample->ConvertToContiguousBuffer(&pBuffer)))
        return CAM_ERR_GENERIC;

    BYTE *pData = NULL;
    DWORD cbMax = 0, cbCurr = 0;
    if (FAILED(pBuffer->Lock(&pData, &cbMax, &cbCurr)))
        return CAM_ERR_GENERIC;

    /* 拷贝出缓冲区：持有者为本实例，调用方只读 */
    p->frame_buf.assign(pData, pData + cbCurr);
    pBuffer->Unlock();

    p->last_frame.data = p->frame_buf.data();
    p->last_frame.len = cbCurr;
    p->last_frame.pts_us = (uint64_t)(llTimeStamp / 10); /* 100ns -> us */

    *frame = p->last_frame;
    return CAM_OK;
}

/* ------------------------------------------------------------------ */
/* 关闭并释放句柄                                                     */
/* ------------------------------------------------------------------ */

static void mf_close(cam_source_t *self)
{
    if (!self || !self->priv)
        return;
    mf_priv *p = PRIV(self);

    p->pReader.Reset();
    p->pSource.Reset();

    if (p->ppActivates) {
        for (UINT i = 0; i < p->cActivates; i++) {
            if (p->ppActivates[i])
                p->ppActivates[i]->Release();
        }
        CoTaskMemFree(p->ppActivates);
        p->ppActivates = NULL;
        p->cActivates = 0;
    }

    /*
     * 只在本实例确实调用过 MFStartup 时才 MFShutdown。
     * 原实现无条件关闭：一个从未 open 的实例 close 一次，就会把整个进程的
     * Media Foundation 关掉，同进程内其他采集实例随之失效。
     */
    if (p->mf_started) {
        MFShutdown();
        p->mf_started = false;
    }
}

/* ------------------------------------------------------------------ */
/* 工厂                                                               */
/* ------------------------------------------------------------------ */

/* 前向声明：create 需把 destroy 指针写进结构体，而 destroy 定义在后面。
 * 两者都必须 extern "C"，cam_factory.c 才能按 C 符号引用。 */
extern "C" void cam_source_destroy_mf(cam_source_t *src);

extern "C" cam_source_t *cam_source_create_mf(void)
{
    /* 分发已上移到 cam_factory.c；本函数只负责构造 MF 后端本身 */
    cam_source_t *src = (cam_source_t *)CoTaskMemAlloc(sizeof(cam_source_t));
    if (!src)
        return NULL;
    src->destroy = cam_source_destroy_mf;
    ZeroMemory(src, sizeof(*src));

    mf_priv *p = new (std::nothrow) mf_priv();
    if (!p) {
        CoTaskMemFree(src);
        return NULL;
    }
    /*
     * 不可再对 p 做 ZeroMemory：mf_priv 含 std::vector 与 ComPtr，
     * 已由构造函数正确初始化，memset 会破坏这些已构造的子对象
     *（GCC 以 -Wclass-memaccess 告警）。
     */

    src->open = mf_open;
    src->capture = mf_capture;
    src->close = mf_close;
    src->enumerate = mf_enumerate;
    src->check_permission = mf_check_permission;
    src->priv = p;
    return src;
}

extern "C" void cam_source_destroy_mf(cam_source_t *src)
{
    if (!src)
        return;
    if (src->close)
        src->close(src);
    if (src->priv) {
        delete (mf_priv *)src->priv;
        src->priv = NULL;
    }
    CoTaskMemFree(src);
}

#endif /* _WIN32 */
