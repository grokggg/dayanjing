/*
 * winsdk_shim/mfapi.h — Media Foundation 接口最小 shim。
 * 仅用于 Linux 下编译验证 cam_mf.cpp。聚合了 mfobjects/mfidl/mfreadwrite/mferror。
 */
#ifndef WSDK_SHIM_MFAPI_H
#define WSDK_SHIM_MFAPI_H

#include <windows.h>

/* 接口 ---------------------------------------------------------------- */
struct IMFAttributes : public IUnknown {
    virtual HRESULT SetGUID(REFGUID guidKey, REFGUID guidValue) = 0;
    virtual HRESULT SetUINT32(REFGUID guidKey, UINT32 unValue) = 0;
    virtual HRESULT SetUINT64(REFGUID guidKey, UINT64 unValue) = 0;
    virtual HRESULT GetGUID(REFGUID guidKey, GUID *pguidValue) = 0;
    virtual HRESULT GetUINT32(REFGUID guidKey, UINT32 *punValue) = 0;
    virtual HRESULT GetUINT64(REFGUID guidKey, UINT64 *punValue) = 0;
    virtual HRESULT GetStringLength(REFGUID guidKey, UINT32 *pcchLength) = 0;
    virtual HRESULT GetString(REFGUID guidKey, LPWSTR pwszValue,
                              UINT32 cchValue, UINT32 *pcchLength) = 0;
    static const GUID &GetIid();
};

struct IMFMediaType : public IMFAttributes {
    static const GUID &GetIid();
};

struct IMFActivate : public IMFAttributes {
    virtual HRESULT ActivateObject(REFIID riid, void **ppv) = 0;
    static const GUID &GetIid();
};

struct IMFMediaSource : public IUnknown {
    static const GUID &GetIid();
};

struct IMFMediaBuffer : public IUnknown {
    virtual HRESULT Lock(BYTE **ppbBuffer, DWORD *pcbMaxLength,
                         DWORD *pcbCurrentLength) = 0;
    virtual HRESULT Unlock(void) = 0;
    static const GUID &GetIid();
};

struct IMFSample : public IUnknown {
    virtual HRESULT ConvertToContiguousBuffer(IMFMediaBuffer **ppBuffer) = 0;
    static const GUID &GetIid();
};

struct IMFSourceReader : public IUnknown {
    virtual HRESULT GetNativeMediaType(DWORD dwStreamIndex,
                                       DWORD dwMediaTypeIndex,
                                       IMFMediaType **ppMediaType) = 0;
    virtual HRESULT SetCurrentMediaType(DWORD dwStreamIndex,
                                        DWORD *pdwReserved,
                                        IMFMediaType *pMediaType) = 0;
    virtual HRESULT ReadSample(DWORD dwStreamIndex, DWORD dwControlFlags,
                               DWORD *pdwActualStreamIndex,
                               DWORD *pdwStreamFlags,
                               LONGLONG *pllTimestamp,
                               IMFSample **ppSample) = 0;
    static const GUID &GetIid();
};

/* 常量 ---------------------------------------------------------------- */
#define MF_VERSION 0x00020070
#define MFSTARTUP_NOSOCKET 0x00000001

#define MF_SOURCE_READER_FIRST_VIDEO_STREAM ((DWORD)0xFFFFFFFC)
#define MF_SOURCE_READERF_ENDOFSTREAM       0x00000200
#define MF_SOURCE_READERF_ENDOFMEDIA        0x00000004

/* MF_MT_* 属性键（值本身不重要，shim 只要求可编译） */
extern const GUID MF_MT_MAJOR_TYPE;
extern const GUID MF_MT_SUBTYPE;
extern const GUID MF_MT_FRAME_SIZE;
extern const GUID MF_MT_FRAME_RATE;

extern const GUID MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE;
extern const GUID MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID;
extern const GUID MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK;
extern const GUID MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME;

/* MFVideoFormat 子类型。FourCC 位于 Data1（小端） */
DEFINE_SHIM_GUID(MFMediaType_Video, 0x73646976, 0x0000, 0x0010,
                 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71);
DEFINE_SHIM_GUID(MFVideoFormat_MJPG, 0x47504A4D, 0x0000, 0x0010,
                 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71);
DEFINE_SHIM_GUID(MFVideoFormat_YUY2, 0x32595559, 0x0000, 0x0010,
                 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71);
DEFINE_SHIM_GUID(MFVideoFormat_NV12, 0x3231564E, 0x0000, 0x0010,
                 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71);
DEFINE_SHIM_GUID(MFVideoFormat_RGB24, 0x00000014, 0x0000, 0x0010,
                 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71);

/* 函数 ---------------------------------------------------------------- */
HRESULT MFStartup(ULONG Version, DWORD dwFlags);
HRESULT MFShutdown(void);
HRESULT MFCreateAttributes(IMFAttributes **ppMFAttributes, UINT32 cInitialSize);
HRESULT MFCreateMediaType(IMFMediaType **ppMFType);
HRESULT MFEnumDeviceSources(IMFAttributes *pAttributes,
                            IMFActivate ***pppSourceActivate,
                            UINT32 *pcSourceActivate);
HRESULT MFCreateSourceReaderFromMediaSource(IMFMediaSource *pMediaSource,
                                            IMFAttributes *pAttributes,
                                            IMFSourceReader **ppSourceReader);

#endif
