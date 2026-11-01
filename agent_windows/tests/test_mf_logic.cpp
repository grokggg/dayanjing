/*
 * agent_windows/tests/test_mf_logic.cpp
 *
 * cam_mf.cpp 的逻辑验证。用 winsdk_shim 提供的 mock Media Foundation
 * 让 Windows 专用源码在 Linux 下「真跑」，验证：
 *   - 设备枚举
 *   - 权限检测
 *   - 格式协商（MJPEG 优先链 + width×height 匹配）
 *   - 取帧
 *
 * 这不是真机执行：验证的是逻辑与契约，不是 Windows MF 的真实行为。
 */
#include <windows.h>
#include <mfapi.h>
#include "camera.h"
#include "wsdk_test.h"
#include <cstdio>
#include <cstring>
#include <string>

static int g_pass = 0, g_fail = 0;

static void chk(bool ok, const char *name, const char *detail = nullptr)
{
    if (ok) { g_pass++; printf("[PASS] %s\n", name); }
    else    { g_fail++; printf("[FAIL] %s%s%s\n", name,
                               detail ? "  " : "", detail ? detail : ""); }
}

int main(void)
{
    printf("=== cam_mf 逻辑验证（mock Media Foundation）===\n\n");

    /* 注入假设备的原生格式：MJPG 1280x720 / YUY2 640x480 / NV12 1920x1080 */
    NativeFmt fmts[3] = {
        { MFVideoFormat_MJPG, 1280, 720 },
        { MFVideoFormat_YUY2,  640, 480 },
        { MFVideoFormat_NV12, 1920, 1080 },
    };
    wsdk_set_native_formats(fmts, 3);

    cam_source_t *src = cam_source_create("mf");
    chk(src != nullptr, "cam_source_create(\"mf\") 返回非 NULL");
    if (!src) { printf("\nresult: %d pass %d fail\n", g_pass, g_fail); return 1; }

    chk(src->open && src->capture && src->close && src->enumerate
        && src->check_permission, "接口函数指针全部挂接");

    /* 1. 权限检测 */
    bool perm = src->check_permission();
    chk(perm == true, "check_permission 识别已授权状态");

    /* 2. 设备枚举 */
    cam_device_info_t info[4];
    memset(info, 0, sizeof(info));
    int n = src->enumerate(info, 4);
    chk(n == 1, "enumerate 返回 1 个设备");
    chk(n > 0 && strcmp(info[0].friendly_name, "Integrated Camera") == 0,
        "friendly_name 正确转换", n > 0 ? info[0].friendly_name : "");
    chk(n > 0 && info[0].device_id[0] != 0, "device_id 非空");
    chk(n > 0 && info[0].has_permission == true, "has_permission 置位");

    /* 3. 打开并协商格式 —— 指定 1280x720，期望选中 MJPG */
    cam_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.width = 1280; cfg.height = 720; cfg.fps = 30; cfg.prefer_mjpeg = true;

    cam_err_t e = src->open(src, &cfg);
    printf("\n[*] open(cfg 1280x720, prefer_mjpeg) -> %s\n", cam_errstr(e));
    chk(e == CAM_OK, "open 成功（格式协商应命中 MJPG 1280x720）",
        "若失败说明 NegotiateFormat 未正确解析 MF_MT_FRAME_SIZE");

    if (e == CAM_OK) {
        GUID got = wsdk_last_set_subtype();
        UINT64 fs = wsdk_last_set_framesize();
        UINT32 w = (UINT32)(fs >> 32), h = (UINT32)(fs & 0xFFFFFFFFu);
        printf("[*] SetCurrentMediaType: subtype.Data1=0x%08X size=%ux%u\n",
               got.Data1, w, h);
        chk(got.Data1 == MFVideoFormat_MJPG.Data1, "协商结果 subtype 为 MJPG");
        chk(w == 1280 && h == 720, "协商结果分辨率为 1280x720");
    }

    /* 4. 取帧（open 成功后才有意义） */
    if (e == CAM_OK) {
        cam_frame_t f;
        memset(&f, 0, sizeof(f));
        cam_err_t ce = src->capture(src, &f);
        printf("[*] capture -> %s\n", cam_errstr(ce));
        chk(ce == CAM_OK, "capture 返回 CAM_OK");
        if (ce == CAM_OK) {
            chk(f.len == 64, "帧长度 64（mock 缓冲）");
            chk(f.data != nullptr && f.data[0] == 0x41, "帧数据内容正确");
            chk(f.pts_us == 123456, "时间戳 100ns->us 换算正确 (1234567/10)");
            chk(f.width == 1280 && f.height == 720, "帧尺寸回填正确");
            chk(f.fmt == CAM_FMT_MJPEG, "帧格式回填为 MJPEG");
        }
    }

    /* 5. 未 open 直接 capture 应报错 */
    {
        cam_source_t *s2 = cam_source_create("mf");
        if (s2) {
            cam_frame_t f; memset(&f, 0, sizeof(f));
            cam_err_t ce = s2->capture(s2, &f);
            chk(ce == CAM_ERR_NOT_OPEN, "未 open 直接 capture -> NOT_OPEN");
            s2->close(s2);
            cam_source_destroy(s2);
        }
    }

    /* 6. 关闭后 MF 应关闭 */
    chk(wsdk_mf_started() == true, "open 后 MF 已启动");
    src->close(src);
    chk(wsdk_mf_started() == false, "close 调用 MFShutdown（释放设备，缩短指示灯窗口）");
    cam_source_destroy(src);

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
