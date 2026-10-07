#ifndef DAYANJING_AGENT_WINDOWS_CAMERA_H
#define DAYANJING_AGENT_WINDOWS_CAMERA_H

/*
 * agent_windows/camera.h
 *
 * 摄像头采集核心接口。
 *
 * 设计目标：
 *   1. 源可替换：采集后端与协议层解耦，Windows 真机走 Media Foundation，
 *      测试/沙盒走 Mock 桩，协议层不感知差异。
 *   2. 格式协商：枚举设备原生格式，按优先级协商（MJPEG > YUYV/NV12），
 *      YUYV/NV12 必须经转码后才能当 JPEG 使用，禁止把 YUV 原始字节
 *      当 JPEG 落盘/传输。
 *   3. 流控：ReadSample 必须循环处理，捕获 ENDOFSTREAM / ENDOFMEDIA 标志。
 *   4. 按需短时触发：采集完立即释放设备句柄，缩短指示灯点亮窗口。
 *
 * 已知约束（硬件层，软件不可解）：
 *   多数现代设备的摄像头指示灯由固件直接控制，软件无法关闭。
 *   本模块不承诺静默，只承诺"短时触发、立即释放"。
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 像素格式。native 为设备原生格式，交付层统一转码为 JPEG。 */
typedef enum {
    CAM_FMT_NONE = 0,
    CAM_FMT_MJPEG,      /* 帧已是 JPEG，可直接使用 */
    CAM_FMT_YUYV422,    /* 需转码 */
    CAM_FMT_NV12,       /* 需转码 */
    CAM_FMT_RGB24,      /* 需转码 */
    CAM_FMT_UNKNOWN
} cam_pixel_fmt_t;

/* 单帧数据。data 归 CameraSource 所有，调用方只读。 */
typedef struct {
    const uint8_t *data;
    size_t         len;
    cam_pixel_fmt_t fmt;
    uint32_t        width;
    uint32_t        height;
    uint64_t        pts_us;   /* 呈现时间戳，微秒 */
} cam_frame_t;

/* 采集配置 */
typedef struct {
    uint32_t width;          /* 期望宽度，0 表示不指定 */
    uint32_t height;         /* 期望高度，0 表示不指定 */
    uint32_t fps;            /* 期望帧率，0 表示不指定 */
    uint32_t capture_ms;     /* 采集窗口时长（毫秒），到点即释放句柄 */
    uint32_t max_frames;     /* 最多采集帧数，0 表示不限（受 capture_ms 约束） */
    bool     prefer_mjpeg;   /* true: 优先 MJPEG；false: 优先未压缩格式 */
} cam_config_t;

/* 错误码 */
typedef enum {
    CAM_OK = 0,
    CAM_ERR_GENERIC,
    CAM_ERR_NO_DEVICE,        /* 无可访问摄像头设备 */
    CAM_ERR_NO_PERMISSION,    /* 权限/授权被拒绝（CapabilityAccessManager） */
    CAM_ERR_FORMAT_NEGOTIATE, /* 格式协商失败 */
    CAM_ERR_TRANSFORM,        /* 转码失败 */
    CAM_ERR_TIMEOUT,
    CAM_ERR_NOT_OPEN,
    CAM_ERR_INVALID_ARG
} cam_err_t;

/* 设备信息 */
typedef struct {
    char   device_id[128];
    char   friendly_name[128];
    bool   has_permission;   /* 当前进程是否被授权访问摄像头 */
} cam_device_info_t;

/* CameraSource 接口（源可替换） */
typedef struct cam_source cam_source_t;

struct cam_source {
    /* 打开设备并协商格式；成功返回 CAM_OK，source 处于就绪态 */
    cam_err_t (*open)(cam_source_t *self, const cam_config_t *cfg);

    /* 采集一帧；阻塞直到拿到帧或超时。frame 指向内部缓冲区，只读 */
    cam_err_t (*capture)(cam_source_t *self, cam_frame_t *frame);

    /* 关闭设备并释放句柄。必须释放，不可泄漏 */
    void      (*close)(cam_source_t *self);

    /* 枚举可用设备，info 数组由调用方提供，最多 count 项；返回实际设备数 */
    int       (*enumerate)(cam_device_info_t *info, int count);

    /* 判断当前进程是否有摄像头权限 */
    bool      (*check_permission)(void);

    void *priv;  /* 后端私有数据 */
};

/*
 * 工厂函数。
 *   backend = "mock"   : 返回 Mock 桩，喂测试帧，沙盒/无设备环境用
 *   backend = "mf"     : 返回 Media Foundation 后端，仅 Windows 真机可用
 *   backend = NULL     : 按当前平台自动选择
 */
cam_source_t *cam_source_create(const char *backend);
void          cam_source_destroy(cam_source_t *src);

/* 转码：将 frame 转成 JPEG，写入 out（调用方分配，容量 *out_cap 传入，
 * 实际写入字节数写回 *out_len）。返回 CAM_OK 表示成功。 */
cam_err_t cam_frame_to_jpeg(const cam_frame_t *frame,
                            uint8_t *out, size_t *out_cap, size_t *out_len);

/* 将 cam_err_t 转为可读字符串 */
const char *cam_errstr(cam_err_t e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_CAMERA_H */
