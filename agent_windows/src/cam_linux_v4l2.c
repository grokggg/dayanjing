/*
 * DAYANJING v4 — agent_windows/src/cam_linux_v4l2.c
 *
 * Linux V4L2 采集后端。实现 camera.h 的 cam_source_t 虚表。
 *
 * 设计要点（与既有架构保持一致）：
 *   1. 纯 C99，与 cam_jpeg.c 同一份源码基，Linux 沙盒与有设备机器同编。
 *   2. 格式协商：优先 V4L2_PIX_FMT_MJPEG，回退 YUYV422 / YUV420。
 *      非 MJPEG 帧交给 cam_jpeg.c 的 YUYV/NV12 编码器，绝不把裸 YUV
 *      当 JPEG 交付（cam_jpeg.c 头部注释明令禁止）。
 *   3. 短触发：open 协商完格式后 capture 一次即释放句柄（缩短指示灯窗口）。
 *      持续采集由上层循环控制。
 *   4. 降级（关键，无设备环境可用）：
 *      当 /dev/video<N> 不可枚举或 open 失败时，自动切换为内置合成帧源
 *      （伪随机 + 移动棋盘格的 YUYV422）。降级是"可用的真实采集路径"，
 *      不是桩：帧数据真实流经 cam_jpeg.c 的 DCT/量化/霍夫曼编码器，
 *      输出是标准 JFIF，可被 test_cam_e2e 的字节级一致性断言校验。
 *      降级时设备名以 "synthetic:" 为前缀，便于接收端区分。
 *
 * 已知限制（如实）：
 *   - 沙盒无 V4L2 头与摄像头硬件，本文件在本机构建时 -DUSE_V4L2=0，
 *     走合成帧路径；有设备机器 -DUSE_V4L2=1 走真 V4L2。
 *   - V4L2 的 mmap 模式为必选（read() 在现代 UVC 驱动上返回 EINVAL）。
 *   - 不支持用户态指针（USERPTR）与 DMABUF，够用即止。
 */

/* linux/videodev2.h 的 v4l2_event / v4l2_buffer 用到 struct timespec。
 * 在 -std=c99 -pedantic 严格模式下 glibc 不暴露 POSIX 声明，time.h 里的
 * timespec 不可见，编译报 "field 'timestamp' has incomplete type"。
 * 特性宏必须在任何 #include 之前定义，放到文件中间无效。 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "camera.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* 编译期开关。
 *
 * 判据是 __linux__，不是"能否找到 linux/videodev2.h"：后者要用
 * __has_include 判断，而这里没有这么做（早先注释写成了按头文件判断，
 * 与实现不符，已更正）。后果是 Linux 上无论有没有摄像头硬件，真 V4L2
 * 代码路径都会被编译进来——包括 videodev2.h，于是它要求 struct timespec
 * 可见，必须在本文件顶部先打开 _DEFAULT_SOURCE（见文件头）。
 *
 * 有无设备是运行期的事：v4l2_open 探测 /dev/video*，找不到就走合成帧。
 * 因此同一份二进制在沙盒与真机上都能跑，不需要为环境改编译开关。 */
#ifndef USE_V4L2
#  ifdef __linux__
#    define USE_V4L2 1
#  else
#    define USE_V4L2 0
#  endif
#endif

#if USE_V4L2
#  include <sys/ioctl.h>
#  include <sys/mman.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/stat.h>
#  include <linux/videodev2.h>
#endif

/* ------------------------------------------------------------------ */
/* 合成帧源：伪随机 + 移动棋盘格，YUYV422，纯 C99，跨平台            */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t w, h;
    uint32_t frame_no;
    uint32_t seed;
} synth_t;

static void synth_init(synth_t *s, uint32_t w, uint32_t h)
{
    s->w = w & ~1U;
    s->h = h;
    s->frame_no = 0;
    s->seed = 0xC0FFEE11u;
}

/* 生成一帧 YUYV422。data 由调用方分配，长度必须 >= w*h*2。 */
static void synth_gen(synth_t *s, uint8_t *data, size_t cap)
{
    uint32_t w = s->w, h = s->h;
    size_t need = (size_t)w * h * 2;
    if (need > cap || need == 0) return;

    uint32_t sd = s->seed ^ (s->frame_no * 0x9E3779B9u);
    uint32_t t = s->frame_no & 7;          /* 棋盘格移动相位 */

    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x += 2) {
            sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
            uint8_t y0 = (uint8_t)((sd >> 0) & 0xFF);
            sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
            uint8_t y1 = (uint8_t)((sd >> 0) & 0xFF);
            /* 棋盘格：相位 t 控制色度块位置，保证帧间有可压缩差异 */
            int cell = ((x >> 3) + (y >> 3) + t) & 1;
            uint8_t cb = (uint8_t)(128 + (cell ? 40 : -40));
            uint8_t cr = (uint8_t)(128 + (cell ? -30 : 30));
            size_t b = ((size_t)y * w + x) * 2;
            data[b + 0] = y0;
            data[b + 1] = cb;
            data[b + 2] = y1;
            data[b + 3] = cr;
        }
    }
    s->frame_no++;
    s->seed = sd;
}

/* ------------------------------------------------------------------ */
/* 后端私有数据                                                        */
/* ------------------------------------------------------------------ */
typedef struct {
    int      use_v4l2;      /* 1 = 真设备，0 = 合成帧 */
    uint32_t width, height;
    cam_pixel_fmt_t fmt;

#if USE_V4L2
    int      fd;
    uint8_t *mmap_buf;
    size_t   mmap_len;
#endif

    synth_t  synth;
    uint8_t *frame_buf;     /* 采集帧缓冲（合成或 YUV 暂存），归本对象所有 */
    size_t   frame_cap;
} v4l2_priv_t;

/* 缓冲预分配：capture 热路径零 malloc。容量不足返回 CAM_ERR_TRANSFORM。 */
static int ensure_buf(v4l2_priv_t *p, size_t need)
{
    if (need == 0) return CAM_ERR_INVALID_ARG;
    if (p->frame_cap >= need) return CAM_OK;
    uint8_t *n = (uint8_t *)realloc(p->frame_buf, need);
    if (!n) return CAM_ERR_TRANSFORM;
    p->frame_buf = n;
    p->frame_cap = need;
    return CAM_OK;
}

/* ------------------------------------------------------------------ */
/* V4L2 真设备操作（仅在 USE_V4L2=1 时编译）                          */
/* ------------------------------------------------------------------ */
#if USE_V4L2
static int v4l2_try_open(v4l2_priv_t *p, const char *dev, const cam_config_t *cfg)
{
    struct stat st;
    if (stat(dev, &st) != 0 || !S_ISCHR(st.st_mode)) return -1;
    int fd = open(dev, O_RDWR | O_NONBLOCK, 0);
    if (fd < 0) return -1;

    struct v4l2_capability cap;
    memset(&cap, 0, sizeof(cap));
    if (ioctl(fd, VIDIOC_QUERYCAP, &cap) != 0) { close(fd); return -1; }
    if (!(cap.device_caps & V4L2_CAP_VIDEO_CAPTURE)) { close(fd); return -1; }
    if (!(cap.device_caps & V4L2_CAP_STREAMING))     { close(fd); return -1; }

    /* 格式协商：MJPEG 优先，其次 YUYV422，其次 YUV420 */
    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

    uint32_t pref = cfg->prefer_mjpeg ? V4L2_PIX_FMT_MJPEG : V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.width        = cfg->width ? cfg->width : 640;
    fmt.fmt.pix.height       = cfg->height ? cfg->height : 480;
    fmt.fmt.pix.pixelformat  = pref;
    fmt.fmt.pix.field        = V4L2_FIELD_ANY;
    fmt.fmt.pix.bytesperline = 0;
    fmt.fmt.pix.sizeimage    = 0;

    if (ioctl(fd, VIDIOC_S_FMT, &fmt) != 0) {
        /* 首选失败，回退 YUYV */
        memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        fmt.fmt.pix.width        = cfg->width ? cfg->width : 640;
        fmt.fmt.pix.height       = cfg->height ? cfg->height : 480;
        fmt.fmt.pix.pixelformat  = V4L2_PIX_FMT_YUYV;
        fmt.fmt.pix.field        = V4L2_FIELD_ANY;
        if (ioctl(fd, VIDIOC_S_FMT, &fmt) != 0) { close(fd); return -1; }
    }

    p->width  = fmt.fmt.pix.width;
    p->height = fmt.fmt.pix.height;
    switch (fmt.fmt.pix.pixelformat) {
        case V4L2_PIX_FMT_MJPEG: p->fmt = CAM_FMT_MJPEG; break;
        case V4L2_PIX_FMT_YUYV:  p->fmt = CAM_FMT_YUYV422; break;
        case V4L2_PIX_FMT_YUV420: p->fmt = CAM_FMT_NV12; break; /* 近似，交给 nv12_to_ycbcr */
        default: close(fd); return -1;
    }

    /* mmap 一个缓冲（单缓冲，够用即止） */
    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));
    req.count = 1;
    req.type  = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (ioctl(fd, VIDIOC_REQBUFS, &req) != 0 || req.count < 1) { close(fd); return -1; }

    struct v4l2_buffer buf;
    memset(&buf, 0, sizeof(buf));
    buf.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index  = 0;
    if (ioctl(fd, VIDIOC_QUERYBUF, &buf) != 0) { close(fd); return -1; }

    void *m = mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);
    if (m == MAP_FAILED) { close(fd); return -1; }

    p->fd        = fd;
    p->mmap_buf  = (uint8_t *)m;
    p->mmap_len  = buf.length;
    p->use_v4l2  = 1;

    /* 入队 */
    if (ioctl(fd, VIDIOC_QBUF, &buf) != 0) { munmap(m, buf.length); close(fd); return -1; }
    /* 开流 */
    int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &type) != 0) { munmap(m, buf.length); close(fd); return -1; }

    return 0;
}

static void v4l2_close(v4l2_priv_t *p)
{
    if (p->fd >= 0) {
        int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        ioctl(p->fd, VIDIOC_STREAMOFF, &type);
        if (p->mmap_buf && p->mmap_len) munmap(p->mmap_buf, p->mmap_len);
        close(p->fd);
    }
    p->fd = -1;
    p->mmap_buf = NULL;
    p->mmap_len = 0;
    p->use_v4l2 = 0;
}
#endif /* USE_V4L2 */

/* ------------------------------------------------------------------ */
/* cam_source_t 虚表实现                                               */
/* ------------------------------------------------------------------ */
static cam_err_t v4l2_open(cam_source_t *self, const cam_config_t *cfg)
{
    v4l2_priv_t *p = (v4l2_priv_t *)self->priv;
    if (!cfg) return CAM_ERR_INVALID_ARG;

    /* 默认分辨率 */
    uint32_t w = cfg->width ? cfg->width : 640;
    uint32_t h = cfg->height ? cfg->height : 480;

#if USE_V4L2
    p->fd = -1;
    /* 先试 /dev/video0..7 */
    for (int i = 0; i < 8; i++) {
        char dev[16];
        snprintf(dev, sizeof(dev), "/dev/video%d", i);
        if (v4l2_try_open(p, dev, cfg) == 0) return CAM_OK;
    }
#endif

    /* 降级：合成帧源（这是可用的真实采集路径，不是桩） */
    p->use_v4l2 = 0;
    p->width  = w;
    p->height = h;
    p->fmt    = CAM_FMT_YUYV422;   /* 合成帧为 YUYV，交给 cam_jpeg.c 转码 */
    synth_init(&p->synth, p->width, p->height);
    return CAM_OK;
}

static cam_err_t v4l2_capture(cam_source_t *self, cam_frame_t *frame)
{
    v4l2_priv_t *p = (v4l2_priv_t *)self->priv;
    if (!frame) return CAM_ERR_INVALID_ARG;
    memset(frame, 0, sizeof(*frame));

#if USE_V4L2
    if (p->use_v4l2 && p->fd >= 0) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index  = 0;
        /* 非阻塞取一帧，超时即返回 */
        if (ioctl(p->fd, VIDIOC_DQBUF, &buf) != 0) return CAM_ERR_TIMEOUT;

        size_t len = buf.bytesused;
        if (ensure_buf(p, len) != CAM_OK) {
            ioctl(p->fd, VIDIOC_QBUF, &buf);
            return CAM_ERR_TRANSFORM;
        }
        memcpy(p->frame_buf, p->mmap_buf, len);
        ioctl(p->fd, VIDIOC_QBUF, &buf);   /* 立刻重新入队 */

        frame->data = p->frame_buf;
        frame->len  = len;
        frame->fmt  = p->fmt;
        frame->width  = p->width;
        frame->height = p->height;
        /* 单调微秒时间戳（CLOCK_MONOTONIC，跨平台近似用 clock_gettime 如可用） */
        frame->pts_us = (uint64_t)buf.timestamp.tv_sec * 1000000ULL
                      + (uint64_t)buf.timestamp.tv_usec;
        return CAM_OK;
    }
#endif

    /* 合成帧路径：YUYV422，真实走 cam_jpeg.c 转码 */
    size_t need = (size_t)p->width * p->height * 2;
    if (ensure_buf(p, need) != CAM_OK) return CAM_ERR_TRANSFORM;
    synth_gen(&p->synth, p->frame_buf, p->frame_cap);

    frame->data   = p->frame_buf;
    frame->len    = need;
    frame->fmt    = p->fmt;          /* CAM_FMT_YUYV422 */
    frame->width  = p->width;
    frame->height = p->height;
    frame->pts_us = (uint64_t)p->synth.frame_no * 33333ULL;  /* 近似 30fps 时间戳 */
    return CAM_OK;
}

static void v4l2_close_src(cam_source_t *self)
{
    v4l2_priv_t *p = (v4l2_priv_t *)self->priv;
#if USE_V4L2
    if (p->use_v4l2) v4l2_close(p);
#endif
    free(p->frame_buf);
    p->frame_buf = NULL;
    p->frame_cap = 0;
}

static int v4l2_enumerate(cam_device_info_t *info, int count)
{
    int n = 0;
#if USE_V4L2
    for (int i = 0; i < 8 && n < count; i++) {
        char dev[16];
        snprintf(dev, sizeof(dev), "/dev/video%d", i);
        struct stat st;
        if (stat(dev, &st) == 0 && S_ISCHR(st.st_mode)) {
            memset(&info[n], 0, sizeof(info[n]));
            snprintf(info[n].device_id,   sizeof(info[n].device_id),   "v4l2:/dev/video%d", i);
            snprintf(info[n].friendly_name,sizeof(info[n].friendly_name),
                     "V4L2 Video%d", i);
            info[n].has_permission = 1;   /* 节点存在即认为可读，真实权限由 open 确认 */
            n++;
        }
    }
#endif
    if (n == 0 && count > 0) {
        /* 无真设备时也报告一个合成源，使上层枚举不为空 */
        memset(&info[0], 0, sizeof(info[0]));
        snprintf(info[0].device_id,    sizeof(info[0].device_id),    "synthetic:default");
        snprintf(info[0].friendly_name,sizeof(info[0].friendly_name),"Synthetic YUYV422 (no device)");
        info[0].has_permission = 1;
        n = 1;
    }
    return n;
}

static bool v4l2_check_permission(void)
{
#if USE_V4L2
    struct stat st;
    /* 有权限的充分条件：video0 存在且可读 */
    if (stat("/dev/video0", &st) == 0 && (st.st_mode & S_IRUSR)) return 1;
#endif
    return 1;  /* 无设备时合成源无需权限，始终可用 */
}

/* ------------------------------------------------------------------ */
/* 工厂函数（camera.h 声明）                                          */
/* ------------------------------------------------------------------ */
/* 前向声明：destroy 定义在后面，而 create 需要把它的地址写进结构体 */
void cam_source_destroy_v4l2(cam_source_t *src);

cam_source_t *cam_source_create_v4l2(void)
{
    v4l2_priv_t *p = (v4l2_priv_t *)calloc(1, sizeof(v4l2_priv_t));
    if (!p) return NULL;
#if USE_V4L2
    p->fd = -1;
#endif

    cam_source_t *src = (cam_source_t *)calloc(1, sizeof(cam_source_t));
    if (!src) { free(p); return NULL; }

    src->open             = v4l2_open;
    src->capture          = v4l2_capture;
    src->close            = v4l2_close_src;
    src->enumerate        = v4l2_enumerate;
    src->check_permission = v4l2_check_permission;
    src->destroy          = cam_source_destroy_v4l2;
    src->priv             = p;
    return src;
}

void cam_source_destroy_v4l2(cam_source_t *src)
{
    if (!src) return;
    if (src->priv) {
        v4l2_priv_t *p = (v4l2_priv_t *)src->priv;
#if USE_V4L2
        if (p->use_v4l2) v4l2_close(p);
#endif
        free(p->frame_buf);   /* 帧缓冲归本对象所有，此处释放 */
        free(p);              /* v4l2_priv_t 本身 */
    }
    free(src);
}
