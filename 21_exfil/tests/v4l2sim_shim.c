/*
 * v4l2sim_shim.c — 用户态 V4L2 ABI 模拟器（LD_PRELOAD）
 *
 * 目的：让真实的 cam_linux_v4l2.c 代码流过完整的 V4L2 驱动交互序列，
 *       而不是只走 mock 合成帧降级分支。
 *
 * 沙盒里没有 /dev/video*，也没有 v4l2loopback 内核模块、没有 modprobe。
 * 但"验不了"的是真硬件，不是这段代码。真硬件的价值在于它会按 V4L2 ABI
 * 回应 ioctl —— 而这个回应可以在用户态精确复刻。
 *
 * 做法：
 *   - 建真实的字符设备节点（mknod c 81 0），让 stat() 的 S_ISCHR 判据通过
 *   - 拦截 open()：命中 /dev/videoN 时改为打开一个真实临时文件并返回其 fd，
 *     这样后续的 mmap() 是真 mmap、memcpy 是真 memcpy
 *   - 拦截 ioctl()：按 V4L2 ABI 回应 QUERYCAP/S_FMT/REQBUFS/QUERYBUF/
 *     QBUF/DQBUF/STREAMON/STREAMOFF
 *   - DQBUF 时把帧数据写进已映射区域（同进程地址空间，直接 memcpy）
 *
 * 这样被验证的是真实产品代码里的：ioctl 编号、结构体布局、格式协商回退、
 * 缓冲生命周期、帧长度解析、MJPEG 直通与 YUYV 转码两条路径。
 *
 * 环境变量：
 *   V4L2SIM_FMT   mjpeg | yuyv        默认 mjpeg
 *   V4L2SIM_W     宽                  默认 320
 *   V4L2SIM_H     高                  默认 240
 *   V4L2SIM_JPEG  MJPEG 模式下的 JPEG 源文件路径
 *   V4L2SIM_NODQBUF=1  让 DQBUF 返回 EAGAIN（模拟无帧）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/videodev2.h>
#include <dlfcn.h>

/* ioctl 编号与内核头文件实测一致：
 *   QUERYCAP 0x80685600  S_FMT 0xc0d05605  REQBUFS 0xc0145608
 *   QUERYBUF 0xc0585609  QBUF 0xc058560f   DQBUF 0xc0585611
 *   STREAMON 0x40045612  STREAMOFF 0x40045613 */

#define MAXFD 4096

typedef struct {
    int      used;
    int      real_fd;      /* 真实临时文件 fd */
    void    *map;          /* 目标进程看到的映射地址 */
    size_t   maplen;
    int      streaming;
    unsigned frame_no;
} simdev_t;

static simdev_t g_dev[MAXFD];
static int      g_init_done = 0;

static int   g_w = 320, g_h = 240;
static int   g_fmt_mjpeg = 1;
static const char *g_jpeg_path = NULL;
static unsigned char *g_jpeg = NULL;
static size_t g_jpeg_len = 0;
static int   g_no_dqbuf = 0;

/* 供守卫查询：真实代码走过的 ioctl 序列计数 */
int sim_count_querycap = 0, sim_count_sfmt = 0, sim_count_reqbufs = 0;
int sim_count_querybuf = 0, sim_count_qbuf = 0, sim_count_dqbuf = 0;
int sim_count_streamon = 0, sim_count_streamoff = 0;
int sim_count_mmap = 0, sim_count_munmap = 0;
int sim_sfmt_rejected = 0;   /* 让 S_FMT 失败一次，验证回退分支 */

static void sim_init(void)
{
    if (g_init_done) return;
    g_init_done = 1;

    const char *e;
    if ((e = getenv("V4L2SIM_FMT")) && strcmp(e, "yuyv") == 0) g_fmt_mjpeg = 0;
    if ((e = getenv("V4L2SIM_W"))) g_w = atoi(e);
    if ((e = getenv("V4L2SIM_H"))) g_h = atoi(e);
    if ((e = getenv("V4L2SIM_JPEG"))) g_jpeg_path = e;
    if ((e = getenv("V4L2SIM_NODQBUF"))) g_no_dqbuf = atoi(e);
    if ((e = getenv("V4L2SIM_SFMT_REJECT"))) sim_sfmt_rejected = atoi(e);

    if (g_w <= 0) g_w = 320;
    if (g_h <= 0) g_h = 240;

    if (g_fmt_mjpeg && g_jpeg_path) {
        FILE *f = fopen(g_jpeg_path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long n = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (n > 0) {
                g_jpeg = malloc((size_t)n);
                if (g_jpeg) g_jpeg_len = fread(g_jpeg, 1, (size_t)n, f);
            }
            fclose(f);
        }
    }
}

static size_t sim_frame_len(void)
{
    if (g_fmt_mjpeg) return g_jpeg_len ? g_jpeg_len : 4096;
    return (size_t)g_w * (size_t)g_h * 2;   /* YUYV422: 2 bytes/pixel */
}

/* 生成一帧。YUYV 模式下构造真实色彩图案（非全零），
 * 这样 cam_frame_to_jpeg 的转码结果可校验 */
static void sim_fill_frame(unsigned char *dst, size_t cap, unsigned n)
{
    if (g_fmt_mjpeg) {
        size_t n2 = g_jpeg_len ? g_jpeg_len : 0;
        if (n2 > cap) n2 = cap;
        if (n2) memcpy(dst, g_jpeg, n2);
        else if (cap >= 4) { dst[0]=0xFF; dst[1]=0xD8; dst[2]=0xFF; dst[3]=0xD9; }
        return;
    }
    size_t want = (size_t)g_w * (size_t)g_h * 2;
    if (want > cap) want = cap;
    for (size_t i = 0; i + 3 < want; i += 4) {
        unsigned x = (unsigned)((i / 2) % (unsigned)g_w);
        unsigned y = (unsigned)((i / 2) / (unsigned)g_w);
        unsigned char y0 = (unsigned char)((x + y + n) & 0xFF);
        unsigned char u  = (unsigned char)((x * 2) & 0xFF);
        unsigned char v  = (unsigned char)((y * 2) & 0xFF);
        dst[i + 0] = y0; dst[i + 1] = u;
        dst[i + 2] = y0; dst[i + 3] = v;
    }
}

/* ---- 拦截 open ---- */
static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_close)(int);
static int (*real_ioctl)(int, unsigned long, ...);
static void *(*real_mmap)(void *, size_t, int, int, int, off_t);
static int (*real_munmap)(void *, size_t);

static void bind_real(void)
{
    if (!real_open)      real_open     = (int(*)(const char*,int,...))dlsym(RTLD_NEXT, "open");
    if (!real_open64)    real_open64   = (int(*)(const char*,int,...))dlsym(RTLD_NEXT, "open64");
    if (!real_close)     real_close    = (int(*)(int))dlsym(RTLD_NEXT, "close");
    if (!real_ioctl)     real_ioctl    = (int(*)(int,unsigned long,...))dlsym(RTLD_NEXT, "ioctl");
    if (!real_mmap)      real_mmap     = (void*(*)(void*,size_t,int,int,int,off_t))dlsym(RTLD_NEXT, "mmap");
    if (!real_munmap)    real_munmap   = (int(*)(void*,size_t))dlsym(RTLD_NEXT, "munmap");
}

static int is_video_path(const char *p)
{
    if (!p) return 0;
    const char *s = strstr(p, "/dev/video");
    return s && (s == p || *(s - 1) == '/');
}

int open(const char *path, int flags, ...)
{
    bind_real(); sim_init();
    mode_t mode = 0;
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);

    if (is_video_path(path)) {
        /* 真实驱动不存在，改为打开一个 backing 文件：
         * 让后续 mmap 是真 mmap、memcpy 是真 memcpy */
        char tmpl[] = "/tmp/v4l2sim/backingXXXXXX";
        int fd = mkstemp(tmpl);
        if (fd < 0) { errno = ENODEV; return -1; }
        unlink(tmpl);
        if (ftruncate(fd, (off_t)sim_frame_len() + 8192) != 0) {
            real_close(fd); errno = ENODEV; return -1;
        }
        if (fd < MAXFD) {
            memset(&g_dev[fd], 0, sizeof(g_dev[fd]));
            g_dev[fd].used    = 1;
            g_dev[fd].real_fd = fd;
        }
        return fd;
    }
    return real_open(path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    bind_real(); sim_init();
    mode_t mode = 0;
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    if (is_video_path(path)) return open(path, flags, mode);
    return real_open64(path, flags, mode);
}

int close(int fd)
{
    bind_real();
    if (fd >= 0 && fd < MAXFD && g_dev[fd].used) {
        g_dev[fd].used = 0;
        g_dev[fd].map  = NULL;
    }
    return real_close(fd);
}

int ioctl(int fd, unsigned long request, ...)
{
    bind_real(); sim_init();
    va_list ap; va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    if (!(fd >= 0 && fd < MAXFD && g_dev[fd].used))
        return real_ioctl(fd, request, arg);

    simdev_t *d = &g_dev[fd];

    switch (request) {
    case VIDIOC_QUERYCAP: {
        sim_count_querycap++;
        struct v4l2_capability *c = (struct v4l2_capability *)arg;
        memset(c, 0, sizeof(*c));
        /* 必须同时具备 VIDEO_CAPTURE 与 STREAMING，否则 v4l2_caps_ok 判否 */
        c->capabilities = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;
        c->device_caps  = c->capabilities;
        snprintf((char *)c->card, sizeof(c->card), "v4l2sim");
        snprintf((char *)c->driver, sizeof(c->driver), "v4l2sim");
        snprintf((char *)c->bus_info, sizeof(c->bus_info), "platform:v4l2sim");
        return 0;
    }
    case VIDIOC_S_FMT: {
        sim_count_sfmt++;
        /* 首次拒绝首选格式，验证代码里的回退分支真的存在且生效 */
        if (sim_sfmt_rejected == 1) { sim_sfmt_rejected = 2; errno = EINVAL; return -1; }
        struct v4l2_format *f = (struct v4l2_format *)arg;
        if (f->type != V4L2_BUF_TYPE_VIDEO_CAPTURE) { errno = EINVAL; return -1; }
        uint32_t want = f->fmt.pix.pixelformat;
        /* 模拟真实摄像头：本设备只支持一种格式。
         * 若请求的不是本设备格式，驱动会改成自己支持的（真实 UVC 行为） */
        uint32_t got;
        if (g_fmt_mjpeg) got = V4L2_PIX_FMT_MJPEG;
        else             got = V4L2_PIX_FMT_YUYV;
        (void)want;
        f->fmt.pix.width       = (__u32)g_w;
        f->fmt.pix.height      = (__u32)g_h;
        f->fmt.pix.pixelformat = got;
        f->fmt.pix.field       = V4L2_FIELD_NONE;
        if (g_fmt_mjpeg) {
            f->fmt.pix.sizeimage = (__u32)(g_jpeg_len ? g_jpeg_len : 4096);
            f->fmt.pix.bytesperline = 0;
        } else {
            f->fmt.pix.bytesperline = (__u32)g_w * 2;
            f->fmt.pix.sizeimage    = (__u32)((size_t)g_w * (size_t)g_h * 2);
        }
        return 0;
    }
    case VIDIOC_REQBUFS: {
        sim_count_reqbufs++;
        struct v4l2_requestbuffers *r = (struct v4l2_requestbuffers *)arg;
        if (r->memory != V4L2_MEMORY_MMAP) { errno = EINVAL; return -1; }
        if (r->count < 1) { errno = EINVAL; return -1; }
        r->count = 1;
        return 0;
    }
    case VIDIOC_QUERYBUF: {
        sim_count_querybuf++;
        struct v4l2_buffer *b = (struct v4l2_buffer *)arg;
        if (b->index != 0) { errno = EINVAL; return -1; }
        b->memory     = V4L2_MEMORY_MMAP;
        b->length     = (__u32)sim_frame_len();
        b->m.offset   = 0;          /* 单缓冲，offset 0 */
        b->bytesused  = 0;
        b->flags      = 0;
        b->field      = V4L2_FIELD_NONE;
        return 0;
    }
    case VIDIOC_QBUF: {
        sim_count_qbuf++;
        struct v4l2_buffer *b = (struct v4l2_buffer *)arg;
        if (b->index != 0) { errno = EINVAL; return -1; }
        return 0;
    }
    case VIDIOC_DQBUF: {
        sim_count_dqbuf++;
        if (g_no_dqbuf) { errno = EAGAIN; return -1; }
        if (!d->streaming) { errno = EINVAL; return -1; }
        if (!d->map || d->maplen == 0) { errno = EINVAL; return -1; }
        /* 真实驱动：DQBUF 时缓冲区内已有一帧。这里把帧写进共享映射区，
         * 目标进程的 memcpy 会真的读到它 */
        sim_fill_frame((unsigned char *)d->map, d->maplen, d->frame_no);
        struct v4l2_buffer *b = (struct v4l2_buffer *)arg;
        b->index     = 0;
        b->bytesused = (__u32)sim_frame_len();
        b->length    = (__u32)sim_frame_len();
        b->flags     = 0;
        b->field     = V4L2_FIELD_NONE;
        d->frame_no++;
        return 0;
    }
    case VIDIOC_STREAMON: {
        sim_count_streamon++;
        d->streaming = 1;
        return 0;
    }
    case VIDIOC_STREAMOFF: {
        sim_count_streamoff++;
        d->streaming = 0;
        return 0;
    }
    default:
        errno = ENOTTY;
        return -1;
    }
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    bind_real(); sim_init();
    if (fd >= 0 && fd < MAXFD && g_dev[fd].used) {
        sim_count_mmap++;
        /* 真 mmap backing 文件：offset 归零（模拟器只有一块缓冲） */
        void *m = real_mmap(addr, len, prot, flags, g_dev[fd].real_fd, 0);
        if (m != MAP_FAILED) {
            g_dev[fd].map    = m;
            g_dev[fd].maplen = len;
        }
        (void)off;
        return m;
    }
    return real_mmap(addr, len, prot, flags, fd, off);
}

int munmap(void *addr, size_t len)
{
    bind_real();
    sim_count_munmap++;
    return real_munmap(addr, len);
}
