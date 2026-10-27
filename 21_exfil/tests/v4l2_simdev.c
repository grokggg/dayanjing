/*
 * DAYANJING v4 — 21_exfil/tests/v4l2_simdev.c
 *
 * 用户态 V4L2 采集设备（基于 FUSE）。
 *
 * 为什么需要它：
 *   沙盒没有 /dev/video*，也没有内核模块目录（无法 modprobe v4l2loopback），
 *   因此 agent_windows/src/cam_linux_v4l2.c 里 USE_V4L2=1 那条真设备分支
 *   ——open/ioctl/mmap/DQBUF——从未被执行过一次。几十轮以来跑的一直是
 *   USE_V4L2 下"找不到设备就降级合成帧"的那条路。
 *
 *   FUSE 能同时提供：字符设备语义（S_IFCHR，后端 stat 的 S_ISCHR 判据要求）、
 *   ioctl 转发（FUSE_IOCTL）、以及 mmap（走 FUSE page cache，读页触发
 *   FUSE_READ）。于是真设备分支可以被真正跑一遍，而不是靠推演。
 *
 * 它不是什么：
 *   - 不是真摄像头硬件。像素由本程序生成（SMPTE 彩条 + 移动方块）。
 *   - 不验证驱动行为、不验证 UVC 协议、不验证指示灯时序。
 *   它验证的是"后端这条代码路径在语义正确的设备上能正确走通"。
 *
 * 【已实证：为什么本设备默认是 S_IFREG 而不是 S_IFCHR】
 *   后端 v4l2_try_open 要求 stat() 满足 S_ISCHR，因此直觉上应该用 S_IFCHR。
 *   实测不行：FUSE 对 S_IFCHR / S_IFBLK / S_IFIFO / S_IFSOCK 的 inode 会走
 *   fuse_init_inode() 里的 init_special_inode()，把 i_fop 换成 def_chr_fops、
 *   i_rdev 设为 attr->rdev。于是 open() 根本不会发 FUSE_OPEN / FUSE_ACCESS，
 *   而是走 chrdev_open() 去找设备号（本设备 rdev=0，无对应驱动）——
 *   表现为 open: Permission denied，且服务端一个请求都收不到。
 *   实测对照：同一份服务端，mode 改 S_IFREG 后 open/ioctl/mmap 全部正常。
 *   因此"用 FUSE 造真字符设备"这条路是堵死的，不是没调对参数。
 *   CUSE 能造真字符设备，但 (a) 本环境无 libfuse3 开发头，无法编译；
 *   (b) 内核 fs/fuse/cuse.c 的 cuse_dev_operations 没有 .mmap，而后端
 *   必走 mmap 模式（read() 在现代 UVC 上返回 EINVAL），故 CUSE 亦不可行。
 *   加上无 /lib/modules、无 modprobe（装不了 v4l2loopback / vivid），
 *   三条路全堵 —— R1（真摄像头采集）在本沙盒是结构性不可验证的。
 *
 *   本文件因此默认提供 S_IFREG 节点（--reg 为默认），用于验证 R1b：
 *   后端真设备分支所依赖的全部内核 ABI（ioctl 命令号、结构体布局与大小、
 *   mmap 取帧、DQBUF 语义）确实正确。差的那一步只是 stat 的设备类型判据。
 *
 * 设备行为刻意做成"严格但合法"：
 *   - QUERYCAP 带 V4L2_CAP_DEVICE_CAPS，device_caps 才是有效字段
 *     （后端 v4l2_eff_caps 的判据；给错会静默降级成合成帧）
 *   - S_FMT 拒 MJPEG 返回 EINVAL，迫使后端走"首选失败回退 YUYV"分支
 *   - DQBUF 返回真实 bytesused 与 timestamp
 *   - 每一步都记进状态文件，供守卫断言完整序列确实执行
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <linux/fuse.h>
#include <linux/videodev2.h>

#define FRAME_W     640
#define FRAME_H     480
#define FRAME_BYTES ((size_t)FRAME_W * FRAME_H * 2)   /* YUYV422 */
#define FILE_SIZE   FRAME_BYTES

#define INO_VIDEO0  2
#define VID_MODE() (g_chr ? (uint32_t)(S_IFCHR | 0666) : (uint32_t)(S_IFREG | 0666))

static int      g_fd = -1;
static char     g_mnt[256];
static char     g_status[256];
static int      g_debug = 0;
static int      g_chr   = 0;   /* 1 = S_IFCHR（实测走不通，仅用于对照） */
static int      g_badoff = 0;  /* 反向注入：QUERYBUF 返回非页对齐 m.offset */
static int      g_nocaps = 0;  /* 反向注入：QUERYCAP 缺 DEVICE_CAPS / 采集能力 */
static uint64_t g_frame_no = 0;
static uint8_t *g_frame = NULL;

/* ioctl 计数，写入状态文件供守卫断言 */
static unsigned long g_n_querycap, g_n_sfmt_mjpeg, g_n_sfmt_yuyv,
                     g_n_reqbufs, g_n_querybuf, g_n_qbuf,
                     g_n_streamon, g_n_dqbuf, g_n_other;

static void do_cleanup(void)
{
    if (g_mnt[0]) umount2(g_mnt, MNT_DETACH);
}

static void on_sig(int s)
{
    (void)s;
    do_cleanup();
    _exit(0);
}

static void status_write(void)
{
    FILE *f = fopen(g_status, "w");
    if (!f) return;
    fprintf(f, "querycap=%lu\n", g_n_querycap);
    fprintf(f, "sfmt_mjpeg=%lu\n", g_n_sfmt_mjpeg);
    fprintf(f, "sfmt_yuyv=%lu\n", g_n_sfmt_yuyv);
    fprintf(f, "reqbufs=%lu\n", g_n_reqbufs);
    fprintf(f, "querybuf=%lu\n", g_n_querybuf);
    fprintf(f, "qbuf=%lu\n", g_n_qbuf);
    fprintf(f, "streamon=%lu\n", g_n_streamon);
    fprintf(f, "dqbuf=%lu\n", g_n_dqbuf);
    fprintf(f, "other=%lu\n", g_n_other);
    fprintf(f, "frame_no=%llu\n", (unsigned long long)g_frame_no);
    fprintf(f, "frame_bytes=%zu\n", FRAME_BYTES);
    fclose(f);
}

/* ---------------------------------------------------------------- */
/* 像素生成：SMPTE 彩条 + 随帧移动的方块                              */
/* 刻意与降级路径的"棋盘格"不同，守卫据此区分两条路径                 */
/* ---------------------------------------------------------------- */
static void gen_frame(uint64_t n)
{
    static const uint8_t bars[7][3] = {
        {235,128,128}, {219,16,138}, {188,154,16}, {150,44,54},
        {106,202,222}, {81,90,240},  {41,240,110}
    };
    int bx = (int)((n * 37) % (unsigned)(FRAME_W - 64));
    int by = (int)((n * 23) % (unsigned)(FRAME_H - 64));

    for (int y = 0; y < FRAME_H; y++) {
        size_t row = (size_t)y * FRAME_W * 2;
        for (int x = 0; x < FRAME_W; x += 2) {
            const uint8_t *c = bars[(x * 7) / FRAME_W];
            uint8_t Y = c[0], U = c[1], V = c[2];
            /* 移动方块：纯白块，且在块内叠加帧号低 8 位的行扰动 */
            if (y >= by && y < by + 64 && x >= bx && x < bx + 64) {
                Y = 210 + (uint8_t)(n & 0x1f);
                U = 128; V = 128;
            }
            g_frame[row + (size_t)x * 2 + 0] = Y;
            g_frame[row + (size_t)x * 2 + 1] = U;
            g_frame[row + (size_t)x * 2 + 2] = Y;
            g_frame[row + (size_t)x * 2 + 3] = V;
        }
    }
}

/* ---------------------------------------------------------------- */
/* FUSE 回复 helpers                                                  */
/* ---------------------------------------------------------------- */
static void reply_err(uint64_t unique, int err)
{
    struct fuse_out_header h;
    memset(&h, 0, sizeof(h));
    h.len = sizeof(h);
    h.error = -err;
    h.unique = unique;
    ssize_t r = write(g_fd, &h, sizeof(h));
    (void)r;
}

static void reply_bytes(uint64_t unique, const void *p, size_t n)
{
    struct fuse_out_header h;
    memset(&h, 0, sizeof(h));
    h.len = sizeof(h) + n;
    h.unique = unique;
    struct iovec v[2];
    v[0].iov_base = &h; v[0].iov_len = sizeof(h);
    v[1].iov_base = (void *)p; v[1].iov_len = n;
    ssize_t r = writev(g_fd, v, 2);
    (void)r;
}

static void fill_attr(struct fuse_attr *a, uint64_t ino, uint64_t size, uint32_t mode)
{
    memset(a, 0, sizeof(*a));
    a->ino = ino;
    a->size = size;
    a->blocks = (size + 511) / 512;
    a->atime = a->mtime = a->ctime = (uint64_t)time(NULL);
    a->atimensec = a->mtimensec = a->ctimensec = 0;
    a->mode = mode;
    a->nlink = 1;
    a->uid = 0;
    a->gid = 0;
    a->rdev = 0;
    a->blksize = 4096;
}

/* ---------------------------------------------------------------- */
/* ioctl 分派                                                         */
/* 返回：ioctl 的返回值（>=0 成功，<0 为 -errno）；out 写入 outbuf     */
/* ---------------------------------------------------------------- */
static int v4l2_ioctl(unsigned int cmd, const void *inbuf, uint32_t insz,
                      void *outbuf, uint32_t outsz, uint32_t *out_len)
{
    (void)insz;
    *out_len = 0;

    if (_IOC_TYPE(cmd) != 'V') { g_n_other++; return -ENOTTY; }

    switch (_IOC_NR(cmd)) {
    case 0: { /* VIDIOC_QUERYCAP */
        g_n_querycap++;
        struct v4l2_capability cap;
        memset(&cap, 0, sizeof(cap));
        snprintf((char *)cap.driver, sizeof(cap.driver), "v4l2sim");
        snprintf((char *)cap.card, sizeof(cap.card), "sim capture");
        snprintf((char *)cap.bus_info, sizeof(cap.bus_info), "fuse:0");
        cap.version = 0x00060000;
        /* 关键：带 DEVICE_CAPS，后端据此读 device_caps 而非 capabilities */
        if (g_nocaps) {
            /* 反向注入：老驱动形态 —— 不带 DEVICE_CAPS，且能力位不含采集。
             * 后端 v4l2_eff_caps 在无该标志时读 capabilities，应判为不可用，
             * 静默降级成合成帧。守卫据此验证该判据真的被验到。 */
            cap.capabilities = V4L2_CAP_READWRITE;   /* 无 CAPTURE、无 DEVICE_CAPS */
            cap.device_caps  = 0;
        } else {
            cap.capabilities = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING
                             | V4L2_CAP_DEVICE_CAPS;
            cap.device_caps  = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;
        }
        if (outsz < sizeof(cap)) return -EINVAL;
        memcpy(outbuf, &cap, sizeof(cap));
        *out_len = sizeof(cap);
        return 0;
    }
    case 5: { /* VIDIOC_S_FMT */
        const struct v4l2_format *f = (const struct v4l2_format *)inbuf;
        uint32_t pf = f->fmt.pix.pixelformat;
        struct v4l2_format o;
        memcpy(&o, f, sizeof(o));
        if (pf == V4L2_PIX_FMT_MJPEG) {
            /* 刻意为难：不接受 MJPEG，迫使后端走"首选失败回退 YUYV" */
            g_n_sfmt_mjpeg++;
            return -EINVAL;
        }
        if (pf != V4L2_PIX_FMT_YUYV) return -EINVAL;
        g_n_sfmt_yuyv++;
        o.fmt.pix.width = (o.fmt.pix.width > 1920) ? 1920 : o.fmt.pix.width;
        o.fmt.pix.height = (o.fmt.pix.height > 1080) ? 1080 : o.fmt.pix.height;
        if (!o.fmt.pix.width)  o.fmt.pix.width = FRAME_W;
        if (!o.fmt.pix.height) o.fmt.pix.height = FRAME_H;
        o.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
        o.fmt.pix.field = V4L2_FIELD_NONE;
        o.fmt.pix.bytesperline = o.fmt.pix.width * 2;
        o.fmt.pix.sizeimage = (uint32_t)FRAME_BYTES;
        if (outsz < sizeof(o)) return -EINVAL;
        memcpy(outbuf, &o, sizeof(o));
        *out_len = sizeof(o);
        return 0;
    }
    case 8: { /* VIDIOC_REQBUFS */
        g_n_reqbufs++;
        struct v4l2_requestbuffers o;
        const struct v4l2_requestbuffers *r = (const struct v4l2_requestbuffers *)inbuf;
        memcpy(&o, r, sizeof(o));
        if (o.memory != V4L2_MEMORY_MMAP) return -EINVAL;
        o.count = 1;
        if (outsz < sizeof(o)) return -EINVAL;
        memcpy(outbuf, &o, sizeof(o));
        *out_len = sizeof(o);
        return 0;
    }
    case 9: { /* VIDIOC_QUERYBUF */
        g_n_querybuf++;
        struct v4l2_buffer o;
        const struct v4l2_buffer *b = (const struct v4l2_buffer *)inbuf;
        memcpy(&o, b, sizeof(o));
        o.index = 0;
        o.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        o.memory = V4L2_MEMORY_MMAP;
        o.length = (uint32_t)FRAME_BYTES;
        o.m.offset = g_badoff ? 100u : 0u;   /* 反向注入：非页对齐 → mmap 必失败 */
        o.bytesused = 0;
        o.flags = 0;
        if (outsz < sizeof(o)) return -EINVAL;
        memcpy(outbuf, &o, sizeof(o));
        *out_len = sizeof(o);
        return 0;
    }
    case 15: { /* VIDIOC_QBUF */
        g_n_qbuf++;
        struct v4l2_buffer o;
        const struct v4l2_buffer *b = (const struct v4l2_buffer *)inbuf;
        memcpy(&o, b, sizeof(o));
        if (outsz < sizeof(o)) return -EINVAL;
        memcpy(outbuf, &o, sizeof(o));
        *out_len = sizeof(o);
        return 0;
    }
    case 17: { /* VIDIOC_DQBUF */
        g_n_dqbuf++;
        struct v4l2_buffer o;
        const struct v4l2_buffer *b = (const struct v4l2_buffer *)inbuf;
        memcpy(&o, b, sizeof(o));
        /* 每次取帧推进图案，证明帧是真的在流 */
        gen_frame(g_frame_no++);
        status_write();
        o.index = 0;
        o.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        o.bytesused = (uint32_t)FRAME_BYTES;
        o.length = (uint32_t)FRAME_BYTES;
        o.flags = V4L2_BUF_FLAG_DONE;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        o.timestamp.tv_sec = ts.tv_sec;
        o.timestamp.tv_usec = ts.tv_nsec / 1000;
        if (outsz < sizeof(o)) return -EINVAL;
        memcpy(outbuf, &o, sizeof(o));
        *out_len = sizeof(o);
        return 0;
    }
    case 18: { /* VIDIOC_STREAMON */
        g_n_streamon++;
        return 0;
    }
    case 19: { /* VIDIOC_STREAMOFF */
        return 0;
    }
    default:
        g_n_other++;
        return -ENOTTY;
    }
}

/* ---------------------------------------------------------------- */
static void handle_ioctl(struct fuse_in_header *ih, void *payload)
{
    struct fuse_ioctl_in *ii = (struct fuse_ioctl_in *)payload;
    const void *indata = (const uint8_t *)payload + sizeof(*ii);

    uint8_t outbuf[4096];
    uint32_t out_len = 0;
    int rc = v4l2_ioctl(ii->cmd, indata, ii->in_size, outbuf,
                        ii->out_size > sizeof(outbuf) ? sizeof(outbuf) : ii->out_size,
                        &out_len);

    if (g_debug)
        fprintf(stderr, "[sim] ioctl cmd=0x%x type=%c nr=%d insz=%u outsz=%u -> rc=%d outlen=%u\n",
                ii->cmd, (char)_IOC_TYPE(ii->cmd), _IOC_NR(ii->cmd),
                ii->in_size, ii->out_size, rc, out_len);

    struct fuse_out_header h;
    struct fuse_ioctl_out o;
    memset(&h, 0, sizeof(h));
    memset(&o, 0, sizeof(o));
    o.result = rc;
    o.flags = FUSE_IOCTL_UNRESTRICTED;
    o.in_iovs = 0;
    o.out_iovs = out_len ? 1 : 0;

    h.unique = ih->unique;
    h.len = sizeof(h) + sizeof(o) + (rc >= 0 ? out_len : 0);

    struct iovec v[3];
    int nv = 2;
    v[0].iov_base = &h; v[0].iov_len = sizeof(h);
    v[1].iov_base = &o; v[1].iov_len = sizeof(o);
    if (rc >= 0 && out_len) { v[2].iov_base = outbuf; v[2].iov_len = out_len; nv = 3; }
    ssize_t w = writev(g_fd, v, nv);
    (void)w;
}

/* ---------------------------------------------------------------- */
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <mountpoint> <statusfile> [--debug] [--chr]\n", argv[0]);
        return 2;
    }
    snprintf(g_mnt, sizeof(g_mnt), "%s", argv[1]);
    snprintf(g_status, sizeof(g_status), "%s", argv[2]);
    for (int i = 3; i < argc; i++)
        if (!strcmp(argv[i], "--debug")) g_debug = 1;
        else if (!strcmp(argv[i], "--chr")) g_chr = 1;
        else if (!strcmp(argv[i], "--bad-offset")) g_badoff = 1;
        else if (!strcmp(argv[i], "--no-devcaps")) g_nocaps = 1;

    g_frame = (uint8_t *)malloc(FRAME_BYTES);
    if (!g_frame) return 2;
    gen_frame(0);

    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    g_fd = open("/dev/fuse", O_RDWR);
    if (g_fd < 0) { perror("open /dev/fuse"); return 2; }

    char opts[256];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=%o,user_id=%u,group_id=%u",
             g_fd, S_IFDIR, getuid(), getgid());
    if (mount("/dev/fuse", g_mnt, "fuse", MS_NOSUID | MS_NODEV, opts) != 0) {
        perror("mount fuse");
        return 2;
    }

    status_write();

    uint8_t buf[1024 * 1024];
    for (;;) {
        ssize_t n = read(g_fd, buf, sizeof(buf));
        if (n <= 0) break;
        if ((size_t)n < sizeof(struct fuse_in_header)) continue;
        struct fuse_in_header *ih = (struct fuse_in_header *)buf;
        void *payload = buf + sizeof(*ih);

        switch (ih->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out o;
            memset(&o, 0, sizeof(o));
            o.major = 7;
            o.minor = 31;
            o.max_readahead = 131072;
            o.flags = FUSE_ASYNC_READ | FUSE_BIG_WRITES;
            o.max_background = 16;
            o.congestion_threshold = 12;
            o.max_write = 131072;
            o.max_pages = 32;
            reply_bytes(ih->unique, &o, sizeof(o));
            break;
        }
        case FUSE_STATFS: {
            struct fuse_statfs_out o;
            memset(&o, 0, sizeof(o));
            o.st.blocks = 0; o.st.bfree = 0; o.st.bavail = 0;
            o.st.files = 2; o.st.ffree = 0;
            o.st.bsize = 4096; o.st.namelen = 255;
            o.st.frsize = 4096;
            reply_bytes(ih->unique, &o, sizeof(o));
            break;
        }
        case FUSE_LOOKUP: {
            /* payload = name */
            const char *name = (const char *)payload;
            if (strcmp(name, "video0")) { reply_err(ih->unique, ENOENT); break; }
            struct fuse_entry_out o;
            memset(&o, 0, sizeof(o));
            o.nodeid = INO_VIDEO0;
            o.generation = 1;
            o.entry_valid = 10; o.attr_valid = 10;
            /* 关键：S_IFCHR —— 后端 stat 的 S_ISCHR 判据 */
            fill_attr(&o.attr, INO_VIDEO0, FILE_SIZE, VID_MODE());
            reply_bytes(ih->unique, &o, sizeof(o));
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out o;
            memset(&o, 0, sizeof(o));
            o.attr_valid = 10;
            uint64_t ino = ih->nodeid;
            uint64_t sz = (ino == INO_VIDEO0) ? FILE_SIZE : 4096;
            uint32_t mode = (ino == INO_VIDEO0) ? VID_MODE() : (uint32_t)(S_IFDIR | 0755);
            fill_attr(&o.attr, ino, sz, mode);
            reply_bytes(ih->unique, &o, sizeof(o));
            break;
        }
        case FUSE_SETATTR: {
            struct fuse_attr_out o;
            memset(&o, 0, sizeof(o));
            o.attr_valid = 10;
            uint64_t ino = ih->nodeid;
            uint64_t sz = (ino == INO_VIDEO0) ? FILE_SIZE : 4096;
            uint32_t mode = (ino == INO_VIDEO0) ? VID_MODE() : (uint32_t)(S_IFDIR | 0755);
            fill_attr(&o.attr, ino, sz, mode);
            reply_bytes(ih->unique, &o, sizeof(o));
            break;
        }
        case FUSE_OPEN: {
            struct fuse_open_out o;
            memset(&o, 0, sizeof(o));
            o.fh = 1;
            o.open_flags = 0;
            reply_bytes(ih->unique, &o, sizeof(o));
            break;
        }
        case FUSE_READ: {
            struct fuse_read_in *r = (struct fuse_read_in *)payload;
            size_t off = (size_t)r->offset;
            size_t len = r->size;
            if (off >= FILE_SIZE) len = 0;
            else if (off + len > FILE_SIZE) len = FILE_SIZE - off;
            uint8_t tmp[131072];
            if (len > sizeof(tmp)) len = sizeof(tmp);
            memcpy(tmp, g_frame + off, len);
            reply_bytes(ih->unique, tmp, len);
            break;
        }
        case FUSE_IOCTL:
            handle_ioctl(ih, payload);
            break;
        case FUSE_ACCESS:
            /* 内核在 open 前发 ACCESS 查权限。不回复成功会让 open 直接 EPERM，
             * 症状是"打不开设备"，排查方向完全不会指向服务端。 */
            reply_bytes(ih->unique, NULL, 0);
            break;
        case FUSE_RELEASE:
        case FUSE_FLUSH:
        case FUSE_OPENDIR:
        case FUSE_RELEASEDIR: {
            struct fuse_open_out o;
            memset(&o, 0, sizeof(o));
            o.fh = 1;
            reply_bytes(ih->unique, &o, sizeof(o));
            break;
        }
        case FUSE_READDIR:
        case FUSE_READDIRPLUS:
            reply_bytes(ih->unique, NULL, 0);
            break;
        default:
            if (g_debug) fprintf(stderr, "[sim] unhandled opcode=%u\n", ih->opcode);
            reply_err(ih->unique, ENOSYS);
            break;
        }
    }

    do_cleanup();
    return 0;
}
