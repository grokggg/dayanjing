/*
 * DAYANJING v4 — 21_exfil/tests/v4l2_abi_probe.c
 *
 * V4L2 ABI 探针：按后端 agent_windows/src/cam_linux_v4l2.c 真设备分支
 * (USE_V4L2=1) 的调用序列，在用户态设备上完整走一遍 open → QUERYCAP →
 * S_FMT → REQBUFS → QUERYBUF → mmap → QBUF → STREAMON → DQBUF → 取帧。
 *
 * 验证的是内核 ABI 这一层：ioctl 命令号、结构体布局与大小、mmap 取帧
 * 语义。这些若与内核不一致，后端在真机上就是 ENOTTY / EINVAL / 段错误，
 * 而本沙盒没有摄像头，此前从未有任何东西验过它们。
 *
 * 输出 KEY=VALUE 行供 verify_v4l2_abi.py 断言。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/videodev2.h>

#define W 640
#define H 480

/* 后端 v4l2_eff_caps / v4l2_caps_ok 的镜像。
 * 说明：这是判据的镜像而非调用后端代码（后端 v4l2_try_open 要求 S_ISCHR，
 * 而 FUSE 无法提供可用字符设备，见 v4l2_simdev.c 头注）。
 * verify_v4l2_abi.py 另有静态断言，保证后端源码确实存在该判据，
 * 避免"镜像与实现脱钩后两边都绿"的恒绿风险。 */
static uint32_t eff_caps(const struct v4l2_capability *c)
{
    return (c->capabilities & V4L2_CAP_DEVICE_CAPS) ? c->device_caps : c->capabilities;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <dev>\n", argv[0]); return 2; }
    const char *dev = argv[1];

    printf("DEV=%s\n", dev);
    struct stat st;
    if (stat(dev, &st) != 0) { printf("OPEN=-1\n"); return 0; }
    printf("MODE_ISCHR=%d\n", S_ISCHR(st.st_mode) ? 1 : 0);

    int fd = open(dev, O_RDWR | O_NONBLOCK);
    if (fd < 0) { printf("OPEN=-1 errno=%d\n", errno); return 0; }
    printf("OPEN=0\n");

    struct v4l2_capability cap;
    memset(&cap, 0, sizeof(cap));
    if (ioctl(fd, VIDIOC_QUERYCAP, &cap) != 0) {
        printf("QUERYCAP=-1\n"); close(fd); return 0;
    }
    printf("QUERYCAP=0 driver=%s caps=%u devcaps=%u qcap_structsz=%zu\n",
           cap.driver, (unsigned)cap.capabilities, (unsigned)cap.device_caps,
           sizeof(cap));
    {
        uint32_t e = eff_caps(&cap);
        int ok = ((e & V4L2_CAP_VIDEO_CAPTURE) && (e & V4L2_CAP_STREAMING)) ? 1 : 0;
        printf("CAPS_OK=%d effcaps=%u\n", ok, e);
    }

    /* 首选 MJPEG —— 本设备刻意拒绝，验证"首选失败回退"分支的触发条件 */
    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = W; fmt.fmt.pix.height = H;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
    int r = ioctl(fd, VIDIOC_S_FMT, &fmt);
    printf("S_FMT_MJPEG_RC=%d errno=%d\n", r, r < 0 ? errno : 0);

    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = W; fmt.fmt.pix.height = H;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    if (ioctl(fd, VIDIOC_S_FMT, &fmt) != 0) {
        printf("S_FMT_YUYV=-1\n"); close(fd); return 0;
    }
    printf("S_FMT_YUYV=0 w=%u h=%u sizeimage=%u sfmt_structsz=%zu\n",
           fmt.fmt.pix.width, fmt.fmt.pix.height, fmt.fmt.pix.sizeimage, sizeof(fmt));

    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));
    req.count = 1; req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; req.memory = V4L2_MEMORY_MMAP;
    if (ioctl(fd, VIDIOC_REQBUFS, &req) != 0) {
        printf("REQBUFS=-1\n"); close(fd); return 0;
    }
    printf("REQBUFS=0 count=%u reqbufs_structsz=%zu\n", req.count, sizeof(req));

    struct v4l2_buffer buf;
    memset(&buf, 0, sizeof(buf));
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; buf.memory = V4L2_MEMORY_MMAP; buf.index = 0;
    if (ioctl(fd, VIDIOC_QUERYBUF, &buf) != 0) {
        printf("QUERYBUF=-1\n"); close(fd); return 0;
    }
    printf("QUERYBUF=0 length=%u offset=%u page_aligned=%d querybuf_structsz=%zu\n",
           buf.length, buf.m.offset, (buf.m.offset % 4096 == 0) ? 1 : 0, sizeof(buf));

    void *m = mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);
    if (m == MAP_FAILED) { printf("MMAP=-1 errno=%d\n", errno); close(fd); return 0; }
    printf("MMAP=0 length=%u\n", buf.length);

    if (ioctl(fd, VIDIOC_QBUF, &buf) != 0) { printf("QBUF=-1\n"); return 0; }
    printf("QBUF=0\n");
    int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &type) != 0) { printf("STREAMON=-1\n"); return 0; }
    printf("STREAMON=0\n");

    /* 取两帧：第二次用于确认设备确实在推进帧（frame_no 由守卫读状态文件） */
    for (int i = 0; i < 2; i++) {
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; buf.memory = V4L2_MEMORY_MMAP;
        if (ioctl(fd, VIDIOC_DQBUF, &buf) != 0) {
            printf("DQBUF%d=-1\n", i); return 0;
        }
        printf("DQBUF%d=0 bytesused=%u\n", i, buf.bytesused);
        ioctl(fd, VIDIOC_QBUF, &buf);
    }

    const unsigned char *p = (const unsigned char *)m;
    printf("PIX0=");
    for (int i = 0; i < 8; i++) printf("%02x", p[i]);
    printf("\n");
    printf("PIX100000=");
    for (int i = 0; i < 8; i++) printf("%02x", p[100000 + i]);
    printf("\n");
    {   /* 不同字节值种类：真图案应远大于 1，全零/单色填充会被这条抓住 */
        int seen[256]; memset(seen, 0, sizeof(seen)); int n = 0;
        for (size_t i = 0; i < buf.length; i += 7) {
            if (!seen[p[i]]) { seen[p[i]] = 1; n++; }
        }
        printf("PIXVARIETY=%d\n", n);
    }

    munmap(m, buf.length);
    close(fd);
    return 0;
}
