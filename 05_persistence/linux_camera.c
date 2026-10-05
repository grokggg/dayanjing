/*
 * Linux Camera Capture - V4L2
 *
 * 从第一性原理实现：直接使用 V4L2 API 捕获摄像头帧
 * 不依赖任何第三方库（除 libv4l2 标准系统库）
 *
 * 编译: gcc -O2 -Wall -s linux_camera.c -o camera_capture -lv4l2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/videodev2.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#define CLEAR(x) memset(&(x), 0, sizeof(x))

struct buffer {
    void* start;
    size_t length;
};

static struct buffer* buffers = NULL;
static unsigned int n_buffers = 0;
static int fd = -1;
static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

int xioctl(int fh, unsigned long request, void* arg) {
    int r;
    do {
        r = ioctl(fh, request, arg);
    } while (r == -1 && errno == EINTR);
    return r;
}

int find_camera_device() {
    char path[32];
    struct v4l2_capability cap;

    for (int i = 0; i < 10; i++) {
        snprintf(path, sizeof(path), "/dev/video%d", i);
        int test_fd = open(path, O_RDWR | O_NONBLOCK);
        if (test_fd < 0) continue;

        if (xioctl(test_fd, VIDIOC_QUERYCAP, &cap) == 0) {
            if (cap.device_caps & V4L2_CAP_VIDEO_CAPTURE) {
                printf("[+] Found camera: %s (%s)\n", path, cap.card);
                close(test_fd);
                return i;
            }
        }
        close(test_fd);
    }
    return -1;
}

int init_camera(int dev_id, int width, int height) {
    char path[32];
    snprintf(path, sizeof(path), "/dev/video%d", dev_id);

    fd = open(path, O_RDWR | O_NONBLOCK, 0);
    if (fd < 0) {
        perror("[-] open");
        return -1;
    }

    struct v4l2_capability cap;
    if (xioctl(fd, VIDIOC_QUERYCAP, &cap) < 0) {
        perror("[-] VIDIOC_QUERYCAP");
        return -1;
    }

    if (!(cap.device_caps & V4L2_CAP_VIDEO_CAPTURE)) {
        printf("[-] Device is not a video capture device\n");
        return -1;
    }

    // 设置格式
    struct v4l2_format fmt;
    CLEAR(fmt);
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = width;
    fmt.fmt.pix.height = height;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;

    if (xioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
        // 尝试 YUYV 格式
        fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
        if (xioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
            perror("[-] VIDIOC_S_FMT");
            return -1;
        }
        printf("[*] Using YUYV format\n");
    } else {
        printf("[*] Using MJPEG format\n");
    }

    printf("[+] Resolution: %dx%d\n", fmt.fmt.pix.width, fmt.fmt.pix.height);

    // 请求缓冲区
    struct v4l2_requestbuffers req;
    CLEAR(req);
    req.count = 4;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (xioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
        perror("[-] VIDIOC_REQBUFS");
        return -1;
    }

    if (req.count < 2) {
        printf("[-] Insufficient buffer memory\n");
        return -1;
    }

    buffers = calloc(req.count, sizeof(*buffers));
    if (!buffers) {
        perror("[-] calloc");
        return -1;
    }

    for (n_buffers = 0; n_buffers < req.count; n_buffers++) {
        struct v4l2_buffer buf;
        CLEAR(buf);

        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = n_buffers;

        if (xioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
            perror("[-] VIDIOC_QUERYBUF");
            return -1;
        }

        buffers[n_buffers].length = buf.length;
        buffers[n_buffers].start = mmap(
            NULL, buf.length,
            PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, buf.m.offset
        );

        if (MAP_FAILED == buffers[n_buffers].start) {
            perror("[-] mmap");
            return -1;
        }
    }

    // 将缓冲区加入队列
    for (unsigned int i = 0; i < n_buffers; i++) {
        struct v4l2_buffer buf;
        CLEAR(buf);
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        if (xioctl(fd, VIDIOC_QBUF, &buf) < 0) {
            perror("[-] VIDIOC_QBUF");
            return -1;
        }
    }

    // 启动流
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(fd, VIDIOC_STREAMON, &type) < 0) {
        perror("[-] VIDIOC_STREAMON");
        return -1;
    }

    printf("[+] Camera initialized and streaming\n");
    return 0;
}

int capture_frame(const char* output_dir) {
    fd_set fds;
    struct timeval tv;
    int r;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    tv.tv_sec = 5;
    tv.tv_usec = 0;

    r = select(fd + 1, &fds, NULL, NULL, &tv);
    if (r == -1) {
        if (errno == EINTR) return 0;
        perror("[-] select");
        return -1;
    }
    if (r == 0) {
        printf("[-] Timeout waiting for frame\n");
        return -1;
    }

    struct v4l2_buffer buf;
    CLEAN(buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;

    if (xioctl(fd, VIDIOC_DQBUF, &buf) < 0) {
        perror("[-] VIDIOC_DQBUF");
        return -1;
    }

    // 生成文件名
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char filename[256];
    snprintf(filename, sizeof(filename),
             "%s/cap_%04d%02d%02d_%02d%02d%02d_%ld.jpg",
             output_dir,
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             (long)getpid());

    // 写入文件
    FILE* fp = fopen(filename, "wb");
    if (fp) {
        fwrite(buffers[buf.index].start, buf.bytesused, 1, fp);
        fclose(fp);
        printf("[+] Saved: %s (%d bytes)\n", filename, buf.bytesused);
    }

    // 重新入队
    if (xioctl(fd, VIDIOC_QBUF, &buf) < 0) {
        perror("[-] VIDIOC_QBUF");
        return -1;
    }

    return 0;
}

void cleanup() {
    if (fd >= 0) {
        enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        ioctl(fd, VIDIOC_STREAMOFF, &type);

        for (unsigned int i = 0; i < n_buffers; i++) {
            if (buffers[i].start != MAP_FAILED) {
                munmap(buffers[i].start, buffers[i].length);
            }
        }
        free(buffers);
        close(fd);
    }
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    setsid();

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    chdir("/");
    umask(0);

    close(0);
    close(1);
    close(2);
}

int main(int argc, char* argv[]) {
    printf("=== Linux Camera Capture (V4L2) ===\n\n");

    int width = 640;
    int height = 480;
    const char* output_dir = "/var/tmp/.cache";
    int daemon = 0;
    int interval = 5;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            width = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            height = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            daemon = 1;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interval = atoi(argv[++i]);
        }
    }

    mkdir(output_dir, 0700);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (daemon) {
        daemonize();
    }

    int dev_id = find_camera_device();
    if (dev_id < 0) {
        printf("[-] No camera found\n");
        return 1;
    }

    if (init_camera(dev_id, width, height) < 0) {
        return 1;
    }

    while (running) {
        if (capture_frame(output_dir) < 0) {
            // 重试
            sleep(1);
            continue;
        }
        sleep(interval);
    }

    cleanup();
    printf("[+] Capture stopped\n");
    return 0;
}
