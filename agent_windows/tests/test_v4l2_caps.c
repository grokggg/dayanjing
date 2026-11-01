/*
 * DAYANJING v4 — agent_windows/tests/test_v4l2_caps.c
 *
 * V4L2 设备能力判定单测。
 *
 * 为什么必须测这个：
 *   v4l2_eff_caps / v4l2_caps_ok 是"这颗设备到底能不能采"的唯一判据。
 *   判错的后果不是报错，而是静默降级到合成帧——上层看到"摄像头在线"，
 *   收到的却是棋盘格，全程零告警。这是采集链路最坏的失效形态。
 *   而沙盒无 /dev/video*，真设备永远测不到，判定逻辑只能这样测。
 *
 * 手法：直接 #include 源文件以触达 static 函数。
 *   不这么做就得为了可测而改生产代码的可见性，那是为测试污染设计。
 *
 * 判据来源：linux/videodev2.h —— device_caps 仅当 capabilities 带
 *   V4L2_CAP_DEVICE_CAPS 时有效（见该头文件对 struct v4l2_capability
 *   的注释）。
 */

#include "../src/cam_linux_v4l2.c"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/sysmacros.h>   /* makedev */

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, name)                                              \
    do {                                                               \
        checks++;                                                      \
        if (cond) { printf("[PASS] %s\n", (name)); }                   \
        else      { printf("[FAIL] %s\n", (name)); failures++; }        \
    } while (0)

static struct v4l2_capability mk(uint32_t capabilities, uint32_t device_caps)
{
    struct v4l2_capability c;
    memset(&c, 0, sizeof(c));
    c.capabilities = capabilities;
    c.device_caps  = device_caps;
    return c;
}

#define CAP_CAP   V4L2_CAP_VIDEO_CAPTURE
#define CAP_STR   V4L2_CAP_STREAMING
#define CAP_DEVC  V4L2_CAP_DEVICE_CAPS

int main(void)
{
    /* --- 1. 老驱动：不带 DEVICE_CAPS，能力只在 capabilities 里 ---
     * 旧实现无条件读 device_caps（此处为 0），会把一颗完好的摄像头判成
     * 不可用并静默降级。这是本测试最关键的一条。 */
    {
        struct v4l2_capability c = mk(CAP_CAP | CAP_STR, 0u);
        CHECK(v4l2_caps_ok(&c) == 1,
              "不带 DEVICE_CAPS 时须回落到 capabilities 判定（老驱动不得被误判）");
        CHECK(v4l2_eff_caps(&c) == (CAP_CAP | CAP_STR),
              "eff_caps 在无 DEVICE_CAPS 时等于 capabilities");
    }

    /* --- 2. 现代驱动：带 DEVICE_CAPS，须读 device_caps --- */
    {
        struct v4l2_capability c = mk(CAP_CAP | CAP_STR | CAP_DEVC,
                                      CAP_CAP | CAP_STR);
        CHECK(v4l2_caps_ok(&c) == 1, "带 DEVICE_CAPS 的正常采集设备须判可用");
        CHECK(v4l2_eff_caps(&c) == (CAP_CAP | CAP_STR),
              "eff_caps 在带 DEVICE_CAPS 时等于 device_caps");
    }

    /* --- 3. Intel IPU 之类的 metadata 节点：能 open，但不是采集设备 --- */
    {
        struct v4l2_capability c = mk(CAP_DEVC, 0u);
        CHECK(v4l2_caps_ok(&c) == 0, "DEVICE_CAPS 且 device_caps=0 须判不可用");
    }
    {
        struct v4l2_capability c = mk(CAP_DEVC | CAP_STR, CAP_STR);
        CHECK(v4l2_caps_ok(&c) == 0, "只有 STREAMING 没有 VIDEO_CAPTURE 须判不可用");
    }

    /* --- 4. 缺 STREAMING：只读设备不得被当成采集设备 --- */
    {
        struct v4l2_capability c = mk(CAP_CAP, 0u);
        CHECK(v4l2_caps_ok(&c) == 0, "无 STREAMING 须判不可用");
    }
    {
        struct v4l2_capability c = mk(CAP_CAP | CAP_DEVC, CAP_CAP);
        CHECK(v4l2_caps_ok(&c) == 0, "device_caps 缺 STREAMING 须判不可用");
    }

    /* --- 5. 全零：驱动什么都没填 --- */
    {
        struct v4l2_capability c = mk(0u, 0u);
        CHECK(v4l2_caps_ok(&c) == 0, "能力全零须判不可用");
    }

    /* --- 6. 探测不存在的节点：必须失败，不能当成"有设备" --- */
    CHECK(v4l2_probe_capture_dev("/dev/definitely-not-a-camera", NULL) != 0,
          "不存在的设备节点须探测失败");

    /* --- 7. 探测非字符设备（本文件自身是常规文件）--- */
    CHECK(v4l2_probe_capture_dev(__FILE__, NULL) != 0,
          "非字符设备须探测失败");

    /* --- 8. enumerate 必须真的探测，不能只 stat ---
     *
     * 构造一个"能 stat 到、能 open、但不是摄像头"的字符设备（major 1 minor 3，
     * 即 /dev/null 语义），逼 enumerate 在"节点存在"与"真是采集设备"之间做出
     * 正确区分。真实世界里对应 Intel IPU 的 metadata 节点——能 open，却没有
     * V4L2_CAP_VIDEO_CAPTURE。
     *
     * 安全前提：仅当本机 /dev/video0..7 一个都不存在时才建诱饵。有真摄像头的
     * 机器上不建、也就不会遮住真设备；建完立即 unlink。无 root 时 mknod 失败，
     * 记 SKIP 而非 FAIL——"没验证"不许冒充"验证通过"。 */
    {
        int any = 0;
        for (int i = 0; i < 8; i++) {
            char d[16]; snprintf(d, sizeof(d), "/dev/video%d", i);
            struct stat s0; if (stat(d, &s0) == 0) { any = 1; break; }
        }
        if (any) {
            printf("[SKIP] enumerate 诱饵：本机已有 /dev/video*，不建诱饵\n");
        } else if (mknod("/dev/video0", S_IFCHR | 0666, makedev(1, 3)) != 0) {
            printf("[SKIP] enumerate 诱饵：mknod 失败（需 root），errno=%d\n", errno);
        } else {
            cam_device_info_t info[8];
            memset(info, 0, sizeof(info));
            int n = v4l2_enumerate(info, 8);
            int listed = 0;
            for (int i = 0; i < n; i++) {
                /* 诱饵不是采集设备，绝不能出现在枚举结果里 */
                if (strncmp(info[i].device_id, "v4l2:/dev/video", 15) == 0) listed = 1;
            }
            CHECK(listed == 0,
                  "enumerate 不得把非采集设备的节点报成摄像头（须真探测而非只 stat）");
            unlink("/dev/video0");
        }
    }

    /* 计数动态输出，不写死数字：此前汇总里写死的 "10 pass" 与实际 11 条断言
     * 不符，正是本仓库反复出现的"记账与实现不符"。动态计数让这类漂移不可能。 */
    printf("=== result: %d pass, %d fail ===\n", checks - failures, failures);
    return failures ? 1 : 0;
}
