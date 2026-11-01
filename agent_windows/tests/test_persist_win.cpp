/*
 * agent_windows/tests/test_persist_win.cpp
 *
 * G2：Windows 持久化「真实安装」验证。
 *
 * 核心判据：用 wsdk_reg_has / wsdk_reg_get 独立读取有状态注册表 mock，
 * 验证值是否真的被写入。
 *
 * 为什么不能只断言 pw_query 返回成功：无状态 mock 下 install 之后 query
 * 恒成功，测试全绿但实际什么都没装。这是本模块最危险的假阳性，
 * 必须用独立的读回路径堵住。
 */
#include <windows.h>

#include <cstdio>
#include <cstring>

#include "persist_win.h"
#include "wsdk_test.h"

static int g_pass = 0, g_fail = 0;

#define CHECK(c, m) do {                        \
    if (c) { printf("[PASS] %s\n", (m)); g_pass++; } \
    else   { printf("[FAIL] %s\n", (m)); g_fail++; } \
} while (0)

#define RUN_PATH "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

/* ---- exec 回调 mock：记录命令行，可控返回值 ---- */
static char g_last_cmd[8192];
static int  g_exec_calls;
static int  g_exec_ret;

static int exec_mock(const char *cmd, void *ud)
{
    (void)ud;
    g_exec_calls++;
    snprintf(g_last_cmd, sizeof(g_last_cmd), "%s", cmd);
    return g_exec_ret;
}

static void reset_exec(int ret)
{
    g_exec_calls = 0;
    g_exec_ret   = ret;
    g_last_cmd[0] = 0;
}

/* ------------------------------------------------------------------ */

static void t_reg_install(void)
{
    char val[512];
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    wsdk_reg_reset();

    c.name    = "OneDriveSyncUpdater";
    c.cmdline = "C:\\Users\\Public\\svc.exe --run";

    CHECK(pw_install(PW_REG_RUN, &c) == PW_OK, "REG_RUN 安装返回 OK");
    CHECK(wsdk_reg_has(RUN_PATH, "OneDriveSyncUpdater"),
          "注册表值真的写进去了（独立读回验证）");
    CHECK(wsdk_reg_get(RUN_PATH, "OneDriveSyncUpdater", val, sizeof(val)),
          "能读回值内容");
    CHECK(strcmp(val, c.cmdline) == 0, "值内容 == 命令行（未被包装/破坏）");
}

static void t_reg_query_uninstall(void)
{
    int inst = -1;
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    wsdk_reg_reset();

    c.name    = "OneDriveSyncUpdater";
    c.cmdline = "svc.exe";

    CHECK(pw_query(PW_REG_RUN, &c, &inst) == PW_OK && inst == 0,
          "安装前 query 返回未安装");
    CHECK(pw_install(PW_REG_RUN, &c) == PW_OK, "安装 OK");
    CHECK(pw_query(PW_REG_RUN, &c, &inst) == PW_OK && inst == 1,
          "安装后 query 返回已安装");
    CHECK(pw_uninstall(PW_REG_RUN, &c) == PW_OK, "卸载 OK");
    CHECK(!wsdk_reg_has(RUN_PATH, "OneDriveSyncUpdater"),
          "卸载后值真的没了（独立读回验证）");
    CHECK(pw_query(PW_REG_RUN, &c, &inst) == PW_OK && inst == 0,
          "卸载后 query 返回未安装");
}

static void t_reg_idempotent(void)
{
    int inst = -1;
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    wsdk_reg_reset();

    c.name    = "NeverInstalled";
    c.cmdline = "x.exe";

    /* 幂等清理：已干净时不应报错，否则会中断上层清理流程并产生可观测失败 */
    CHECK(pw_uninstall(PW_REG_RUN, &c) == PW_OK,
          "卸载不存在的项返回 OK（幂等清理）");
    CHECK(pw_query(PW_REG_RUN, &c, &inst) == PW_OK && inst == 0,
          "未安装项 query 返回 0");
}

static void t_reg_overwrite(void)
{
    char val[512];
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    wsdk_reg_reset();

    c.name    = "N";
    c.cmdline = "old.exe";
    pw_install(PW_REG_RUN, &c);

    c.cmdline = "new.exe";
    CHECK(pw_install(PW_REG_RUN, &c) == PW_OK, "重复安装返回 OK（幂等）");
    wsdk_reg_get(RUN_PATH, "N", val, sizeof(val));
    CHECK(strcmp(val, "new.exe") == 0, "值被覆盖为最新命令行");
}

static void t_name_validation(void)
{
    char big[PW_NAME_MAX + 8];
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    wsdk_reg_reset();

    c.cmdline = "app.exe";

    c.name = "";
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_NAME, "空名被拒");
    c.name = "bad\\name";
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_NAME, "含反斜杠的名被拒");
    c.name = "bad/name";
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_NAME, "含斜杠的名被拒");
    c.name = "bad:name";
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_NAME, "含冒号的名被拒");
    c.name = "bad\x01name";
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_NAME, "含控制字符的名被拒");

    memset(big, 'A', sizeof(big));
    big[PW_NAME_MAX + 1] = 0;
    c.name = big;
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_NAME, "超长名被拒");
}

static void t_cmd_validation(void)
{
    char big[PW_CMD_MAX + 8];
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    wsdk_reg_reset();

    c.name = "Ok";
    c.cmdline = "";
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_CMD, "空命令行被拒");

    memset(big, 'B', sizeof(big));
    big[PW_CMD_MAX + 1] = 0;
    c.cmdline = big;
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_CMD, "超长命令行被拒");
}

static void t_schtask(void)
{
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    reset_exec(0);

    c.name    = "AdobeARM";
    c.cmdline = "C:\\Program Files\\Common Files\\svc.exe";
    c.exec    = exec_mock;

    CHECK(pw_install(PW_SCHTASK, &c) == PW_OK, "SCHTASK 安装返回 OK");
    CHECK(g_exec_calls == 1, "exec 回调被调用一次");
    CHECK(strstr(g_last_cmd, "schtasks /create") != NULL, "命令含 schtasks /create");
    CHECK(strstr(g_last_cmd, "/tn \"AdobeARM\"") != NULL, "任务名正确");
    CHECK(strstr(g_last_cmd, "/sc onlogon") != NULL, "触发方式为 onlogon");
    CHECK(strstr(g_last_cmd, "/f") != NULL, "带 /f 覆盖已存在项");
    /* 含空格的命令行必须整体引号包裹，否则 schtasks 解析歧义导致失败 */
    CHECK(strstr(g_last_cmd, "\"\"C:\\Program Files") != NULL,
          "含空格命令行被引号包裹");

    /* 无空格时不额外加引号 */
    reset_exec(0);
    c.cmdline = "C:\\simple.exe";
    CHECK(pw_install(PW_SCHTASK, &c) == PW_OK, "无空格命令行安装 OK");
    CHECK(strstr(g_last_cmd, "/tr \"C:\\simple.exe\"") != NULL,
          "无空格命令行不额外加引号");

    /* 卸载命令 */
    reset_exec(0);
    CHECK(pw_uninstall(PW_SCHTASK, &c) == PW_OK, "SCHTASK 卸载 OK");
    CHECK(strstr(g_last_cmd, "schtasks /delete") != NULL, "卸载命令含 /delete");
    CHECK(strstr(g_last_cmd, "/tn \"AdobeARM\"") != NULL, "卸载任务名正确");
}

static void t_schtask_query(void)
{
    int inst = -1;
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.name    = "AdobeARM";
    c.cmdline = "x.exe";
    c.exec    = exec_mock;

    reset_exec(0);
    CHECK(pw_query(PW_SCHTASK, &c, &inst) == PW_OK && inst == 1,
          "exec 成功视为已安装");
    CHECK(strstr(g_last_cmd, "schtasks /query") != NULL, "查询命令含 /query");

    reset_exec(1);
    CHECK(pw_query(PW_SCHTASK, &c, &inst) == PW_OK && inst == 0,
          "exec 失败视为未安装");
}

static void t_wmi(void)
{
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    reset_exec(0);

    c.name    = "SysMonFilter";
    c.cmdline = "C:\\Windows\\Temp\\a.exe";
    c.exec    = exec_mock;

    CHECK(pw_install(PW_WMI_EVENT, &c) == PW_OK, "WMI 安装返回 OK");
    CHECK(strstr(g_last_cmd, "__EventFilter") != NULL, "含 __EventFilter");
    CHECK(strstr(g_last_cmd, "CommandLineEventConsumer") != NULL, "含 consumer");
    CHECK(strstr(g_last_cmd, "__FilterToConsumerBinding") != NULL, "含 binding");
    CHECK(strstr(g_last_cmd, "root/subscription") != NULL, "命名空间为 root/subscription");
    CHECK(strstr(g_last_cmd, "CommandLineTemplate='C:\\Windows\\Temp\\a.exe'") != NULL,
          "命令行模板正确嵌入");
}

static void t_wmi_escape(void)
{
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    reset_exec(0);

    c.name    = "SysMonFilter";
    c.cmdline = "C:\\a.exe -p 'secret'";
    c.exec    = exec_mock;

    CHECK(pw_install(PW_WMI_EVENT, &c) == PW_OK, "含单引号命令行安装 OK");
    /* PowerShell 单引号字符串内的 ' 必须写成 ''，否则命令破损 */
    CHECK(strstr(g_last_cmd, "''secret''") != NULL, "单引号被转义为 ''");
}

static void t_wmi_uninstall_order(void)
{
    const char *pb, *pc;
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    reset_exec(0);

    c.name    = "SysMonFilter";
    c.cmdline = "a.exe";
    c.exec    = exec_mock;

    CHECK(pw_uninstall(PW_WMI_EVENT, &c) == PW_OK, "WMI 卸载 OK");
    pb = strstr(g_last_cmd, "__FilterToConsumerBinding");
    pc = strstr(g_last_cmd, "CommandLineEventConsumer");
    CHECK(pb != NULL && pc != NULL && pb < pc,
          "卸载先解绑 binding 再删 consumer（顺序正确）");
    CHECK(strstr(g_last_cmd, "Remove-WmiObject") != NULL, "卸载命令含 Remove-WmiObject");
}

static void t_exec_fail(void)
{
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    reset_exec(1);

    c.name    = "AdobeARM";
    c.cmdline = "x.exe";
    c.exec    = exec_mock;
    CHECK(pw_install(PW_SCHTASK, &c) == PW_ERR_EXEC, "exec 失败返回 PW_ERR_EXEC");

    /* 缺 exec 回调 */
    c.exec = NULL;
    CHECK(pw_install(PW_SCHTASK, &c) == PW_ERR_PARAM, "缺 exec 回调返回 PARAM");
}

static void t_uninstall_needs_only_name(void)
{
    char buf[512];
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    reset_exec(0);

    /* 卸载只需 name；cmdline 为 NULL 也应可用 */
    c.name = "AdobeARM";
    c.exec = exec_mock;
    CHECK(pw_uninstall(PW_SCHTASK, &c) == PW_OK, "卸载只需 name（cmdline 可为 NULL）");
    CHECK(pw_build_cmd(PW_SCHTASK, PW_MODE_UNINSTALL, &c, buf, sizeof(buf)) > 0,
          "卸载命令行可独立构造");
}

static void t_build_cmd_reg(void)
{
    char buf[256];
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.name    = "N";
    c.cmdline = "x.exe";
    CHECK(pw_build_cmd(PW_REG_RUN, PW_MODE_INSTALL, &c, buf, sizeof(buf)) == 0,
          "REG_RUN 无命令行形态，build_cmd 返回 0");
}

static void t_stealth(void)
{
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    reset_exec(0);

    c.name    = "AdobeARM";
    c.cmdline = "x.exe";
    c.exec    = exec_mock;
    pw_install(PW_SCHTASK, &c);
    CHECK(strstr(g_last_cmd, "dayanjing") == NULL, "命令行不含产品特征串");

    reset_exec(0);
    pw_install(PW_WMI_EVENT, &c);
    CHECK(strstr(g_last_cmd, "dayanjing") == NULL, "WMI 命令不含产品特征串");
}

static void t_misc(void)
{
    CHECK(strcmp(pw_errstr(PW_ERR_NAME), "invalid name") == 0, "errstr 正确");
    CHECK(strcmp(pw_method_name(PW_REG_RUN), "registry_run") == 0, "method_name 正确");
    CHECK(strcmp(pw_method_name(PW_WMI_EVENT), "wmi_event") == 0, "method_name WMI 正确");

    /* 参数校验 */
    CHECK(pw_install(PW_REG_RUN, NULL) == PW_ERR_PARAM, "cfg 为 NULL 被拒");
    pw_cfg_t c;
    memset(&c, 0, sizeof(c));
    CHECK(pw_install(PW_REG_RUN, &c) == PW_ERR_PARAM, "name 为 NULL 被拒");
    CHECK(pw_install((pw_method_t)99, &c) == PW_ERR_PARAM, "越界方法被拒");
}

int main(void)
{
    printf("=== test_persist_win ===\n");
    t_reg_install();
    t_reg_query_uninstall();
    t_reg_idempotent();
    t_reg_overwrite();
    t_name_validation();
    t_cmd_validation();
    t_schtask();
    t_schtask_query();
    t_wmi();
    t_wmi_escape();
    t_wmi_uninstall_order();
    t_exec_fail();
    t_uninstall_needs_only_name();
    t_build_cmd_reg();
    t_stealth();
    t_misc();
    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
