#ifndef PERSIST_H
#define PERSIST_H
#include <stddef.h>

/* 生成 crontab 行（每分钟执行）。返回写入长度（不含 NUL），失败 0 */
size_t persist_cron_line(const char *cmd, char *out, size_t cap);

/* 生成 systemd user unit 内容（不写盘，只返回文本） */
size_t persist_systemd_unit(const char *name, const char *exec, char *out, size_t cap);

/* 生成 LaunchAgent plist 内容 */
size_t persist_launch_agent(const char *label, const char *exec, char *out, size_t cap);

#endif
