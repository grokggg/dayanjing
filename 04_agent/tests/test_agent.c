#include "agent.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int test_collect(void) {
    agent_info_t info;
    if (agent_collect(&info) != AGENT_OK) { printf("collect fail\n"); return 1; }
    if (strlen(info.hostname) == 0) { printf("hostname empty\n"); return 1; }
    if (strlen(info.os_name) == 0) { printf("os empty\n"); return 1; }
    if (info.pid <= 0) { printf("pid invalid\n"); return 1; }
    printf("collect ok: %s@%s pid=%d\n", info.username, info.hostname, info.pid);
    return 0;
}

static int test_exec(void) {
    char stdout_buf[1024] = {0};
    char stderr_buf[1024] = {0};
    int rc = agent_exec("echo hello && sleep 0.1 && echo world",
                        stdout_buf, sizeof(stdout_buf),
                        stderr_buf, sizeof(stderr_buf), 5);
    if (rc != AGENT_OK) { printf("exec fail: %d\n", rc); return 1; }
    if (strstr(stdout_buf, "hello") == NULL) { printf("stdout missing hello: %s\n", stdout_buf); return 1; }
    if (strstr(stdout_buf, "world") == NULL) { printf("stdout missing world: %s\n", stdout_buf); return 1; }
    printf("exec ok: %s\n", stdout_buf);
    return 0;
}

static int test_persist_dryrun(void) {
    int rc = agent_persist("/tmp/fake_payload", 1); /* dry_run=1 */
    if (rc != AGENT_OK) { printf("persist dryrun fail\n"); return 1; }
    printf("persist_dryrun ok\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_collect();
    rc |= test_exec();
    rc |= test_persist_dryrun();
    printf("ALL TESTS %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
