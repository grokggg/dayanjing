#include "agent.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    /* ---- collect ---- */
    agent_info_t info;
    CHECK(agent_collect(&info) == 0);
    CHECK(strlen(info.hostname) > 0);
    CHECK(strlen(info.os) > 0);
    CHECK(strlen(info.user) > 0);
    CHECK(info.pid == (int)getpid());
    printf("collect: host=%s os=%s user=%s pid=%d\n", info.hostname, info.os, info.user, info.pid);

    /* ---- exec: echo ---- */
    char out[256];
    size_t olen = 0;
    int rc = agent_exec("echo hello", out, sizeof out, &olen, 1000);
    CHECK(rc == 0);
    CHECK(olen == 6);              /* "hello\n" */
    CHECK(strcmp(out, "hello\n") == 0);

    /* ---- exec: exit code ---- */
    rc = agent_exec("exit 3", out, sizeof out, &olen, 1000);
    CHECK(rc == 3);

    /* ---- exec: timeout ---- */
    rc = agent_exec("sleep 5", out, sizeof out, &olen, 200);
    CHECK(rc == -1);               /* timeout */

    /* ---- exec: command not found -> 127 ---- */
    rc = agent_exec("no_such_cmd_xyz", out, sizeof out, &olen, 1000);
    CHECK(rc == 127);

    printf("04_agent tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
