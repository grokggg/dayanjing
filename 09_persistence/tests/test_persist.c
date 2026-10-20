#include "persist.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    char buf[1024];

    size_t n = persist_cron_line("/tmp/agent --run", buf, sizeof buf);
    CHECK(n > 0);
    CHECK(strncmp(buf, "* * * * * ", 10) == 0);
    CHECK(strstr(buf, "/tmp/agent --run") != NULL);

    n = persist_systemd_unit("dayanjing", "/tmp/agent --run", buf, sizeof buf);
    CHECK(n > 0);
    CHECK(strstr(buf, "[Unit]") != NULL);
    CHECK(strstr(buf, "ExecStart=/tmp/agent --run") != NULL);
    CHECK(strstr(buf, "WantedBy=default.target") != NULL);

    n = persist_launch_agent("com.dayanjing.agent", "/tmp/agent --run", buf, sizeof buf);
    CHECK(n > 0);
    CHECK(strstr(buf, "<string>com.dayanjing.agent</string>") != NULL);
    CHECK(strstr(buf, "/tmp/agent --run") != NULL);
    CHECK(strstr(buf, "RunAtLoad") != NULL);

    /* 缓冲区不足应返回 0 而不是截断 */
    CHECK(persist_cron_line("/tmp/agent --run", buf, 5) == 0);
    CHECK(persist_systemd_unit("n", "e", buf, 8) == 0);

    printf("09_persistence tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
