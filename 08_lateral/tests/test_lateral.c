#include "lateral.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    lat_cidr_t c;
    uint32_t hosts = 0;

    CHECK(lat_cidr_parse("192.168.1.0/24", &c) == 0);
    CHECK(c.base == 0xC0A80100u);
    CHECK(c.mask == 0xFFFFFF00u);
    CHECK(lat_cidr_hosts(&c, &hosts) == 0);
    CHECK(hosts == 254);

    CHECK(lat_cidr_parse("10.0.0.1/32", &c) == 0);
    CHECK(lat_cidr_hosts(&c, &hosts) == 0);
    CHECK(hosts == 1);

    CHECK(lat_cidr_parse("0.0.0.0/0", &c) == 0);
    CHECK(c.mask == 0);
    CHECK(lat_cidr_hosts(&c, &hosts) == 0);
    CHECK(hosts == 0xFFFFFFFEu);   /* 2^32 - 2 */

    /* 非法输入 */
    CHECK(lat_cidr_parse("192.168.1.0", &c) != 0);      /* 无掩码 */
    CHECK(lat_cidr_parse("192.168.1.0/33", &c) != 0);
    CHECK(lat_cidr_parse("300.1.1.1/24", &c) != 0);
    CHECK(lat_cidr_parse("", &c) != 0);

    /* 端口解析 */
    int ports[64];
    size_t n = 0;
    CHECK(lat_ports_parse("80,443,1000-1002", ports, 64, &n) == 0);
    CHECK(n == 5);
    CHECK(ports[0] == 80 && ports[1] == 443);
    CHECK(ports[2] == 1000 && ports[3] == 1001 && ports[4] == 1002);

    n = 0;
    CHECK(lat_ports_parse("22", ports, 64, &n) == 0);
    CHECK(n == 1 && ports[0] == 22);

    /* 容量不足时按 cap 截断，不越界 */
    n = 0;
    CHECK(lat_ports_parse("1-10", ports, 3, &n) == 0);
    CHECK(n == 3);

    /* 非法端口 */
    n = 0;
    CHECK(lat_ports_parse("70000", ports, 64, &n) != 0);
    CHECK(lat_ports_parse("5-3", ports, 64, &n) != 0);

    printf("08_lateral tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
