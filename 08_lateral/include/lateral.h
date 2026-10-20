#ifndef LATERAL_H
#define LATERAL_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t base; uint32_t mask; } lat_cidr_t;

/* 解析 "192.168.1.0/24"。成功 0。base/mask 为主机字节序 */
int lat_cidr_parse(const char *s, lat_cidr_t *out);
/* 该 CIDR 内可用主机数（不含网络号/广播，/32 与 /31 特殊处理）。成功 0 */
int lat_cidr_hosts(const lat_cidr_t *c, uint32_t *hosts);
/* 解析端口规格 "80,443,1000-1002"，填充 ports；*n 为端口数。成功 0 */
int lat_ports_parse(const char *spec, int *ports, size_t cap, size_t *n);

#endif
