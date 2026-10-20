#ifndef TRANSPORT_H
#define TRANSPORT_H
#include <stddef.h>
#include <stdint.h>

typedef enum { TX_HTTP = 0, TX_DNS, TX_ICMP } tx_kind_t;

/* HTTP: wrap frame into a POST body request; returns bytes written or 0 on error */
size_t tx_http_wrap(const uint8_t *frame, size_t len, uint8_t *out, size_t cap);
/* HTTP: extract frame from response body. *outlen in=capacity, out=actual; 0 ok */
int tx_http_unwrap(const uint8_t *resp, size_t rlen, uint8_t *out, size_t *outlen);

/* DNS: base32 (RFC4648, no padding) encode into label string */
size_t tx_dns_wrap(const uint8_t *frame, size_t len, char *out, size_t cap);
int tx_dns_unwrap(const char *label, uint8_t *out, size_t *outlen);

/* ICMP: wrap into echo payload with magic+len header */
size_t tx_icmp_wrap(const uint8_t *frame, size_t len, uint8_t *out, size_t cap);
int tx_icmp_unwrap(const uint8_t *payload, size_t plen, uint8_t *out, size_t *outlen);

#endif
