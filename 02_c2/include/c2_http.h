#ifndef C2_HTTP_H
#define C2_HTTP_H

#include "c2.h"

#ifdef __cplusplus
extern "C" {
#endif

struct c2_transport *c2_http_transport_create(const char *user_agent,
                                              const char *host_header);
void                 c2_http_transport_destroy(struct c2_transport *t);

c2_err_t c2_http_set_url_path(struct c2_transport *t, const char *path);
c2_err_t c2_http_set_header(struct c2_transport *t,
                            const char *name, const char *value);
c2_err_t c2_http_set_jitter(struct c2_transport *t, int min_ms, int max_ms);

#ifdef __cplusplus
}
#endif

#endif /* C2_HTTP_H */
