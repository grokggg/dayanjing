#include <string.h>

int f(const void *a)
{
    /* SEC-CMP:SECRET: 秘密或认证判据，必须改用 crypto_constant_time_eq */
    return memcmp(a, "MAGIC", 5);
}
