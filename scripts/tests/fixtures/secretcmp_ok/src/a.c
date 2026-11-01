#include <string.h>

int f(const void *a)
{
    /* SEC-CMP:PUBLIC: 双方均为公开数据，无秘密可泄露 */
    return memcmp(a, "MAGIC", 5);
}
