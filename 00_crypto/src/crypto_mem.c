#include "crypto.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/* ==================== 安全清零 ====================
 * memset 会被编译器在"死存储"分析下优化掉。这里用 volatile 指针
 * 写入，并保证至少执行一次全量覆盖。另提供 memset_s 兼容。
 */
CRYPTO_API void crypto_wipe(void *buf, size_t len) {
    if (!buf || len == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;
}

/* ==================== 内存锁 ==================== */
CRYPTO_API int crypto_mlock(const void *addr, size_t len) {
    if (!addr) return -1;
    /* mlock 可能受 RLIMIT_MEMLOCK 限制；失败不致命，返回错误码即可 */
    return mlock(addr, len);
}

CRYPTO_API int crypto_munlock(void *addr, size_t len) {
    if (!addr) return -1;
    return munlock(addr, len);
}

/* ==================== 常量时间比较 ====================
 * 逐字节 XOR 累加，最后检查累计差是否为 0。
 * 不早退，不分支于字节值。
 */
CRYPTO_API int crypto_ct_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)(pa[i] ^ pb[i]);
    }
    return (int)diff;
}

/* ==================== 错误信息 ==================== */
CRYPTO_API const char *crypto_strerror(crypto_err_t e) {
    switch (e) {
        case CRYPTO_OK:            return "success";
        case CRYPTO_ERR:           return "generic error";
        case CRYPTO_INVALID_KEY:   return "invalid key";
        case CRYPTO_INVALID_NONCE: return "invalid nonce";
        case CRYPTO_TAG_MISMATCH:  return "authentication tag mismatch";
        case CRYPTO_NOMEM:         return "out of memory";
        case CRYPTO_RNG_FAILED:    return "RNG failed";
        case CRYPTO_NOTSUP:        return "not supported";
        case CRYPTO_OVERFLOW:      return "length overflow";
    }
    return "unknown";
}

/* ==================== RNG ====================
 * Linux 上优先用 getrandom(2) syscall，未就绪时（early boot）回退 /dev/urandom。
 * 不用 rand() / /dev/random（后者会因熵不足阻塞）。
 */
static crypto_err_t fill_random(void *out, size_t len) {
    unsigned char *p = (unsigned char *)out;
    while (len > 0) {
        long rc;
#if defined(__NR_getrandom)
        rc = syscall(__NR_getrandom, p, len, 0);
        if (rc < 0 && errno == ENOSYS) {
            /* 内核不支持，降级 fallback */
            goto fallback;
        }
#else
        goto fallback;
#endif
        if (rc < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            return CRYPTO_RNG_FAILED;
        }
        p += (size_t)rc;
        len -= (size_t)rc;
    }
    return CRYPTO_OK;

fallback:
    do {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return CRYPTO_RNG_FAILED;
        ssize_t n = read(fd, out, len);
        close(fd);
        if (n < 0) {
            if (errno == EINTR) continue;
            return CRYPTO_RNG_FAILED;
        }
        if ((size_t)n == len) return CRYPTO_OK;
        out = (char *)out + n;
        len -= (size_t)n;
    } while (len > 0);
    return CRYPTO_RNG_FAILED;
}

CRYPTO_API crypto_err_t crypto_rng(void *out, size_t len) {
    if (len == 0) return CRYPTO_OK;
    if (!out) return CRYPTO_ERR;
    return fill_random(out, len);
}

CRYPTO_API uint32_t crypto_rng_u32(void) {
    uint32_t v;
    crypto_rng(&v, sizeof(v));
    return v;
}

CRYPTO_API uint64_t crypto_rng_u64(void) {
    uint64_t v;
    crypto_rng(&v, sizeof(v));
    return v;
}
