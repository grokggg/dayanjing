#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int test_rng(void) {
    uint8_t a[32], b[32];
    if (crypto_rng(a, 32) != CRYPTO_OK) { printf("rng fail\n"); return 1; }
    if (crypto_rng(b, 32) != CRYPTO_OK) { printf("rng fail2\n"); return 1; }
    if (memcmp(a, b, 32) == 0) { printf("rng not random\n"); return 1; }
    printf("rng ok\n");
    return 0;
}

static int test_hmac(void) {
    uint8_t out[32];
    const char *key = "key";
    const char *msg = "The quick brown fox jumps over the lazy dog";
    if (crypto_hmac((const uint8_t*)key, 3, (const uint8_t*)msg, strlen(msg), out) != CRYPTO_OK) {
        printf("hmac fail\n"); return 1;
    }
    /* RFC 4231 Test case 1 expected */
    uint8_t expected[32] = {
        0xf7,0xbc,0x83,0xf4,0x30,0x53,0x84,0x24,
        0xb1,0x32,0x98,0xe6,0xaa,0x6f,0xb1,0x43,
        0xef,0x4d,0x59,0xa1,0x49,0x46,0x17,0x59,
        0x97,0x47,0x9d,0xbc,0x2d,0x1a,0x3c,0xd8
    };
    if (memcmp(out, expected, 32) != 0) {
        printf("hmac mismatch\n");
        for (int i = 0; i < 32; i++) printf("%02x", out[i]);
        printf("\n");
        return 1;
    }
    if (!crypto_hmac_verify(out, expected, 32)) { printf("verify fail\n"); return 1; }
    out[0] ^= 1;
    if (crypto_hmac_verify(out, expected, 32)) { printf("verify false-positive\n"); return 1; }
    printf("hmac ok\n");
    return 0;
}

static int test_hkdf(void) {
    uint8_t out[42];
    const uint8_t ikm[22] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
    const uint8_t salt[13] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    const uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    if (crypto_hkdf(salt, 13, ikm, 22, info, 10, out, 42) != CRYPTO_OK) { printf("hkdf fail\n"); return 1; }
    /* RFC 5869 Test case 1 expected */
    uint8_t expected[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
        0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
        0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };
    if (memcmp(out, expected, 42) != 0) {
        printf("hkdf mismatch\n");
        for (int i = 0; i < 42; i++) printf("%02x", out[i]);
        printf("\n");
        return 1;
    }
    printf("hkdf ok\n");
    return 0;
}

static int test_aead(void) {
    uint8_t key[32], nonce[12], tag[16];
    crypto_rng(key, 32);
    crypto_rng(nonce, 12);
    const char *plain = "secret payload 12345";
    uint8_t cipher[64], dec[64];
    if (crypto_aead_seal(key, nonce, 12, NULL, 0, (const uint8_t*)plain, strlen(plain), cipher, tag) != CRYPTO_OK) {
        printf("seal fail\n"); return 1;
    }
    if (crypto_aead_open(key, nonce, 12, NULL, 0, cipher, strlen(plain), tag, dec) != CRYPTO_OK) {
        printf("open fail\n"); return 1;
    }
    if (memcmp(dec, plain, strlen(plain)) != 0) { printf("aead plaintext mismatch\n"); return 1; }
    /* tamper detection */
    cipher[0] ^= 1;
    if (crypto_aead_open(key, nonce, 12, NULL, 0, cipher, strlen(plain), tag, dec) != CRYPTO_ERR_AUTH) {
        printf("tamper not detected\n"); return 1;
    }
    printf("aead ok\n");
    return 0;
}

static int test_sha256(void) {
    uint8_t digest[32];
    const char *msg = "abc";
    crypto_sha256((const uint8_t*)msg, 3, digest);
    /* Known answer: ba7816bf... */
    uint8_t expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    if (memcmp(digest, expected, 32) != 0) {
        printf("sha256 mismatch\n");
        for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
        printf("\n");
        return 1;
    }
    printf("sha256 ok\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_rng();
    rc |= test_sha256();
    rc |= test_hmac();
    rc |= test_hkdf();
    rc |= test_aead();
    printf("ALL TESTS %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
