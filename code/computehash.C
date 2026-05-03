#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROTL(x, b) ((uint64_t)(((x) << (b)) | ((x) >> (64 - (b)))))
#define P1 ((1UL << 32) - 5)
#define P2 ((1UL << 32) - 17)

// UMAC1 implementation
uint64_t my_umac1(unsigned *in, size_t insz, uint64_t k1, uint64_t k2) {
    uint64_t k11 = k1 & 0xffffffff;
    uint64_t k12 = k1 >> 32;
    uint32_t rv1 = in[0]; if (rv1 >= P1) rv1 -= P1;
    uint32_t rv2 = in[1]; if (rv2 >= P2) rv2 -= P2;

    for (unsigned j = 2; j < insz - 1; j += 2) {
        uint64_t x = (uint64_t)rv1 * k11 + in[j];
        uint64_t y = (uint64_t)rv2 * k12 + in[j+1];
        rv1 = x % P1;
        rv2 = y % P2;
    }

    return (k2 ^ rv1) ^ (((uint64_t)rv2) << 32);
}

// UMAC3 implementation
uint64_t my_umac3(unsigned *in, size_t insz, uint64_t k1, uint64_t k2) {
    uint64_t k11 = k1 & 0xffffffff;
    uint64_t k12 = k1 >> 32;
    uint32_t rv1 = in[0]; if (rv1 >= P1) rv1 -= P1;
    uint32_t rv2 = in[0]; if (rv2 >= P2) rv2 -= P2;
    //printf("rv1=%u rv2=%u\n", rv1, rv2);

    for (unsigned j = 1; j < insz; j++) {
        uint64_t x = (uint64_t)rv1 * k11 + in[j];
        uint64_t y = (uint64_t)rv2 * k12 + in[j];
        rv1 = x % P1;
        rv2 = y % P2;
        // printf("i=%d m=%u x=%lu y=%lu\n", j, in[j], x, y);
        // printf("i=%d rv1=%u rv2=%u\n", j, rv1, rv2);
  
    }

    return (k2 ^ rv1) ^ (((uint64_t)rv2) << 32);
}

// SipHash constants and macro
#define SIPROUND \
    do { \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32); \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32); \
    } while (0)

// SipHash implementation
uint64_t get_siphash(const uint64_t *in, size_t inlen, const uint8_t *k) {
    uint64_t v0 = 0x736f6d6570736575ULL;
    uint64_t v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL;
    uint64_t v3 = 0x7465646279746573ULL;
    uint64_t k0 = ((uint64_t *)k)[0];
    uint64_t k1 = ((uint64_t *)k)[1];
    uint64_t b = ((uint64_t)inlen) << 56;
    uint64_t m, hash;
    const uint64_t *end = in + (inlen / sizeof(uint64_t));
    
    v0 ^= k0; v1 ^= k1;
    v2 ^= k0; v3 ^= k1;

    for (; in != end; in++) {
        m = *in;
        v3 ^= m;

        SIPROUND;
        SIPROUND;

        v0 ^= m;
    }

    v3 ^= b;

    SIPROUND;
    SIPROUND;

    v0 ^= b;
    v2 ^= 0xff;

    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    hash = v0 ^ v1 ^ v2 ^ v3;
    return hash;
}

uint64_t compute_hash(const uint8_t *in, size_t inlen, const uint8_t *k, int algo) {
    uint64_t k1 = 0, k2 = 0;
    for (int i = 0; i < 8; i++) {
        k1 |= ((uint64_t)k[i]) << (8 * i);
        k2 |= ((uint64_t)k[i + 8]) << (8 * i);
    }
    
    size_t padded_len = (inlen + 3) / 4;
    unsigned *data32 = (unsigned *)calloc(padded_len, sizeof(unsigned));
    // printf("dlen:%ld ,padded_len=%ld\n", inlen, padded_len);
    if (!data32) { return 0; }

    for (size_t i = 0; i < padded_len; i++) {
        for (int j = 0; j < 4; j++) {
            size_t byte_idx = i * 4 + j;
            if (byte_idx < inlen) {
                data32[i] |= ((uint32_t)in[byte_idx]) << (8 * j);
            }
        }
    }

    uint64_t hash = 0;
    if (algo == 1) {
        hash = get_siphash((uint64_t*) in, inlen, k);
    } else if (algo == 2) {
        hash = my_umac1(data32, padded_len, k1, k2);
    } else if (algo == 3) {
        hash = my_umac3(data32, padded_len, k1, k2);
    } else {
        free(data32);
        return 0;
    }
    free(data32);
    return hash;
}
