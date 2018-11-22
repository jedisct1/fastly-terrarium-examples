#ifndef common_H
#define common_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ROTR32(X, B) (uint32_t)(((X) >> (B)) | ((X) << (32 - (B))))
#define ROTL64(X, B) (uint64_t)(((X) << (B)) | ((X) >> (64 - (B))))

/* Assume little endian and no alignment rules for webassembly */

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t load32_le(const uint8_t src[4])
{
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void store32_le(uint8_t dst[4], uint32_t w)
{
    memcpy(dst, &w, sizeof w);
}

#define G(A, B, C, D)                \
    do {                             \
        (A) += (B);                  \
        (D) = ROTR32((D) ^ (A), 16); \
        (C) += (D);                  \
        (B) = ROTR32((B) ^ (C), 12); \
        (A) += (B);                  \
        (D) = ROTR32((D) ^ (A), 8);  \
        (C) += (D);                  \
        (B) = ROTR32((B) ^ (C), 7);  \
    } while (0)

static const uint32_t IV[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

#endif
