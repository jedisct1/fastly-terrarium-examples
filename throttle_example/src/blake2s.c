/*
 * A tiny implementation of the BLAKE2S hash function.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "blake2s.h"
#include "common.h"

static const uint8_t BLAKE2S_SIGMA[10][8] = {
    { 1, 35, 69, 103, 137, 171, 205, 239 },   { 234, 72, 159, 214, 28, 2, 183, 83 },
    { 184, 192, 82, 253, 174, 54, 113, 148 }, { 121, 49, 220, 190, 38, 90, 64, 248 },
    { 144, 87, 36, 175, 225, 188, 104, 61 },  { 44, 106, 11, 131, 77, 117, 254, 25 },
    { 197, 31, 237, 74, 7, 99, 146, 139 },    { 219, 126, 193, 57, 80, 244, 134, 42 },
    { 111, 233, 179, 8, 194, 215, 20, 165 },  { 162, 132, 118, 21, 251, 158, 60, 208 }
};

#define BLAKE2S_G(M, R, I, A, B, C, D)         \
    do {                                       \
        const uint8_t x = BLAKE2S_SIGMA[R][I]; \
        (A) += (B) + (M)[(x >> 4) & 0xf];      \
        (D) = ROTR32((D) ^ (A), 16);           \
        (C) += (D);                            \
        (B) = ROTR32((B) ^ (C), 12);           \
        (A) += (B) + (M)[x & 0xf];             \
        (D) = ROTR32((D) ^ (A), 8);            \
        (C) += (D);                            \
        (B) = ROTR32((B) ^ (C), 7);            \
    } while (0)

static inline void blake2s_round(uint32_t state[16], const uint32_t mb32[16], int round)
{
    BLAKE2S_G(mb32, round, 0, state[0], state[4], state[8], state[12]);
    BLAKE2S_G(mb32, round, 1, state[1], state[5], state[9], state[13]);
    BLAKE2S_G(mb32, round, 2, state[2], state[6], state[10], state[14]);
    BLAKE2S_G(mb32, round, 3, state[3], state[7], state[11], state[15]);

    BLAKE2S_G(mb32, round, 4, state[0], state[5], state[10], state[15]);
    BLAKE2S_G(mb32, round, 5, state[1], state[6], state[11], state[12]);
    BLAKE2S_G(mb32, round, 6, state[2], state[7], state[8], state[13]);
    BLAKE2S_G(mb32, round, 7, state[3], state[4], state[9], state[14]);
}

static void blake2s_hashblock(uint32_t state[16], uint32_t h[8], uint32_t t[2],
                              const uint8_t message_block[64], uint32_t inc, int is_last)
{
    uint32_t mb32[16];
    int      round;
    int      i;

    for (i = 0; i < 16; i++) {
        mb32[i] = LOAD32_LE(&message_block[(size_t) i * sizeof mb32[0]]);
    }
    memcpy(&state[0], h, 8 * sizeof state[0]);
    memcpy(&state[8], IV, 8 * sizeof state[0]);
    t[0] += inc;
    if (t[0] < inc) {
        t[1]++;
    }
    state[12] ^= t[0];
    state[13] ^= t[1];
    if (is_last) {
        state[14] = ~state[14];
    }
    for (round = 0; round < 10; round++) {
        blake2s_round(state, mb32, round);
    }
    for (i = 0; i < 8; i++) {
        h[i] ^= state[i] ^ state[i + 8];
    }
}

void blake2s(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, const uint8_t *key,
             size_t key_len)
{
    uint8_t  out_tmp[32];
    uint32_t state[16];
    uint8_t  block[64];
    uint32_t h[8];
    uint32_t t[2] = { 0 };
    size_t   off;
    int      i;

    memcpy(h, IV, sizeof h);
    h[0] ^= (out_len | (key_len << 8) | (1 << 16) | (1 << 24));
    if (key_len > 0) {
        memset(block, 0, sizeof block);
        memcpy(block, key, key_len);
        blake2s_hashblock(state, h, t, block, 64U, in_len == 0);
    }
    for (off = 0U; in_len > 64U; off += 64U) {
        blake2s_hashblock(state, h, t, &in[off], 64U, 0);
        in_len -= 64U;
    }
    if (in_len > 0U || key_len == 0U) {
        memset(block, 0, sizeof block);
        if (in_len > 0U) {
            memcpy(block, &in[off], in_len);
        }
        blake2s_hashblock(state, h, t, block, (uint32_t) in_len, 1);
    }
    for (i = 0; i < 8; i++) {
        STORE32_LE(&out_tmp[(size_t) i * sizeof h[0]], h[i]);
    }
    memcpy(out, out_tmp, out_len);
}
