/*
 * Use decaying count-min sketech to record the approximate number of hits
 * recently seen from client IP addresses.
 */

#include <sys/socket.h>
#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "common.h"
#include "ratelimit.h"
#include "utils.h"

int ratelimiter_init(RateLimiter *rate_limiter, size_t slots_len, size_t period,
                     const unsigned char key[16])
{
    if ((rate_limiter->slots = calloc(slots_len, sizeof *rate_limiter->slots)) == NULL) {
        return -1;
    }
    if (period < slots_len) {
        period = slots_len;
    }
    rate_limiter->slots_mask = slots_len - (uint64_t) 1U;
    rate_limiter->period     = period;
    rate_limiter->pos        = (size_t) 0U;
    memcpy(&rate_limiter->v0, &key[0], 8);
    memcpy(&rate_limiter->v1, &key[8], 8);

    return 0;
}

void ratelimiter_free(RateLimiter *rate_limiter)
{
    free(rate_limiter->slots);
    memset(rate_limiter, 0, sizeof *rate_limiter);
    rate_limiter->slots = NULL;
}

#define SIPROUND             \
    do {                     \
        v0 += v1;            \
        v1 = ROTL64(v1, 13); \
        v1 ^= v0;            \
        v0 = ROTL64(v0, 32); \
        v2 += v3;            \
        v3 = ROTL64(v3, 16); \
        v3 ^= v2;            \
        v0 += v3;            \
        v3 = ROTL64(v3, 21); \
        v3 ^= v0;            \
        v2 += v1;            \
        v1 = ROTL64(v1, 17); \
        v1 ^= v2;            \
        v2 = ROTL64(v2, 32); \
    } while (0)

static void ratelimiter_hashes(uint64_t *i, uint64_t *j, const unsigned char ip[16], uint64_t v0,
                               uint64_t v1)
{
    uint64_t v2 = 0x736f6d6570736575ULL ^ 0x6c7967656e657261ULL ^ v0;
    uint64_t v3 = 0x646f72616e646f6dULL ^ 0x7465646279746573ULL ^ v1;
    uint64_t m;

    memcpy(&m, &ip[0], 8);
    v3 ^= m;
    SIPROUND;
    v0 ^= m;
    memcpy(&m, &ip[8], 8);
    v3 ^= m;
    SIPROUND;
    v0 ^= m;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    *i = v0 ^ v1 ^ v2 ^ v3;
    SIPROUND;
    *j = v0 ^ v1 ^ v2 ^ v3;
}

int ratelimiter_hit(RateLimiter *rate_limiter, const uint8_t ip[16], uint64_t peak)
{
    uint64_t slot_i, slot_j;
    int      ret;

    if (rate_limiter->pos <= rate_limiter->slots_mask) {
        rate_limiter->slots[rate_limiter->pos] /= 2U;
    }
    rate_limiter->pos++;
    if (rate_limiter->pos >= rate_limiter->period) {
        rate_limiter->pos = 0U;
    }
    ratelimiter_hashes(&slot_i, &slot_j, ip, rate_limiter->v0, rate_limiter->v1);
    slot_i &= rate_limiter->slots_mask;
    slot_j &= rate_limiter->slots_mask;
    if (rate_limiter->slots[slot_i] < peak) {
        rate_limiter->slots[slot_i]++;
        ret = 0;
    } else {
        ret = 1;
    }
    if (rate_limiter->slots[slot_j] < peak) {
        rate_limiter->slots[slot_j]++;
        ret = 0;
    }
    return ret;
}

int ratelimit_clear(RateLimiter *rate_limiter, const uint8_t ip[16])
{
    uint64_t slot_i, _slot_j;

    ratelimiter_hashes(&slot_i, &_slot_j, ip, rate_limiter->v0, rate_limiter->v1);
    slot_i &= rate_limiter->slots_mask;
    rate_limiter->slots[slot_i] = 0U;
    (void) _slot_j;

    return 0;
}

void ratelimiter_rekey(RateLimiter *rate_limiter)
{
    static unsigned char tmp[16] = { 0U };

    ratelimiter_hashes(&rate_limiter->v0, &rate_limiter->v1, tmp, rate_limiter->v0,
                       rate_limiter->v1);
}
