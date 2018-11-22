#ifndef ratelimit_H
#define ratelimit_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct RateLimiter_ {
    unsigned int *slots;
    uint64_t      v0, v1;
    size_t        slots_mask;
    size_t        period;
    size_t        pos;
} RateLimiter;

/**
 * Creates a new rate limiter with `slots_len` slots.
 * `period` controls how long blocked IPs stay blocked, and must be at least
 * equal to `slots_len`.
 * `key` is a random, 16 bytes secret key.
 */
int ratelimiter_init(RateLimiter *rate_limiter, size_t slots_len, size_t period,
                     const unsigned char key[16]);

/**
 * What the function name suggests.
 */
void ratelimiter_free(RateLimiter *rate_limiter);

/**
 * Records a new hit by the given address `ip` (can be IPv4 or IPv6).
 * Returns `1` if more than `peak` queries have been observed in the period, and
 * the IP should thus be rate limited. Returns `-1` if `sa` contains junk.
 * Returns `0` otherwise.
 */
int ratelimiter_hit(RateLimiter *rate_limiter, const uint8_t ip[16], uint64_t peak);

/**
 * Clear the counter for a given IP. Due to the probabilistic data structure,
 * this will also clear the counter for other IPs.
 */
int ratelimit_clear(RateLimiter *rate_limiter, const uint8_t ip[16]);

/**
 * Updates the key, so that IP addresses are likely to end up in a different
 * slot.
 */
void ratelimiter_rekey(RateLimiter *rate_limiter);

#endif
