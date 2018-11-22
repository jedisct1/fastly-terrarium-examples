#ifndef config_H
#define config_H

/*
 * This is the base URL to proxy requests to.
 *
 * You may want to change this.
 *
 * A query to <path> will be forwarded to UPSTREAM_BASE_URL || <path>
 * Do not include a trailing / here/
 */
#define UPSTREAM_BASE_URL "https://example.com"

/*
 * The value of the Host: header to set when communicating with the
 * upstream server. Should usually match the host name from
 * UPSTREAM_BASE_URL.
 */
#define UPSTREAM_HOSTNAME "example.com"

/*
 * How long a successfully passed challenge is valid for
 */
#define CHALLENGE_TTL 600

/*
 * Send the challenge when the counter for an IP address goes above this value.
 * The default is intentionally low in order to easily test this example.
 */
#define RATELIMIT_PEAK 10

/*
 * How many counter to use. This should be adjusted according to the number of
 * expected simultaneous IP addresses hitting the proxy.
 */
#define RATELIMIT_SLOTS 1000

/*
 * This controls how counters decay. A lower value means faster decay.
 */
#define RATELIMIT_PERIOD (RATELIMIT_SLOTS * 10)

/*
 * Work factor required by the challenge
 */
#define CHALLENGE_LEVEL_FIRST 5
#define CHALLENGE_LEVEL_LAST 20
#define CHALLENGE_ITERATIONS 5

/* Do not change this */
#define CHALLENGE_COUNT ((CHALLENGE_LEVEL_LAST - CHALLENGE_LEVEL_FIRST + 1) * CHALLENGE_ITERATIONS)

#endif