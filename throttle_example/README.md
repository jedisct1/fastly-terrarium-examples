# Throttling example

This example implements a HTTP proxy, forwarding requests to an upstream server and responses back to clients.

When too many recent requests have been observed from the same IP address, the proxy stops forwarding queries for this IP address, and immediately responds with a mathematical puzzle instead.

Solving this puzzle is computationally intensive. The web browser  runs Javascript code to perform the computation, and sends the solution back to the proxy. Once the response has been verified, the hit counter for the client IP address is reset.

## What this example shows

- How to persist internal data structures to the KV store
- How to proxy HTTP connections
- How to inspect, add and modify HTTP headers
- How to parse query parameters
- How to access the client IP address
- How to use the random number generator

## Code overview

### config.h

This is where the main configuration parameters are stored, including the URL of the upstream server.

You may want to change these.

The default values are intentionally very low, so that the example can easily be tested.

### ratelimit.c

A count-min sketch data structure is used to estimate how many connections have been recently made by a client IP.

A fixed-length vector of counters is allocated and persisted to the KV store. Metadata and counters are stored separately.

For every hit, two counters are incremented, whose location depends on the output of two randomized hash functions.

A cursor linearly traversing all the counters is responsible for adding a slow decay to these.

Note that any update to the structure also requires an update to the KV store.

### hashseq.c, hashseq.ts

This creates puzzles and verifies solutions. Puzzles are chained hashcash-like challenges where the solver has to find `x` so that `H(x|suffix)` is below some fixed value.
This particular implementation uses the internal permutation of the BLAKE2S hash function. It is just provided as a short code example and shouldn't be used for any other purpose.

A Javascript implementation can be found in the `hashseq.ts` file. This is the code we send to web browsers to have them solve the challenges.

The event loop is given a chance to run after every step in order to avoid browsers warnings about Javascript possibly being stuck.

### utils.c

Some helpers functions, to parse query parameters, retrieve the client IP address, set and get headers with a single value, fill arbitrary-long buffers with random values, and copy HTTP headers between handles.

Client IP addresses are transmitted via a HTTP header named `fastly-client-ip`. These addresses can be IPv4 or IPv6.

### blake2s.c

A tiny implementation of the BLAKE2S hash function.

Challenges sent to clients consist of a seed (the hashseq `suffix`), as well as the challenge difficulty.

Seeds are derived from the client IP address, as well as the current timestamp and a secret key, using the hash function implemented here.

### main.c

IP addresses are encoded as 16 bytes. IPv4 addresses are seen as IPv4-mapped IPv6 addreses.

The rate limiter, as well as the secret keys (the rate limiter key used for randomized hashing, and the key used to compute suffixes), are persisted to the KV store. They are created using the random number generation hostcall if necessary.

If the counter for the client IP is below an acceptable level, queries are proxied to the upstream server. The headers are individually copied, as well as the body.

A notable exception is the `Host` header, that has to be replaced with the name of the origin.

If the counter has gone past the acceptable threshold, a `text/html` response with Javascript code containing the code to solve the challenge is sent instead.

Solutions are sent as a reload of the current page, with the addition of the `_fst_challenge_ts` and `_fst_challenge_solutions` query parameters.

The former is a copy of the timestamp of the challenge, which can be used by the server, along with the client IP address and the secret key, to recover the seed.

The later is a serialized version of the solutions.

When these query parameters are received, the timestamp is checked for freshness. Note that there are no authentication tags; authenticity in this example solely depends on the verification of the challenge solutions.

If the solutions appear to be valid for the given challenge, one of the slots the client IP address maps to is reset.

