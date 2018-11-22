DNS-over-HTTPS example
======================

DNS-over-HTTPS (RFC8484) uses HTTP/2 to tunnel DNS traffic. In addition to improving privacy and security, DoH opens new possibilities to improve web performance.

This is an example of a server-side implementation of the protocol.

It accepts `GET` queries, and is compatible with the main existing clients.

Compile this example, and navigate to any URL within the example website in order to display the required parameters to connect.

This example leverages Terrarium's raw DNS interface (`DNS::query_raw()`), that forwards raw queries to an upstream recursive resolver, but also ensures that both a query and its associated response are properly formed. Transaction identifiers are also transparently randomized.

DoH clients are expected to accept the `application/dns-message` content type.

In order to leverage caching proxies, HTTP responses need to be valid up to the lowest TTL of all DNS records. The `dns::min_ttl()` function parses DNS responses in order to compute this minimum TTL, eventually reflected in the `Cache-Control` header of the HTTP response.

Queries and response sizes leak some information about what a transaction may contain. In order to mitigate this, responses are padded using an extra `X-Padding` header whose size is derived from the response size. DoH clients are expected to do the same.
This assumes that no extra compression layer exists.