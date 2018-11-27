#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "blake2s.h"
#include "config.h"
#include "hashseq.h"
#include "http_hostcalls.h"
#include "ratelimit.h"
#include "utils.h"

static uint8_t *kvstore_limiter;
static uint8_t *kvstore_limiter_slots;
static uint8_t *kvstore_limiter_key;
static uint8_t *kvstore_auth_key;

static uint8_t *kvget_limiter_key(void)
{
    static uint8_t *limiter_key;
    size_t          limiter_key_len;

    if (limiter_key != NULL) {
        return limiter_key;
    }
    hostcall_kvstore_get(&limiter_key, &limiter_key_len, "limiter_key", sizeof "limiter_key" - 1U);
    if (limiter_key == NULL) {
        limiter_key_len = 16U;
        if ((limiter_key = malloc(limiter_key_len)) == NULL) {
            bail("Out of memory");
        }
        rnd_fill(limiter_key, limiter_key_len);
        hostcall_kvstore_insert("limiter_key", sizeof "limiter_key" - 1U,
                                (const void *) limiter_key, limiter_key_len);
    }
    return limiter_key;
}

static uint8_t *kvget_auth_key(void)
{
    static uint8_t *auth_key;
    size_t          auth_key_len;

    if (auth_key != NULL) {
        return auth_key;
    }
    hostcall_kvstore_get(&auth_key, &auth_key_len, "auth_key", sizeof "auth_key" - 1U);
    if (auth_key == NULL) {
        auth_key_len = 16U;
        if ((auth_key = malloc(auth_key_len)) == NULL) {
            bail("Out of memory");
        }
        rnd_fill(auth_key, auth_key_len);
        hostcall_kvstore_insert("auth_key", sizeof "auth_key" - 1U, (const void *) auth_key,
                                auth_key_len);
    }
    return auth_key;
}

static void kvupdate_limiter(const RateLimiter *limiter)
{
    size_t limiter_len = sizeof *limiter;
    hostcall_kvstore_insert("limiter", sizeof "limiter" - 1U, (const void *) limiter, limiter_len);
    hostcall_kvstore_insert("limiter_slots", sizeof "limiter_slots" - 1U,
                            (const void *) limiter->slots,
                            RATELIMIT_SLOTS * sizeof *limiter->slots);
}

static RateLimiter *kvget_limiter(void)
{
    static RateLimiter *limiter;
    size_t              limiter_len;
    size_t              limiter_slots_len;

    if (limiter != NULL) {
        debug("cached limiter");
        return limiter;
    }
    hostcall_kvstore_get((void *) &limiter, &limiter_len, "limiter", sizeof "limiter" - 1U);
    if (limiter == NULL) {
        limiter_len = sizeof *limiter;
        if ((limiter = malloc(limiter_len)) == NULL) {
            bail("Out of memory");
        }
        if (ratelimiter_init(limiter, RATELIMIT_SLOTS, RATELIMIT_PERIOD, kvget_limiter_key()) !=
            0) {
            bail("Out of memory");
        }
        kvupdate_limiter(limiter);
        free(limiter->slots);
    } else {
        debug("Limiter found in the kvstore");
    }
    hostcall_kvstore_get((void *) &limiter->slots, &limiter_slots_len, "limiter_slots",
                         sizeof "limiter_slots" - 1U);
    return limiter;
}

static int str_to_ip(uint8_t ip[16], const char *ip_s)
{
    struct in_addr  in;
    struct in6_addr in6;

    if (inet_pton(AF_INET, ip_s, &in) == 1) {
        memset(ip, 0, 10);
        ip[10] = 0xff;
        ip[11] = 0xff;
        memcpy(&ip[12], &in.s_addr, 4);
        return 0;
    } else if (inet_pton(AF_INET6, ip_s, &in6) == 1) {
        memcpy(ip, &in6.s6_addr, 16);
        return 0;
    }
    return -1;
}

static int extract_solutions(HashSeqSolution *solutions, int solutions_count,
                             const char *fst_challenge_solutions)
{
    const char *p;
    int         i = 0;

    p = fst_challenge_solutions;
    for (;;) {
        solutions[i].s0 = strtoul(p, NULL, 10);
        if ((p = strchr(p, '_')) == NULL) {
            return -1;
        }
        p++;
        solutions[i].s1 = strtoul(p, NULL, 10);
        if (++i >= solutions_count) {
            break;
        }
        if ((p = strchr(p, ',')) == NULL) {
            return -1;
        }
        p++;
    }
    return 0;
}

static void get_suffix_for_ip_and_timestamp(uint32_t suffix[8], const uint8_t ip[16], time_t ts)
{
    uint8_t  ip_and_timestamp[16 + 8];
    uint64_t ts_u64;

    memcpy(&ip_and_timestamp[0], ip, 16U);
    ts_u64 = (uint64_t) ts;
    memcpy(&ip_and_timestamp[16], &ts_u64, 8U);

    blake2s((void *) suffix, 8U * sizeof suffix[0], ip_and_timestamp, sizeof ip_and_timestamp,
            kvget_auth_key(), 32U);
}

static int send_new_challenge(const uint8_t ip[16])
{
    char     jscode[4096];
    uint32_t suffix[8];
    uint64_t now;

    static const char *format =
        "<!doctype html><html><head><meta charset=utf-8></head>"
        "<body>Please wait...<script>var HashSeq;!function(n){function "
        "r(n,r,e,t){n[0]=1779033703,n[1]=3144134277,n[2]=1013904242,n[3]="
        "2773480762,n[4]=1359893119,n[5]=2600822924,n[6]=528734635,n[7]="
        "1541459225,n[8]=n[0]^r[0],n[9]=n[1]^r[1],n[10]=n[2]^r[2],n[11]=n[3]^"
        "r[3],n[12]=n[4]^r[4],n[13]=n[5]^r[5],n[14]=n[6]^r[6],n[15]=n[7]^r[7]"
        ",n[7]^=e<<16|t}function "
        "e(n,r,e,t){r[0]=1779033703^e.s0,r[1]=3144134277^e.s1,n.set(r);for("
        "var "
        "s=0;s<6;s++)(f=n)[0]+=f[4],f[12]=(f[12]^f[0])>>>16|(f[12]^f[0])<<16,"
        "f[8]+=f[12],f[4]=(f[4]^f[8])>>>12|(f[4]^f[8])<<20,f[0]+=f[4],f[12]=("
        "f[12]^f[0])>>>8|(f[12]^f[0])<<24,f[8]+=f[12],f[4]=(f[4]^f[8])>>>7|("
        "f[4]^f[8])<<25,f[1]+=f[5],f[13]=(f[13]^f[1])>>>16|(f[13]^f[1])<<16,"
        "f[9]+=f[13],f[5]=(f[5]^f[9])>>>12|(f[5]^f[9])<<20,f[1]+=f[5],f[13]=("
        "f[13]^f[1])>>>8|(f[13]^f[1])<<24,f[9]+=f[13],f[5]=(f[5]^f[9])>>>7|("
        "f[5]^f[9])<<25,f[2]+=f[6],f[14]=(f[14]^f[2])>>>16|(f[14]^f[2])<<16,"
        "f[10]+=f[14],f[6]=(f[6]^f[10])>>>12|(f[6]^f[10])<<20,f[2]+=f[6],f["
        "14]=(f[14]^f[2])>>>8|(f[14]^f[2])<<24,f[10]+=f[14],f[6]=(f[6]^f[10])"
        ">>>7|(f[6]^f[10])<<25,f[3]+=f[7],f[15]=(f[15]^f[3])>>>16|(f[15]^f[3]"
        ")<<16,f[11]+=f[15],f[7]=(f[7]^f[11])>>>12|(f[7]^f[11])<<20,f[3]+=f["
        "7],f[15]=(f[15]^f[3])>>>8|(f[15]^f[3])<<24,f[11]+=f[15],f[7]=(f[7]^"
        "f[11])>>>7|(f[7]^f[11])<<25,f[0]+=f[5],f[15]=(f[15]^f[0])>>>16|(f["
        "15]^f[0])<<16,f[10]+=f[15],f[5]=(f[5]^f[10])>>>12|(f[5]^f[10])<<20,"
        "f[0]+=f[5],f[15]=(f[15]^f[0])>>>8|(f[15]^f[0])<<24,f[10]+=f[15],f[5]"
        "=(f[5]^f[10])>>>7|(f[5]^f[10])<<25,f[1]+=f[6],f[12]=(f[12]^f[1])>>>"
        "16|(f[12]^f[1])<<16,f[11]+=f[12],f[6]=(f[6]^f[11])>>>12|(f[6]^f[11])"
        "<<20,f[1]+=f[6],f[12]=(f[12]^f[1])>>>8|(f[12]^f[1])<<24,f[11]+=f[12]"
        ",f[6]=(f[6]^f[11])>>>7|(f[6]^f[11])<<25,f[2]+=f[7],f[13]=(f[13]^f[2]"
        ")>>>16|(f[13]^f[2])<<16,f[8]+=f[13],f[7]=(f[7]^f[8])>>>12|(f[7]^f[8]"
        ")<<20,f[2]+=f[7],f[13]=(f[13]^f[2])>>>8|(f[13]^f[2])<<24,f[8]+=f[13]"
        ",f[7]=(f[7]^f[8])>>>7|(f[7]^f[8])<<25,f[3]+=f[4],f[14]=(f[14]^f[3])>"
        ">>16|(f[14]^f[3])<<16,f[9]+=f[14],f[4]=(f[4]^f[9])>>>12|(f[4]^f[9])<"
        "<20,f[3]+=f[4],f[14]=(f[14]^f[3])>>>8|(f[14]^f[3])<<24,f[9]+=f[14],"
        "f[4]=(f[4]^f[9])>>>7|(f[4]^f[9])<<25;var "
        "f,i=n[0],o=n[1];for(s=2;s<16;s+=2)i^=n[s],o^=n[s+1];return "
        "0==(i&t.m0|o&t.m1)}function "
        "t(n,r){r>32?(n.m0=-1,n.m1=(1<<r-32)-1|0):(n.m1=0,n.m0=(1<<r)-1|0)}"
        "function s(n,s,f){var i=new Uint32Array(16),o=new "
        "Uint32Array(16),c={m0:0,m1:0};r(i,n,s,f),t(c,s);for(var "
        "u={s0:0,s1:0};!e(o,i,u,c);)u.s0=u.s0+1|0,0===u.s0&&(u.s1=u.s1+1|0);"
        "return n.set(o.slice(8)),u}function f(n,s,f,i){var o=new "
        "Uint32Array(16),c={m0:0,m1:0};return "
        "r(o,s,f,i),t(c,f),!!e(o,o,n,c)&&(s.set(o.slice(8)),!0)}n.solve="
        "function(n,r,e,t){for(var f=n.slice(),i=[],o=r;o<=e;o++)for(var "
        "c=0;c<t;c++)i.push(s(f,o,c));return "
        "i},n.solveAsync=function(n,r,e,t,f){var i=r.slice(),o=[];!function "
        "r(e,c){if(o.push(s(i,e,c)),++c>=f&&(c=0,++e>t))return "
        "n(o);setTimeout(function(){r(e,c)},0)}(e,0)},n.verify=function(n,r,"
        "e,t,s){for(var i=r.slice(),o=0,c=e;c<=t;c++)for(var "
        "u=0;u<s;u++)if(!f(n[o++],i,c,u))return!1;return!0}}(HashSeq||("
        "HashSeq={}));let "
        "href=window.location.href;if(href.indexOf('_fst_challenge')>=0)"
        "throw'Loop';HashSeq.solveAsync(function(n){href.indexOf('?')<0?href+"
        "='?':href+='&';const r=n.map(function(n){return "
        "n.s0+'_'+n.s1}).join(',');href+='_fst_challenge_ts=%" PRIu64
        "&_fst_"
        "challenge_solutions='+r;window.location.replace(href);},new "
        "Uint32Array([%" PRIu32 ", %" PRIu32 ", %" PRIu32 ", %" PRIu32 ", %" PRIu32 ", %" PRIu32
        ", %" PRIu32 ", %" PRIu32 "]),%" PRIu32 ",%" PRIu32 ",%" PRIu32
        ");"
        "</script></body></html>";

    now = time_now();
    get_suffix_for_ip_and_timestamp(suffix, ip, now);

    snprintf(jscode, sizeof jscode, format, now, suffix[0], suffix[1], suffix[2], suffix[3],
             suffix[4], suffix[5], suffix[6], suffix[7], CHALLENGE_LEVEL_FIRST,
             CHALLENGE_LEVEL_LAST, CHALLENGE_ITERATIONS);
    hostcall_resp_set_body(RESPONSE_OUTGOING, jscode, strlen(jscode));
    set_resp_http_header(RESPONSE_OUTGOING, "Cache-Control", "private, no-cache, no-store, must-revalidate, max-age=0");
    set_resp_http_header(RESPONSE_OUTGOING, "Content-Type", "text/html");

    return 0;
}

static int challenge_already_passed(const uint8_t ip[16])
{
    HashSeqSolution solutions[CHALLENGE_COUNT];
    uint32_t        suffix[8];
    unsigned int    fst_challenge_ts;
    const char *    fst_challenge_solutions;
    char *          fst_challenge_solutions_;
    size_t          fst_challenge_solutions_size;
    uint64_t        now;

    now = time_now();
    if (get_query_ival(&fst_challenge_ts, "_fst_challenge_ts") != 0) {
        debug("no fst challenge");
        return 0;
    }
    if (now < fst_challenge_ts || now - fst_challenge_ts > CHALLENGE_TTL) {
        debug("timestamp too old");
        return 0;
    }
    if (get_query_param(&fst_challenge_solutions, &fst_challenge_solutions_size,
                        "_fst_challenge_solutions") != 0) {
        debug("no fst solutions");
        return 0;
    }
    fst_challenge_solutions_ = malloc(fst_challenge_solutions_size + (size_t) 1U);
    memcpy(fst_challenge_solutions_, fst_challenge_solutions, fst_challenge_solutions_size);
    fst_challenge_solutions_[fst_challenge_solutions_size] = 0;

    get_suffix_for_ip_and_timestamp(suffix, ip, fst_challenge_ts);
    if (extract_solutions(solutions, CHALLENGE_COUNT, fst_challenge_solutions_) != 0) {
        debug("unable to parse the solutions");
        return 0;
    }
    free(fst_challenge_solutions_);

    if (hashseq_verify(solutions, suffix, CHALLENGE_LEVEL_FIRST, CHALLENGE_LEVEL_LAST,
                       CHALLENGE_ITERATIONS) == 0) {
        debug("challenge failed");
        return 0;
    }
    debug("challenge passed");

    return 1;
}

static void proxy(void)
{
    request_t  upstream_req;
    response_t upstream_resp;
    char *     path;
    char *     method;
    char *     url;
    uint8_t *  body;
    size_t     path_len;
    size_t     method_len;
    size_t     body_len;
    size_t     url_len;

    hostcall_req_get_path(&path, &path_len, REQUEST_INCOMING);
    url_len = sizeof UPSTREAM_BASE_URL - 1U + path_len;
    url     = malloc(url_len + 1U);
    snprintf(url, url_len + 1U, "%s%s", UPSTREAM_BASE_URL, path);
    free(path);
    if (url == NULL) {
        bail("Out of memory");
    }
    hostcall_req_get_method(&method, &method_len, REQUEST_INCOMING);
    hostcall_req_get_body(&body, &body_len, REQUEST_INCOMING);
    upstream_req = hostcall_req_create(method, method_len, url, strlen(url));
    free(url);
    hostcall_req_set_body(upstream_req, (const void *) body, body_len);
    set_req_http_header(upstream_req, "Host", UPSTREAM_HOSTNAME);
    upstream_resp = hostcall_req_send(upstream_req);
    free(body);
    free(method);
    copy_resp_headers(RESPONSE_OUTGOING, upstream_resp);
    set_resp_http_header(RESPONSE_OUTGOING, "Cache-Control", "private, no-cache, no-store, must-revalidate, max-age=0");
    hostcall_resp_get_body(&body, &body_len, upstream_resp);
    hostcall_resp_set_body(RESPONSE_OUTGOING, (const void *) body, body_len);
    free(body);
}

void run(void)
{
    uint8_t      ip[16];
    char *       ip_s;
    int          hit;
    RateLimiter *limiter;

    init_mm();
    if ((ip_s = get_client_ip_s()) == NULL) {
        bail("Unable to retrieve the client IP address");
    }
    if (str_to_ip(ip, ip_s) != 0) {
        bail("Unable to parse the client IP address");
    }
    free(ip_s);
    limiter = kvget_limiter();
    limiter->slots[0]++;
    hit = ratelimiter_hit(limiter, ip, RATELIMIT_PEAK);
    if (hit == 0) {
        kvupdate_limiter(limiter);
        proxy();
        return;
    }
    if (challenge_already_passed(ip) == 1) {
        ratelimit_clear(limiter, ip);
        kvupdate_limiter(limiter);
        proxy();
        return;
    }
    send_new_challenge(ip);
}
