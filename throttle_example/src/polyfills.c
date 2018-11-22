/*
 * Polyfills for functions currently missing from the Terrarium C library.
 */

/*
 * inet_pton() implementation from OpenBSD 6.4.
 *
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifndef INADDRSZ
#define INADDRSZ 4
#endif
#ifndef IN6ADDRSZ
#define IN6ADDRSZ 16
#endif
#ifndef INT16SZ
#define INT16SZ 2
#endif

static int inet_pton4(const char *src, unsigned char *dst);
static int inet_pton6(const char *src, unsigned char *dst);

int inet_pton(int af, const char *src, void *dst)
{
    switch (af) {
    case AF_INET:
        return inet_pton4(src, dst);
    case AF_INET6:
        return inet_pton6(src, dst);
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }
    /* NOTREACHED */
}

static int inet_pton4(const char *src, unsigned char *dst)
{
    static const char digits[] = "0123456789";
    int               saw_digit, octets, ch;
    unsigned char     tmp[INADDRSZ], *tp;

    saw_digit   = 0;
    octets      = 0;
    *(tp = tmp) = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;

        if ((pch = strchr(digits, ch)) != NULL) {
            unsigned int new = *tp * 10 + (pch - digits);

            if (new > 255) {
                return 0;
            }
            if (!saw_digit) {
                if (++octets > 4) {
                    return 0;
                }
                saw_digit = 1;
            }
            *tp = new;
        } else if (ch == '.' && saw_digit) {
            if (octets == 4) {
                return 0;
            }
            *++tp     = 0;
            saw_digit = 0;
        } else {
            return 0;
        }
    }
    if (octets < 4) {
        return 0;
    }
    memcpy(dst, tmp, INADDRSZ);
    return 1;
}

static int inet_pton6(const char *src, unsigned char *dst)
{
    static const char xdigits_l[] = "0123456789abcdef", xdigits_u[] = "0123456789ABCDEF";
    unsigned char     tmp[IN6ADDRSZ], *tp, *endp, *colonp;
    const char *      xdigits, *curtok;
    int               ch, saw_xdigit, count_xdigit;
    unsigned int      val;

    memset((tp = tmp), '\0', IN6ADDRSZ);
    endp   = tp + IN6ADDRSZ;
    colonp = NULL;
    if (*src == ':') {
        if (*++src != ':') {
            return 0;
        }
    }
    curtok     = src;
    saw_xdigit = count_xdigit = 0;
    val                       = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;

        if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL) {
            pch = strchr((xdigits = xdigits_u), ch);
        }
        if (pch != NULL) {
            if (count_xdigit >= 4) {
                return 0;
            }
            val <<= 4;
            val |= (pch - xdigits);
            if (val > 0xffff) {
                return 0;
            }
            saw_xdigit = 1;
            count_xdigit++;
            continue;
        }
        if (ch == ':') {
            curtok = src;
            if (!saw_xdigit) {
                if (colonp) {
                    return 0;
                }
                colonp = tp;
                continue;
            } else if (*src == '\0') {
                return 0;
            }
            if (tp + INT16SZ > endp) {
                return 0;
            }
            *tp++        = (unsigned char) (val >> 8) & 0xff;
            *tp++        = (unsigned char) val & 0xff;
            saw_xdigit   = 0;
            count_xdigit = 0;
            val          = 0;
            continue;
        }
        if (ch == '.' && ((tp + INADDRSZ) <= endp) && inet_pton4(curtok, tp) > 0) {
            tp += INADDRSZ;
            saw_xdigit   = 0;
            count_xdigit = 0;
            break;
        }
        return 0;
    }
    if (saw_xdigit) {
        if (tp + INT16SZ > endp) {
            return 0;
        }
        *tp++ = (unsigned char) (val >> 8) & 0xff;
        *tp++ = (unsigned char) val & 0xff;
    }
    if (colonp != NULL) {
        const int n = tp - colonp;
        int       i;

        if (tp == endp) {
            return 0;
        }
        for (i = 1; i <= n; i++) {
            endp[-i]      = colonp[n - i];
            colonp[n - i] = 0;
        }
        tp = endp;
    }
    if (tp != endp) {
        return 0;
    }
    memcpy(dst, tmp, IN6ADDRSZ);
    return 1;
}

char *strdup(const char *str)
{
    size_t siz;
    char * copy;

    siz = strlen(str) + 1;
    if ((copy = malloc(siz)) == NULL) {
        return NULL;
    }
    memcpy(copy, str, siz);
    return copy;
}
