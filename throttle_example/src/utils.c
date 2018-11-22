/*
 * Miscellaneous helper functions
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake2s.h"
#include "http_hostcalls.h"
#include "utils.h"

void *guest_malloc(size_t size)
{
    return malloc(size);
}

void guest_free(void *ptr)
{
    return free(ptr);
}

void init_mm(void)
{
    hostcall_init_mm(guest_malloc, guest_free);
}

int get_query_param(const char **value_p, size_t *value_len_p, const char *name)
{
    static char *params;
    char *       path;
    char *       p, *q, *r;
    size_t       path_len;
    size_t       found_name_len;
    size_t       name_len;

    *value_p = NULL;
    if (value_len_p != NULL) {
        *value_len_p = 0;
    }
    name_len = strlen(name);
    if (params == NULL) {
        hostcall_req_get_path(&path, &path_len, REQUEST_INCOMING);
        if ((p = strchr(path, '?')) == NULL || *++p == 0) {
            free(path);
            return -1;
        }
        params = p;
    }
    p = params;
    while (*p != 0) {
        r = strchr(p, '&');
        if (r == NULL) {
            r = p + strlen(p);
        }
        q = strchr(p, '=');
        if (q > r) {
            return -1;
        }
        found_name_len = q - p;
        if (found_name_len == name_len && memcmp(name, p, found_name_len) == 0) {
            *value_p = q + 1;
            if (value_len_p != NULL) {
                *value_len_p = (r - q) - 1;
            }
            return 0;
        }
        if (*r != '&') {
            break;
        }
        p = r + 1;
    }
    return -1;
}

int get_query_ival(unsigned int *value_p, const char *name)
{
    unsigned long lvalue;
    const char *  str_value;

    if (get_query_param(&str_value, NULL, name) != 0) {
        return -1;
    }
    if (*str_value == 0) {
        return -1;
    }
    errno  = 0;
    lvalue = strtoul(str_value, NULL, 10);
    if (errno == ERANGE || lvalue > UINT_MAX) {
        return -1;
    }
    *value_p = (unsigned int) lvalue;

    return 0;
}

char *get_http_header(request_t handle, const char *name)
{
    struct string_slice *values;
    size_t               values_size;
    size_t               i;
    char *               value;

    hostcall_req_get_header(&values, &values_size, handle, name, strlen(name));
    if (values_size <= 0U) {
        return NULL;
    }
    value = strdup(values[0].ptr);
    for (i = 0U; i < values_size; i++) {
        free((char *) values[i].ptr);
    }
    return value;
}

void set_req_http_header(request_t handle, const char *name, const char *value)
{
    struct string_slice value_slice = { .ptr = value, .len = strlen(value) };
    hostcall_req_set_header(handle, name, strlen(name), &value_slice, 1U);
}

void set_resp_http_header(response_t handle, const char *name, const char *value)
{
    struct string_slice value_slice = { .ptr = value, .len = strlen(value) };
    hostcall_resp_set_header(handle, name, strlen(name), &value_slice, 1U);
}

char *get_client_ip_s(void)
{
    char *ip_s;

    if ((ip_s = get_http_header(REQUEST_INCOMING, "x-fastly-client-ip")) == NULL &&
        (ip_s = get_http_header(REQUEST_INCOMING, "fastly-client-ip")) == NULL) {
        return NULL;
    }
    return ip_s;
}

void rnd_fill(void *buf, size_t len)
{
    uint8_t *buf_      = buf;
    size_t   available = 0U;
    size_t   i         = 0U;
    uint64_t v;

    while (i < len) {
        if (available == 0U) {
            v         = hostcall_rng_next_u64();
            available = sizeof v;
        }
        available--;
        buf_[i++] = (uint8_t) v;
        v >>= 8;
    }
}

uint64_t time_now(void)
{
    return hostcall_time_now(NULL) & 0x1fffffffffffff;
}

void copy_resp_headers(response_t to, response_t from)
{
    struct string_slice *header_names;
    struct string_slice *header_values;
    size_t               header_names_len;
    size_t               header_values_len;
    size_t               i, j;

    hostcall_resp_get_headers(&header_names, &header_names_len, from);
    for (i = 0U; i < header_names_len; i++) {
        hostcall_resp_get_header(&header_values, &header_values_len, from, header_names[i].ptr,
                                 header_names[i].len);
        hostcall_resp_set_header(to, header_names[i].ptr, header_names[i].len, header_values,
                                 header_values_len);
        for (j = 0U; j < header_values_len; j++) {
            free((void *) header_values[j].ptr);
        }
        free(header_values);
        free((void *) header_names[i].ptr);
    }
    free(header_names);
}

void debug(const char *msg)
{
    hostcall_debug(msg, -1);
}

void bail(const char *msg)
{
    debug(msg);
    hostcall_resp_set_response_code(RESPONSE_OUTGOING, 500);
    hostcall_resp_set_body(RESPONSE_OUTGOING, msg, strlen(msg));
    set_resp_http_header(RESPONSE_OUTGOING, "Cache-Control", "no-cache");
    set_resp_http_header(RESPONSE_OUTGOING, "Content-Type", "text/plain");
    exit(1);
}