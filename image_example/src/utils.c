#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_hostcalls.h"
#include "image.h"

void *guest_malloc(size_t size)
{
    return malloc(size);
}

void guest_free(void *ptr)
{
    free(ptr);
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

static int get_query_param(const char **value_p, size_t *value_len_p, const char *name)
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

void set_resp_http_header(response_t handle, const char *name, const char *value)
{
    struct string_slice value_slice = { .ptr = value, .len = strlen(value) };
    hostcall_resp_set_header(handle, name, strlen(name), &value_slice, 1U);
}

void set_nocache(response_t handle)
{
    set_resp_http_header(handle, "Cache-Control",
                         "private, no-cache, no-store, must-revalidate, max-age=0");
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

char *url_for_static_asset(const char *asset)
{
    char * url;
    char * host;
    size_t url_size;

    if ((host = get_http_header(REQUEST_INCOMING, "Host")) == NULL) {
        return NULL;
    }
    url_size = sizeof "https://" - 1U + strlen(host) + sizeof "/" - 1U + strlen(asset) + 1U;
    if ((url = malloc(url_size)) == NULL) {
        return NULL;
    }
    snprintf(url, url_size, "https://%s/%s", host, asset);
    free(host);

    return url;
}