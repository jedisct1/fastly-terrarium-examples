#include <errno.h>
#include <limits.h>
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
    return free(ptr);
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