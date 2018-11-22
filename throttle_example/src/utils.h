#ifndef utils_H
#define utils_H

#include <stdlib.h>

#include "http_hostcalls.h"

void init_mm(void);

int get_query_param(const char **value_p, size_t *value_len_p, const char *name);

int get_query_ival(unsigned int *value_p, const char *name);

char *get_client_ip_s(void);

void rnd_fill(void *buf, size_t len);

void bail(const char *msg);

void debug(const char *msg);

char *get_http_header(request_t handle, const char *name);

void set_req_http_header(request_t handle, const char *name, const char *value);

void set_resp_http_header(response_t handle, const char *name, const char *value);

void copy_resp_headers(response_t to, response_t from);

uint64_t time_now(void);

#endif
