#ifndef image_H
#define image_H

#include <stdint.h>
#include <stdlib.h>

#include "http_hostcalls.h"

// Change the URI below and uncomment the line - It should be the URI of a JPEG image.
// If not defined, the local LOCAL_IMAGE_URI image (from the `assets` directory) will be loaded
// instead.

// #define IMAGE_URI "https://example.com/image.jpg"

#define LOCAL_IMAGE_URI "cat.jpg"

// --- Do not change anything below ---

// Images are cached in the K/V store to reduce latency - This is the key used for caching.
#define CACHE_KEY "image-demo-cached-image"

// Resizing precision. Must be a power of 2.
#define THETA 256

// Maximum opacity of the sharpening layer.
#define OPACITY_MAX 100

typedef struct Image {
    uint8_t *     buf;
    size_t        buf_len;
    unsigned int  width;
    unsigned int  height;
    unsigned int  depth;
    unsigned long row_stride;
} Image;

void *guest_malloc(size_t size);

void guest_free(void *ptr);

int get_query_ival(unsigned int *value_p, const char *name);

void set_resp_http_header(response_t handle, const char *name, const char *value);

void set_nocache(response_t handle);

char *url_for_static_asset(const char *asset);

#endif
