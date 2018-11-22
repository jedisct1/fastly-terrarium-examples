#ifndef blake2s_H
#define blake2s_H

#include <stdint.h>
#include <stdlib.h>

void blake2s(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, const uint8_t *key,
             size_t key_len);

#endif
