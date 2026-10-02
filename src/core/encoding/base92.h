#ifndef ECLIPSE_BASE92_H
#define ECLIPSE_BASE92_H

#include <stddef.h>
#include <stdint.h>

#include "../error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Compatible with the 13-bit encoding of thenoviceoof/base92. The returned
 * capacity includes the terminating NUL; 0 means a size_t overflow. */
size_t eclipse_base92_encoded_capacity(size_t input_length);

/* *written excludes the terminating NUL. On error it is zero. No secret data
 * belongs in logs: this codec may later handle wallet backup material. */
eclipse_error_t eclipse_base92_encode(const uint8_t *input, size_t input_length,
                                      char *output, size_t capacity,
                                      size_t *written);

/* Accepts only the canonical spelling produced by encode(). Empty input is
 * represented by '~'. The caller supplies text length, excluding any NUL. */
eclipse_error_t eclipse_base92_decode(const char *text, size_t text_length,
                                      uint8_t *output, size_t capacity,
                                      size_t *written);

#ifdef __cplusplus
}
#endif

#endif
