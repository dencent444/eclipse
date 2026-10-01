#ifndef BLOCK_H
#define BLOCK_H

#include <stddef.h>
#include <stdint.h>
#include "../error.h"

/* The wire size is fixed; sizeof(eclipse_block_header_t) may include padding. */
#define ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE 88u

typedef struct {
    uint32_t version;
    uint8_t prev_block_hash[32];
    uint8_t merkle_root[32];

    uint64_t timestamp;
    uint32_t difficulty;

    uint64_t nonce;
} eclipse_block_header_t;

/*
Eclipse Block Header v1

offset   size
----------------------------
0        4    version
4        8    timestamp
12       4    difficulty
16       8    nonce
24       32   prev_block_hash
56       32   merkle_root
----------------------------
TOTAL    88 bytes

Integers: big-endian
Hashes: raw bytes, preserved in their original order.

This layout is independent of the struct's member order, alignment, and the
host's byte order. Never serialize the struct by copying its memory directly.
*/


/*
 * Encode/decode one header using the v1 layout above. The caller owns both
 * objects and supplies the actual number of accessible bytes in buffer.
 * Source and destination must not overlap.
 *
 * NULL arguments return ECLIPSE_ERROR_NULL_POINTER. A non-NULL buffer shorter
 * than ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE returns ECLIPSE_ERROR_INVALID_ARGUMENT.
 * Validation happens before any output is modified. Larger buffers are allowed:
 * only the first 88 bytes are written/read; any trailing bytes are left alone.
 * The return value is a status code, not serialized data; bytes go into buffer.
 */
eclipse_error_t eclipse_block_header_serialize(
    const eclipse_block_header_t *header, uint8_t *buffer, size_t buffer_size);
eclipse_error_t eclipse_block_header_deserialize(
    const uint8_t *buffer, eclipse_block_header_t *header, size_t buffer_size);

#endif // BLOCK_H
