#ifndef BLOCK_H
#define BLOCK_H

#include <stddef.h>
#include <stdint.h>
#include "../error.h"
#include "../tx/tx.h"

/* The wire size is fixed; sizeof(eclipse_block_header_t) may include padding. */
#define ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE 88u
#define ECLIPSE_BLOCK_VERSION 1u
#define ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS 8u
#define ECLIPSE_BLOCK_MAX_TRANSACTIONS 8u
#define ECLIPSE_BLOCK_MAX_WIRE_SIZE (4u + ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE + 1u + 11u + ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE + ECLIPSE_BLOCK_MAX_TRANSACTIONS * (4u + ECLIPSE_TX_MAX_WIRE_SIZE))

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

/* Owned developer block. The reward is a separate, input-free coinbase claim;
 * ordinary ETX0 transactions cannot mint coins. The header root commits to
 * that claim and to every signed transaction in order. */
typedef struct eclipse_block eclipse_block_t;
eclipse_error_t eclipse_block_create(
    const uint8_t prev_hash[32], uint64_t timestamp,
    const eclipse_tx_output_t *reward, eclipse_block_t **out);
void eclipse_block_free(eclipse_block_t *block);
eclipse_error_t eclipse_block_add_transaction(eclipse_block_t *block,
                                              const eclipse_tx_t *tx);
eclipse_error_t eclipse_block_header(const eclipse_block_t *block,
                                     eclipse_block_header_t *out);
eclipse_error_t eclipse_block_reward(const eclipse_block_t *block,
                                     eclipse_tx_output_t *out);
size_t eclipse_block_transaction_count(const eclipse_block_t *block);
eclipse_error_t eclipse_block_transaction(const eclipse_block_t *block,
                                          size_t index, eclipse_tx_t *out);
eclipse_error_t eclipse_block_set_nonce(eclipse_block_t *block, uint64_t nonce);
eclipse_error_t eclipse_block_compute_root(const eclipse_block_t *block,
                                           uint8_t out[32]);
eclipse_error_t eclipse_block_hash(const eclipse_block_t *block,
                                   uint8_t out[32]);
/* Reward UTXO outpoint is (this ID, index 0); it is spendable from the next
 * block. It is distinct from ordinary transaction IDs. */
eclipse_error_t eclipse_block_reward_id(const eclipse_block_t *block,
                                        uint8_t out[32]);
eclipse_error_t eclipse_block_serialize(const eclipse_block_t *block,
                                        uint8_t *out, size_t capacity,
                                        size_t *written);
eclipse_error_t eclipse_block_deserialize(const uint8_t *wire, size_t length,
                                          eclipse_block_t **out);

#endif // BLOCK_H
