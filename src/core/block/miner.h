#ifndef ECLIPSE_BLOCK_MINER_H
#define ECLIPSE_BLOCK_MINER_H

#include <stdbool.h>
#include <stdint.h>
#include "block.h"

/* Difficulty is the number of required leading zero bits in the block hash.
 * The dev chain currently fixes it to eight; no retarget rule exists yet. */
bool eclipse_pow_hash_meets_target(const uint8_t hash[32], uint32_t bits);

/* Tries at most max_attempts nonces from the block's current nonce. found=false
 * is ordinary exhaustion, not a validation error. The next call can resume. */
eclipse_error_t eclipse_miner_mine(eclipse_block_t *block,
                                   uint64_t max_attempts, bool *found);

#endif
