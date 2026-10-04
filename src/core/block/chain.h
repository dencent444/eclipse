#ifndef ECLIPSE_BLOCK_CHAIN_H
#define ECLIPSE_BLOCK_CHAIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "block.h"

/* The dev genesis is a fixed empty anchor with zero spendable supply.
 * Height one is the first mined reward. Parameters are NOT mainnet rules. */
#define ECLIPSE_DEV_INITIAL_SUBSIDY UINT64_C(5000000000)
#define ECLIPSE_DEV_HALVING_INTERVAL UINT64_C(210000)
#define ECLIPSE_DEV_MAX_BLOCK_TIME_STEP UINT64_C(7200)

typedef struct eclipse_chain eclipse_chain_t;
eclipse_error_t eclipse_chain_create(eclipse_chain_t **out);
/* Open/create an append-only journal and replay every complete block through
 * normal validation. A partial final record is truncated after a crash. */
eclipse_error_t eclipse_chain_open(const char *path, eclipse_chain_t **out);
void eclipse_chain_free(eclipse_chain_t *chain);
uint64_t eclipse_chain_subsidy(uint64_t height);
eclipse_error_t eclipse_chain_genesis_hash(uint8_t out[32]);
eclipse_error_t eclipse_chain_tip(const eclipse_chain_t *chain,
                                 uint8_t hash[32], uint64_t *height);
/* Finds an output only in the current canonical branch. */
eclipse_error_t eclipse_chain_find_utxo(const eclipse_chain_t *chain,
    const uint8_t txid[32], uint32_t index, eclipse_tx_output_t *out,
    bool *found);
/* Build a candidate on the tip or an existing side branch. Candidate fees and
 * reward are computed from that parent's validated state. No mining occurs. */
eclipse_error_t eclipse_chain_make_candidate(const eclipse_chain_t *chain,
    const uint8_t parent_hash[32], uint64_t timestamp,
    const eclipse_tx_output_t *miner_destination,
    const eclipse_tx_t *const *transactions, size_t count,
    eclipse_block_t **out);
/* Rejects invalid blocks without changing any branch. On success, a higher
 * work branch becomes canonical; equal work uses the smallest tip hash. */
eclipse_error_t eclipse_chain_accept(eclipse_chain_t *chain,
                                     const eclipse_block_t *block,
                                     bool *became_tip);
/* A future transport can request validated blocks by hash. Returned object is
 * independently owned by the caller. */
eclipse_error_t eclipse_chain_get_block(const eclipse_chain_t *chain,
                                        const uint8_t hash[32],
                                        eclipse_block_t **out);

#endif
