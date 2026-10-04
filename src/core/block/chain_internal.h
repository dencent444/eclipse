#ifndef ECLIPSE_BLOCK_CHAIN_INTERNAL_H
#define ECLIPSE_BLOCK_CHAIN_INTERNAL_H

#include "chain.h"
#include "../tx/utxo.h"

/* Internal read-only hooks for mempool validation and reorganization. */
eclipse_error_t eclipse_chain_clone_tip_state(const eclipse_chain_t *chain,
                                              eclipse_utxo_set_t **out);
bool eclipse_chain_is_canonical_block(const eclipse_chain_t *chain,
                                      const uint8_t hash[32]);

#endif
