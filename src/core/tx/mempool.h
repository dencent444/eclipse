#ifndef ECLIPSE_TX_MEMPOOL_H
#define ECLIPSE_TX_MEMPOOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "tx.h"
#include "../block/chain.h"

#define ECLIPSE_MEMPOOL_MAX_TRANSACTIONS 64u
#define ECLIPSE_MEMPOOL_MAX_WIRE_BYTES (1024u * 1024u)

typedef struct eclipse_mempool eclipse_mempool_t;

/* The pool is volatile and belongs to one local chain. Transactions are
 * replayed in insertion order so dependent unconfirmed spends can follow
 * their parents. There is no replacement-by-fee policy in developer v0. */
eclipse_error_t eclipse_mempool_create(const eclipse_chain_t *chain,
                                      eclipse_mempool_t **out);
void eclipse_mempool_free(eclipse_mempool_t *pool);
size_t eclipse_mempool_count(const eclipse_mempool_t *pool);
/* Copies one currently pending signed transaction for local peer relay.
 * The caller must still respect its own synchronization around the pool. */
eclipse_error_t eclipse_mempool_transaction(const eclipse_mempool_t *pool,
                                            size_t index, eclipse_tx_t *out);

/* Refresh after a canonical-tip change. Confirmed/conflicting entries are
 * removed; valid transactions from disconnected blocks are reconsidered. */
eclipse_error_t eclipse_mempool_sync(eclipse_mempool_t *pool,
                                    const eclipse_chain_t *chain);
/* accepted=false covers malformed, unauthorized, duplicate, conflicting or
 * capacity-limited transfers; it leaves the existing pool intact. */
eclipse_error_t eclipse_mempool_submit(eclipse_mempool_t *pool,
    const eclipse_chain_t *chain, const eclipse_tx_t *tx, bool *accepted);
/* Build one block from the first up to eight pending transactions. The call
 * refreshes a stale pool first; after block acceptance call sync again. */
eclipse_error_t eclipse_mempool_make_candidate(eclipse_mempool_t *pool,
    const eclipse_chain_t *chain, uint64_t timestamp,
    const eclipse_tx_output_t *miner_destination, eclipse_block_t **out);

#endif
