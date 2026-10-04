#include "mempool.h"
#include "../block/chain_internal.h"
#include "../log.h"
#include "utxo.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t id[32];
    eclipse_tx_t *tx;
    size_t wire_bytes;
} pending_entry_t;

struct eclipse_mempool {
    uint8_t observed_tip[32];
    eclipse_utxo_set_t *pending_state;
    pending_entry_t entries[ECLIPSE_MEMPOOL_MAX_TRANSACTIONS];
    size_t count;
    size_t wire_bytes;
};

typedef struct orphan_block {
    eclipse_block_t *block;
    struct orphan_block *next;
} orphan_block_t;

static void clear_pool(eclipse_mempool_t *pool)
{
    for (size_t i = 0; i < pool->count; ++i)
        free(pool->entries[i].tx);
    eclipse_utxo_set_free(pool->pending_state);
    pool->count = 0;
    pool->wire_bytes = 0;
    pool->pending_state = NULL;
}

static void free_orphans(orphan_block_t *head)
{
    while (head != NULL) {
        orphan_block_t *next = head->next;
        eclipse_block_free(head->block);
        free(head);
        head = next;
    }
}

eclipse_error_t eclipse_mempool_create(const eclipse_chain_t *chain,
                                      eclipse_mempool_t **out)
{
    if (chain == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    eclipse_mempool_t *pool = calloc(1, sizeof(*pool));
    if (pool == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    uint64_t height = 0;
    eclipse_error_t status = eclipse_chain_tip(chain, pool->observed_tip,
                                               &height);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_clone_tip_state(chain, &pool->pending_state);
    if (status != ECLIPSE_SUCCESS) {
        free(pool);
        return status;
    }
    *out = pool;
    ECLIPSE_LOG_INFO(2, "empty mempool opened at chain height %llu",
                     (unsigned long long)height);
    return ECLIPSE_SUCCESS;
}

void eclipse_mempool_free(eclipse_mempool_t *pool)
{
    if (pool == NULL) return;
    clear_pool(pool);
    free(pool);
    ECLIPSE_LOG_INFO(3, "mempool released");
}

size_t eclipse_mempool_count(const eclipse_mempool_t *pool)
{
    return pool == NULL ? 0 : pool->count;
}

/* Canonicalize before storing and apply only after capacity/allocations have
 * succeeded. Invalid or conflicting transactions leave pending_state intact. */
static eclipse_error_t add_candidate(eclipse_mempool_t *pool,
    const eclipse_tx_t *tx, bool *accepted)
{
    *accepted = false;
    if (pool->count == ECLIPSE_MEMPOOL_MAX_TRANSACTIONS) return ECLIPSE_SUCCESS;
    uint8_t wire[ECLIPSE_TX_MAX_WIRE_SIZE];
    size_t length = 0;
    eclipse_error_t status = eclipse_tx_serialize(tx, wire, sizeof(wire), &length);
    if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) return ECLIPSE_SUCCESS;
    if (status != ECLIPSE_SUCCESS) return status;
    if (length > ECLIPSE_MEMPOOL_MAX_WIRE_BYTES - pool->wire_bytes)
        return ECLIPSE_SUCCESS;
    uint8_t id[32];
    status = eclipse_tx_id(tx, id);
    if (status != ECLIPSE_SUCCESS) return status;
    for (size_t i = 0; i < pool->count; ++i)
        if (memcmp(pool->entries[i].id, id, 32) == 0)
            return ECLIPSE_SUCCESS;
    eclipse_tx_t *owned = malloc(sizeof(*owned));
    if (owned == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    status = eclipse_tx_deserialize(wire, length, owned);
    if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) {
        free(owned);
        return ECLIPSE_SUCCESS;
    }
    if (status != ECLIPSE_SUCCESS) { free(owned); return status; }
    /* A confirmed or conflicting transaction is an expected result during
     * reorganization. Check it without emitting an application warning. */
    bool valid = false;
    status = eclipse_tx_validate(owned, pool->pending_state, &valid);
    if (status != ECLIPSE_SUCCESS || !valid) {
        free(owned);
        return status;
    }
    uint8_t applied_id[32];
    status = eclipse_tx_apply(owned, pool->pending_state, applied_id);
    if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) {
        free(owned);
        return ECLIPSE_SUCCESS;
    }
    if (status != ECLIPSE_SUCCESS) { free(owned); return status; }
    pending_entry_t *entry = &pool->entries[pool->count++];
    memcpy(entry->id, id, 32);
    entry->tx = owned;
    entry->wire_bytes = length;
    pool->wire_bytes += length;
    *accepted = true;
    ECLIPSE_LOG_INFO(3, "validated transaction admitted to mempool");
    return ECLIPSE_SUCCESS;
}

/* Walk the previously observed branch back to the first block still on the
 * canonical path. Prepending yields oldest-to-newest replay order. */
static eclipse_error_t collect_detached(const eclipse_chain_t *chain,
    const uint8_t old_tip[32], orphan_block_t **head)
{
    *head = NULL;
    uint8_t genesis[32], cursor[32];
    eclipse_error_t status = eclipse_chain_genesis_hash(genesis);
    if (status != ECLIPSE_SUCCESS) return status;
    memcpy(cursor, old_tip, 32);
    while (memcmp(cursor, genesis, 32) != 0 &&
           !eclipse_chain_is_canonical_block(chain, cursor)) {
        eclipse_block_t *block = NULL;
        status = eclipse_chain_get_block(chain, cursor, &block);
        if (status != ECLIPSE_SUCCESS) return status;
        eclipse_block_header_t header;
        status = eclipse_block_header(block, &header);
        if (status != ECLIPSE_SUCCESS) { eclipse_block_free(block); return status; }
        orphan_block_t *node = malloc(sizeof(*node));
        if (node == NULL) {
            eclipse_block_free(block);
            return ECLIPSE_ERROR_OUT_OF_MEMORY;
        }
        node->block = block;
        node->next = *head;
        *head = node;
        memcpy(cursor, header.prev_block_hash, 32);
    }
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_mempool_sync(eclipse_mempool_t *pool,
                                    const eclipse_chain_t *chain)
{
    if (pool == NULL || chain == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t current[32];
    uint64_t height = 0;
    eclipse_error_t status = eclipse_chain_tip(chain, current, &height);
    if (status != ECLIPSE_SUCCESS) return status;
    if (memcmp(current, pool->observed_tip, 32) == 0)
        return ECLIPSE_SUCCESS;
    orphan_block_t *detached = NULL;
    status = collect_detached(chain, pool->observed_tip, &detached);
    if (status != ECLIPSE_SUCCESS) { free_orphans(detached); return status; }
    eclipse_mempool_t next = {0};
    memcpy(next.observed_tip, current, 32);
    status = eclipse_chain_clone_tip_state(chain, &next.pending_state);
    if (status != ECLIPSE_SUCCESS) goto fail;
    for (orphan_block_t *node = detached; node != NULL; node = node->next) {
        size_t count = eclipse_block_transaction_count(node->block);
        for (size_t i = 0; i < count; ++i) {
            eclipse_tx_t *tx = malloc(sizeof(*tx));
            if (tx == NULL) { status = ECLIPSE_ERROR_OUT_OF_MEMORY; goto fail; }
            status = eclipse_block_transaction(node->block, i, tx);
            if (status == ECLIPSE_SUCCESS) {
                bool accepted = false;
                status = add_candidate(&next, tx, &accepted);
            }
            free(tx);
            if (status != ECLIPSE_SUCCESS) goto fail;
        }
    }
    for (size_t i = 0; i < pool->count; ++i) {
        bool accepted = false;
        status = add_candidate(&next, pool->entries[i].tx, &accepted);
        if (status != ECLIPSE_SUCCESS) goto fail;
    }
    eclipse_mempool_t previous = *pool;
    *pool = next;
    clear_pool(&previous);
    free_orphans(detached);
    ECLIPSE_LOG_INFO(2, "mempool reconciled at height %llu: %zu pending",
                     (unsigned long long)height, pool->count);
    return ECLIPSE_SUCCESS;
fail:
    clear_pool(&next);
    free_orphans(detached);
    return status;
}

eclipse_error_t eclipse_mempool_submit(eclipse_mempool_t *pool,
    const eclipse_chain_t *chain, const eclipse_tx_t *tx, bool *accepted)
{
    if (pool == NULL || chain == NULL || tx == NULL || accepted == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *accepted = false;
    eclipse_error_t status = eclipse_mempool_sync(pool, chain);
    if (status != ECLIPSE_SUCCESS) return status;
    status = add_candidate(pool, tx, accepted);
    if (status == ECLIPSE_SUCCESS && !*accepted)
        ECLIPSE_LOG_INFO(4, "transaction not admitted to mempool");
    return status;
}

eclipse_error_t eclipse_mempool_make_candidate(eclipse_mempool_t *pool,
    const eclipse_chain_t *chain, uint64_t timestamp,
    const eclipse_tx_output_t *miner_destination, eclipse_block_t **out)
{
    if (pool == NULL || chain == NULL || miner_destination == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    eclipse_error_t status = eclipse_mempool_sync(pool, chain);
    if (status != ECLIPSE_SUCCESS) return status;
    const eclipse_tx_t *selected[ECLIPSE_BLOCK_MAX_TRANSACTIONS];
    size_t count = pool->count < ECLIPSE_BLOCK_MAX_TRANSACTIONS ?
                   pool->count : ECLIPSE_BLOCK_MAX_TRANSACTIONS;
    for (size_t i = 0; i < count; ++i)
        selected[i] = pool->entries[i].tx;
    return eclipse_chain_make_candidate(chain, pool->observed_tip, timestamp,
                                        miner_destination, selected, count, out);
}
