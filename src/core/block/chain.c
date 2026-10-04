#include "chain_internal.h"
#include "miner.h"
#include "chain_store.h"
#include "../log.h"
#include "../tx/utxo_internal.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t genesis_domain[] = "ECLIPSE/DEV/GENESIS/V1";

typedef struct {
    uint8_t hash[32];
    eclipse_block_t *block;
    eclipse_utxo_set_t *state;
    uint64_t height;
    uint64_t work;
    size_t parent; /* SIZE_MAX means the virtual genesis anchor. */
} chain_entry_t;

struct eclipse_chain {
    uint8_t genesis[32];
    eclipse_utxo_set_t *genesis_state;
    chain_entry_t *entries;
    size_t count;
    size_t capacity;
    size_t tip; /* SIZE_MAX denotes the empty genesis anchor. */
    eclipse_chain_store_t *store; /* NULL for a temporary in-memory chain. */
};

static eclipse_error_t hash_bytes(const uint8_t *bytes, size_t size,
                                  uint8_t output[32])
{
    size_t written = 0;
    if (EVP_Q_digest(NULL, "SHA3-256", NULL, bytes, size,
                     output, &written) != 1 || written != 32)
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_chain_genesis_hash(uint8_t out[32])
{
    if (out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    return hash_bytes(genesis_domain, sizeof(genesis_domain) - 1, out);
}

uint64_t eclipse_chain_subsidy(uint64_t height)
{
    if (height == 0) return 0;
    uint64_t halvings = (height - 1) / ECLIPSE_DEV_HALVING_INTERVAL;
    return halvings >= 64 ? 0 : ECLIPSE_DEV_INITIAL_SUBSIDY >> halvings;
}

static size_t find_index(const eclipse_chain_t *chain, const uint8_t hash[32])
{
    for (size_t i = 0; i < chain->count; ++i)
        if (memcmp(chain->entries[i].hash, hash, 32) == 0) return i;
    return SIZE_MAX;
}

static bool parent_info(const eclipse_chain_t *chain,
                        const uint8_t hash[32],
                        const eclipse_utxo_set_t **state,
                        uint64_t *height, uint64_t *timestamp,
                        uint64_t *work)
{
    if (memcmp(hash, chain->genesis, 32) == 0) {
        *state = chain->genesis_state;
        *height = 0;
        *timestamp = 0;
        *work = 0;
        return true;
    }
    size_t i = find_index(chain, hash);
    if (i == SIZE_MAX) return false;
    *state = chain->entries[i].state;
    *height = chain->entries[i].height;
    *work = chain->entries[i].work;
    eclipse_block_header_t header;
    if (eclipse_block_header(chain->entries[i].block, &header) != ECLIPSE_SUCCESS)
        return false;
    *timestamp = header.timestamp;
    return true;
}

eclipse_error_t eclipse_chain_create(eclipse_chain_t **out)
{
    if (out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    eclipse_chain_t *chain = calloc(1, sizeof(*chain));
    if (chain == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    chain->tip = SIZE_MAX;
    eclipse_error_t status = eclipse_chain_genesis_hash(chain->genesis);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_utxo_set_create(&chain->genesis_state);
    if (status != ECLIPSE_SUCCESS) {
        free(chain);
        return status;
    }
    *out = chain;
    ECLIPSE_LOG_INFO(2, "empty dev chain created: zero-supply genesis");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_chain_open(const char *path, eclipse_chain_t **out)
{
    if (path == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    eclipse_chain_t *chain = NULL;
    eclipse_error_t status = eclipse_chain_create(&chain);
    if (status != ECLIPSE_SUCCESS) return status;
    eclipse_chain_store_t *store = NULL;
    status = eclipse_chain_store_open(path, chain->genesis, &store);
    if (status != ECLIPSE_SUCCESS) goto fail;
    /* The store is attached only after replay, so validation cannot append
     * records while reconstructing the chain from existing journal bytes. */
    for (;;) {
        eclipse_block_t *block = NULL;
        bool end = false;
        status = eclipse_chain_store_next(store, &block, &end);
        if (status != ECLIPSE_SUCCESS || end) break;
        bool became_tip = false;
        status = eclipse_chain_accept(chain, block, &became_tip);
        eclipse_block_free(block);
        if (status != ECLIPSE_SUCCESS) {
            if (status == ECLIPSE_ERROR_INVALID_ARGUMENT)
                status = ECLIPSE_ERROR_IO;
            ECLIPSE_LOG_WARNING("saved chain failed independent replay validation");
            break;
        }
    }
    if (status != ECLIPSE_SUCCESS) {
        eclipse_chain_store_close(store);
        goto fail;
    }
    chain->store = store;
    *out = chain;
    ECLIPSE_LOG_INFO(2, "saved dev chain replay completed");
    return ECLIPSE_SUCCESS;
fail:
    eclipse_chain_free(chain);
    return status;
}

void eclipse_chain_free(eclipse_chain_t *chain)
{
    if (chain == NULL) return;
    eclipse_chain_store_close(chain->store);
    for (size_t i = 0; i < chain->count; ++i) {
        eclipse_block_free(chain->entries[i].block);
        eclipse_utxo_set_free(chain->entries[i].state);
    }
    free(chain->entries);
    eclipse_utxo_set_free(chain->genesis_state);
    free(chain);
    ECLIPSE_LOG_INFO(3, "dev chain released");
}

eclipse_error_t eclipse_chain_tip(const eclipse_chain_t *chain,
                                  uint8_t hash[32], uint64_t *height)
{
    if (chain == NULL || hash == NULL || height == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    if (chain->tip == SIZE_MAX) {
        memcpy(hash, chain->genesis, 32);
        *height = 0;
    } else {
        memcpy(hash, chain->entries[chain->tip].hash, 32);
        *height = chain->entries[chain->tip].height;
    }
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_chain_canonical_hash_at_height(
    const eclipse_chain_t *chain, uint64_t height, uint8_t out[32])
{
    if (chain == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (height == 0) {
        memcpy(out, chain->genesis, 32);
        return ECLIPSE_SUCCESS;
    }
    if (chain->tip == SIZE_MAX || height > chain->entries[chain->tip].height)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    /* Parent indexes are immutable after acceptance, including on reorgs. */
    for (size_t i = chain->tip; i != SIZE_MAX; i = chain->entries[i].parent) {
        if (chain->entries[i].height == height) {
            memcpy(out, chain->entries[i].hash, 32);
            return ECLIPSE_SUCCESS;
        }
    }
    return ECLIPSE_ERROR_INVALID_ARGUMENT;
}

bool eclipse_chain_has_block(const eclipse_chain_t *chain, const uint8_t hash[32])
{
    return chain != NULL && hash != NULL && find_index(chain, hash) != SIZE_MAX;
}

eclipse_error_t eclipse_chain_block_height(const eclipse_chain_t *chain,
                                           const uint8_t hash[32],
                                           uint64_t *height)
{
    if (chain == NULL || hash == NULL || height == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    if (memcmp(hash, chain->genesis, 32) == 0) { *height = 0; return ECLIPSE_SUCCESS; }
    size_t i = find_index(chain, hash);
    if (i == SIZE_MAX) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    *height = chain->entries[i].height;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_chain_last_accepted(const eclipse_chain_t *chain,
                                            uint8_t hash[32], uint64_t *height)
{
    if (chain == NULL || hash == NULL || height == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    if (chain->count == 0) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    const chain_entry_t *last = &chain->entries[chain->count - 1];
    memcpy(hash, last->hash, 32);
    *height = last->height;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_chain_find_utxo(const eclipse_chain_t *chain,
    const uint8_t txid[32], uint32_t index, eclipse_tx_output_t *out,
    bool *found)
{
    if (chain == NULL || txid == NULL || out == NULL || found == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    const eclipse_utxo_set_t *state = chain->tip == SIZE_MAX ?
        chain->genesis_state : chain->entries[chain->tip].state;
    return eclipse_utxo_set_find(state, txid, index, out, found);
}

eclipse_error_t eclipse_chain_clone_tip_state(const eclipse_chain_t *chain,
                                              eclipse_utxo_set_t **out)
{
    if (chain == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    const eclipse_utxo_set_t *state = chain->tip == SIZE_MAX ?
        chain->genesis_state : chain->entries[chain->tip].state;
    return eclipse_utxo_set_clone(state, out);
}

bool eclipse_chain_is_canonical_block(const eclipse_chain_t *chain,
                                      const uint8_t hash[32])
{
    if (chain == NULL || hash == NULL) return false;
    for (size_t i = chain->tip; i != SIZE_MAX; i = chain->entries[i].parent)
        if (memcmp(chain->entries[i].hash, hash, 32) == 0) return true;
    return false;
}

static eclipse_error_t clone_block(const eclipse_block_t *source,
                                   eclipse_block_t **out)
{
    uint8_t *wire = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
    if (wire == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    size_t length = 0;
    eclipse_error_t status = eclipse_block_serialize(
        source, wire, ECLIPSE_BLOCK_MAX_WIRE_SIZE, &length);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_block_deserialize(wire, length, out);
    free(wire);
    return status;
}

eclipse_error_t eclipse_chain_get_block(const eclipse_chain_t *chain,
                                        const uint8_t hash[32],
                                        eclipse_block_t **out)
{
    if (chain == NULL || hash == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    size_t i = find_index(chain, hash);
    if (i == SIZE_MAX) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    return clone_block(chain->entries[i].block, out);
}

eclipse_error_t eclipse_chain_make_candidate(const eclipse_chain_t *chain,
    const uint8_t parent_hash[32], uint64_t timestamp,
    const eclipse_tx_output_t *miner_destination,
    const eclipse_tx_t *const *transactions, size_t count,
    eclipse_block_t **out)
{
    if (chain == NULL || parent_hash == NULL || miner_destination == NULL ||
        out == NULL || (count != 0 && transactions == NULL))
        return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (count > ECLIPSE_BLOCK_MAX_TRANSACTIONS)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    const eclipse_utxo_set_t *parent = NULL;
    uint64_t height = 0, previous_time = 0, parent_work = 0;
    if (!parent_info(chain, parent_hash, &parent, &height, &previous_time,
                     &parent_work) ||
        height == UINT64_MAX ||
        UINT64_MAX - parent_work < (UINT64_C(1) << ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS) ||
        timestamp <= previous_time ||
        timestamp - previous_time > ECLIPSE_DEV_MAX_BLOCK_TIME_STEP)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_utxo_set_t *working = NULL;
    eclipse_error_t status = eclipse_utxo_set_clone(parent, &working);
    if (status != ECLIPSE_SUCCESS) return status;
    uint64_t fees = 0;
    for (size_t i = 0; i < count; ++i) {
        if (transactions[i] == NULL || UINT64_MAX - fees < transactions[i]->fee) {
            status = ECLIPSE_ERROR_INVALID_ARGUMENT;
            goto done;
        }
        uint8_t id[32];
        status = eclipse_tx_apply(transactions[i], working, id);
        if (status != ECLIPSE_SUCCESS) goto done;
        fees += transactions[i]->fee;
    }
    eclipse_tx_output_t payout = *miner_destination;
    uint64_t subsidy = eclipse_chain_subsidy(height + 1);
    if (UINT64_MAX - subsidy < fees) {
        status = ECLIPSE_ERROR_INVALID_ARGUMENT;
        goto done;
    }
    payout.amount = subsidy + fees;
    status = eclipse_block_create(parent_hash, timestamp, &payout, out);
    if (status != ECLIPSE_SUCCESS) goto done;
    for (size_t i = 0; i < count; ++i) {
        status = eclipse_block_add_transaction(*out, transactions[i]);
        if (status != ECLIPSE_SUCCESS) {
            eclipse_block_free(*out);
            *out = NULL;
            goto done;
        }
    }
    ECLIPSE_LOG_INFO(3, "candidate prepared at height %llu, fees=%llu",
                     (unsigned long long)(height + 1),
                     (unsigned long long)fees);
done:
    eclipse_utxo_set_free(working);
    return status;
}

eclipse_error_t eclipse_chain_accept(eclipse_chain_t *chain,
                                     const eclipse_block_t *block,
                                     bool *became_tip)
{
    if (chain == NULL || block == NULL || became_tip == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *became_tip = false;
    eclipse_block_header_t header;
    eclipse_error_t status = eclipse_block_header(block, &header);
    if (status != ECLIPSE_SUCCESS) return status;
    const eclipse_utxo_set_t *parent = NULL;
    uint64_t height = 0, previous_time = 0, parent_work = 0;
    if (!parent_info(chain, header.prev_block_hash, &parent,
                     &height, &previous_time, &parent_work) || height == UINT64_MAX ||
        UINT64_MAX - parent_work < (UINT64_C(1) << ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS) ||
        header.version != ECLIPSE_BLOCK_VERSION ||
        header.difficulty != ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS ||
        header.timestamp <= previous_time ||
        header.timestamp - previous_time > ECLIPSE_DEV_MAX_BLOCK_TIME_STEP)
        goto invalid;
    uint8_t root[32], hash[32];
    status = eclipse_block_compute_root(block, root);
    if (status != ECLIPSE_SUCCESS) return status;
    if (memcmp(root, header.merkle_root, 32) != 0) goto invalid;
    status = eclipse_block_hash(block, hash);
    if (status != ECLIPSE_SUCCESS) return status;
    if (!eclipse_pow_hash_meets_target(hash, header.difficulty) ||
        find_index(chain, hash) != SIZE_MAX)
        goto invalid;

    /* Each fork inherits the UTXOs of its own parent. Validate on a private
     * copy so even a late failure cannot alter any accepted branch. */
    eclipse_utxo_set_t *working = NULL;
    status = eclipse_utxo_set_clone(parent, &working);
    if (status != ECLIPSE_SUCCESS) return status;
    uint64_t fees = 0;
    size_t count = eclipse_block_transaction_count(block);
    if (count > ECLIPSE_BLOCK_MAX_TRANSACTIONS) goto invalid_state;
    /* Transaction order is part of consensus: a later transfer may spend an
     * earlier output, while a double spend fails on this same snapshot. */
    for (size_t i = 0; i < count; ++i) {
        eclipse_tx_t *tx = malloc(sizeof(*tx));
        if (tx == NULL) { status = ECLIPSE_ERROR_OUT_OF_MEMORY; goto fail_state; }
        status = eclipse_block_transaction(block, i, tx);
        if (status == ECLIPSE_SUCCESS && UINT64_MAX - fees < tx->fee)
            status = ECLIPSE_ERROR_INVALID_ARGUMENT;
        if (status == ECLIPSE_SUCCESS) {
            uint8_t id[32];
            status = eclipse_tx_apply(tx, working, id);
        }
        if (status == ECLIPSE_SUCCESS) fees += tx->fee;
        free(tx);
        if (status != ECLIPSE_SUCCESS) goto fail_state;
    }
    eclipse_tx_output_t payout;
    status = eclipse_block_reward(block, &payout);
    if (status != ECLIPSE_SUCCESS) goto fail_state;
    uint64_t subsidy = eclipse_chain_subsidy(height + 1);
    if (UINT64_MAX - subsidy < fees || payout.amount != subsidy + fees)
        goto invalid_state;
    /* Credit the reward after ordinary transactions. This both enforces the
     * exact issuance rule and prevents spending this block's reward in it. */
    uint8_t payout_id[32];
    status = eclipse_block_reward_id(block, payout_id);
    if (status != ECLIPSE_SUCCESS) goto fail_state;
    status = eclipse_utxo_set_credit_reward(working, payout_id, &payout);
    if (status != ECLIPSE_SUCCESS) goto fail_state;
    /* The caller retains ownership of its candidate; store a canonical copy
     * only after all validation and state transitions have succeeded. */
    eclipse_block_t *owned = NULL;
    status = clone_block(block, &owned);
    if (status != ECLIPSE_SUCCESS) goto fail_state;
    if (chain->count == chain->capacity) {
        size_t capacity = chain->capacity == 0 ? 8 : chain->capacity * 2;
        if (capacity < chain->capacity ||
            capacity > SIZE_MAX / sizeof(*chain->entries)) {
            status = ECLIPSE_ERROR_OUT_OF_MEMORY;
            eclipse_block_free(owned);
            goto fail_state;
        }
        chain_entry_t *grown = realloc(chain->entries,
                                       capacity * sizeof(*chain->entries));
        if (grown == NULL) {
            status = ECLIPSE_ERROR_OUT_OF_MEMORY;
            eclipse_block_free(owned);
            goto fail_state;
        }
        chain->entries = grown;
        chain->capacity = capacity;
    }
    /* Commit the validated packet before publishing it as an accepted block.
     * A failed append leaves the tip and all branch states unchanged. */
    if (chain->store != NULL) {
        status = eclipse_chain_store_append(chain->store, owned);
        if (status != ECLIPSE_SUCCESS) {
            eclipse_block_free(owned);
            goto fail_state;
        }
    }
    size_t slot = chain->count++;
    chain_entry_t *entry = &chain->entries[slot];
    memcpy(entry->hash, hash, 32);
    entry->height = height + 1;
    entry->work = parent_work +
                  (UINT64_C(1) << ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS);
    entry->parent = memcmp(header.prev_block_hash, chain->genesis, 32) == 0 ?
                    SIZE_MAX : find_index(chain, header.prev_block_hash);
    entry->state = working;
    entry->block = owned;
    /* Fixed dev difficulty makes work proportional to height today. Keep the
     * explicit accumulator so fork choice states the intended rule. */
    if (chain->tip == SIZE_MAX ||
        entry->work > chain->entries[chain->tip].work ||
        (entry->work == chain->entries[chain->tip].work &&
         memcmp(hash, chain->entries[chain->tip].hash, 32) < 0)) {
        chain->tip = slot;
        *became_tip = true;
        ECLIPSE_LOG_INFO(2, "canonical dev tip selected at height %llu",
                         (unsigned long long)entry->height);
    } else ECLIPSE_LOG_INFO(3, "valid side-branch block retained");
    return ECLIPSE_SUCCESS;
invalid_state:
    status = ECLIPSE_ERROR_INVALID_ARGUMENT;
fail_state:
    eclipse_utxo_set_free(working);
    if (status == ECLIPSE_ERROR_INVALID_ARGUMENT)
        ECLIPSE_LOG_WARNING("invalid block state transition rejected");
    return status;
invalid:
    ECLIPSE_LOG_WARNING("invalid block header, parent, or PoW rejected");
    return ECLIPSE_ERROR_INVALID_ARGUMENT;
}
