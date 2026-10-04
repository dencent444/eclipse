#include "utxo_internal.h"
#include "../log.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t txid[ECLIPSE_TX_ID_SIZE];
    uint32_t index;
    eclipse_tx_output_t output;
} utxo_entry_t;

struct eclipse_utxo_set {
    utxo_entry_t *entries;
    size_t count;
    size_t capacity;
    /* Open addressing: zero is empty, SIZE_MAX is a deletion marker, and
     * every other slot stores a dense entry index plus one. */
    size_t *slots;
    size_t slot_capacity;
    size_t tombstones;
    uint64_t hash_seed;
};

static uint64_t outpoint_hash(const eclipse_utxo_set_t *set,
                              const uint8_t txid[ECLIPSE_TX_ID_SIZE],
                              uint32_t index)
{
    /* txids are SHA3 digests. A local random seed makes deliberate table
     * collision grinding harder without affecting consensus-visible state. */
    uint64_t hash = set->hash_seed ^ UINT64_C(14695981039346656037);
    for (size_t i = 0; i < ECLIPSE_TX_ID_SIZE; ++i) {
        hash ^= txid[i];
        hash *= UINT64_C(1099511628211);
    }
    for (unsigned i = 0; i < 4; ++i) {
        hash ^= (uint8_t)(index >> (i * 8));
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static size_t find_slot(const eclipse_utxo_set_t *set,
                        const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index)
{
    if (set->slot_capacity == 0) return SIZE_MAX;
    size_t mask = set->slot_capacity - 1;
    size_t slot = (size_t)outpoint_hash(set, txid, index) & mask;
    for (size_t probes = 0; probes < set->slot_capacity; ++probes) {
        size_t value = set->slots[slot];
        if (value == 0) return SIZE_MAX;
        if (value != SIZE_MAX) {
            const utxo_entry_t *entry = &set->entries[value - 1];
            if (entry->index == index &&
                memcmp(entry->txid, txid, ECLIPSE_TX_ID_SIZE) == 0)
                return slot;
        }
        slot = (slot + 1) & mask;
    }
    return SIZE_MAX;
}

static utxo_entry_t *lookup(const eclipse_utxo_set_t *set,
                            const uint8_t txid[ECLIPSE_TX_ID_SIZE],
                            uint32_t index)
{
    size_t slot = find_slot(set, txid, index);
    return slot == SIZE_MAX ? NULL : &set->entries[set->slots[slot] - 1];
}

/* Call after allocating entry capacity and before any transaction mutation.
 * Rebuilding also clears deletion markers, preserving bounded probe length. */
static eclipse_error_t reserve_slots(eclipse_utxo_set_t *set, size_t needed)
{
    if (needed > SIZE_MAX / 2) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    size_t capacity = set->slot_capacity == 0 ? 16 : set->slot_capacity;
    while (capacity < needed * 2) {
        if (capacity > SIZE_MAX / 2) return ECLIPSE_ERROR_OUT_OF_MEMORY;
        capacity *= 2;
    }
    if (capacity == set->slot_capacity &&
        set->tombstones <= capacity / 4) return ECLIPSE_SUCCESS;
    if (capacity > SIZE_MAX / sizeof(*set->slots))
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    size_t *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    size_t mask = capacity - 1;
    for (size_t i = 0; i < set->count; ++i) {
        const utxo_entry_t *entry = &set->entries[i];
        size_t slot = (size_t)outpoint_hash(set, entry->txid,
                                            entry->index) & mask;
        while (slots[slot] != 0) slot = (slot + 1) & mask;
        slots[slot] = i + 1;
    }
    free(set->slots);
    set->slots = slots;
    set->slot_capacity = capacity;
    set->tombstones = 0;
    ECLIPSE_LOG_INFO(5, "UTXO lookup index rebuilt for %zu live outputs",
                     set->count);
    return ECLIPSE_SUCCESS;
}

/* Insertion is infallible after reserve_slots. Caller already validated the
 * key, duplicate outpoint and entry capacity. */
static void insert_unchecked(eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index,
    const eclipse_tx_output_t *output)
{
    size_t mask = set->slot_capacity - 1;
    size_t slot = (size_t)outpoint_hash(set, txid, index) & mask;
    size_t first_tombstone = SIZE_MAX;
    while (set->slots[slot] != 0) {
        if (set->slots[slot] == SIZE_MAX && first_tombstone == SIZE_MAX)
            first_tombstone = slot;
        slot = (slot + 1) & mask;
    }
    if (first_tombstone != SIZE_MAX) {
        slot = first_tombstone;
        --set->tombstones;
    }
    utxo_entry_t *entry = &set->entries[set->count];
    memcpy(entry->txid, txid, ECLIPSE_TX_ID_SIZE);
    entry->index = index;
    entry->output = *output;
    set->slots[slot] = ++set->count;
}

/* Remove an input and keep the live array dense. The moved final entry's
 * bucket is updated before its old array position is forgotten. */
static void remove_unchecked(eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index)
{
    size_t slot = find_slot(set, txid, index);
    size_t removed = set->slots[slot] - 1;
    set->slots[slot] = SIZE_MAX;
    ++set->tombstones;
    size_t last = set->count - 1;
    if (removed != last) {
        utxo_entry_t moved = set->entries[last];
        size_t moved_slot = find_slot(set, moved.txid, moved.index);
        set->entries[removed] = moved;
        set->slots[moved_slot] = removed + 1;
    }
    --set->count;
}

/* Grow before changing any live output. Allocation failure leaves the set's
 * externally visible contents in their original state. */
static eclipse_error_t reserve(eclipse_utxo_set_t *set, size_t needed)
{
    if (needed <= set->capacity) return ECLIPSE_SUCCESS;
    if (needed > SIZE_MAX / sizeof(*set->entries))
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    size_t capacity = set->capacity == 0 ? 16 : set->capacity;
    while (capacity < needed) {
        if (capacity > (SIZE_MAX / sizeof(*set->entries)) / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    utxo_entry_t *new_entries = realloc(set->entries,
                                         capacity * sizeof(*new_entries));
    if (new_entries == NULL) {
        ECLIPSE_LOG_ERROR("UTXO set allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    set->entries = new_entries;
    set->capacity = capacity;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_utxo_set_create(eclipse_utxo_set_t **out)
{
    if (out == NULL) {
        ECLIPSE_LOG_WARNING("UTXO set creation output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = calloc(1, sizeof(**out));
    if (*out == NULL) {
        ECLIPSE_LOG_ERROR("UTXO set allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    if (RAND_bytes((uint8_t *)&(*out)->hash_seed,
                   sizeof((*out)->hash_seed)) != 1) {
        free(*out);
        *out = NULL;
        ECLIPSE_LOG_ERROR("UTXO lookup seed generation failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    ECLIPSE_LOG_INFO(3, "empty developer UTXO set created");
    return ECLIPSE_SUCCESS;
}

void eclipse_utxo_set_free(eclipse_utxo_set_t *set)
{
    if (set == NULL) return;
    free(set->slots);
    free(set->entries);
    free(set);
    ECLIPSE_LOG_INFO(3, "developer UTXO set released");
}

size_t eclipse_utxo_set_count(const eclipse_utxo_set_t *set)
{
    return set == NULL ? 0 : set->count;
}

eclipse_error_t eclipse_utxo_set_clone(const eclipse_utxo_set_t *source,
                                      eclipse_utxo_set_t **out)
{
    if (source == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    eclipse_utxo_set_t *copy = NULL;
    eclipse_error_t status = eclipse_utxo_set_create(&copy);
    if (status != ECLIPSE_SUCCESS) return status;
    copy->hash_seed = source->hash_seed;
    status = reserve(copy, source->count);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_utxo_set_free(copy);
        return status;
    }
    if (source->count != 0)
        memcpy(copy->entries, source->entries,
               source->count * sizeof(*copy->entries));
    copy->count = source->count;
    /* Rebuild after copying: slot values refer to this dense entry array. */
    status = reserve_slots(copy, copy->count);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_utxo_set_free(copy);
        return status;
    }
    *out = copy;
    ECLIPSE_LOG_INFO(5, "UTXO branch snapshot cloned");
    return ECLIPSE_SUCCESS;
}

/* Shared low-level output insertion. Only the chain validates a reward amount;
 * the public seed helper remains an explicitly local test fixture. */
static eclipse_error_t insert_unspent(eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index,
    const eclipse_tx_output_t *output)
{
    if (set == NULL || txid == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("UTXO insertion rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    eclipse_ml_dsa_info_t info;
    if (output->amount == 0 ||
        !eclipse_ml_dsa_info(output->scheme, &info) ||
        output->public_key_length != info.public_key_size ||
        lookup(set, txid, index) != NULL) {
        ECLIPSE_LOG_WARNING("UTXO insertion rejected malformed or duplicate output");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_ml_dsa_key_t *checked = NULL;
    eclipse_error_t status = eclipse_ml_dsa_import_public(
        output->scheme, output->public_key, output->public_key_length, &checked);
    eclipse_ml_dsa_key_free(checked);
    if (status != ECLIPSE_SUCCESS) return status;
    if (set->count == SIZE_MAX) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    status = reserve(set, set->count + 1);
    if (status != ECLIPSE_SUCCESS) return status;
    status = reserve_slots(set, set->count + 1);
    if (status != ECLIPSE_SUCCESS) return status;
    insert_unchecked(set, txid, index, output);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_utxo_set_seed_dev(eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index,
    const eclipse_tx_output_t *output)
{
    eclipse_error_t status = insert_unspent(set, txid, index, output);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(2, "developer UTXO test seed inserted");
    return status;
}

eclipse_error_t eclipse_utxo_set_credit_reward(eclipse_utxo_set_t *set,
    const uint8_t id[ECLIPSE_TX_ID_SIZE], const eclipse_tx_output_t *output)
{
    eclipse_error_t status = insert_unspent(set, id, 0, output);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(3, "validated block reward credited to branch state");
    return status;
}

eclipse_error_t eclipse_utxo_set_find(const eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index,
    eclipse_tx_output_t *out, bool *found)
{
    if (set == NULL || txid == NULL || out == NULL || found == NULL) {
        ECLIPSE_LOG_WARNING("UTXO lookup rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *found = false;
    utxo_entry_t *entry = lookup(set, txid, index);
    if (entry != NULL) {
        *out = entry->output;
        *found = true;
    }
    ECLIPSE_LOG_INFO(5, *found ? "unspent output found" : "unspent output absent");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tx_validate(const eclipse_tx_t *tx,
                                    const eclipse_utxo_set_t *set, bool *valid)
{
    if (tx == NULL || set == NULL || valid == NULL) {
        ECLIPSE_LOG_WARNING("transaction validation rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *valid = false;
    /* The same canonical format check applies to constructed and decoded
       objects. A caller cannot bypass count, network, or signature lengths. */
    uint8_t wire[ECLIPSE_TX_MAX_WIRE_SIZE];
    size_t wire_length = 0;
    eclipse_error_t status = eclipse_tx_serialize(tx, wire, sizeof(wire),
                                                  &wire_length);
    if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) return ECLIPSE_SUCCESS;
    if (status != ECLIPSE_SUCCESS) return status;

    uint64_t output_total = tx->fee;
    for (size_t i = 0; i < tx->output_count; ++i) {
        const eclipse_tx_output_t *output = &tx->outputs[i];
        if (UINT64_MAX - output_total < output->amount) {
            ECLIPSE_LOG_INFO(4, "transaction rejected: output sum overflows");
            return ECLIPSE_SUCCESS;
        }
        output_total += output->amount;
        eclipse_ml_dsa_key_t *checked = NULL;
        status = eclipse_ml_dsa_import_public(output->scheme, output->public_key,
                                               output->public_key_length, &checked);
        eclipse_ml_dsa_key_free(checked);
        if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) return ECLIPSE_SUCCESS;
        if (status != ECLIPSE_SUCCESS) return status;
    }

    uint64_t input_total = 0;
    for (size_t i = 0; i < tx->input_count; ++i) {
        const eclipse_tx_input_t *input = &tx->inputs[i];
        utxo_entry_t *entry = lookup(set, input->txid, input->index);
        if (entry == NULL) {
            ECLIPSE_LOG_INFO(4, "transaction rejected: input missing or spent");
            return ECLIPSE_SUCCESS;
        }
        eclipse_ml_dsa_info_t info;
        if (!eclipse_ml_dsa_info(entry->output.scheme, &info) ||
            input->signature_length != info.signature_size ||
            UINT64_MAX - input_total < entry->output.amount) {
            ECLIPSE_LOG_INFO(4, "transaction rejected: input scheme or sum invalid");
            return ECLIPSE_SUCCESS;
        }
        input_total += entry->output.amount;

        uint8_t message[ECLIPSE_TX_MAX_SIGNING_SIZE];
        size_t message_length = 0;
        status = eclipse_tx_signing_message(tx, i, message, sizeof(message),
                                             &message_length);
        if (status != ECLIPSE_SUCCESS) return status;
        eclipse_ml_dsa_key_t *owner = NULL;
        status = eclipse_ml_dsa_import_public(entry->output.scheme,
                                               entry->output.public_key,
                                               entry->output.public_key_length,
                                               &owner);
        if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) return ECLIPSE_SUCCESS;
        if (status != ECLIPSE_SUCCESS) return status;
        bool signature_valid = false;
        static const uint8_t context[] = ECLIPSE_TX_SIGNATURE_CONTEXT;
        status = eclipse_ml_dsa_verify(owner, message, message_length,
                                        context, sizeof(context) - 1,
                                        input->signature, input->signature_length,
                                        &signature_valid);
        eclipse_ml_dsa_key_free(owner);
        if (status != ECLIPSE_SUCCESS) return status;
        if (!signature_valid) {
            ECLIPSE_LOG_INFO(4, "transaction rejected: input signature invalid");
            return ECLIPSE_SUCCESS;
        }
    }
    if (input_total != output_total) {
        ECLIPSE_LOG_INFO(4, "transaction rejected: value is not conserved");
        return ECLIPSE_SUCCESS;
    }
    *valid = true;
    ECLIPSE_LOG_INFO(3, "transaction validated against developer UTXO state");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tx_apply(const eclipse_tx_t *tx, eclipse_utxo_set_t *set,
                                 uint8_t txid_out[ECLIPSE_TX_ID_SIZE])
{
    if (tx == NULL || set == NULL || txid_out == NULL) {
        ECLIPSE_LOG_WARNING("transaction application rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    bool valid = false;
    eclipse_error_t status = eclipse_tx_validate(tx, set, &valid);
    if (status != ECLIPSE_SUCCESS) return status;
    if (!valid) {
        ECLIPSE_LOG_WARNING("transaction application rejected invalid transfer");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    uint8_t id[ECLIPSE_TX_ID_SIZE];
    status = eclipse_tx_id(tx, id);
    if (status != ECLIPSE_SUCCESS) return status;
    for (size_t i = 0; i < tx->output_count; ++i)
        if (lookup(set, id, (uint32_t)i) != NULL) {
            ECLIPSE_LOG_WARNING("transaction rejected: output ID collides with state");
            return ECLIPSE_ERROR_INVALID_ARGUMENT;
        }
    if (set->count > SIZE_MAX - tx->output_count)
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    status = reserve(set, set->count + tx->output_count);
    if (status != ECLIPSE_SUCCESS) return status;
    status = reserve_slots(set, set->count + tx->output_count);
    if (status != ECLIPSE_SUCCESS) return status;

    /* No failing operation remains: remove spent outputs and insert new ones
     * as one deterministic state transition. Old spent entries are discarded. */
    for (size_t i = 0; i < tx->input_count; ++i)
        remove_unchecked(set, tx->inputs[i].txid, tx->inputs[i].index);
    for (size_t i = 0; i < tx->output_count; ++i)
        insert_unchecked(set, id, (uint32_t)i, &tx->outputs[i]);
    memcpy(txid_out, id, sizeof(id));
    ECLIPSE_LOG_INFO(2, "transaction applied to developer UTXO state");
    return ECLIPSE_SUCCESS;
}
