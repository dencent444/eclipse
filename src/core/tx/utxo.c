#include "utxo.h"
#include "../log.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t txid[ECLIPSE_TX_ID_SIZE];
    uint32_t index;
    eclipse_tx_output_t output;
    bool spent;
} utxo_entry_t;

struct eclipse_utxo_set {
    utxo_entry_t *entries;
    size_t count;
    size_t capacity;
};

static utxo_entry_t *lookup(const eclipse_utxo_set_t *set,
                            const uint8_t txid[ECLIPSE_TX_ID_SIZE],
                            uint32_t index)
{
    for (size_t i = 0; i < set->count; ++i)
        if (set->entries[i].index == index &&
            memcmp(set->entries[i].txid, txid, ECLIPSE_TX_ID_SIZE) == 0)
            return &set->entries[i];
    return NULL;
}

/* Grow before changing any spent bit. That makes an allocation failure leave
 * the entire UTXO set in its original state. */
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
    ECLIPSE_LOG_INFO(3, "empty developer UTXO set created");
    return ECLIPSE_SUCCESS;
}

void eclipse_utxo_set_free(eclipse_utxo_set_t *set)
{
    if (set == NULL) return;
    free(set->entries);
    free(set);
    ECLIPSE_LOG_INFO(3, "developer UTXO set released");
}

/* Explicit test/bootstrap insertion is deliberately outside transaction
 * validation. It cannot be mistaken for an emission or mining rule. */
eclipse_error_t eclipse_utxo_set_seed_dev(eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index,
    const eclipse_tx_output_t *output)
{
    if (set == NULL || txid == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("developer UTXO seed rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    eclipse_ml_dsa_info_t info;
    if (output->amount == 0 ||
        !eclipse_ml_dsa_info(output->scheme, &info) ||
        output->public_key_length != info.public_key_size ||
        lookup(set, txid, index) != NULL) {
        ECLIPSE_LOG_WARNING("developer UTXO seed rejected malformed or duplicate output");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_ml_dsa_key_t *checked = NULL;
    eclipse_error_t status = eclipse_ml_dsa_import_public(
        output->scheme, output->public_key, output->public_key_length, &checked);
    eclipse_ml_dsa_key_free(checked);
    if (status != ECLIPSE_SUCCESS) return status;
    status = reserve(set, set->count + 1);
    if (status != ECLIPSE_SUCCESS) return status;
    utxo_entry_t *entry = &set->entries[set->count++];
    memcpy(entry->txid, txid, ECLIPSE_TX_ID_SIZE);
    entry->index = index;
    entry->output = *output;
    entry->spent = false;
    ECLIPSE_LOG_INFO(2, "developer UTXO seed inserted");
    return ECLIPSE_SUCCESS;
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
    if (entry != NULL && !entry->spent) {
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
        if (entry == NULL || entry->spent) {
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

    /* No failing operation remains after this point: apply all input spends
       and output creations as one deterministic state transition. */
    for (size_t i = 0; i < tx->input_count; ++i)
        lookup(set, tx->inputs[i].txid, tx->inputs[i].index)->spent = true;
    for (size_t i = 0; i < tx->output_count; ++i) {
        utxo_entry_t *entry = &set->entries[set->count++];
        memcpy(entry->txid, id, sizeof(id));
        entry->index = (uint32_t)i;
        entry->output = tx->outputs[i];
        entry->spent = false;
    }
    memcpy(txid_out, id, sizeof(id));
    ECLIPSE_LOG_INFO(2, "transaction applied to developer UTXO state");
    return ECLIPSE_SUCCESS;
}
