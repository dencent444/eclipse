#ifndef ECLIPSE_TX_UTXO_H
#define ECLIPSE_TX_UTXO_H

#include "tx.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eclipse_utxo_set eclipse_utxo_set_t;

eclipse_error_t eclipse_utxo_set_create(eclipse_utxo_set_t **out);
void eclipse_utxo_set_free(eclipse_utxo_set_t *set);
/* Number of currently spendable outputs; spent entries are discarded. */
size_t eclipse_utxo_set_count(const eclipse_utxo_set_t *set);
/* Snapshot for validating a candidate branch without modifying its parent. */
eclipse_error_t eclipse_utxo_set_clone(const eclipse_utxo_set_t *source,
                                      eclipse_utxo_set_t **out);

/* DEV ONLY: seed an independent local UTXO test fixture. The chain never calls
 * this function, and it is not a transaction, mining reward, or network API. */
eclipse_error_t eclipse_utxo_set_seed_dev(eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index,
    const eclipse_tx_output_t *output);

/* Copy an unspent output. Missing/spent outpoints return success with
 * found=false and leave *out unchanged. */
eclipse_error_t eclipse_utxo_set_find(const eclipse_utxo_set_t *set,
    const uint8_t txid[ECLIPSE_TX_ID_SIZE], uint32_t index,
    eclipse_tx_output_t *out, bool *found);

/* A malformed, unauthorized, overspending, or double-spending transaction
 * returns success with valid=false. Resource/provider errors return a code.
 * Validation never mutates the set. */
eclipse_error_t eclipse_tx_validate(const eclipse_tx_t *tx,
                                    const eclipse_utxo_set_t *set, bool *valid);
/* Validate, reserve space, then atomically spend inputs and create outputs.
 * The chain applies this to an isolated parent snapshot for each block. */
eclipse_error_t eclipse_tx_apply(const eclipse_tx_t *tx, eclipse_utxo_set_t *set,
                                 uint8_t txid_out[ECLIPSE_TX_ID_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
