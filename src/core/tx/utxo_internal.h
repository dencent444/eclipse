#ifndef ECLIPSE_TX_UTXO_INTERNAL_H
#define ECLIPSE_TX_UTXO_INTERNAL_H

#include "utxo.h"

/* Chain-only insertion after its reward amount and block PoW were checked.
 * This does not establish consensus validity by itself. */
eclipse_error_t eclipse_utxo_set_credit_reward(eclipse_utxo_set_t *set,
    const uint8_t id[ECLIPSE_TX_ID_SIZE], const eclipse_tx_output_t *output);

#endif
