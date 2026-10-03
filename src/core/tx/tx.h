#ifndef ECLIPSE_TX_H
#define ECLIPSE_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../crypto/ml_dsa.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Developer format IDs. They are deliberately not mainnet consensus rules. */
#define ECLIPSE_TX_VERSION 0u
#define ECLIPSE_TX_DEV_NETWORK_ID UINT32_C(0x45564431) /* ASCII "EVD1" */
#define ECLIPSE_TX_MAX_INPUTS 8u
#define ECLIPSE_TX_MAX_OUTPUTS 8u
#define ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE 2592u
#define ECLIPSE_TX_MAX_SIGNATURE_SIZE 4627u
#define ECLIPSE_TX_ID_SIZE 32u
#define ECLIPSE_TX_MAX_WIRE_SIZE 58163u
#define ECLIPSE_TX_MAX_SIGNING_SIZE 21154u
#define ECLIPSE_TX_SIGNATURE_CONTEXT "ECLIPSE/DEV/TX/V0"

typedef struct {
    uint8_t txid[ECLIPSE_TX_ID_SIZE];
    uint32_t index;
    size_t signature_length;
    uint8_t signature[ECLIPSE_TX_MAX_SIGNATURE_SIZE];
} eclipse_tx_input_t;

typedef struct {
    uint64_t amount;
    eclipse_ml_dsa_scheme_t scheme;
    size_t public_key_length;
    uint8_t public_key[ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE];
} eclipse_tx_output_t;

typedef struct eclipse_tx {
    uint8_t version;
    uint32_t network_id;
    uint8_t input_count;
    uint8_t output_count;
    uint64_t fee;
    eclipse_tx_input_t inputs[ECLIPSE_TX_MAX_INPUTS];
    eclipse_tx_output_t outputs[ECLIPSE_TX_MAX_OUTPUTS];
} eclipse_tx_t;

/* Initialize a new unsigned developer transaction with fixed version and
 * network ID. Fields can be inspected directly, but every external object
 * still passes full structural and state validation before use. */
eclipse_error_t eclipse_tx_init(eclipse_tx_t *tx);
eclipse_error_t eclipse_tx_add_input(eclipse_tx_t *tx,
                                    const uint8_t prev_txid[ECLIPSE_TX_ID_SIZE],
                                    uint32_t prev_index);
eclipse_error_t eclipse_tx_add_output(eclipse_tx_t *tx, uint64_t amount,
                                     eclipse_ml_dsa_scheme_t scheme,
                                     const uint8_t *public_key,
                                     size_t public_key_length);
eclipse_error_t eclipse_tx_set_fee(eclipse_tx_t *tx, uint64_t fee);

/* Canonical signed wire bytes: ETX0, version, network ID, counts, fee,
 * outpoints with ML-DSA signatures, then amount/key outputs. Integers are
 * unsigned big-endian. Exactly one transaction consumes the whole buffer. */
eclipse_error_t eclipse_tx_serialize(const eclipse_tx_t *tx, uint8_t *output,
                                     size_t capacity, size_t *written);
eclipse_error_t eclipse_tx_deserialize(const uint8_t *input, size_t length,
                                       eclipse_tx_t *out);

/* Signing bytes exclude all signatures but bind every outpoint, output,
 * fee, dev network ID, and this input's index. They are signed with the
 * fixed Pure ML-DSA context above. The public helper lets the wallet's
 * opaque spend key use the same preimage as standalone key experiments. */
eclipse_error_t eclipse_tx_signing_message(const eclipse_tx_t *tx,
                                           size_t input_index,
                                           uint8_t *output, size_t capacity,
                                           size_t *written);
eclipse_error_t eclipse_tx_sign_input(eclipse_tx_t *tx, size_t input_index,
                                      const eclipse_ml_dsa_key_t *private_key);

/* Hash signed wire bytes with a separate domain. Re-signing can change txid.
 * This ID does not prove the transaction is valid or included in a chain. */
eclipse_error_t eclipse_tx_id(const eclipse_tx_t *tx,
                              uint8_t output[ECLIPSE_TX_ID_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
