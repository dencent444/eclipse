#ifndef ECLIPSE_WALLET_H
#define ECLIPSE_WALLET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../crypto/ml_dsa.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ECLIPSE_WALLET_POOL_SIZE 24u
#define ECLIPSE_WALLET_PUBLIC_MAX_SIZE 2592u

typedef enum {
    ECLIPSE_WALLET_RECEIVE = 1,
    ECLIPSE_WALLET_SPEND = 2,
} eclipse_wallet_role_t;

typedef struct eclipse_wallet eclipse_wallet_t;

/* A standalone public key. No role, pool index, master key, or certificate is
 * carried in the network representation, to avoid an unnecessary link. */
typedef struct {
    eclipse_ml_dsa_scheme_t scheme;
    size_t length;
    uint8_t bytes[ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
} eclipse_wallet_public_key_t;

/* Creates two independent master ML-DSA pairs and 24 independently random
 * child pairs per role. Each master signs its own child keys with role/index
 * domain separation. There is no wallet seed or deterministic derivation. */
eclipse_error_t eclipse_wallet_create(eclipse_ml_dsa_scheme_t scheme,
                                      eclipse_wallet_t **out);
void eclipse_wallet_free(eclipse_wallet_t *wallet);

eclipse_error_t eclipse_wallet_master_public(const eclipse_wallet_t *wallet,
                                              eclipse_wallet_role_t role,
                                              eclipse_wallet_public_key_t *out);
eclipse_error_t eclipse_wallet_child_public(const eclipse_wallet_t *wallet,
                                             eclipse_wallet_role_t role,
                                             size_t index,
                                             eclipse_wallet_public_key_t *out);
/* Public certificate bytes for a child. Keeping them separate from the key
 * packet avoids automatically revealing that multiple keys share a master. */
eclipse_error_t eclipse_wallet_child_binding_signature(
    const eclipse_wallet_t *wallet, eclipse_wallet_role_t role, size_t index,
    uint8_t *output, size_t capacity, size_t *written);
/* Anyone with the public master, child, role, index, and signature can check
 * the binding. Passing a different role or index must fail verification. */
eclipse_error_t eclipse_wallet_verify_public_binding(
    const eclipse_wallet_public_key_t *master,
    const eclipse_wallet_public_key_t *child,
    eclipse_wallet_role_t role, size_t index,
    const uint8_t *signature, size_t signature_length, bool *valid);
/* Rechecks the binding stored inside this wallet. */
eclipse_error_t eclipse_wallet_verify_child_binding(const eclipse_wallet_t *wallet,
                                                     eclipse_wallet_role_t role,
                                                     size_t index, bool *valid);

/* Separate, unencrypted Base92 export of ONE expanded master private key.
 * This does not include child private keys and cannot restore the pool. The
 * returned text is secret; the caller must avoid logs and cleanse the buffer.
 * Capacity includes the terminating NUL; *written excludes it. */
size_t eclipse_wallet_master_export_capacity(eclipse_ml_dsa_scheme_t scheme);
eclipse_error_t eclipse_wallet_export_master_base92(const eclipse_wallet_t *wallet,
                                                     eclipse_wallet_role_t role,
                                                     char *output, size_t capacity,
                                                     size_t *written);

/* Versioned developer transport format for ONE public key; not a consensus
 * object. Both binary and Base92 forms contain exactly the same public data. */
size_t eclipse_wallet_public_serialized_size(eclipse_ml_dsa_scheme_t scheme);
eclipse_error_t eclipse_wallet_public_serialize(const eclipse_wallet_public_key_t *key,
                                                 uint8_t *output, size_t capacity,
                                                 size_t *written);
eclipse_error_t eclipse_wallet_public_deserialize(const uint8_t *input, size_t length,
                                                   eclipse_wallet_public_key_t *out);
eclipse_error_t eclipse_wallet_public_to_base92(const eclipse_wallet_public_key_t *key,
                                                 char *output, size_t capacity,
                                                 size_t *written);
eclipse_error_t eclipse_wallet_public_from_base92(const char *text, size_t length,
                                                   eclipse_wallet_public_key_t *out);

#ifdef __cplusplus
}
#endif

#endif
