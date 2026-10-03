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
typedef struct eclipse_wallet_recovery eclipse_wallet_recovery_t;
typedef struct eclipse_wallet_domain eclipse_wallet_domain_t;

/* A standalone public key. No role, pool index, master key, or certificate is
 * carried in the network representation, to avoid an unnecessary link. */
typedef struct {
    eclipse_ml_dsa_scheme_t scheme;
    size_t length;
    uint8_t bytes[ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
} eclipse_wallet_public_key_t;

/* Generates one random recovery root and opens both derived key domains.
 * The root is returned separately and is NEVER stored in the wallet object.
 * Free it promptly after an intentional manual export. No backup file is made. */
eclipse_error_t eclipse_wallet_create(eclipse_ml_dsa_scheme_t scheme,
                                      eclipse_wallet_recovery_t **recovery_out,
                                      eclipse_wallet_t **wallet_out);
/* Rebuilds both pools from the same root, or only one from a role secret. */
eclipse_error_t eclipse_wallet_open(const eclipse_wallet_recovery_t *recovery,
                                    eclipse_wallet_t **out);
eclipse_error_t eclipse_wallet_open_domain(const eclipse_wallet_domain_t *domain,
                                           eclipse_wallet_t **out);
void eclipse_wallet_free(eclipse_wallet_t *wallet);

/* A root restores both domains. A receive domain cannot derive spend keys.
 * These types are opaque so callers cannot accidentally print raw secrets. */
eclipse_error_t eclipse_wallet_recovery_generate(eclipse_ml_dsa_scheme_t scheme,
                                                 eclipse_wallet_recovery_t **out);
eclipse_error_t eclipse_wallet_derive_domain(const eclipse_wallet_recovery_t *recovery,
                                             eclipse_wallet_role_t role,
                                             eclipse_wallet_domain_t **out);
void eclipse_wallet_recovery_free(eclipse_wallet_recovery_t *recovery);
void eclipse_wallet_domain_free(eclipse_wallet_domain_t *domain);

/* Explicit, unencrypted Base92 exports/imports. They never write a file.
 * Root export restores both roles; domain export restores only its role.
 * The caller must protect and cleanse exported text. Capacity includes NUL. */
size_t eclipse_wallet_recovery_export_capacity(void);
eclipse_error_t eclipse_wallet_recovery_export_base92(
    const eclipse_wallet_recovery_t *recovery, char *output, size_t capacity,
    size_t *written);
eclipse_error_t eclipse_wallet_recovery_import_base92(
    const char *text, size_t length, eclipse_wallet_recovery_t **out);
size_t eclipse_wallet_domain_export_capacity(void);
eclipse_error_t eclipse_wallet_domain_export_base92(
    const eclipse_wallet_domain_t *domain, char *output, size_t capacity,
    size_t *written);
eclipse_error_t eclipse_wallet_domain_import_base92(
    const char *text, size_t length, eclipse_wallet_domain_t **out);

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
