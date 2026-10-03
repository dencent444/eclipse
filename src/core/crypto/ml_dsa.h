#ifndef ECLIPSE_ML_DSA_H
#define ECLIPSE_ML_DSA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Local API identifiers. These are not consensus or wire-format IDs. */
typedef enum {
    ECLIPSE_ML_DSA_44 = 1,
    ECLIPSE_ML_DSA_65 = 2,
    ECLIPSE_ML_DSA_87 = 3,
} eclipse_ml_dsa_scheme_t;

typedef struct eclipse_ml_dsa_key eclipse_ml_dsa_key_t;

typedef struct {
    size_t public_key_size;
    size_t signature_size;
    size_t private_key_size;
} eclipse_ml_dsa_info_t;

/* Returns false for an unknown scheme. Sizes are from FIPS 204. */
bool eclipse_ml_dsa_info(eclipse_ml_dsa_scheme_t scheme,
                         eclipse_ml_dsa_info_t *info);

/* The caller owns *out and releases it with eclipse_ml_dsa_key_free(). */
eclipse_error_t eclipse_ml_dsa_generate(eclipse_ml_dsa_scheme_t scheme,
                                        eclipse_ml_dsa_key_t **out);
/* Deterministically generates one pair from exactly 32 secret bytes. The
 * caller retains and must cleanse the seed; it is not a wallet recovery root. */
eclipse_error_t eclipse_ml_dsa_generate_from_seed(eclipse_ml_dsa_scheme_t scheme,
                                                  const uint8_t *seed,
                                                  size_t seed_length,
                                                  eclipse_ml_dsa_key_t **out);
eclipse_error_t eclipse_ml_dsa_import_public(eclipse_ml_dsa_scheme_t scheme,
                                             const uint8_t *bytes, size_t length,
                                             eclipse_ml_dsa_key_t **out);
eclipse_error_t eclipse_ml_dsa_export_public(const eclipse_ml_dsa_key_t *key,
                                             uint8_t *bytes, size_t capacity);

/* Expanded FIPS 204 sk bytes, not a wallet master seed. These bytes are
 * secret: the caller must protect and cleanse exported buffers. */
eclipse_error_t eclipse_ml_dsa_export_private(const eclipse_ml_dsa_key_t *key,
                                              uint8_t *bytes, size_t capacity);
void eclipse_ml_dsa_key_free(eclipse_ml_dsa_key_t *key);

/*
 * Pure ML-DSA over the original message. The context is bound into the
 * signature by FIPS 204, may be 0..255 bytes, and must be fixed by the
 * calling protocol. A non-NULL pointer is required for nonempty data.
 *
 * Signing requires a generated private key. Verification accepts either a
 * generated key or one imported from public bytes. A wrong signature yields
 * ECLIPSE_SUCCESS with *valid == false; API/provider errors have error codes.
 * On error, *signature_length / *valid are set to zero / false.
 */
eclipse_error_t eclipse_ml_dsa_sign(const eclipse_ml_dsa_key_t *key,
                                    const uint8_t *message, size_t message_length,
                                    const uint8_t *context, size_t context_length,
                                    uint8_t *signature, size_t capacity,
                                    size_t *signature_length);
eclipse_error_t eclipse_ml_dsa_verify(const eclipse_ml_dsa_key_t *key,
                                      const uint8_t *message, size_t message_length,
                                      const uint8_t *context, size_t context_length,
                                      const uint8_t *signature, size_t signature_length,
                                      bool *valid);

#ifdef __cplusplus
}
#endif

#endif
