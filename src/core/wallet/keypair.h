#ifndef ECLIPSE_WALLET_KEYPAIR_H
#define ECLIPSE_WALLET_KEYPAIR_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/ml_dsa.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One independently generated ML-DSA key pair. The private key is opaque and
 * stays inside this object; the public bytes are borrowed until free(). */
typedef struct eclipse_wallet_keypair eclipse_wallet_keypair_t;

eclipse_error_t eclipse_wallet_generate_keypair(eclipse_ml_dsa_scheme_t scheme,
                                                 eclipse_wallet_keypair_t **out);
eclipse_error_t eclipse_wallet_keypair_public(const eclipse_wallet_keypair_t *pair,
                                               eclipse_ml_dsa_scheme_t *scheme,
                                               const uint8_t **bytes,
                                               size_t *length);
void eclipse_wallet_keypair_free(eclipse_wallet_keypair_t *pair);

#ifdef __cplusplus
}
#endif

#endif
