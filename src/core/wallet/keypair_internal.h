#ifndef ECLIPSE_WALLET_KEYPAIR_INTERNAL_H
#define ECLIPSE_WALLET_KEYPAIR_INTERNAL_H

#include "keypair.h"

/* Private wallet operations. Do not expose these through network-facing APIs. */
eclipse_error_t eclipse_wallet_keypair_from_seed(eclipse_ml_dsa_scheme_t scheme,
                                                 const uint8_t *seed,
                                                 size_t seed_length,
                                                 eclipse_wallet_keypair_t **out);
eclipse_error_t eclipse_wallet_keypair_sign(const eclipse_wallet_keypair_t *pair,
                                            const uint8_t *message, size_t length,
                                            const uint8_t *context, size_t context_length,
                                            uint8_t *signature, size_t capacity,
                                            size_t *written);

#endif
