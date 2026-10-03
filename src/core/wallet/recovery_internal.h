#ifndef ECLIPSE_WALLET_RECOVERY_INTERNAL_H
#define ECLIPSE_WALLET_RECOVERY_INTERNAL_H

#include "wallet.h"

#define ECLIPSE_WALLET_SECRET_SIZE 32u

struct eclipse_wallet_recovery {
    eclipse_ml_dsa_scheme_t scheme;
    uint8_t secret[ECLIPSE_WALLET_SECRET_SIZE];
};

struct eclipse_wallet_domain {
    eclipse_ml_dsa_scheme_t scheme;
    eclipse_wallet_role_t role;
    uint8_t secret[ECLIPSE_WALLET_SECRET_SIZE];
};

/* kind 0 is the role's certificate master; kind 1 is a child key. The caller
 * must cleanse the 32-byte output immediately after key generation. */
eclipse_error_t eclipse_wallet_derive_key_seed(const eclipse_wallet_domain_t *domain,
                                               uint8_t kind, uint32_t index,
                                               uint8_t output[ECLIPSE_WALLET_SECRET_SIZE]);

#endif
