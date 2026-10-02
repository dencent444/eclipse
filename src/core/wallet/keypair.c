#include "keypair_internal.h"
#include "../log.h"

#include <stdlib.h>

struct eclipse_wallet_keypair {
    eclipse_ml_dsa_scheme_t scheme;
    eclipse_ml_dsa_key_t *private_key;
    uint8_t *public_key;
    size_t public_key_size;
};

static eclipse_error_t wrap_private_key(eclipse_ml_dsa_scheme_t scheme,
                                        eclipse_ml_dsa_key_t *private_key,
                                        eclipse_wallet_keypair_t **out)
{
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(scheme, &info)) {
        eclipse_ml_dsa_key_free(private_key);
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    eclipse_wallet_keypair_t *pair = calloc(1, sizeof(*pair));
    if (pair == NULL) {
        eclipse_ml_dsa_key_free(private_key);
        ECLIPSE_LOG_ERROR("key-pair handle allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    pair->scheme = scheme;
    pair->private_key = private_key;
    pair->public_key_size = info.public_key_size;
    pair->public_key = malloc(pair->public_key_size);
    eclipse_error_t status = pair->public_key == NULL ? ECLIPSE_ERROR_OUT_OF_MEMORY :
                             ECLIPSE_SUCCESS;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_export_public(pair->private_key, pair->public_key,
                                               pair->public_key_size);
    if (status != ECLIPSE_SUCCESS) {
        ECLIPSE_LOG_ERROR("key-pair generation failed with code %d", status);
        eclipse_wallet_keypair_free(pair);
        return status;
    }

    *out = pair;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_generate_keypair(eclipse_ml_dsa_scheme_t scheme,
                                                 eclipse_wallet_keypair_t **out)
{
    if (out == NULL) {
        ECLIPSE_LOG_WARNING("key-pair output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    /* The OpenSSL provider obtains cryptographic randomness for this call.
       No wallet-level seed or deterministic derivation is involved. */
    eclipse_ml_dsa_key_t *private_key = NULL;
    eclipse_error_t status = eclipse_ml_dsa_generate(scheme, &private_key);
    if (status != ECLIPSE_SUCCESS) return status;
    status = wrap_private_key(scheme, private_key, out);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(3, "wallet key pair generated");
    return status;
}

eclipse_error_t eclipse_wallet_keypair_export_private(
    const eclipse_wallet_keypair_t *pair, uint8_t *bytes, size_t capacity)
{
    if (pair == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    return eclipse_ml_dsa_export_private(pair->private_key, bytes, capacity);
}

eclipse_error_t eclipse_wallet_keypair_sign(const eclipse_wallet_keypair_t *pair,
                                            const uint8_t *message, size_t length,
                                            const uint8_t *context, size_t context_length,
                                            uint8_t *signature, size_t capacity,
                                            size_t *written)
{
    if (pair == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    return eclipse_ml_dsa_sign(pair->private_key, message, length, context,
                                context_length, signature, capacity, written);
}

eclipse_error_t eclipse_wallet_keypair_public(const eclipse_wallet_keypair_t *pair,
                                               eclipse_ml_dsa_scheme_t *scheme,
                                               const uint8_t **bytes,
                                               size_t *length)
{
    if (pair == NULL || scheme == NULL || bytes == NULL || length == NULL) {
        ECLIPSE_LOG_WARNING("public-key view rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *scheme = pair->scheme;
    *bytes = pair->public_key;
    *length = pair->public_key_size;
    ECLIPSE_LOG_INFO(5, "wallet public-key view returned");
    return ECLIPSE_SUCCESS;
}

void eclipse_wallet_keypair_free(eclipse_wallet_keypair_t *pair)
{
    if (pair == NULL) return;
    eclipse_ml_dsa_key_free(pair->private_key);
    free(pair->public_key);
    free(pair);
    ECLIPSE_LOG_INFO(5, "wallet key-pair handle released");
}
