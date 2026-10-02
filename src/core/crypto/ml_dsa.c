#include "ml_dsa.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdlib.h>

struct eclipse_ml_dsa_key {
    eclipse_ml_dsa_scheme_t scheme;
    EVP_PKEY *pkey;
    bool has_private;
};

static const char *algorithm_name(eclipse_ml_dsa_scheme_t scheme)
{
    switch (scheme) {
    case ECLIPSE_ML_DSA_44: return "ML-DSA-44";
    case ECLIPSE_ML_DSA_65: return "ML-DSA-65";
    case ECLIPSE_ML_DSA_87: return "ML-DSA-87";
    default: return NULL;
    }
}

bool eclipse_ml_dsa_info(eclipse_ml_dsa_scheme_t scheme,
                         eclipse_ml_dsa_info_t *info)
{
    if (info == NULL) return false;
    switch (scheme) {
    case ECLIPSE_ML_DSA_44: *info = (eclipse_ml_dsa_info_t){1312, 2420}; return true;
    case ECLIPSE_ML_DSA_65: *info = (eclipse_ml_dsa_info_t){1952, 3309}; return true;
    case ECLIPSE_ML_DSA_87: *info = (eclipse_ml_dsa_info_t){2592, 4627}; return true;
    default: return false;
    }
}

static eclipse_error_t wrap_key(eclipse_ml_dsa_scheme_t scheme, EVP_PKEY *pkey,
                                bool has_private, eclipse_ml_dsa_key_t **out)
{
    eclipse_ml_dsa_key_t *key = malloc(sizeof(*key));
    if (key == NULL) {
        EVP_PKEY_free(pkey);
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    key->scheme = scheme;
    key->pkey = pkey;
    key->has_private = has_private;
    *out = key;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ml_dsa_generate(eclipse_ml_dsa_scheme_t scheme,
                                        eclipse_ml_dsa_key_t **out)
{
    if (out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    const char *name = algorithm_name(scheme);
    if (name == NULL) return ECLIPSE_ERROR_INVALID_ARGUMENT;

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, name);
    if (pkey == NULL) return ECLIPSE_ERROR_CRYPTO_FAILURE;
    return wrap_key(scheme, pkey, true, out);
}

eclipse_error_t eclipse_ml_dsa_import_public(eclipse_ml_dsa_scheme_t scheme,
                                             const uint8_t *bytes, size_t length,
                                             eclipse_ml_dsa_key_t **out)
{
    if (out == NULL || bytes == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(scheme, &info) || length != info.public_key_size)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm_name(scheme), NULL);
    if (ctx == NULL) return ECLIPSE_ERROR_CRYPTO_FAILURE;
    /* OSSL_PARAM uses void*, but EVP_PKEY_fromdata only reads this input. */
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          (void *)bytes, length),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY *pkey = NULL;
    int ok = EVP_PKEY_fromdata_init(ctx) > 0 &&
             EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0;
    EVP_PKEY_CTX_free(ctx);
    if (ok) {
        EVP_PKEY_CTX *check = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        ok = check != NULL && EVP_PKEY_public_check(check) == 1;
        EVP_PKEY_CTX_free(check);
    }
    if (!ok) {
        EVP_PKEY_free(pkey);
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    return wrap_key(scheme, pkey, false, out);
}

eclipse_error_t eclipse_ml_dsa_export_public(const eclipse_ml_dsa_key_t *key,
                                             uint8_t *bytes, size_t capacity)
{
    if (key == NULL || bytes == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(key->scheme, &info)) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (capacity < info.public_key_size) return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    size_t written = 0;
    if (EVP_PKEY_get_octet_string_param(key->pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        bytes, capacity, &written) <= 0 ||
        written != info.public_key_size)
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    return ECLIPSE_SUCCESS;
}

void eclipse_ml_dsa_key_free(eclipse_ml_dsa_key_t *key)
{
    if (key == NULL) return;
    EVP_PKEY_free(key->pkey);
    free(key);
}

static bool valid_data(const uint8_t *data, size_t length)
{
    return data != NULL || length == 0;
}

static OSSL_PARAM context_params(const uint8_t *context, size_t length)
{
    static const uint8_t empty = 0;
    /* OpenSSL's parameter API accepts void* for input buffers. */
    return OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                             (void *)(length ? context : &empty),
                                             length);
}

eclipse_error_t eclipse_ml_dsa_sign(const eclipse_ml_dsa_key_t *key,
                                    const uint8_t *message, size_t message_length,
                                    const uint8_t *context, size_t context_length,
                                    uint8_t *signature, size_t capacity,
                                    size_t *signature_length)
{
    if (signature_length == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *signature_length = 0;
    if (key == NULL || signature == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (!valid_data(message, message_length) || !valid_data(context, context_length))
        return ECLIPSE_ERROR_NULL_POINTER;
    if (context_length > 255 || !key->has_private) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(key->scheme, &info)) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (capacity < info.signature_size) return ECLIPSE_ERROR_BUFFER_TOO_SMALL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL);
    EVP_SIGNATURE *algorithm = EVP_SIGNATURE_fetch(NULL, algorithm_name(key->scheme), NULL);
    if (ctx == NULL || algorithm == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_SIGNATURE_free(algorithm);
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    OSSL_PARAM params[] = {context_params(context, context_length), OSSL_PARAM_construct_end()};
    const uint8_t empty = 0;
    size_t written = capacity;
    int ok = EVP_PKEY_sign_message_init(ctx, algorithm, params) > 0 &&
             EVP_PKEY_sign(ctx, signature, &written,
                           message_length ? message : &empty, message_length) > 0;
    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_CTX_free(ctx);
    if (!ok || written != info.signature_size) return ECLIPSE_ERROR_CRYPTO_FAILURE;
    *signature_length = written;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ml_dsa_verify(const eclipse_ml_dsa_key_t *key,
                                      const uint8_t *message, size_t message_length,
                                      const uint8_t *context, size_t context_length,
                                      const uint8_t *signature, size_t signature_length,
                                      bool *valid)
{
    if (valid == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *valid = false;
    if (key == NULL || signature == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (!valid_data(message, message_length) || !valid_data(context, context_length))
        return ECLIPSE_ERROR_NULL_POINTER;
    if (context_length > 255) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(key->scheme, &info)) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (signature_length != info.signature_size) return ECLIPSE_SUCCESS;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL);
    EVP_SIGNATURE *algorithm = EVP_SIGNATURE_fetch(NULL, algorithm_name(key->scheme), NULL);
    if (ctx == NULL || algorithm == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_SIGNATURE_free(algorithm);
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    OSSL_PARAM params[] = {context_params(context, context_length), OSSL_PARAM_construct_end()};
    const uint8_t empty = 0;
    int result = -1;
    if (EVP_PKEY_verify_message_init(ctx, algorithm, params) > 0)
        result = EVP_PKEY_verify(ctx, signature, signature_length,
                                 message_length ? message : &empty, message_length);
    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_CTX_free(ctx);
    if (result < 0) return ECLIPSE_ERROR_CRYPTO_FAILURE;
    *valid = result == 1;
    return ECLIPSE_SUCCESS;
}
