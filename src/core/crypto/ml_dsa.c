#include "ml_dsa.h"
#include "../log.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
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
    if (info == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA info output is null");
        return false;
    }
    switch (scheme) {
    case ECLIPSE_ML_DSA_44: *info = (eclipse_ml_dsa_info_t){1312, 2420, 2560}; break;
    case ECLIPSE_ML_DSA_65: *info = (eclipse_ml_dsa_info_t){1952, 3309, 4032}; break;
    case ECLIPSE_ML_DSA_87: *info = (eclipse_ml_dsa_info_t){2592, 4627, 4896}; break;
    default:
        ECLIPSE_LOG_INFO(4, "unknown ML-DSA scheme rejected");
        return false;
    }
    ECLIPSE_LOG_INFO(5, "ML-DSA scheme information returned");
    return true;
}

static eclipse_error_t wrap_key(eclipse_ml_dsa_scheme_t scheme, EVP_PKEY *pkey,
                                bool has_private, eclipse_ml_dsa_key_t **out)
{
    eclipse_ml_dsa_key_t *key = malloc(sizeof(*key));
    if (key == NULL) {
        EVP_PKEY_free(pkey);
        ECLIPSE_LOG_ERROR("ML-DSA key handle allocation failed");
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
    if (out == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA key generation output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    const char *name = algorithm_name(scheme);
    if (name == NULL) {
        ECLIPSE_LOG_INFO(4, "unknown ML-DSA scheme rejected for key generation");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, name);
    if (pkey == NULL) {
        ECLIPSE_LOG_ERROR("ML-DSA key generation failed for %s", name);
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    eclipse_error_t status = wrap_key(scheme, pkey, true, out);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(3, "ML-DSA key pair generated for %s", name);
    return status;
}

eclipse_error_t eclipse_ml_dsa_generate_from_seed(eclipse_ml_dsa_scheme_t scheme,
                                                  const uint8_t *seed,
                                                  size_t seed_length,
                                                  eclipse_ml_dsa_key_t **out)
{
    if (out == NULL || seed == NULL) {
        ECLIPSE_LOG_WARNING("seeded ML-DSA generation rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    const char *name = algorithm_name(scheme);
    if (name == NULL || seed_length != 32) {
        ECLIPSE_LOG_WARNING("seeded ML-DSA generation rejected scheme or seed length");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (ctx == NULL) {
        ECLIPSE_LOG_ERROR("seeded ML-DSA generation setup failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    /* OpenSSL reads the seed while generating; it is never logged or copied
       into a wallet recovery packet by this wrapper. */
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                          (void *)seed, seed_length),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY *pkey = NULL;
    int ok = EVP_PKEY_keygen_init(ctx) > 0 &&
             EVP_PKEY_CTX_set_params(ctx, params) > 0 &&
             EVP_PKEY_keygen(ctx, &pkey) > 0;
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        EVP_PKEY_free(pkey);
        ECLIPSE_LOG_ERROR("seeded ML-DSA generation failed for %s", name);
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    eclipse_error_t status = wrap_key(scheme, pkey, true, out);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(4, "ML-DSA key pair derived for %s", name);
    return status;
}

eclipse_error_t eclipse_ml_dsa_import_public(eclipse_ml_dsa_scheme_t scheme,
                                             const uint8_t *bytes, size_t length,
                                             eclipse_ml_dsa_key_t **out)
{
    if (out == NULL || bytes == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA public-key import rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(scheme, &info) || length != info.public_key_size) {
        ECLIPSE_LOG_INFO(4, "ML-DSA public key rejected: scheme or length invalid");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm_name(scheme), NULL);
    if (ctx == NULL) {
        ECLIPSE_LOG_ERROR("ML-DSA public-key import setup failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
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
        ECLIPSE_LOG_INFO(4, "ML-DSA public key rejected by provider");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_error_t status = wrap_key(scheme, pkey, false, out);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(4, "ML-DSA public key imported");
    return status;
}

eclipse_error_t eclipse_ml_dsa_export_public(const eclipse_ml_dsa_key_t *key,
                                             uint8_t *bytes, size_t capacity)
{
    if (key == NULL || bytes == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA public-key export rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(key->scheme, &info)) {
        ECLIPSE_LOG_WARNING("ML-DSA public-key export has an invalid scheme");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    if (capacity < info.public_key_size) {
        ECLIPSE_LOG_WARNING("ML-DSA public-key export buffer is too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }
    size_t written = 0;
    if (EVP_PKEY_get_octet_string_param(key->pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        bytes, capacity, &written) <= 0 ||
        written != info.public_key_size) {
        ECLIPSE_LOG_ERROR("ML-DSA public-key export failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    ECLIPSE_LOG_INFO(5, "ML-DSA public key exported");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ml_dsa_export_private(const eclipse_ml_dsa_key_t *key,
                                              uint8_t *bytes, size_t capacity)
{
    if (key == NULL || bytes == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA private-key export rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (!key->has_private) {
        ECLIPSE_LOG_WARNING("ML-DSA private-key export rejected a public-only key");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(key->scheme, &info))
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (capacity < info.private_key_size)
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    size_t written = 0;
    if (EVP_PKEY_get_octet_string_param(key->pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                        bytes, capacity, &written) <= 0 ||
        written != info.private_key_size) {
        OPENSSL_cleanse(bytes, info.private_key_size);
        ECLIPSE_LOG_ERROR("ML-DSA private-key export failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    ECLIPSE_LOG_INFO(4, "expanded ML-DSA private key exported");
    return ECLIPSE_SUCCESS;
}

void eclipse_ml_dsa_key_free(eclipse_ml_dsa_key_t *key)
{
    if (key == NULL) {
        ECLIPSE_LOG_INFO(5, "null ML-DSA key release ignored");
        return;
    }
    EVP_PKEY_free(key->pkey);
    free(key);
    ECLIPSE_LOG_INFO(5, "ML-DSA key handle released");
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
    if (signature_length == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA signing length output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *signature_length = 0;
    if (key == NULL || signature == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA signing rejected a null key or output");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (!valid_data(message, message_length) || !valid_data(context, context_length)) {
        ECLIPSE_LOG_WARNING("ML-DSA signing rejected null nonempty data");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (context_length > 255 || !key->has_private) {
        ECLIPSE_LOG_WARNING("ML-DSA signing rejected context or public-only key");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(key->scheme, &info)) {
        ECLIPSE_LOG_WARNING("ML-DSA signing key has an invalid scheme");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    if (capacity < info.signature_size) {
        ECLIPSE_LOG_WARNING("ML-DSA signature output buffer is too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL);
    EVP_SIGNATURE *algorithm = EVP_SIGNATURE_fetch(NULL, algorithm_name(key->scheme), NULL);
    if (ctx == NULL || algorithm == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_SIGNATURE_free(algorithm);
        ECLIPSE_LOG_ERROR("ML-DSA signing setup failed");
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
    if (!ok || written != info.signature_size) {
        ECLIPSE_LOG_ERROR("ML-DSA signing failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    *signature_length = written;
    ECLIPSE_LOG_INFO(3, "ML-DSA message signed");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ml_dsa_verify(const eclipse_ml_dsa_key_t *key,
                                      const uint8_t *message, size_t message_length,
                                      const uint8_t *context, size_t context_length,
                                      const uint8_t *signature, size_t signature_length,
                                      bool *valid)
{
    if (valid == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA verification result output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *valid = false;
    if (key == NULL || signature == NULL) {
        ECLIPSE_LOG_WARNING("ML-DSA verification rejected a null key or signature");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (!valid_data(message, message_length) || !valid_data(context, context_length)) {
        ECLIPSE_LOG_WARNING("ML-DSA verification rejected null nonempty data");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (context_length > 255) {
        ECLIPSE_LOG_INFO(4, "ML-DSA verification rejected an oversized context");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(key->scheme, &info)) {
        ECLIPSE_LOG_INFO(4, "ML-DSA verification rejected an invalid scheme");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    if (signature_length != info.signature_size) {
        ECLIPSE_LOG_INFO(4, "ML-DSA signature rejected: invalid length");
        return ECLIPSE_SUCCESS;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL);
    EVP_SIGNATURE *algorithm = EVP_SIGNATURE_fetch(NULL, algorithm_name(key->scheme), NULL);
    if (ctx == NULL || algorithm == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_SIGNATURE_free(algorithm);
        ECLIPSE_LOG_ERROR("ML-DSA verification setup failed");
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
    if (result < 0) {
        ECLIPSE_LOG_ERROR("ML-DSA verification failed internally");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    *valid = result == 1;
    ECLIPSE_LOG_INFO(4, "%s", *valid ? "ML-DSA signature accepted" :
                    "ML-DSA signature rejected");
    return ECLIPSE_SUCCESS;
}
