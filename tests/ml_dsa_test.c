#include "crypto/ml_dsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static void exercise_scheme(eclipse_ml_dsa_scheme_t scheme)
{
    static const uint8_t context[] = "eclipse-test-transaction-v0";
    static const uint8_t wrong_context[] = "other-protocol";
    uint8_t message[] = "pay one test coin";
    eclipse_ml_dsa_info_t info;
    CHECK(eclipse_ml_dsa_info(scheme, &info));

    eclipse_ml_dsa_key_t *private_key = NULL;
    eclipse_ml_dsa_key_t *public_key = NULL;
    eclipse_ml_dsa_key_t *other_key = NULL;
    CHECK(eclipse_ml_dsa_generate(scheme, &private_key) == ECLIPSE_SUCCESS);
    CHECK(eclipse_ml_dsa_generate(scheme, &other_key) == ECLIPSE_SUCCESS);

    uint8_t *public_bytes = malloc(info.public_key_size);
    uint8_t *signature = malloc(info.signature_size);
    CHECK(public_bytes != NULL && signature != NULL);
    CHECK(eclipse_ml_dsa_export_public(private_key, public_bytes,
                                       info.public_key_size - 1) ==
          ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    CHECK(eclipse_ml_dsa_export_public(private_key, public_bytes,
                                       info.public_key_size) == ECLIPSE_SUCCESS);
    CHECK(eclipse_ml_dsa_import_public(scheme, public_bytes,
                                       info.public_key_size - 1, &public_key) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(public_key == NULL);
    CHECK(eclipse_ml_dsa_import_public(scheme, public_bytes,
                                       info.public_key_size, &public_key) ==
          ECLIPSE_SUCCESS);

    size_t written = 99;
    CHECK(eclipse_ml_dsa_sign(private_key, message, sizeof(message),
                              context, sizeof(context) - 1, signature,
                              info.signature_size - 1, &written) ==
          ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    CHECK(written == 0);
    CHECK(eclipse_ml_dsa_sign(private_key, message, sizeof(message),
                              context, sizeof(context) - 1, signature,
                              info.signature_size, &written) == ECLIPSE_SUCCESS);
    CHECK(written == info.signature_size);
    CHECK(eclipse_ml_dsa_sign(public_key, message, sizeof(message),
                              context, sizeof(context) - 1, signature,
                              info.signature_size, &written) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);

    bool valid = false;
    CHECK(eclipse_ml_dsa_verify(public_key, message, sizeof(message),
                                context, sizeof(context) - 1,
                                signature, info.signature_size, &valid) ==
          ECLIPSE_SUCCESS && valid);
    CHECK(eclipse_ml_dsa_sign(private_key, NULL, 0, NULL, 0, signature,
                              info.signature_size, &written) == ECLIPSE_SUCCESS);
    CHECK(eclipse_ml_dsa_verify(public_key, NULL, 0, NULL, 0,
                                signature, written, &valid) ==
          ECLIPSE_SUCCESS && valid);
    CHECK(eclipse_ml_dsa_sign(private_key, NULL, 1, context,
                              sizeof(context) - 1, signature,
                              info.signature_size, &written) ==
          ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_ml_dsa_sign(private_key, message, sizeof(message),
                              context, 256, signature, info.signature_size,
                              &written) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    /* Restore the signature of the nonempty message for adversarial checks. */
    CHECK(eclipse_ml_dsa_sign(private_key, message, sizeof(message),
                              context, sizeof(context) - 1, signature,
                              info.signature_size, &written) == ECLIPSE_SUCCESS);
    message[0] ^= 1;
    CHECK(eclipse_ml_dsa_verify(public_key, message, sizeof(message),
                                context, sizeof(context) - 1,
                                signature, info.signature_size, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    message[0] ^= 1;
    CHECK(eclipse_ml_dsa_verify(public_key, message, sizeof(message),
                                wrong_context, sizeof(wrong_context) - 1,
                                signature, info.signature_size, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    CHECK(eclipse_ml_dsa_verify(other_key, message, sizeof(message),
                                context, sizeof(context) - 1,
                                signature, info.signature_size, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    signature[0] ^= 1;
    CHECK(eclipse_ml_dsa_verify(public_key, message, sizeof(message),
                                context, sizeof(context) - 1,
                                signature, info.signature_size, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    signature[0] ^= 1;
    CHECK(eclipse_ml_dsa_verify(public_key, message, sizeof(message),
                                context, sizeof(context) - 1,
                                signature, info.signature_size - 1, &valid) ==
          ECLIPSE_SUCCESS && !valid);

    free(signature);
    free(public_bytes);
    eclipse_ml_dsa_key_free(public_key);
    eclipse_ml_dsa_key_free(other_key);
    eclipse_ml_dsa_key_free(private_key);
}

int main(void)
{
    CHECK(!eclipse_ml_dsa_info((eclipse_ml_dsa_scheme_t)999, NULL));
    eclipse_ml_dsa_key_t *key = NULL;
    CHECK(eclipse_ml_dsa_generate((eclipse_ml_dsa_scheme_t)999, &key) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(key == NULL);
    exercise_scheme(ECLIPSE_ML_DSA_44);
    exercise_scheme(ECLIPSE_ML_DSA_65);
    exercise_scheme(ECLIPSE_ML_DSA_87);
    puts("ML-DSA tests passed");
    return EXIT_SUCCESS;
}
