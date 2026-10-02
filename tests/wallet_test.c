#include "wallet/wallet.h"
#include "encoding/base92.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static void check_master_export(const eclipse_wallet_t *wallet,
                                eclipse_wallet_role_t role, const char *text,
                                size_t text_length)
{
    eclipse_ml_dsa_info_t info;
    CHECK(eclipse_ml_dsa_info(ECLIPSE_ML_DSA_44, &info));
    size_t raw_length = 9 + info.private_key_size + 32;
    uint8_t *raw = OPENSSL_malloc(raw_length);
    CHECK(raw != NULL);
    size_t decoded_length = 0;
    CHECK(eclipse_base92_decode(text, text_length, raw, raw_length,
                                &decoded_length) == ECLIPSE_SUCCESS);
    CHECK(decoded_length == raw_length);
    CHECK(memcmp(raw, "EWMS", 4) == 0);
    CHECK(raw[4] == 1 && raw[5] == (uint8_t)role && raw[6] == 1);
    CHECK((((size_t)raw[7] << 8) | raw[8]) == info.private_key_size);
    uint8_t digest[32];
    size_t digest_length = 0;
    CHECK(EVP_Q_digest(NULL, "SHA2-256", NULL, raw, raw_length - 32,
                       digest, &digest_length) == 1);
    CHECK(digest_length == sizeof(digest));
    CHECK(memcmp(digest, raw + raw_length - 32, 32) == 0);

    /* Prove the exported expanded private bytes belong to the master public
       key by asking OpenSSL to derive that public key again. */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
    CHECK(ctx != NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                          raw + 9, info.private_key_size),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY *imported = NULL;
    CHECK(EVP_PKEY_fromdata_init(ctx) > 0);
    CHECK(EVP_PKEY_fromdata(ctx, &imported, EVP_PKEY_KEYPAIR, params) > 0);
    EVP_PKEY_CTX_free(ctx);
    eclipse_wallet_public_key_t master;
    CHECK(eclipse_wallet_master_public(wallet, role, &master) == ECLIPSE_SUCCESS);
    uint8_t derived[ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
    size_t derived_length = 0;
    CHECK(EVP_PKEY_get_octet_string_param(imported, OSSL_PKEY_PARAM_PUB_KEY,
                                          derived, sizeof(derived),
                                          &derived_length) > 0);
    CHECK(derived_length == master.length);
    CHECK(memcmp(derived, master.bytes, master.length) == 0);
    EVP_PKEY_free(imported);
    OPENSSL_clear_free(raw, raw_length);
}

static void check_other_scheme(eclipse_ml_dsa_scheme_t scheme)
{
    eclipse_ml_dsa_info_t info;
    CHECK(eclipse_ml_dsa_info(scheme, &info));
    eclipse_wallet_t *wallet = NULL;
    CHECK(eclipse_wallet_create(scheme, &wallet) == ECLIPSE_SUCCESS);
    eclipse_wallet_public_key_t child;
    CHECK(eclipse_wallet_child_public(wallet, ECLIPSE_WALLET_SPEND,
                                       ECLIPSE_WALLET_POOL_SIZE - 1,
                                       &child) == ECLIPSE_SUCCESS);
    CHECK(child.length == info.public_key_size);
    bool valid = false;
    CHECK(eclipse_wallet_verify_child_binding(wallet, ECLIPSE_WALLET_SPEND,
                                               ECLIPSE_WALLET_POOL_SIZE - 1,
                                               &valid) == ECLIPSE_SUCCESS && valid);

    size_t capacity = eclipse_wallet_master_export_capacity(scheme);
    char *secret = malloc(capacity);
    CHECK(secret != NULL);
    size_t written = 0;
    CHECK(eclipse_wallet_export_master_base92(wallet, ECLIPSE_WALLET_SPEND,
                                               secret, capacity,
                                               &written) == ECLIPSE_SUCCESS);
    CHECK(written + 1 == capacity);
    OPENSSL_cleanse(secret, capacity);
    free(secret);
    eclipse_wallet_free(wallet);
}

int main(void)
{
    eclipse_wallet_t *wallet = NULL;
    CHECK(eclipse_wallet_create((eclipse_ml_dsa_scheme_t)0, &wallet) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(wallet == NULL);
    CHECK(eclipse_wallet_create(ECLIPSE_ML_DSA_44, &wallet) == ECLIPSE_SUCCESS);
    CHECK(wallet != NULL);

    eclipse_wallet_public_key_t master_receive;
    eclipse_wallet_public_key_t master_spend;
    CHECK(eclipse_wallet_master_public(wallet, ECLIPSE_WALLET_RECEIVE,
                                       &master_receive) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_master_public(wallet, ECLIPSE_WALLET_SPEND,
                                       &master_spend) == ECLIPSE_SUCCESS);
    CHECK(master_receive.length == 1312 && master_spend.length == 1312);
    CHECK(memcmp(master_receive.bytes, master_spend.bytes, 1312) != 0);

    eclipse_wallet_public_key_t children[2][ECLIPSE_WALLET_POOL_SIZE];
    for (size_t role_index = 0; role_index < 2; ++role_index) {
        eclipse_wallet_role_t role = role_index == 0 ? ECLIPSE_WALLET_RECEIVE :
                                                       ECLIPSE_WALLET_SPEND;
        for (size_t i = 0; i < ECLIPSE_WALLET_POOL_SIZE; ++i) {
            CHECK(eclipse_wallet_child_public(wallet, role, i,
                                               &children[role_index][i]) == ECLIPSE_SUCCESS);
            CHECK(children[role_index][i].length == 1312);
            bool valid = false;
            CHECK(eclipse_wallet_verify_child_binding(wallet, role, i,
                                                       &valid) == ECLIPSE_SUCCESS);
            CHECK(valid);
        }
    }
    for (size_t a = 0; a < 2 * ECLIPSE_WALLET_POOL_SIZE; ++a) {
        const eclipse_wallet_public_key_t *left =
            &children[a / ECLIPSE_WALLET_POOL_SIZE][a % ECLIPSE_WALLET_POOL_SIZE];
        for (size_t b = a + 1; b < 2 * ECLIPSE_WALLET_POOL_SIZE; ++b) {
            const eclipse_wallet_public_key_t *right =
                &children[b / ECLIPSE_WALLET_POOL_SIZE][b % ECLIPSE_WALLET_POOL_SIZE];
            CHECK(memcmp(left->bytes, right->bytes, left->length) != 0);
        }
    }

    /* The certificate binds the public child to the correct master, role,
       and slot. A different receive/spend master cannot validate it. */
    eclipse_ml_dsa_info_t scheme_info;
    CHECK(eclipse_ml_dsa_info(ECLIPSE_ML_DSA_44, &scheme_info));
    uint8_t *binding = malloc(scheme_info.signature_size);
    CHECK(binding != NULL);
    size_t binding_length = 0;
    CHECK(eclipse_wallet_child_binding_signature(wallet, ECLIPSE_WALLET_RECEIVE,
                                                  0, binding,
                                                  scheme_info.signature_size - 1,
                                                  &binding_length) ==
          ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    CHECK(binding_length == 0);
    CHECK(eclipse_wallet_child_binding_signature(wallet, ECLIPSE_WALLET_RECEIVE,
                                                  0, binding,
                                                  scheme_info.signature_size,
                                                  &binding_length) == ECLIPSE_SUCCESS);
    CHECK(binding_length == scheme_info.signature_size);
    bool valid = false;
    CHECK(eclipse_wallet_verify_public_binding(&master_receive, &children[0][0],
                                                ECLIPSE_WALLET_RECEIVE, 0,
                                                binding, binding_length,
                                                &valid) == ECLIPSE_SUCCESS && valid);
    CHECK(eclipse_wallet_verify_public_binding(&master_receive, &children[0][0],
                                                ECLIPSE_WALLET_SPEND, 0,
                                                binding, binding_length,
                                                &valid) == ECLIPSE_SUCCESS && !valid);
    CHECK(eclipse_wallet_verify_public_binding(&master_receive, &children[0][0],
                                                ECLIPSE_WALLET_RECEIVE, 1,
                                                binding, binding_length,
                                                &valid) == ECLIPSE_SUCCESS && !valid);
    CHECK(eclipse_wallet_verify_public_binding(&master_spend, &children[0][0],
                                                ECLIPSE_WALLET_RECEIVE, 0,
                                                binding, binding_length,
                                                &valid) == ECLIPSE_SUCCESS && !valid);
    binding[0] ^= 1;
    CHECK(eclipse_wallet_verify_public_binding(&master_receive, &children[0][0],
                                                ECLIPSE_WALLET_RECEIVE, 0,
                                                binding, binding_length,
                                                &valid) == ECLIPSE_SUCCESS && !valid);
    free(binding);

    uint8_t wire[8 + ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
    size_t wire_length = 0;
    CHECK(eclipse_wallet_public_serialize(&children[0][0], wire, sizeof(wire),
                                           &wire_length) == ECLIPSE_SUCCESS);
    CHECK(wire_length == 8 + children[0][0].length);
    CHECK(memcmp(wire, "EWPK", 4) == 0 && wire[4] == 1 && wire[5] == 1);
    eclipse_wallet_public_key_t parsed = {0};
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length,
                                             &parsed) == ECLIPSE_SUCCESS);
    CHECK(parsed.scheme == children[0][0].scheme &&
          parsed.length == children[0][0].length);
    CHECK(memcmp(parsed.bytes, children[0][0].bytes, parsed.length) == 0);

    size_t public_capacity = eclipse_base92_encoded_capacity(wire_length);
    char *public_text = malloc(public_capacity);
    CHECK(public_text != NULL);
    size_t public_length = 0;
    CHECK(eclipse_wallet_public_to_base92(&children[0][0], public_text,
                                           public_capacity, &public_length) == ECLIPSE_SUCCESS);
    CHECK(public_length == strlen(public_text));
    eclipse_wallet_public_key_t from_text = {0};
    CHECK(eclipse_wallet_public_from_base92(public_text, public_length,
                                             &from_text) == ECLIPSE_SUCCESS);
    CHECK(memcmp(from_text.bytes, parsed.bytes, parsed.length) == 0);
    CHECK(eclipse_wallet_public_from_base92(public_text, public_length - 1,
                                             &from_text) != ECLIPSE_SUCCESS);
    free(public_text);

    parsed.bytes[0] = 0xa5;
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length - 1,
                                             &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(parsed.bytes[0] == 0xa5);
    wire[6] ^= 1;
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length,
                                             &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[6] ^= 1;
    wire[5] = 99;
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length,
                                             &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[5] = 1;
    wire[0] ^= 1;
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length,
                                             &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[0] ^= 1;
    CHECK(eclipse_wallet_child_public(wallet, ECLIPSE_WALLET_RECEIVE,
                                       ECLIPSE_WALLET_POOL_SIZE,
                                       &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_wallet_child_public(wallet, (eclipse_wallet_role_t)99, 0,
                                       &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);

    size_t secret_capacity = eclipse_wallet_master_export_capacity(ECLIPSE_ML_DSA_44);
    char *receive_text = malloc(secret_capacity);
    char *spend_text = malloc(secret_capacity);
    CHECK(receive_text != NULL && spend_text != NULL);
    size_t receive_length = 0;
    size_t spend_length = 0;
    CHECK(eclipse_wallet_export_master_base92(wallet, ECLIPSE_WALLET_RECEIVE,
                                               receive_text, secret_capacity,
                                               &receive_length) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_export_master_base92(wallet, ECLIPSE_WALLET_SPEND,
                                               spend_text, secret_capacity,
                                               &spend_length) == ECLIPSE_SUCCESS);
    CHECK(receive_length == spend_length);
    CHECK(memcmp(receive_text, spend_text, receive_length) != 0);
    check_master_export(wallet, ECLIPSE_WALLET_RECEIVE, receive_text, receive_length);
    check_master_export(wallet, ECLIPSE_WALLET_SPEND, spend_text, spend_length);
    CHECK(eclipse_wallet_export_master_base92(wallet, ECLIPSE_WALLET_RECEIVE,
                                               receive_text, 1,
                                               &receive_length) == ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    OPENSSL_cleanse(receive_text, secret_capacity);
    OPENSSL_cleanse(spend_text, secret_capacity);
    free(receive_text);
    free(spend_text);
    eclipse_wallet_free(wallet);
    check_other_scheme(ECLIPSE_ML_DSA_65);
    check_other_scheme(ECLIPSE_ML_DSA_87);
    puts("Wallet tests passed");
    return EXIT_SUCCESS;
}
