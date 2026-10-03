/* Recovery and domain tests check deterministic rebuilding, role isolation,
 * child signatures, and versioned public/secret packet boundaries. */
#include "wallet/wallet.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static char *export_root(const eclipse_wallet_recovery_t *root, size_t *length)
{
    size_t capacity = eclipse_wallet_recovery_export_capacity();
    char *text = malloc(capacity);
    CHECK(text != NULL);
    CHECK(eclipse_wallet_recovery_export_base92(root, text, capacity,
                                                length) == ECLIPSE_SUCCESS);
    CHECK(*length + 1 == capacity);
    return text;
}

static char *export_domain(const eclipse_wallet_domain_t *domain, size_t *length)
{
    size_t capacity = eclipse_wallet_domain_export_capacity();
    char *text = malloc(capacity);
    CHECK(text != NULL);
    CHECK(eclipse_wallet_domain_export_base92(domain, text, capacity,
                                              length) == ECLIPSE_SUCCESS);
    CHECK(*length + 1 == capacity);
    return text;
}

static void compare_role(const eclipse_wallet_t *left, const eclipse_wallet_t *right,
                         eclipse_wallet_role_t role)
{
    eclipse_wallet_public_key_t left_key, right_key;
    CHECK(eclipse_wallet_master_public(left, role, &left_key) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_master_public(right, role, &right_key) == ECLIPSE_SUCCESS);
    CHECK(left_key.scheme == right_key.scheme && left_key.length == right_key.length);
    CHECK(memcmp(left_key.bytes, right_key.bytes, left_key.length) == 0);
    for (size_t i = 0; i < ECLIPSE_WALLET_POOL_SIZE; ++i) {
        CHECK(eclipse_wallet_child_public(left, role, i, &left_key) == ECLIPSE_SUCCESS);
        CHECK(eclipse_wallet_child_public(right, role, i, &right_key) == ECLIPSE_SUCCESS);
        CHECK(left_key.length == right_key.length);
        CHECK(memcmp(left_key.bytes, right_key.bytes, left_key.length) == 0);
        bool valid = false;
        CHECK(eclipse_wallet_verify_child_binding(left, role, i, &valid) ==
              ECLIPSE_SUCCESS && valid);
        CHECK(eclipse_wallet_verify_child_binding(right, role, i, &valid) ==
              ECLIPSE_SUCCESS && valid);
    }
}

static void check_distinct_children(const eclipse_wallet_t *wallet)
{
    eclipse_wallet_public_key_t keys[2][ECLIPSE_WALLET_POOL_SIZE];
    for (size_t role = 0; role < 2; ++role)
        for (size_t i = 0; i < ECLIPSE_WALLET_POOL_SIZE; ++i)
            CHECK(eclipse_wallet_child_public(wallet,
                  role == 0 ? ECLIPSE_WALLET_RECEIVE : ECLIPSE_WALLET_SPEND,
                  i, &keys[role][i]) == ECLIPSE_SUCCESS);
    for (size_t a = 0; a < 2 * ECLIPSE_WALLET_POOL_SIZE; ++a) {
        const eclipse_wallet_public_key_t *left =
            &keys[a / ECLIPSE_WALLET_POOL_SIZE][a % ECLIPSE_WALLET_POOL_SIZE];
        for (size_t b = a + 1; b < 2 * ECLIPSE_WALLET_POOL_SIZE; ++b) {
            const eclipse_wallet_public_key_t *right =
                &keys[b / ECLIPSE_WALLET_POOL_SIZE][b % ECLIPSE_WALLET_POOL_SIZE];
            CHECK(left->length == right->length);
            CHECK(memcmp(left->bytes, right->bytes, left->length) != 0);
        }
    }
}

static void check_public_transport(const eclipse_wallet_t *wallet)
{
    eclipse_wallet_public_key_t child;
    CHECK(eclipse_wallet_child_public(wallet, ECLIPSE_WALLET_RECEIVE, 0,
                                      &child) == ECLIPSE_SUCCESS);
    uint8_t wire[8 + ECLIPSE_WALLET_PUBLIC_MAX_SIZE + 32 + 1];
    size_t wire_length = 0;
    CHECK(eclipse_wallet_public_serialize(&child, wire, sizeof(wire),
                                          &wire_length) == ECLIPSE_SUCCESS);
    CHECK(wire_length == eclipse_wallet_public_serialized_size(child.scheme));
    CHECK(wire[4] == 2);
    eclipse_wallet_public_key_t parsed = {0};
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length,
                                            &parsed) == ECLIPSE_SUCCESS);
    CHECK(parsed.scheme == child.scheme && parsed.length == child.length);
    CHECK(memcmp(parsed.bytes, child.bytes, child.length) == 0);
    size_t capacity = wire_length * 2 + 2;
    char *text = malloc(capacity);
    CHECK(text != NULL);
    size_t text_length = 0;
    CHECK(eclipse_wallet_public_to_base92(&child, text, capacity,
                                          &text_length) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_public_from_base92(text, text_length,
                                            &parsed) == ECLIPSE_SUCCESS);
    CHECK(memcmp(parsed.bytes, child.bytes, child.length) == 0);
    /* The public key encoding itself has no spare invalid byte patterns.
       Packet integrity catches a changed key, while header and size checks
       reject unsupported interpretations before the key reaches OpenSSL. */
    uint8_t changed[sizeof(wire)];
    memcpy(changed, wire, wire_length);
    changed[8] ^= 1;
    CHECK(eclipse_wallet_public_deserialize(changed, wire_length, &parsed) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    memcpy(changed, wire, wire_length);
    changed[wire_length - 1] ^= 1;
    CHECK(eclipse_wallet_public_deserialize(changed, wire_length, &parsed) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    memcpy(changed, wire, wire_length);
    changed[4] = 1;
    CHECK(eclipse_wallet_public_deserialize(changed, wire_length, &parsed) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    memcpy(changed, wire, wire_length);
    changed[5] = 0xff;
    CHECK(eclipse_wallet_public_deserialize(changed, wire_length, &parsed) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    memcpy(changed, wire, wire_length);
    changed[7] ^= 1;
    CHECK(eclipse_wallet_public_deserialize(changed, wire_length, &parsed) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length - 1,
                                            &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_wallet_public_deserialize(wire, wire_length + 1,
                                            &parsed) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(memcmp(parsed.bytes, child.bytes, child.length) == 0);
    eclipse_wallet_public_key_t invalid_key = child;
    invalid_key.length--;
    CHECK(eclipse_wallet_public_serialize(&invalid_key, changed, sizeof(changed),
                                          &wire_length) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    text[0] = text[0] == '!' ? '#' : '!';
    CHECK(eclipse_wallet_public_from_base92(text, text_length, &parsed) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    free(text);
}

static void check_binding_rejects_wrong_context(const eclipse_wallet_t *wallet,
                                                eclipse_ml_dsa_scheme_t scheme)
{
    eclipse_ml_dsa_info_t info;
    CHECK(eclipse_ml_dsa_info(scheme, &info));
    uint8_t *binding = malloc(info.signature_size);
    CHECK(binding != NULL);
    size_t length = 0;
    CHECK(eclipse_wallet_child_binding_signature(wallet, ECLIPSE_WALLET_RECEIVE,
                                                  0, binding, info.signature_size,
                                                  &length) == ECLIPSE_SUCCESS);
    CHECK(length == info.signature_size);
    eclipse_wallet_public_key_t receive_master, spend_master, child;
    CHECK(eclipse_wallet_master_public(wallet, ECLIPSE_WALLET_RECEIVE,
                                       &receive_master) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_master_public(wallet, ECLIPSE_WALLET_SPEND,
                                       &spend_master) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_child_public(wallet, ECLIPSE_WALLET_RECEIVE, 0,
                                      &child) == ECLIPSE_SUCCESS);
    bool valid = false;
    CHECK(eclipse_wallet_verify_public_binding(&receive_master, &child,
                                                ECLIPSE_WALLET_RECEIVE, 0,
                                                binding, length, &valid) ==
          ECLIPSE_SUCCESS && valid);
    CHECK(eclipse_wallet_verify_public_binding(&receive_master, &child,
                                                ECLIPSE_WALLET_SPEND, 0,
                                                binding, length, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    CHECK(eclipse_wallet_verify_public_binding(&receive_master, &child,
                                                ECLIPSE_WALLET_RECEIVE, 1,
                                                binding, length, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    CHECK(eclipse_wallet_verify_public_binding(&spend_master, &child,
                                                ECLIPSE_WALLET_RECEIVE, 0,
                                                binding, length, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    binding[0] ^= 1;
    CHECK(eclipse_wallet_verify_public_binding(&receive_master, &child,
                                                ECLIPSE_WALLET_RECEIVE, 0,
                                                binding, length, &valid) ==
          ECLIPSE_SUCCESS && !valid);
    free(binding);
}

static void exercise_scheme(eclipse_ml_dsa_scheme_t scheme)
{
    eclipse_wallet_recovery_t *root = NULL;
    eclipse_wallet_t *wallet = NULL;
    CHECK(eclipse_wallet_create(scheme, &root, &wallet) == ECLIPSE_SUCCESS);
    CHECK(root != NULL && wallet != NULL);
    check_distinct_children(wallet);

    /* A single root rebuilds both masters and all 48 child public keys. */
    size_t root_length = 0;
    char *root_text = export_root(root, &root_length);
    eclipse_wallet_recovery_t *restored_root = NULL;
    CHECK(eclipse_wallet_recovery_import_base92(root_text, root_length,
                                                &restored_root) == ECLIPSE_SUCCESS);
    eclipse_wallet_t *restored = NULL;
    CHECK(eclipse_wallet_open(restored_root, &restored) == ECLIPSE_SUCCESS);
    compare_role(wallet, restored, ECLIPSE_WALLET_RECEIVE);
    compare_role(wallet, restored, ECLIPSE_WALLET_SPEND);

    /* Export one branch, import it, and prove the other branch is absent. */
    eclipse_wallet_domain_t *receive = NULL, *spend = NULL;
    CHECK(eclipse_wallet_derive_domain(root, ECLIPSE_WALLET_RECEIVE,
                                       &receive) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_derive_domain(root, ECLIPSE_WALLET_SPEND,
                                       &spend) == ECLIPSE_SUCCESS);
    eclipse_wallet_domain_t *invalid_domain = NULL;
    CHECK(eclipse_wallet_derive_domain(root, (eclipse_wallet_role_t)99,
                                       &invalid_domain) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(invalid_domain == NULL);
    size_t receive_length = 0, spend_length = 0;
    char *receive_text = export_domain(receive, &receive_length);
    char *spend_text = export_domain(spend, &spend_length);
    CHECK(receive_length == spend_length);
    CHECK(memcmp(receive_text, spend_text, receive_length) != 0);
    eclipse_wallet_domain_t *restored_receive = NULL, *restored_spend = NULL;
    CHECK(eclipse_wallet_domain_import_base92(receive_text, receive_length,
                                               &restored_receive) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_domain_import_base92(spend_text, spend_length,
                                               &restored_spend) == ECLIPSE_SUCCESS);
    eclipse_wallet_t *receive_only = NULL, *spend_only = NULL;
    CHECK(eclipse_wallet_open_domain(restored_receive, &receive_only) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_open_domain(restored_spend, &spend_only) == ECLIPSE_SUCCESS);
    compare_role(wallet, receive_only, ECLIPSE_WALLET_RECEIVE);
    compare_role(wallet, spend_only, ECLIPSE_WALLET_SPEND);
    eclipse_wallet_public_key_t public_key;
    CHECK(eclipse_wallet_master_public(receive_only, ECLIPSE_WALLET_SPEND,
                                       &public_key) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_wallet_child_public(receive_only, ECLIPSE_WALLET_SPEND, 0,
                                      &public_key) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_wallet_master_public(spend_only, ECLIPSE_WALLET_RECEIVE,
                                       &public_key) == ECLIPSE_ERROR_INVALID_ARGUMENT);

    /* Edited or wrong packet types never produce recovery objects. */
    root_text[0] = root_text[0] == '!' ? '#' : '!';
    eclipse_wallet_recovery_t *bad_root = NULL;
    CHECK(eclipse_wallet_recovery_import_base92(root_text, root_length,
                                                &bad_root) != ECLIPSE_SUCCESS);
    CHECK(bad_root == NULL);
    CHECK(eclipse_wallet_recovery_import_base92(receive_text, receive_length,
                                                &bad_root) != ECLIPSE_SUCCESS);
    eclipse_wallet_domain_t *bad_domain = NULL;
    CHECK(eclipse_wallet_domain_import_base92(root_text, root_length,
                                              &bad_domain) != ECLIPSE_SUCCESS);
    CHECK(bad_domain == NULL);
    size_t written = 99;
    CHECK(eclipse_wallet_recovery_export_base92(root, root_text, 1,
                                                &written) == ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    CHECK(written == 0);

    check_public_transport(wallet);
    check_binding_rejects_wrong_context(wallet, scheme);
    eclipse_wallet_recovery_free(root);
    eclipse_wallet_recovery_free(restored_root);
    eclipse_wallet_domain_free(receive);
    eclipse_wallet_domain_free(spend);
    eclipse_wallet_domain_free(restored_receive);
    eclipse_wallet_domain_free(restored_spend);
    /* Open wallets own their derived key pairs, not the imported secrets. */
    compare_role(wallet, receive_only, ECLIPSE_WALLET_RECEIVE);
    compare_role(wallet, spend_only, ECLIPSE_WALLET_SPEND);
    eclipse_wallet_free(wallet);
    eclipse_wallet_free(restored);
    eclipse_wallet_free(receive_only);
    eclipse_wallet_free(spend_only);
    OPENSSL_cleanse(root_text, eclipse_wallet_recovery_export_capacity());
    OPENSSL_cleanse(receive_text, eclipse_wallet_domain_export_capacity());
    OPENSSL_cleanse(spend_text, eclipse_wallet_domain_export_capacity());
    free(root_text);
    free(receive_text);
    free(spend_text);
}

int main(void)
{
    eclipse_wallet_recovery_t *root = NULL;
    eclipse_wallet_t *wallet = NULL;
    CHECK(eclipse_wallet_create((eclipse_ml_dsa_scheme_t)0, &root,
                                &wallet) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(root == NULL && wallet == NULL);
    exercise_scheme(ECLIPSE_ML_DSA_44);
    exercise_scheme(ECLIPSE_ML_DSA_65);
    exercise_scheme(ECLIPSE_ML_DSA_87);
    puts("Wallet recovery and domain tests passed");
    return EXIT_SUCCESS;
}
