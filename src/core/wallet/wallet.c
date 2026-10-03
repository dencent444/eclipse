#include "wallet.h"
#include "keypair_internal.h"
#include "recovery_internal.h"
#include "../encoding/base92.h"
#include "../log.h"

#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>

#define PUBLIC_PACKET_HEADER_SIZE 8u
#define CHILD_BINDING_HEADER_SIZE 8u

static const uint8_t binding_context[] = "ECLIPSE/WALLET/CHILD/V1";

typedef struct {
    eclipse_wallet_keypair_t *master;
    eclipse_wallet_keypair_t *children[ECLIPSE_WALLET_POOL_SIZE];
    uint8_t *signatures[ECLIPSE_WALLET_POOL_SIZE];
    size_t signature_lengths[ECLIPSE_WALLET_POOL_SIZE];
} wallet_pool_t;

struct eclipse_wallet {
    eclipse_ml_dsa_scheme_t scheme;
    bool has_receive;
    bool has_spend;
    wallet_pool_t receive;
    wallet_pool_t spend;
};

static uint8_t wire_scheme(eclipse_ml_dsa_scheme_t scheme)
{
    switch (scheme) {
    case ECLIPSE_ML_DSA_44: return 1;
    case ECLIPSE_ML_DSA_65: return 2;
    case ECLIPSE_ML_DSA_87: return 3;
    default: return 0;
    }
}

static eclipse_ml_dsa_scheme_t scheme_from_wire(uint8_t wire)
{
    switch (wire) {
    case 1: return ECLIPSE_ML_DSA_44;
    case 2: return ECLIPSE_ML_DSA_65;
    case 3: return ECLIPSE_ML_DSA_87;
    default: return 0;
    }
}

static const wallet_pool_t *role_pool(const eclipse_wallet_t *wallet,
                                      eclipse_wallet_role_t role)
{
    if (role == ECLIPSE_WALLET_RECEIVE && wallet->has_receive)
        return &wallet->receive;
    if (role == ECLIPSE_WALLET_SPEND && wallet->has_spend)
        return &wallet->spend;
    return NULL;
}

static void pool_free(wallet_pool_t *pool)
{
    for (size_t i = 0; i < ECLIPSE_WALLET_POOL_SIZE; ++i) {
        free(pool->signatures[i]);
        eclipse_wallet_keypair_free(pool->children[i]);
    }
    eclipse_wallet_keypair_free(pool->master);
}

static eclipse_error_t public_from_pair(const eclipse_wallet_keypair_t *pair,
                                         eclipse_wallet_public_key_t *out)
{
    const uint8_t *bytes;
    size_t length;
    eclipse_ml_dsa_scheme_t scheme;
    eclipse_error_t status = eclipse_wallet_keypair_public(pair, &scheme,
                                                            &bytes, &length);
    if (status != ECLIPSE_SUCCESS) return status;
    if (length > sizeof(out->bytes)) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_wallet_public_key_t result = {0};
    result.scheme = scheme;
    result.length = length;
    memcpy(result.bytes, bytes, length);
    *out = result;
    return ECLIPSE_SUCCESS;
}

static eclipse_error_t binding_message(const eclipse_wallet_public_key_t *child,
                                        eclipse_wallet_role_t role, size_t index,
                                        uint8_t *message, size_t *length)
{
    eclipse_ml_dsa_info_t info;
    if ((role != ECLIPSE_WALLET_RECEIVE && role != ECLIPSE_WALLET_SPEND) ||
        index >= ECLIPSE_WALLET_POOL_SIZE ||
        !eclipse_ml_dsa_info(child->scheme, &info) ||
        child->length != info.public_key_size ||
        child->length > ECLIPSE_WALLET_PUBLIC_MAX_SIZE)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;

    /* A fixed domain, version, role, index, scheme, and exact public bytes
       prevent the same signature from describing another wallet slot. */
    memcpy(message, "EWCH", 4);
    message[4] = 1;
    message[5] = (uint8_t)role;
    message[6] = (uint8_t)index;
    message[7] = wire_scheme(child->scheme);
    memcpy(message + CHILD_BINDING_HEADER_SIZE, child->bytes, child->length);
    *length = CHILD_BINDING_HEADER_SIZE + child->length;
    return ECLIPSE_SUCCESS;
}

static eclipse_error_t pool_derive(wallet_pool_t *pool,
                                   const eclipse_wallet_domain_t *domain)
{
    const eclipse_ml_dsa_scheme_t scheme = domain->scheme;
    const eclipse_wallet_role_t role = domain->role;
    uint8_t seed[ECLIPSE_WALLET_SECRET_SIZE] = {0};
    eclipse_error_t status = eclipse_wallet_derive_key_seed(domain, 0, 0, seed);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_wallet_keypair_from_seed(scheme, seed, sizeof(seed),
                                                  &pool->master);
    OPENSSL_cleanse(seed, sizeof(seed));
    if (status != ECLIPSE_SUCCESS) return status;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(scheme, &info)) return ECLIPSE_ERROR_INVALID_ARGUMENT;

    for (size_t i = 0; i < ECLIPSE_WALLET_POOL_SIZE; ++i) {
        status = eclipse_wallet_derive_key_seed(domain, 1, (uint32_t)i, seed);
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_wallet_keypair_from_seed(scheme, seed, sizeof(seed),
                                                      &pool->children[i]);
        OPENSSL_cleanse(seed, sizeof(seed));
        if (status != ECLIPSE_SUCCESS) return status;
        pool->signatures[i] = malloc(info.signature_size);
        if (pool->signatures[i] == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;

        uint8_t message[CHILD_BINDING_HEADER_SIZE + ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
        size_t message_length = 0;
        eclipse_wallet_public_key_t child_public;
        status = public_from_pair(pool->children[i], &child_public);
        if (status != ECLIPSE_SUCCESS) return status;
        status = binding_message(&child_public, role, i, message, &message_length);
        if (status != ECLIPSE_SUCCESS) return status;
        status = eclipse_wallet_keypair_sign(pool->master, message, message_length,
                                             binding_context,
                                             sizeof(binding_context) - 1,
                                             pool->signatures[i], info.signature_size,
                                             &pool->signature_lengths[i]);
        if (status != ECLIPSE_SUCCESS) return status;
    }
    ECLIPSE_LOG_INFO(2, "%s pool deterministically derived with %u child keys",
                     role == ECLIPSE_WALLET_RECEIVE ? "receive" : "spend",
                     ECLIPSE_WALLET_POOL_SIZE);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_create(eclipse_ml_dsa_scheme_t scheme,
                                      eclipse_wallet_recovery_t **recovery_out,
                                      eclipse_wallet_t **wallet_out)
{
    if (recovery_out == NULL || wallet_out == NULL) {
        ECLIPSE_LOG_WARNING("wallet creation output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *recovery_out = NULL;
    *wallet_out = NULL;
    eclipse_wallet_recovery_t *recovery = NULL;
    eclipse_error_t status = eclipse_wallet_recovery_generate(scheme, &recovery);
    if (status != ECLIPSE_SUCCESS) return status;
    status = eclipse_wallet_open(recovery, wallet_out);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_wallet_recovery_free(recovery);
        return status;
    }
    *recovery_out = recovery;
    ECLIPSE_LOG_INFO(1, "recoverable wallet created; root kept separate");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_open(const eclipse_wallet_recovery_t *recovery,
                                    eclipse_wallet_t **out)
{
    if (out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (recovery == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(recovery->scheme, &info)) {
        ECLIPSE_LOG_WARNING("wallet open rejected an unknown ML-DSA scheme");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_wallet_domain_t *receive = NULL;
    eclipse_wallet_domain_t *spend = NULL;
    eclipse_error_t status = eclipse_wallet_derive_domain(
        recovery, ECLIPSE_WALLET_RECEIVE, &receive);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_wallet_derive_domain(recovery, ECLIPSE_WALLET_SPEND, &spend);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_wallet_domain_free(receive);
        eclipse_wallet_domain_free(spend);
        return status;
    }
    eclipse_wallet_t *wallet = calloc(1, sizeof(*wallet));
    if (wallet == NULL) {
        eclipse_wallet_domain_free(receive);
        eclipse_wallet_domain_free(spend);
        ECLIPSE_LOG_ERROR("wallet handle allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    wallet->scheme = recovery->scheme;

    ECLIPSE_LOG_INFO(1, "wallet key-pool derivation started");
    status = pool_derive(&wallet->receive, receive);
    if (status == ECLIPSE_SUCCESS) {
        wallet->has_receive = true;
        status = pool_derive(&wallet->spend, spend);
    }
    if (status == ECLIPSE_SUCCESS) wallet->has_spend = true;
    eclipse_wallet_domain_free(receive);
    eclipse_wallet_domain_free(spend);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_wallet_free(wallet); /* Also handles a partially built pool. */
        ECLIPSE_LOG_ERROR("wallet key-pool derivation failed with code %d", status);
        return status;
    }
    *out = wallet;
    ECLIPSE_LOG_INFO(1, "wallet key-pool derivation completed");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_open_domain(const eclipse_wallet_domain_t *domain,
                                           eclipse_wallet_t **out)
{
    if (out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (domain == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(domain->scheme, &info) ||
        (domain->role != ECLIPSE_WALLET_RECEIVE &&
         domain->role != ECLIPSE_WALLET_SPEND))
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_wallet_t *wallet = calloc(1, sizeof(*wallet));
    if (wallet == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    wallet->scheme = domain->scheme;
    wallet_pool_t *pool = domain->role == ECLIPSE_WALLET_RECEIVE ?
                          &wallet->receive : &wallet->spend;
    eclipse_error_t status = pool_derive(pool, domain);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_wallet_free(wallet);
        return status;
    }
    if (domain->role == ECLIPSE_WALLET_RECEIVE) wallet->has_receive = true;
    else wallet->has_spend = true;
    *out = wallet;
    ECLIPSE_LOG_INFO(2, "%s-only wallet opened without the other domain",
                     domain->role == ECLIPSE_WALLET_RECEIVE ? "receive" : "spend");
    return ECLIPSE_SUCCESS;
}

void eclipse_wallet_free(eclipse_wallet_t *wallet)
{
    if (wallet == NULL) return;
    pool_free(&wallet->receive);
    pool_free(&wallet->spend);
    free(wallet);
    ECLIPSE_LOG_INFO(3, "wallet key pools released");
}

eclipse_error_t eclipse_wallet_master_public(const eclipse_wallet_t *wallet,
                                              eclipse_wallet_role_t role,
                                              eclipse_wallet_public_key_t *out)
{
    if (wallet == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("master public-key view rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    const wallet_pool_t *pool = role_pool(wallet, role);
    if (pool == NULL) {
        ECLIPSE_LOG_WARNING("master public-key view rejected an invalid role");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_error_t status = public_from_pair(pool->master, out);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(5, "master public-key copy returned");
    return status;
}

eclipse_error_t eclipse_wallet_child_public(const eclipse_wallet_t *wallet,
                                             eclipse_wallet_role_t role,
                                             size_t index,
                                             eclipse_wallet_public_key_t *out)
{
    if (wallet == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("child public-key view rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    const wallet_pool_t *pool = role_pool(wallet, role);
    if (pool == NULL || index >= ECLIPSE_WALLET_POOL_SIZE) {
        ECLIPSE_LOG_WARNING("child public-key view rejected role or index");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_error_t status = public_from_pair(pool->children[index], out);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(5, "child public-key copy returned");
    return status;
}

eclipse_error_t eclipse_wallet_verify_child_binding(const eclipse_wallet_t *wallet,
                                                     eclipse_wallet_role_t role,
                                                     size_t index, bool *valid)
{
    if (valid == NULL) {
        ECLIPSE_LOG_WARNING("binding verification result output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *valid = false;
    if (wallet == NULL) {
        ECLIPSE_LOG_WARNING("binding verification wallet is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    const wallet_pool_t *pool = role_pool(wallet, role);
    if (pool == NULL || index >= ECLIPSE_WALLET_POOL_SIZE) {
        ECLIPSE_LOG_WARNING("binding verification rejected role or index");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    eclipse_wallet_public_key_t master;
    eclipse_wallet_public_key_t child;
    eclipse_error_t status = public_from_pair(pool->master, &master);
    if (status != ECLIPSE_SUCCESS) return status;
    status = public_from_pair(pool->children[index], &child);
    if (status != ECLIPSE_SUCCESS) return status;
    status = eclipse_wallet_verify_public_binding(&master, &child, role, index,
                                                    pool->signatures[index],
                                                    pool->signature_lengths[index],
                                                    valid);
    ECLIPSE_LOG_INFO(4, "wallet child binding %s",
                     status == ECLIPSE_SUCCESS && *valid ? "verified" : "rejected");
    return status;
}

eclipse_error_t eclipse_wallet_child_binding_signature(
    const eclipse_wallet_t *wallet, eclipse_wallet_role_t role, size_t index,
    uint8_t *output, size_t capacity, size_t *written)
{
    if (written == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *written = 0;
    if (wallet == NULL || output == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    const wallet_pool_t *pool = role_pool(wallet, role);
    if (pool == NULL || index >= ECLIPSE_WALLET_POOL_SIZE)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    size_t length = pool->signature_lengths[index];
    if (capacity < length) return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    memcpy(output, pool->signatures[index], length);
    *written = length;
    ECLIPSE_LOG_INFO(5, "wallet child binding signature copied");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_verify_public_binding(
    const eclipse_wallet_public_key_t *master,
    const eclipse_wallet_public_key_t *child,
    eclipse_wallet_role_t role, size_t index,
    const uint8_t *signature, size_t signature_length, bool *valid)
{
    if (valid == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *valid = false;
    if (master == NULL || child == NULL || signature == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    if (master->scheme != child->scheme) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    uint8_t message[CHILD_BINDING_HEADER_SIZE + ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
    size_t message_length = 0;
    eclipse_error_t status = binding_message(child, role, index, message,
                                              &message_length);
    if (status != ECLIPSE_SUCCESS) return status;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(master->scheme, &info) ||
        master->length != info.public_key_size)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;

    /* Both public components are validated before treating the certificate
       as a statement about a usable ML-DSA child key. */
    eclipse_ml_dsa_key_t *child_key = NULL;
    status = eclipse_ml_dsa_import_public(child->scheme, child->bytes,
                                           child->length, &child_key);
    eclipse_ml_dsa_key_free(child_key);
    if (status != ECLIPSE_SUCCESS) return status;
    eclipse_ml_dsa_key_t *master_key = NULL;
    status = eclipse_ml_dsa_import_public(master->scheme, master->bytes,
                                           master->length, &master_key);
    if (status != ECLIPSE_SUCCESS) return status;
    status = eclipse_ml_dsa_verify(master_key, message, message_length,
                                    binding_context, sizeof(binding_context) - 1,
                                    signature, signature_length, valid);
    eclipse_ml_dsa_key_free(master_key);
    ECLIPSE_LOG_INFO(4, "public wallet binding %s",
                     status == ECLIPSE_SUCCESS && *valid ? "accepted" : "rejected");
    return status;
}

size_t eclipse_wallet_public_serialized_size(eclipse_ml_dsa_scheme_t scheme)
{
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(scheme, &info)) return 0;
    return PUBLIC_PACKET_HEADER_SIZE + info.public_key_size;
}

eclipse_error_t eclipse_wallet_public_serialize(const eclipse_wallet_public_key_t *key,
                                                 uint8_t *output, size_t capacity,
                                                 size_t *written)
{
    if (written == NULL) {
        ECLIPSE_LOG_WARNING("public serialization length output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *written = 0;
    if (key == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("public serialization rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    size_t size = eclipse_wallet_public_serialized_size(key->scheme);
    if (size == 0 || key->length != size - PUBLIC_PACKET_HEADER_SIZE) {
        ECLIPSE_LOG_WARNING("public serialization rejected scheme or key length");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    if (capacity < size) {
        ECLIPSE_LOG_WARNING("public serialization buffer is too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }

    /* Validate even caller-constructed key structs before producing bytes. */
    eclipse_ml_dsa_key_t *checked = NULL;
    eclipse_error_t status = eclipse_ml_dsa_import_public(key->scheme, key->bytes,
                                                           key->length, &checked);
    eclipse_ml_dsa_key_free(checked);
    if (status != ECLIPSE_SUCCESS) return status;
    memcpy(output, "EWPK", 4);
    output[4] = 1;
    output[5] = wire_scheme(key->scheme);
    output[6] = (uint8_t)(key->length >> 8);
    output[7] = (uint8_t)key->length;
    memcpy(output + PUBLIC_PACKET_HEADER_SIZE, key->bytes, key->length);
    *written = size;
    ECLIPSE_LOG_INFO(5, "wallet public key serialized");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_public_deserialize(const uint8_t *input, size_t length,
                                                   eclipse_wallet_public_key_t *out)
{
    if (input == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("public deserialization rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (length < PUBLIC_PACKET_HEADER_SIZE || memcmp(input, "EWPK", 4) != 0 ||
        input[4] != 1) {
        ECLIPSE_LOG_INFO(4, "public packet rejected: header invalid");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_ml_dsa_scheme_t scheme = scheme_from_wire(input[5]);
    size_t expected = eclipse_wallet_public_serialized_size(scheme);
    size_t declared = ((size_t)input[6] << 8) | input[7];
    if (expected == 0 || length != expected ||
        declared != expected - PUBLIC_PACKET_HEADER_SIZE) {
        ECLIPSE_LOG_INFO(4, "public packet rejected: scheme or length invalid");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    eclipse_wallet_public_key_t result = {0};
    result.scheme = scheme;
    result.length = declared;
    memcpy(result.bytes, input + PUBLIC_PACKET_HEADER_SIZE, declared);
    eclipse_ml_dsa_key_t *checked = NULL;
    eclipse_error_t status = eclipse_ml_dsa_import_public(scheme, result.bytes,
                                                           result.length, &checked);
    eclipse_ml_dsa_key_free(checked);
    if (status != ECLIPSE_SUCCESS) return status;
    *out = result;
    ECLIPSE_LOG_INFO(5, "wallet public key deserialized");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_public_to_base92(const eclipse_wallet_public_key_t *key,
                                                 char *output, size_t capacity,
                                                 size_t *written)
{
    if (written == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *written = 0;
    if (key == NULL || output == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t raw[PUBLIC_PACKET_HEADER_SIZE + ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
    size_t raw_length = 0;
    eclipse_error_t status = eclipse_wallet_public_serialize(key, raw,
                                                              sizeof(raw), &raw_length);
    if (status != ECLIPSE_SUCCESS) return status;
    return eclipse_base92_encode(raw, raw_length, output, capacity, written);
}

eclipse_error_t eclipse_wallet_public_from_base92(const char *text, size_t length,
                                                   eclipse_wallet_public_key_t *out)
{
    if (text == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t raw[PUBLIC_PACKET_HEADER_SIZE + ECLIPSE_WALLET_PUBLIC_MAX_SIZE];
    if (length >= eclipse_base92_encoded_capacity(sizeof(raw)))
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    size_t raw_length = 0;
    eclipse_error_t status = eclipse_base92_decode(text, length, raw,
                                                    sizeof(raw), &raw_length);
    if (status != ECLIPSE_SUCCESS) return status;
    return eclipse_wallet_public_deserialize(raw, raw_length, out);
}
