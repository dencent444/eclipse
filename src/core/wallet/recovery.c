#include "recovery_internal.h"
#include "../encoding/base92.h"
#include "../log.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <string.h>

#define ROOT_PREFIX_SIZE 6u
#define DOMAIN_PREFIX_SIZE 7u
#define CHECKSUM_SIZE 32u
#define ROOT_PACKET_SIZE (ROOT_PREFIX_SIZE + ECLIPSE_WALLET_SECRET_SIZE + CHECKSUM_SIZE)
#define DOMAIN_PACKET_SIZE (DOMAIN_PREFIX_SIZE + ECLIPSE_WALLET_SECRET_SIZE + CHECKSUM_SIZE)

/* This is a dev-wallet format. A future network needs its own network ID and
 * versioned derivation specification before any keys are used for funds. */
static const uint8_t kdf_salt[] = "ECLIPSE/DEV/WALLET/V1/HKDF-SHA256";
static const uint8_t domain_label[] = "ECLIPSE/DEV/WALLET/V1/DOMAIN";
static const uint8_t key_label[] = "ECLIPSE/DEV/WALLET/V1/KEY";

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

static bool valid_role(eclipse_wallet_role_t role)
{
    return role == ECLIPSE_WALLET_RECEIVE || role == ECLIPSE_WALLET_SPEND;
}

static eclipse_error_t derive32(const uint8_t parent[ECLIPSE_WALLET_SECRET_SIZE],
                                const uint8_t *info, size_t info_length,
                                uint8_t output[ECLIPSE_WALLET_SECRET_SIZE])
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = kdf == NULL ? NULL : EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        ECLIPSE_LOG_ERROR("wallet HKDF setup failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    char digest[] = "SHA256";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                          (void *)parent, ECLIPSE_WALLET_SECRET_SIZE),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          (void *)kdf_salt, sizeof(kdf_salt) - 1),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          (void *)info, info_length),
        OSSL_PARAM_construct_end()
    };
    int ok = EVP_KDF_derive(ctx, output, ECLIPSE_WALLET_SECRET_SIZE, params) > 0;
    EVP_KDF_CTX_free(ctx);
    if (!ok) {
        OPENSSL_cleanse(output, ECLIPSE_WALLET_SECRET_SIZE);
        ECLIPSE_LOG_ERROR("wallet HKDF derivation failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_recovery_generate(eclipse_ml_dsa_scheme_t scheme,
                                                 eclipse_wallet_recovery_t **out)
{
    if (out == NULL) {
        ECLIPSE_LOG_WARNING("recovery generation output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    if (wire_scheme(scheme) == 0) {
        ECLIPSE_LOG_WARNING("recovery generation rejected an unknown scheme");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_wallet_recovery_t *root = OPENSSL_zalloc(sizeof(*root));
    if (root == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    root->scheme = scheme;
    if (RAND_priv_bytes(root->secret, sizeof(root->secret)) != 1) {
        eclipse_wallet_recovery_free(root);
        ECLIPSE_LOG_ERROR("wallet recovery root generation failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    *out = root;
    ECLIPSE_LOG_INFO(1, "new wallet recovery root generated in memory");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_derive_domain(const eclipse_wallet_recovery_t *recovery,
                                             eclipse_wallet_role_t role,
                                             eclipse_wallet_domain_t **out)
{
    if (out == NULL) {
        ECLIPSE_LOG_WARNING("domain derivation output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    if (recovery == NULL) {
        ECLIPSE_LOG_WARNING("domain derivation root is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (!valid_role(role) || wire_scheme(recovery->scheme) == 0) {
        ECLIPSE_LOG_WARNING("domain derivation rejected role or scheme");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_wallet_domain_t *domain = OPENSSL_zalloc(sizeof(*domain));
    if (domain == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    domain->scheme = recovery->scheme;
    domain->role = role;
    uint8_t info[sizeof(domain_label) - 1 + 2];
    memcpy(info, domain_label, sizeof(domain_label) - 1);
    info[sizeof(domain_label) - 1] = wire_scheme(recovery->scheme);
    info[sizeof(domain_label)] = (uint8_t)role;
    eclipse_error_t status = derive32(recovery->secret, info, sizeof(info),
                                      domain->secret);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_wallet_domain_free(domain);
        return status;
    }
    *out = domain;
    ECLIPSE_LOG_INFO(2, "%s wallet domain derived",
                     role == ECLIPSE_WALLET_RECEIVE ? "receive" : "spend");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_wallet_derive_key_seed(const eclipse_wallet_domain_t *domain,
                                               uint8_t kind, uint32_t index,
                                               uint8_t output[ECLIPSE_WALLET_SECRET_SIZE])
{
    if (domain == NULL || output == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (!valid_role(domain->role) || wire_scheme(domain->scheme) == 0 ||
        kind > 1 || (kind == 0 && index != 0))
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    uint8_t info[sizeof(key_label) - 1 + 7];
    memcpy(info, key_label, sizeof(key_label) - 1);
    size_t at = sizeof(key_label) - 1;
    info[at++] = wire_scheme(domain->scheme);
    info[at++] = (uint8_t)domain->role;
    info[at++] = kind;
    info[at++] = (uint8_t)(index >> 24);
    info[at++] = (uint8_t)(index >> 16);
    info[at++] = (uint8_t)(index >> 8);
    info[at++] = (uint8_t)index;
    eclipse_error_t status = derive32(domain->secret, info, sizeof(info), output);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(5, "wallet role-scoped ML-DSA seed derived");
    return status;
}

void eclipse_wallet_recovery_free(eclipse_wallet_recovery_t *recovery)
{
    if (recovery == NULL) return;
    OPENSSL_clear_free(recovery, sizeof(*recovery));
    ECLIPSE_LOG_INFO(3, "wallet recovery root erased from its object");
}

void eclipse_wallet_domain_free(eclipse_wallet_domain_t *domain)
{
    if (domain == NULL) return;
    OPENSSL_clear_free(domain, sizeof(*domain));
    ECLIPSE_LOG_INFO(4, "wallet domain secret erased from its object");
}

static eclipse_error_t export_packet(const char magic[4], uint8_t scheme,
                                     uint8_t role, size_t prefix_size,
                                     const uint8_t secret[ECLIPSE_WALLET_SECRET_SIZE],
                                     char *output, size_t capacity, size_t *written)
{
    if (written == NULL) {
        ECLIPSE_LOG_WARNING("wallet secret export length output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *written = 0;
    if (secret == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("wallet secret export rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    size_t packet_size = prefix_size + ECLIPSE_WALLET_SECRET_SIZE + CHECKSUM_SIZE;
    size_t needed = eclipse_base92_encoded_capacity(packet_size);
    if (capacity < needed) {
        ECLIPSE_LOG_WARNING("wallet secret export buffer is too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }
    uint8_t packet[DOMAIN_PACKET_SIZE] = {0};
    memcpy(packet, magic, 4);
    packet[4] = 1;
    packet[5] = scheme;
    if (prefix_size == DOMAIN_PREFIX_SIZE) packet[6] = role;
    memcpy(packet + prefix_size, secret, ECLIPSE_WALLET_SECRET_SIZE);
    size_t digest_length = 0;
    eclipse_error_t status = ECLIPSE_SUCCESS;
    if (EVP_Q_digest(NULL, "SHA2-256", NULL, packet,
                     packet_size - CHECKSUM_SIZE,
                     packet + packet_size - CHECKSUM_SIZE,
                     &digest_length) != 1 || digest_length != CHECKSUM_SIZE)
        status = ECLIPSE_ERROR_CRYPTO_FAILURE;
    if (status == ECLIPSE_SUCCESS) {
        status = eclipse_base92_encode(packet, packet_size, output, capacity, written);
        if (status != ECLIPSE_SUCCESS) OPENSSL_cleanse(output, needed);
    }
    OPENSSL_cleanse(packet, sizeof(packet));
    if (status != ECLIPSE_SUCCESS) ECLIPSE_LOG_ERROR("wallet secret export failed");
    return status;
}

static eclipse_error_t import_packet(const char *text, size_t length,
                                     const char magic[4], size_t prefix_size,
                                     uint8_t *scheme, uint8_t *role,
                                     uint8_t secret[ECLIPSE_WALLET_SECRET_SIZE])
{
    if (text == NULL || scheme == NULL || role == NULL || secret == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    size_t packet_size = prefix_size + ECLIPSE_WALLET_SECRET_SIZE + CHECKSUM_SIZE;
    if (length != eclipse_base92_encoded_capacity(packet_size) - 1)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    uint8_t packet[DOMAIN_PACKET_SIZE] = {0};
    size_t decoded = 0;
    eclipse_error_t status = eclipse_base92_decode(text, length, packet,
                                                   packet_size, &decoded);
    if (status == ECLIPSE_SUCCESS) {
        uint8_t digest[CHECKSUM_SIZE];
        size_t digest_length = 0;
        int digest_ok = EVP_Q_digest(NULL, "SHA2-256", NULL, packet,
                                     packet_size - CHECKSUM_SIZE,
                                     digest, &digest_length) == 1;
        if (!digest_ok || decoded != packet_size || digest_length != CHECKSUM_SIZE ||
            CRYPTO_memcmp(digest, packet + packet_size - CHECKSUM_SIZE,
                          CHECKSUM_SIZE) != 0 ||
            memcmp(packet, magic, 4) != 0 || packet[4] != 1 ||
            scheme_from_wire(packet[5]) == 0 ||
            (prefix_size == DOMAIN_PREFIX_SIZE &&
             !valid_role((eclipse_wallet_role_t)packet[6])))
            status = ECLIPSE_ERROR_INVALID_ARGUMENT;
        OPENSSL_cleanse(digest, sizeof(digest));
    }
    if (status == ECLIPSE_SUCCESS) {
        *scheme = packet[5];
        *role = prefix_size == DOMAIN_PREFIX_SIZE ? packet[6] : 0;
        memcpy(secret, packet + prefix_size, ECLIPSE_WALLET_SECRET_SIZE);
    }
    OPENSSL_cleanse(packet, sizeof(packet));
    if (status != ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(4, "wallet secret packet rejected");
    return status;
}

size_t eclipse_wallet_recovery_export_capacity(void)
{
    return eclipse_base92_encoded_capacity(ROOT_PACKET_SIZE);
}

eclipse_error_t eclipse_wallet_recovery_export_base92(
    const eclipse_wallet_recovery_t *recovery, char *output, size_t capacity,
    size_t *written)
{
    if (written == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *written = 0;
    if (recovery == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (wire_scheme(recovery->scheme) == 0) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_error_t status = export_packet("EWRT", wire_scheme(recovery->scheme),
                                           0, ROOT_PREFIX_SIZE, recovery->secret,
                                           output, capacity, written);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(1, "wallet recovery root explicitly exported");
    return status;
}

eclipse_error_t eclipse_wallet_recovery_import_base92(
    const char *text, size_t length, eclipse_wallet_recovery_t **out)
{
    if (out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (text == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    eclipse_wallet_recovery_t *recovery = OPENSSL_zalloc(sizeof(*recovery));
    if (recovery == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    uint8_t scheme = 0, role = 0;
    eclipse_error_t status = import_packet(text, length, "EWRT", ROOT_PREFIX_SIZE,
                                           &scheme, &role, recovery->secret);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_wallet_recovery_free(recovery);
        return status;
    }
    recovery->scheme = scheme_from_wire(scheme);
    *out = recovery;
    ECLIPSE_LOG_INFO(2, "wallet recovery root imported from explicit text");
    return ECLIPSE_SUCCESS;
}

size_t eclipse_wallet_domain_export_capacity(void)
{
    return eclipse_base92_encoded_capacity(DOMAIN_PACKET_SIZE);
}

eclipse_error_t eclipse_wallet_domain_export_base92(
    const eclipse_wallet_domain_t *domain, char *output, size_t capacity,
    size_t *written)
{
    if (written == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *written = 0;
    if (domain == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (wire_scheme(domain->scheme) == 0 || !valid_role(domain->role))
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_error_t status = export_packet("EWDM", wire_scheme(domain->scheme),
                                           (uint8_t)domain->role,
                                           DOMAIN_PREFIX_SIZE, domain->secret,
                                           output, capacity, written);
    if (status == ECLIPSE_SUCCESS)
        ECLIPSE_LOG_INFO(2, "%s wallet domain explicitly exported",
                         domain->role == ECLIPSE_WALLET_RECEIVE ? "receive" : "spend");
    return status;
}

eclipse_error_t eclipse_wallet_domain_import_base92(
    const char *text, size_t length, eclipse_wallet_domain_t **out)
{
    if (out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (text == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    eclipse_wallet_domain_t *domain = OPENSSL_zalloc(sizeof(*domain));
    if (domain == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    uint8_t scheme = 0, role = 0;
    eclipse_error_t status = import_packet(text, length, "EWDM", DOMAIN_PREFIX_SIZE,
                                           &scheme, &role, domain->secret);
    if (status != ECLIPSE_SUCCESS) {
        eclipse_wallet_domain_free(domain);
        return status;
    }
    domain->scheme = scheme_from_wire(scheme);
    domain->role = (eclipse_wallet_role_t)role;
    *out = domain;
    ECLIPSE_LOG_INFO(3, "%s wallet domain imported from explicit text",
                     domain->role == ECLIPSE_WALLET_RECEIVE ? "receive" : "spend");
    return ECLIPSE_SUCCESS;
}
