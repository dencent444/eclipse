#include "particle.h"
#include "../log.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

/* Exact bytes are documented in protocol.md. The terminator is not hashed. */
static const uint8_t commitment_domain[] = "ECLIPSE/PARTICLE/COMMIT/V1";

#define COMMITMENT_PREIMAGE_SIZE (sizeof(commitment_domain) - 1u + 8u + \
                                  ECLIPSE_PARTICLE_MATERIAL_SIZE * 2u + \
                                  ECLIPSE_PARTICLE_RANDOMNESS_SIZE)

eclipse_error_t eclipse_particle_create(
    uint64_t amount,
    const uint8_t receive_material[ECLIPSE_PARTICLE_MATERIAL_SIZE],
    const uint8_t spend_authority[ECLIPSE_PARTICLE_MATERIAL_SIZE],
    eclipse_particle_t *out)
{
    if (receive_material == NULL || spend_authority == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("particle creation rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    eclipse_particle_t particle = {0};
    particle.amount = amount;
    memcpy(particle.receive_material, receive_material,
           ECLIPSE_PARTICLE_MATERIAL_SIZE);
    memcpy(particle.spend_authority, spend_authority,
           ECLIPSE_PARTICLE_MATERIAL_SIZE);
    if (RAND_priv_bytes(particle.randomness,
                        ECLIPSE_PARTICLE_RANDOMNESS_SIZE) != 1) {
        eclipse_particle_clear(&particle);
        ECLIPSE_LOG_ERROR("particle randomness generation failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    *out = particle;
    eclipse_particle_clear(&particle); /* Remove the temporary secret copy. */
    ECLIPSE_LOG_INFO(3, "particle opening created with fresh randomness");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_particle_commitment(const eclipse_particle_t *particle,
                                            uint8_t *output, size_t capacity)
{
    if (particle == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("particle commitment rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (capacity < ECLIPSE_PARTICLE_COMMITMENT_SIZE) {
        ECLIPSE_LOG_WARNING("particle commitment output buffer is too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t preimage[COMMITMENT_PREIMAGE_SIZE];
    size_t at = 0;
    memcpy(preimage + at, commitment_domain, sizeof(commitment_domain) - 1u);
    at += sizeof(commitment_domain) - 1u;
    /* A fixed byte order prevents different machines from committing to
       different values for the same in-memory uint64_t amount. */
    for (unsigned i = 0; i < 8; ++i)
        preimage[at++] = (uint8_t)(particle->amount >> (56u - 8u * i));
    memcpy(preimage + at, particle->receive_material,
           ECLIPSE_PARTICLE_MATERIAL_SIZE);
    at += ECLIPSE_PARTICLE_MATERIAL_SIZE;
    memcpy(preimage + at, particle->spend_authority,
           ECLIPSE_PARTICLE_MATERIAL_SIZE);
    at += ECLIPSE_PARTICLE_MATERIAL_SIZE;
    memcpy(preimage + at, particle->randomness,
           ECLIPSE_PARTICLE_RANDOMNESS_SIZE);
    at += ECLIPSE_PARTICLE_RANDOMNESS_SIZE;

    size_t digest_length = 0;
    uint8_t digest[ECLIPSE_PARTICLE_COMMITMENT_SIZE];
    int ok = at == sizeof(preimage) &&
             EVP_Q_digest(NULL, "SHA3-256", NULL, preimage, sizeof(preimage),
                          digest, &digest_length) == 1 &&
             digest_length == sizeof(digest);
    OPENSSL_cleanse(preimage, sizeof(preimage));
    if (!ok) {
        OPENSSL_cleanse(digest, sizeof(digest));
        ECLIPSE_LOG_ERROR("particle SHA3-256 commitment failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    memcpy(output, digest, sizeof(digest));
    OPENSSL_cleanse(digest, sizeof(digest));
    ECLIPSE_LOG_INFO(5, "particle commitment computed");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_particle_verify_commitment(
    const eclipse_particle_t *particle, const uint8_t *commitment,
    size_t commitment_length, bool *valid)
{
    if (valid == NULL) {
        ECLIPSE_LOG_WARNING("particle commitment verification result is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *valid = false;
    if (particle == NULL || commitment == NULL) {
        ECLIPSE_LOG_WARNING("particle commitment verification input is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (commitment_length != ECLIPSE_PARTICLE_COMMITMENT_SIZE) {
        ECLIPSE_LOG_INFO(4, "particle commitment rejected: wrong length");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    uint8_t expected[ECLIPSE_PARTICLE_COMMITMENT_SIZE];
    eclipse_error_t status = eclipse_particle_commitment(
        particle, expected, sizeof(expected));
    if (status != ECLIPSE_SUCCESS) return status;
    *valid = CRYPTO_memcmp(expected, commitment, sizeof(expected)) == 0;
    OPENSSL_cleanse(expected, sizeof(expected));
    ECLIPSE_LOG_INFO(4, "particle commitment opening %s",
                     *valid ? "matched" : "did not match");
    return ECLIPSE_SUCCESS;
}

void eclipse_particle_clear(eclipse_particle_t *particle)
{
    if (particle == NULL) return;
    OPENSSL_cleanse(particle, sizeof(*particle));
    ECLIPSE_LOG_INFO(5, "particle opening cleared");
}
