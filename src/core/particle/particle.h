#ifndef ECLIPSE_PARTICLE_H
#define ECLIPSE_PARTICLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ECLIPSE_PARTICLE_MATERIAL_SIZE 32u
#define ECLIPSE_PARTICLE_RANDOMNESS_SIZE 32u
#define ECLIPSE_PARTICLE_COMMITMENT_SIZE 32u

/* Private note opening. These fields must not be put on the public chain.
 * receive_material and spend_authority are opaque 32-byte placeholders until
 * the viewing, authorization, and proof protocols are specified. A commitment
 * is derived separately; including it here would duplicate mutable state. */
typedef struct {
    uint64_t amount;
    uint8_t receive_material[ECLIPSE_PARTICLE_MATERIAL_SIZE];
    uint8_t spend_authority[ECLIPSE_PARTICLE_MATERIAL_SIZE];
    uint8_t randomness[ECLIPSE_PARTICLE_RANDOMNESS_SIZE];
} eclipse_particle_t;

/* Creates an opening with fresh private randomness. Existing *out is only
 * changed on success. The caller may also populate the struct explicitly
 * when loading a previously stored opening or constructing test vectors. */
eclipse_error_t eclipse_particle_create(
    uint64_t amount,
    const uint8_t receive_material[ECLIPSE_PARTICLE_MATERIAL_SIZE],
    const uint8_t spend_authority[ECLIPSE_PARTICLE_MATERIAL_SIZE],
    eclipse_particle_t *out);

/* SHA3-256 of a versioned, canonical encoding of the FOUR fields above.
 * output capacity must be at least ECLIPSE_PARTICLE_COMMITMENT_SIZE bytes.
 * The commitment itself is never part of its own preimage. */
eclipse_error_t eclipse_particle_commitment(const eclipse_particle_t *particle,
                                            uint8_t *output, size_t capacity);

/* Checks an opening against a public commitment. A mismatch returns SUCCESS
 * with *valid == false, as with the existing signature verification API. */
eclipse_error_t eclipse_particle_verify_commitment(
    const eclipse_particle_t *particle, const uint8_t *commitment,
    size_t commitment_length, bool *valid);

/* Wipes the private opening, including amount and randomness, from its struct. */
void eclipse_particle_clear(eclipse_particle_t *particle);

#ifdef __cplusplus
}
#endif

#endif
