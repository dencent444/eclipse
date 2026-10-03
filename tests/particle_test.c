#include "particle/particle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static void hex(const uint8_t *bytes, size_t length, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 15];
    }
    out[2 * length] = '\0';
}

int main(void)
{
    /* This vector was computed independently with Python's hashlib.sha3_256.
       It fixes domain bytes, field order, and big-endian amount encoding. */
    eclipse_particle_t particle = {.amount = UINT64_C(0x0102030405060708)};
    for (size_t i = 0; i < 32; ++i) {
        particle.receive_material[i] = (uint8_t)i;
        particle.spend_authority[i] = (uint8_t)(i + 32);
        particle.randomness[i] = (uint8_t)(i + 64);
    }
    uint8_t commitment[ECLIPSE_PARTICLE_COMMITMENT_SIZE];
    CHECK(eclipse_particle_commitment(&particle, commitment,
                                      sizeof(commitment)) == ECLIPSE_SUCCESS);
    char value[65];
    hex(commitment, sizeof(commitment), value);
    CHECK(strcmp(value,
          "cbadd903974ab7eb94d7a9790cb606c02169be1f11eeda6c1f839a361c8cc702") == 0);
    bool valid = false;
    CHECK(eclipse_particle_verify_commitment(&particle, commitment,
                                              sizeof(commitment), &valid) ==
          ECLIPSE_SUCCESS && valid);

    /* Every opening field is bound to the digest. */
    eclipse_particle_t changed = particle;
    changed.amount++;
    CHECK(eclipse_particle_verify_commitment(&changed, commitment,
                                              sizeof(commitment), &valid) ==
          ECLIPSE_SUCCESS && !valid);
    changed = particle;
    changed.receive_material[0] ^= 1;
    CHECK(eclipse_particle_verify_commitment(&changed, commitment,
                                              sizeof(commitment), &valid) ==
          ECLIPSE_SUCCESS && !valid);
    changed = particle;
    changed.spend_authority[0] ^= 1;
    CHECK(eclipse_particle_verify_commitment(&changed, commitment,
                                              sizeof(commitment), &valid) ==
          ECLIPSE_SUCCESS && !valid);
    changed = particle;
    changed.randomness[0] ^= 1;
    CHECK(eclipse_particle_verify_commitment(&changed, commitment,
                                              sizeof(commitment), &valid) ==
          ECLIPSE_SUCCESS && !valid);
    CHECK(eclipse_particle_verify_commitment(&particle, commitment, 31,
                                              &valid) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT && !valid);

    eclipse_particle_t first, second;
    CHECK(eclipse_particle_create(7, particle.receive_material,
                                  particle.spend_authority, &first) == ECLIPSE_SUCCESS);
    CHECK(eclipse_particle_create(7, particle.receive_material,
                                  particle.spend_authority, &second) == ECLIPSE_SUCCESS);
    CHECK(first.amount == 7 && second.amount == 7);
    CHECK(memcmp(first.randomness, second.randomness, 32) != 0);
    uint8_t first_commitment[32], second_commitment[32];
    CHECK(eclipse_particle_commitment(&first, first_commitment,
                                      sizeof(first_commitment)) == ECLIPSE_SUCCESS);
    CHECK(eclipse_particle_commitment(&second, second_commitment,
                                      sizeof(second_commitment)) == ECLIPSE_SUCCESS);
    CHECK(memcmp(first_commitment, second_commitment, 32) != 0);
    CHECK(eclipse_particle_commitment(&first, first_commitment, 31) ==
          ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    CHECK(eclipse_particle_create(7, NULL, particle.spend_authority,
                                  &changed) == ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_particle_commitment(NULL, commitment, sizeof(commitment)) ==
          ECLIPSE_ERROR_NULL_POINTER);

    eclipse_particle_clear(&first);
    eclipse_particle_clear(&second);
    eclipse_particle_clear(&particle);
    eclipse_particle_clear(&changed);
    eclipse_particle_t zero = {0};
    CHECK(memcmp(&particle, &zero, sizeof(particle)) == 0);
    puts("Particle commitment tests passed");
    return EXIT_SUCCESS;
}
