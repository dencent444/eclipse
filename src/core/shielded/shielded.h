#ifndef ECLIPSE_SHIELDED_H
#define ECLIPSE_SHIELDED_H

#include <stddef.h>
#include <stdint.h>
#include "../error.h"

#define ECLIPSE_SHIELDED_MAX_ACTIONS 8u
#define ECLIPSE_SHIELDED_MAX_WIRE_SIZE 32000u
#define ECLIPSE_SHIELDED_FLAG_SPENDS_ENABLED 0x01u
#define ECLIPSE_SHIELDED_FLAG_OUTPUTS_ENABLED 0x02u

/* Fixed-layout C representation of the Rust verifier receipt. These public
 * values are enough to enforce network, fee, anchor, nullifier, and commitment
 * rules on a branch. They reveal no note openings or wallet secret keys. */
typedef struct {
    uint32_t network_id;
    uint64_t fee;
    uint64_t public_input;
    int64_t value_balance;
    uint8_t action_count;
    /* Orchard v2 wire flags. A shielded reward requires SPENDS_ENABLED clear. */
    uint8_t flags;
    uint8_t anchor[32];
    uint8_t nullifiers[ECLIPSE_SHIELDED_MAX_ACTIONS][32];
    uint8_t commitments[ECLIPSE_SHIELDED_MAX_ACTIONS][32];
} eclipse_shielded_receipt_t;

/* Performs canonical ESX1 decoding plus Orchard proof and signature checks.
 * The caller must additionally enforce the branch anchor/nullifier set and
 * the block's permitted public input. This function does not accept a tx. */
eclipse_error_t eclipse_shielded_verify_wire(const uint8_t *wire, size_t length,
    uint32_t expected_network_id, eclipse_shielded_receipt_t *out);

#endif
