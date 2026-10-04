#include "shielded.h"
#include "../log.h"

/* Rust staticlib entry point; all panics are caught before crossing the ABI. */
extern int eclipse_shielded_verify_esx1(const uint8_t *wire, size_t length,
    uint32_t expected_network_id, eclipse_shielded_receipt_t *out);

eclipse_error_t eclipse_shielded_verify_wire(const uint8_t *wire, size_t length,
    uint32_t expected_network_id, eclipse_shielded_receipt_t *out)
{
    if (wire == NULL || out == NULL || length == 0 ||
        length > ECLIPSE_SHIELDED_MAX_WIRE_SIZE) {
        ECLIPSE_LOG_WARNING("ESX1 verifier rejected null or oversized input");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    const int result = eclipse_shielded_verify_esx1(
        wire, length, expected_network_id, out);
    if (result == 0) {
        ECLIPSE_LOG_INFO(4, "ESX1 proof and signatures verified");
        return ECLIPSE_SUCCESS;
    }
    if (result == 1) {
        ECLIPSE_LOG_INFO(3, "invalid ESX1 bundle rejected");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    ECLIPSE_LOG_ERROR("ESX1 verifier failed at Rust ABI boundary: %d", result);
    return ECLIPSE_ERROR_CRYPTO_FAILURE;
}
