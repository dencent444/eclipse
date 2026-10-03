#include "tx.h"
#include "../log.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <string.h>

#define TX_HEADER_SIZE 19u
#define TX_INPUT_BASE_SIZE 38u
#define TX_OUTPUT_BASE_SIZE 11u

static const uint8_t signing_domain[] = "ECLIPSE/DEV/TX/SIGN/V0";
static const uint8_t id_domain[] = "ECLIPSE/DEV/TX/ID/V0";
static const uint8_t signature_context[] = ECLIPSE_TX_SIGNATURE_CONTEXT;

_Static_assert(ECLIPSE_TX_MAX_WIRE_SIZE ==
               TX_HEADER_SIZE + ECLIPSE_TX_MAX_INPUTS *
               (TX_INPUT_BASE_SIZE + ECLIPSE_TX_MAX_SIGNATURE_SIZE) +
               ECLIPSE_TX_MAX_OUTPUTS *
               (TX_OUTPUT_BASE_SIZE + ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE),
               "transaction wire buffer must cover the largest packet");
_Static_assert(ECLIPSE_TX_MAX_SIGNING_SIZE ==
               sizeof(signing_domain) - 1u + TX_HEADER_SIZE +
               ECLIPSE_TX_MAX_INPUTS * (ECLIPSE_TX_ID_SIZE + 4u) +
               ECLIPSE_TX_MAX_OUTPUTS *
               (TX_OUTPUT_BASE_SIZE + ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE) + 1u,
               "signing buffer must cover the largest unsigned transaction");

/* Explicit big-endian helpers keep C structure padding and host byte order
 * out of signed bytes. They only run after the destination size was checked. */
static void write_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void write_u32(uint8_t *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        out[i] = (uint8_t)(value >> (24u - i * 8u));
}

static void write_u64(uint8_t *out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i)
        out[i] = (uint8_t)(value >> (56u - i * 8u));
}

static uint16_t read_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t read_u32(const uint8_t *in)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value = (value << 8) | in[i];
    return value;
}

static uint64_t read_u64(const uint8_t *in)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | in[i];
    return value;
}

/* Fixed IDs are deliberately spelled out instead of casting enum storage
 * or assuming future enum values belong to the wire protocol. */
static uint8_t scheme_to_wire(eclipse_ml_dsa_scheme_t scheme)
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

static bool known_signature_size(size_t length)
{
    static const eclipse_ml_dsa_scheme_t schemes[] = {
        ECLIPSE_ML_DSA_44, ECLIPSE_ML_DSA_65, ECLIPSE_ML_DSA_87
    };
    eclipse_ml_dsa_info_t info;
    for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); ++i)
        if (eclipse_ml_dsa_info(schemes[i], &info) &&
            length == info.signature_size)
            return true;
    return false;
}

/* All invariants reachable through direct struct edits are rechecked before
 * serialization. Signature bytes are opaque until the UTXO owner verifies
 * them; their wire length is still unambiguous here. */
static bool tx_shape_valid(const eclipse_tx_t *tx, bool signed_form)
{
    if (tx->version != ECLIPSE_TX_VERSION ||
        tx->network_id != ECLIPSE_TX_DEV_NETWORK_ID ||
        tx->input_count == 0 || tx->input_count > ECLIPSE_TX_MAX_INPUTS ||
        tx->output_count == 0 || tx->output_count > ECLIPSE_TX_MAX_OUTPUTS)
        return false;
    for (size_t i = 0; i < tx->input_count; ++i) {
        if (signed_form && !known_signature_size(tx->inputs[i].signature_length))
            return false;
        for (size_t j = 0; j < i; ++j)
            if (tx->inputs[i].index == tx->inputs[j].index &&
                memcmp(tx->inputs[i].txid, tx->inputs[j].txid,
                       ECLIPSE_TX_ID_SIZE) == 0)
                return false;
    }
    for (size_t i = 0; i < tx->output_count; ++i) {
        eclipse_ml_dsa_info_t info;
        const eclipse_tx_output_t *output = &tx->outputs[i];
        if (output->amount == 0 || !eclipse_ml_dsa_info(output->scheme, &info) ||
            output->public_key_length != info.public_key_size ||
            scheme_to_wire(output->scheme) == 0)
            return false;
    }
    return true;
}

static void encode_header(const eclipse_tx_t *tx, uint8_t *out)
{
    memcpy(out, "ETX0", 4);
    out[4] = tx->version;
    write_u32(out + 5, tx->network_id);
    out[9] = tx->input_count;
    out[10] = tx->output_count;
    write_u64(out + 11, tx->fee);
}

static void encode_output(const eclipse_tx_output_t *output, uint8_t *out)
{
    write_u64(out, output->amount);
    out[8] = scheme_to_wire(output->scheme);
    write_u16(out + 9, (uint16_t)output->public_key_length);
    memcpy(out + TX_OUTPUT_BASE_SIZE, output->public_key,
           output->public_key_length);
}

eclipse_error_t eclipse_tx_init(eclipse_tx_t *tx)
{
    if (tx == NULL) {
        ECLIPSE_LOG_WARNING("transaction initialization output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    memset(tx, 0, sizeof(*tx));
    tx->version = ECLIPSE_TX_VERSION;
    tx->network_id = ECLIPSE_TX_DEV_NETWORK_ID;
    ECLIPSE_LOG_INFO(4, "developer transaction initialized");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tx_add_input(eclipse_tx_t *tx,
                                    const uint8_t prev_txid[ECLIPSE_TX_ID_SIZE],
                                    uint32_t prev_index)
{
    if (tx == NULL || prev_txid == NULL) {
        ECLIPSE_LOG_WARNING("transaction input rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (tx->version != ECLIPSE_TX_VERSION ||
        tx->network_id != ECLIPSE_TX_DEV_NETWORK_ID ||
        tx->input_count >= ECLIPSE_TX_MAX_INPUTS) {
        ECLIPSE_LOG_WARNING("transaction input rejected: header or count invalid");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    for (size_t i = 0; i < tx->input_count; ++i)
        if (tx->inputs[i].index == prev_index &&
            memcmp(tx->inputs[i].txid, prev_txid, ECLIPSE_TX_ID_SIZE) == 0) {
            ECLIPSE_LOG_WARNING("duplicate transaction input rejected");
            return ECLIPSE_ERROR_INVALID_ARGUMENT;
        }
    eclipse_tx_input_t *input = &tx->inputs[tx->input_count++];
    memset(input, 0, sizeof(*input));
    memcpy(input->txid, prev_txid, ECLIPSE_TX_ID_SIZE);
    input->index = prev_index;
    ECLIPSE_LOG_INFO(4, "transaction input added");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tx_add_output(eclipse_tx_t *tx, uint64_t amount,
                                     eclipse_ml_dsa_scheme_t scheme,
                                     const uint8_t *public_key,
                                     size_t public_key_length)
{
    if (tx == NULL || public_key == NULL) {
        ECLIPSE_LOG_WARNING("transaction output rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    eclipse_ml_dsa_info_t info;
    if (tx->version != ECLIPSE_TX_VERSION ||
        tx->network_id != ECLIPSE_TX_DEV_NETWORK_ID ||
        tx->output_count >= ECLIPSE_TX_MAX_OUTPUTS || amount == 0 ||
        !eclipse_ml_dsa_info(scheme, &info) ||
        public_key_length != info.public_key_size) {
        ECLIPSE_LOG_WARNING("transaction output rejected: amount, key, or count invalid");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_ml_dsa_key_t *checked = NULL;
    eclipse_error_t status = eclipse_ml_dsa_import_public(
        scheme, public_key, public_key_length, &checked);
    eclipse_ml_dsa_key_free(checked);
    if (status != ECLIPSE_SUCCESS) return status;
    eclipse_tx_output_t *output = &tx->outputs[tx->output_count++];
    memset(output, 0, sizeof(*output));
    output->amount = amount;
    output->scheme = scheme;
    output->public_key_length = public_key_length;
    memcpy(output->public_key, public_key, public_key_length);
    ECLIPSE_LOG_INFO(4, "transaction output added");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tx_set_fee(eclipse_tx_t *tx, uint64_t fee)
{
    if (tx == NULL) {
        ECLIPSE_LOG_WARNING("transaction fee setter rejected a null object");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    tx->fee = fee;
    ECLIPSE_LOG_INFO(4, "transaction fee set");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tx_serialize(const eclipse_tx_t *tx, uint8_t *output,
                                     size_t capacity, size_t *written)
{
    if (written == NULL) {
        ECLIPSE_LOG_WARNING("transaction serialization length output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *written = 0;
    if (tx == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("transaction serialization rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (!tx_shape_valid(tx, true)) {
        ECLIPSE_LOG_WARNING("transaction serialization rejected malformed fields");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    size_t needed = TX_HEADER_SIZE;
    for (size_t i = 0; i < tx->input_count; ++i)
        needed += TX_INPUT_BASE_SIZE + tx->inputs[i].signature_length;
    for (size_t i = 0; i < tx->output_count; ++i)
        needed += TX_OUTPUT_BASE_SIZE + tx->outputs[i].public_key_length;
    if (needed > ECLIPSE_TX_MAX_WIRE_SIZE) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (capacity < needed) {
        ECLIPSE_LOG_WARNING("transaction serialization buffer is too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }
    encode_header(tx, output);
    size_t at = TX_HEADER_SIZE;
    for (size_t i = 0; i < tx->input_count; ++i) {
        const eclipse_tx_input_t *input = &tx->inputs[i];
        memcpy(output + at, input->txid, ECLIPSE_TX_ID_SIZE);
        at += ECLIPSE_TX_ID_SIZE;
        write_u32(output + at, input->index);
        at += 4;
        write_u16(output + at, (uint16_t)input->signature_length);
        at += 2;
        memcpy(output + at, input->signature, input->signature_length);
        at += input->signature_length;
    }
    for (size_t i = 0; i < tx->output_count; ++i) {
        encode_output(&tx->outputs[i], output + at);
        at += TX_OUTPUT_BASE_SIZE + tx->outputs[i].public_key_length;
    }
    *written = at;
    ECLIPSE_LOG_INFO(5, "transaction serialized: %zu bytes", at);
    return ECLIPSE_SUCCESS;
}

static bool has_bytes(size_t length, size_t at, size_t needed)
{
    return at <= length && needed <= length - at;
}

eclipse_error_t eclipse_tx_deserialize(const uint8_t *input, size_t length,
                                       eclipse_tx_t *out)
{
    if (input == NULL || out == NULL) {
        ECLIPSE_LOG_WARNING("transaction deserialization rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (length < TX_HEADER_SIZE || length > ECLIPSE_TX_MAX_WIRE_SIZE ||
        memcmp(input, "ETX0", 4) != 0 || input[4] != ECLIPSE_TX_VERSION ||
        read_u32(input + 5) != ECLIPSE_TX_DEV_NETWORK_ID ||
        input[9] == 0 || input[9] > ECLIPSE_TX_MAX_INPUTS ||
        input[10] == 0 || input[10] > ECLIPSE_TX_MAX_OUTPUTS) {
        ECLIPSE_LOG_WARNING("transaction packet rejected: header invalid");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_tx_t parsed = {0};
    parsed.version = input[4];
    parsed.network_id = read_u32(input + 5);
    parsed.input_count = input[9];
    parsed.output_count = input[10];
    parsed.fee = read_u64(input + 11);
    size_t at = TX_HEADER_SIZE;
    for (size_t i = 0; i < parsed.input_count; ++i) {
        if (!has_bytes(length, at, TX_INPUT_BASE_SIZE)) goto malformed;
        eclipse_tx_input_t *current = &parsed.inputs[i];
        memcpy(current->txid, input + at, ECLIPSE_TX_ID_SIZE);
        at += ECLIPSE_TX_ID_SIZE;
        current->index = read_u32(input + at);
        at += 4;
        current->signature_length = read_u16(input + at);
        at += 2;
        if (!known_signature_size(current->signature_length) ||
            !has_bytes(length, at, current->signature_length)) goto malformed;
        memcpy(current->signature, input + at, current->signature_length);
        at += current->signature_length;
    }
    for (size_t i = 0; i < parsed.output_count; ++i) {
        if (!has_bytes(length, at, TX_OUTPUT_BASE_SIZE)) goto malformed;
        eclipse_tx_output_t *current = &parsed.outputs[i];
        current->amount = read_u64(input + at);
        at += 8;
        current->scheme = scheme_from_wire(input[at++]);
        current->public_key_length = read_u16(input + at);
        at += 2;
        eclipse_ml_dsa_info_t info;
        if (current->amount == 0 ||
            !eclipse_ml_dsa_info(current->scheme, &info) ||
            current->public_key_length != info.public_key_size ||
            !has_bytes(length, at, current->public_key_length)) goto malformed;
        memcpy(current->public_key, input + at, current->public_key_length);
        at += current->public_key_length;
        eclipse_ml_dsa_key_t *checked = NULL;
        eclipse_error_t status = eclipse_ml_dsa_import_public(
            current->scheme, current->public_key, current->public_key_length,
            &checked);
        eclipse_ml_dsa_key_free(checked);
        if (status != ECLIPSE_SUCCESS) {
            if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) goto malformed;
            return status;
        }
    }
    if (at != length || !tx_shape_valid(&parsed, true)) goto malformed;
    *out = parsed;
    ECLIPSE_LOG_INFO(5, "transaction deserialized");
    return ECLIPSE_SUCCESS;
malformed:
    ECLIPSE_LOG_WARNING("transaction packet rejected: malformed body");
    return ECLIPSE_ERROR_INVALID_ARGUMENT;
}

eclipse_error_t eclipse_tx_signing_message(const eclipse_tx_t *tx,
                                           size_t input_index,
                                           uint8_t *output, size_t capacity,
                                           size_t *written)
{
    if (written == NULL) {
        ECLIPSE_LOG_WARNING("transaction signing length output is null");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *written = 0;
    if (tx == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("transaction signing message rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (!tx_shape_valid(tx, false) || input_index >= tx->input_count) {
        ECLIPSE_LOG_WARNING("transaction signing message rejected malformed transaction");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    size_t needed = sizeof(signing_domain) - 1 + TX_HEADER_SIZE + 1;
    needed += (size_t)tx->input_count * (ECLIPSE_TX_ID_SIZE + 4u);
    for (size_t i = 0; i < tx->output_count; ++i)
        needed += TX_OUTPUT_BASE_SIZE + tx->outputs[i].public_key_length;
    if (needed > ECLIPSE_TX_MAX_SIGNING_SIZE) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (capacity < needed) {
        ECLIPSE_LOG_WARNING("transaction signing message buffer is too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }
    size_t at = 0;
    memcpy(output, signing_domain, sizeof(signing_domain) - 1);
    at += sizeof(signing_domain) - 1;
    encode_header(tx, output + at);
    at += TX_HEADER_SIZE;
    for (size_t i = 0; i < tx->input_count; ++i) {
        memcpy(output + at, tx->inputs[i].txid, ECLIPSE_TX_ID_SIZE);
        at += ECLIPSE_TX_ID_SIZE;
        write_u32(output + at, tx->inputs[i].index);
        at += 4;
    }
    for (size_t i = 0; i < tx->output_count; ++i) {
        encode_output(&tx->outputs[i], output + at);
        at += TX_OUTPUT_BASE_SIZE + tx->outputs[i].public_key_length;
    }
    output[at++] = (uint8_t)input_index;
    *written = at;
    ECLIPSE_LOG_INFO(5, "transaction signing message built");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tx_sign_input(eclipse_tx_t *tx, size_t input_index,
                                      const eclipse_ml_dsa_key_t *private_key)
{
    if (tx == NULL || private_key == NULL) {
        ECLIPSE_LOG_WARNING("transaction signing rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (input_index >= tx->input_count) {
        ECLIPSE_LOG_WARNING("transaction signing rejected an invalid input index");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    uint8_t message[ECLIPSE_TX_MAX_SIGNING_SIZE];
    size_t message_length = 0;
    eclipse_error_t status = eclipse_tx_signing_message(
        tx, input_index, message, sizeof(message), &message_length);
    if (status != ECLIPSE_SUCCESS) return status;
    eclipse_tx_input_t *input = &tx->inputs[input_index];
    input->signature_length = 0;
    status = eclipse_ml_dsa_sign(private_key, message, message_length,
                                  signature_context, sizeof(signature_context) - 1,
                                  input->signature, sizeof(input->signature),
                                  &input->signature_length);
    if (status != ECLIPSE_SUCCESS)
        OPENSSL_cleanse(input->signature, sizeof(input->signature));
    else ECLIPSE_LOG_INFO(3, "transaction input signed");
    return status;
}

eclipse_error_t eclipse_tx_id(const eclipse_tx_t *tx,
                              uint8_t output[ECLIPSE_TX_ID_SIZE])
{
    if (tx == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("transaction ID calculation rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    uint8_t wire[ECLIPSE_TX_MAX_WIRE_SIZE];
    size_t length = 0;
    eclipse_error_t status = eclipse_tx_serialize(tx, wire, sizeof(wire), &length);
    if (status != ECLIPSE_SUCCESS) return status;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    uint8_t digest[ECLIPSE_TX_ID_SIZE];
    unsigned digest_length = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, id_domain, sizeof(id_domain) - 1) == 1 &&
             EVP_DigestUpdate(ctx, wire, length) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
             digest_length == ECLIPSE_TX_ID_SIZE;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        ECLIPSE_LOG_ERROR("transaction ID hash failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    memcpy(output, digest, sizeof(digest));
    ECLIPSE_LOG_INFO(5, "transaction ID computed");
    return ECLIPSE_SUCCESS;
}
