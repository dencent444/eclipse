#include "block.h"
#include "../log.h"
#include "../platform.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static void write_big_endian(uint8_t *buffer, uint64_t value, size_t width);
static uint64_t read_big_endian(const uint8_t *buffer, size_t width);

struct eclipse_block {
    eclipse_block_header_t header;
    eclipse_tx_output_t reward;
    size_t count;
    eclipse_tx_t *transactions[ECLIPSE_BLOCK_MAX_TRANSACTIONS];
};

static const uint8_t reward_domain[] = "ECLIPSE/DEV/BLOCK/REWARD/V1";
static const uint8_t tx_domain[] = "ECLIPSE/DEV/BLOCK/TX/V1";
static const uint8_t node_domain[] = "ECLIPSE/DEV/BLOCK/NODE/V1";
static const uint8_t id_domain[] = "ECLIPSE/DEV/BLOCK/ID/V1";
static const uint8_t reward_id_domain[] = "ECLIPSE/DEV/REWARD/ID/V1";

static eclipse_error_t digest(const uint8_t *bytes, size_t length, uint8_t out[32])
{
    size_t written = 0;
    if (EVP_Q_digest(NULL, "SHA3-256", NULL, bytes, length, out, &written) != 1 ||
        written != 32) {
        ECLIPSE_LOG_ERROR("SHA3-256 block digest failed");
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    }
    return ECLIPSE_SUCCESS;
}

static uint8_t scheme_wire(eclipse_ml_dsa_scheme_t scheme)
{
    switch (scheme) {
    case ECLIPSE_ML_DSA_44: return 1;
    case ECLIPSE_ML_DSA_65: return 2;
    case ECLIPSE_ML_DSA_87: return 3;
    default: return 0;
    }
}

static eclipse_ml_dsa_scheme_t wire_scheme(uint8_t scheme)
{
    switch (scheme) {
    case 1: return ECLIPSE_ML_DSA_44;
    case 2: return ECLIPSE_ML_DSA_65;
    case 3: return ECLIPSE_ML_DSA_87;
    default: return (eclipse_ml_dsa_scheme_t)0;
    }
}

static eclipse_error_t check_reward(const eclipse_tx_output_t *reward)
{
    eclipse_ml_dsa_info_t info;
    if (reward->amount == 0 ||
        !eclipse_ml_dsa_info(reward->scheme, &info) ||
        reward->public_key_length != info.public_key_size)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_ml_dsa_key_t *key = NULL;
    eclipse_error_t status = eclipse_ml_dsa_import_public(
        reward->scheme, reward->public_key, reward->public_key_length, &key);
    eclipse_ml_dsa_key_free(key);
    return status;
}

static size_t encode_reward(const eclipse_tx_output_t *reward, uint8_t *out)
{
    write_big_endian(out, reward->amount, 8);
    out[8] = scheme_wire(reward->scheme);
    write_big_endian(out + 9, reward->public_key_length, 2);
    memcpy(out + 11, reward->public_key, reward->public_key_length);
    return 11 + reward->public_key_length;
}

/*
 * These private helpers are called with widths of 4 or 8 bytes only. Work with
 * unsigned 64-bit values so shifts remain defined even when the top bit is set.
 * Writing the least significant byte from right to left puts the most
 * significant byte first, regardless of the machine's native endianness.
 */
static void write_big_endian(uint8_t *buffer, uint64_t value, size_t width)
{
    for (size_t i = width; i > 0; --i) {
        buffer[i - 1] = (uint8_t)(value & UINT64_C(0xff));
        value >>= 8;
    }
}

/* Reconstruct a 4- or 8-byte unsigned value from protocol-order bytes.
 * Shifting one byte at a time avoids host-endianness and alignment concerns. */
static uint64_t read_big_endian(const uint8_t *buffer, size_t width)
{
    uint64_t value = 0;

    /*
     * Consume one byte per iteration. Combining several buffer[offset++]
     * expressions with bitwise OR would modify offset without sequencing,
     * which is undefined behavior in C; separate iterations avoid that bug.
     */
    for (size_t i = 0; i < width; ++i) {
        value = (value << 8) | (uint64_t)buffer[i];
    }
    return value;
}

/* Write the v1 header wire layout. Check the accessible output length first,
 * then write each field at a fixed offset; C struct padding is irrelevant. */
eclipse_error_t eclipse_block_header_serialize(
    const eclipse_block_header_t *header, uint8_t *buffer, size_t buffer_size)
{
    if (header == NULL || buffer == NULL) {
        ECLIPSE_LOG_WARNING("header serialization rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    /* Check the wire size before writing, so failures leave buffer untouched. */
    if (buffer_size < ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE) {
        ECLIPSE_LOG_WARNING("header serialization buffer is too short: %zu bytes",
                            buffer_size);
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    /* Fixed offsets match the public wire layout, not the struct's padding. */
    write_big_endian(buffer, header->version, 4);
    write_big_endian(buffer + 4, header->timestamp, 8);
    write_big_endian(buffer + 12, header->difficulty, 4);
    write_big_endian(buffer + 16, header->nonce, 8);

    /* Hashes are opaque byte arrays: do not apply integer byte swapping. */
    memcpy(buffer + 24, header->prev_block_hash, 32);
    memcpy(buffer + 56, header->merkle_root, 32);
    ECLIPSE_LOG_INFO(5, "block header serialized");
    return ECLIPSE_SUCCESS;
}

/* Read one untrusted v1 header after verifying its full 88-byte length.
 * This decodes fields only; chain acceptance checks validity and PoW. */
eclipse_error_t eclipse_block_header_deserialize(
    const uint8_t *buffer, eclipse_block_header_t *header, size_t buffer_size)
{
    if (buffer == NULL || header == NULL) {
        ECLIPSE_LOG_WARNING("header deserialization rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    /*
     * sizeof(*header) is not the encoded size: padding can make it larger.
     * Validate before reading any bytes or changing the destination header.
     */
    if (buffer_size < ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE) {
        ECLIPSE_LOG_INFO(4, "truncated block header rejected: %zu bytes",
                         buffer_size);
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    /* Four-byte reads fit in uint32_t; eight-byte reads retain all 64 bits. */
    header->version = (uint32_t)read_big_endian(buffer, 4);
    header->timestamp = read_big_endian(buffer + 4, 8);
    header->difficulty = (uint32_t)read_big_endian(buffer + 12, 4);
    header->nonce = read_big_endian(buffer + 16, 8);
    memcpy(header->prev_block_hash, buffer + 24, 32);
    memcpy(header->merkle_root, buffer + 56, 32);
    ECLIPSE_LOG_INFO(5, "block header deserialized");
    return ECLIPSE_SUCCESS;
}

/* A leaf commits to the full payout; ordinary leaves commit to signed txids.
 * Duplicate the final leaf at odd widths, so every block has one exact root. */
eclipse_error_t eclipse_block_compute_root(const eclipse_block_t *block,
                                           uint8_t out[32])
{
    if (block == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t leaves[ECLIPSE_BLOCK_MAX_TRANSACTIONS + 1][32];
    uint8_t payout[sizeof(reward_domain) - 1 + 11 + ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE];
    memcpy(payout, reward_domain, sizeof(reward_domain) - 1);
    size_t length = sizeof(reward_domain) - 1 +
        encode_reward(&block->reward, payout + sizeof(reward_domain) - 1);
    eclipse_error_t status = digest(payout, length, leaves[0]);
    if (status != ECLIPSE_SUCCESS) return status;
    for (size_t i = 0; i < block->count; ++i) {
        uint8_t preimage[sizeof(tx_domain) - 1 + 32];
        memcpy(preimage, tx_domain, sizeof(tx_domain) - 1);
        status = eclipse_tx_id(block->transactions[i],
                               preimage + sizeof(tx_domain) - 1);
        if (status != ECLIPSE_SUCCESS) return status;
        status = digest(preimage, sizeof(preimage), leaves[i + 1]);
        if (status != ECLIPSE_SUCCESS) return status;
    }
    size_t width = block->count + 1;
    while (width > 1) {
        size_t next = 0;
        for (size_t i = 0; i < width; i += 2) {
            uint8_t preimage[sizeof(node_domain) - 1 + 64];
            memcpy(preimage, node_domain, sizeof(node_domain) - 1);
            memcpy(preimage + sizeof(node_domain) - 1, leaves[i], 32);
            memcpy(preimage + sizeof(node_domain) - 1 + 32,
                   leaves[i + 1 < width ? i + 1 : i], 32);
            status = digest(preimage, sizeof(preimage), leaves[next++]);
            if (status != ECLIPSE_SUCCESS) return status;
        }
        width = next;
    }
    memcpy(out, leaves[0], 32);
    ECLIPSE_LOG_INFO(5, "block Merkle root computed for %zu transactions",
                     block->count);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_block_create(const uint8_t prev_hash[32],
                                     uint64_t timestamp,
                                     const eclipse_tx_output_t *reward,
                                     eclipse_block_t **out)
{
    if (prev_hash == NULL || reward == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    eclipse_error_t status = check_reward(reward);
    if (status != ECLIPSE_SUCCESS) {
        ECLIPSE_LOG_WARNING("block creation rejected malformed reward output");
        return status;
    }
    eclipse_block_t *block = calloc(1, sizeof(*block));
    if (block == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    block->header.version = ECLIPSE_BLOCK_VERSION;
    block->header.timestamp = timestamp;
    block->header.difficulty = ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS;
    memcpy(block->header.prev_block_hash, prev_hash, 32);
    block->reward.amount = reward->amount;
    block->reward.scheme = reward->scheme;
    block->reward.public_key_length = reward->public_key_length;
    memcpy(block->reward.public_key, reward->public_key,
           reward->public_key_length);
    status = eclipse_block_compute_root(block, block->header.merkle_root);
    if (status != ECLIPSE_SUCCESS) { free(block); return status; }
    *out = block;
    ECLIPSE_LOG_INFO(3, "developer block candidate created");
    return ECLIPSE_SUCCESS;
}

void eclipse_block_free(eclipse_block_t *block)
{
    if (block == NULL) return;
    for (size_t i = 0; i < block->count; ++i) free(block->transactions[i]);
    free(block);
    ECLIPSE_LOG_INFO(4, "developer block released");
}

eclipse_error_t eclipse_block_add_transaction(eclipse_block_t *block,
                                               const eclipse_tx_t *tx)
{
    if (block == NULL || tx == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (block->count >= ECLIPSE_BLOCK_MAX_TRANSACTIONS)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    uint8_t wire[ECLIPSE_TX_MAX_WIRE_SIZE];
    size_t length = 0;
    eclipse_error_t status = eclipse_tx_serialize(tx, wire, sizeof(wire), &length);
    if (status != ECLIPSE_SUCCESS) return status;
    eclipse_tx_t *copy = malloc(sizeof(*copy));
    if (copy == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    status = eclipse_tx_deserialize(wire, length, copy);
    if (status != ECLIPSE_SUCCESS) {
        free(copy);
        return status;
    }
    block->transactions[block->count++] = copy;
    uint8_t root[32];
    status = eclipse_block_compute_root(block, root);
    if (status != ECLIPSE_SUCCESS) {
        block->count--;
        free(copy);
        return status;
    }
    memcpy(block->header.merkle_root, root, 32);
    block->header.nonce = 0;
    ECLIPSE_LOG_INFO(4, "transaction added to developer block");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_block_header(const eclipse_block_t *block,
                                     eclipse_block_header_t *out)
{
    if (block == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = block->header;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_block_reward(const eclipse_block_t *block,
                                     eclipse_tx_output_t *out)
{
    if (block == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = block->reward;
    return ECLIPSE_SUCCESS;
}

size_t eclipse_block_transaction_count(const eclipse_block_t *block)
{
    return block == NULL ? 0 : block->count;
}

eclipse_error_t eclipse_block_transaction(const eclipse_block_t *block,
                                          size_t index, eclipse_tx_t *out)
{
    if (block == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (index >= block->count) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    *out = *block->transactions[index];
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_block_set_nonce(eclipse_block_t *block, uint64_t nonce)
{
    if (block == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    block->header.nonce = nonce;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_block_hash(const eclipse_block_t *block, uint8_t out[32])
{
    if (block == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t preimage[sizeof(id_domain) - 1 + ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    memcpy(preimage, id_domain, sizeof(id_domain) - 1);
    eclipse_error_t status = eclipse_block_header_serialize(
        &block->header, preimage + sizeof(id_domain) - 1,
        ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE);
    if (status != ECLIPSE_SUCCESS) return status;
    return digest(preimage, sizeof(preimage), out);
}

eclipse_error_t eclipse_block_reward_id(const eclipse_block_t *block,
                                        uint8_t out[32])
{
    if (block == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t preimage[sizeof(reward_id_domain) - 1 + 32];
    memcpy(preimage, reward_id_domain, sizeof(reward_id_domain) - 1);
    eclipse_error_t status = eclipse_block_hash(
        block, preimage + sizeof(reward_id_domain) - 1);
    if (status != ECLIPSE_SUCCESS) return status;
    return digest(preimage, sizeof(preimage), out);
}

eclipse_error_t eclipse_block_serialize(const eclipse_block_t *block,
                                        uint8_t *out, size_t capacity,
                                        size_t *written)
{
    if (written == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *written = 0;
    if (block == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t root[32];
    eclipse_error_t status = eclipse_block_compute_root(block, root);
    if (status != ECLIPSE_SUCCESS) return status;
    if (block->header.version != ECLIPSE_BLOCK_VERSION ||
        memcmp(root, block->header.merkle_root, 32) != 0)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    size_t needed = 4 + ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE + 1 +
                    11 + block->reward.public_key_length;
    for (size_t i = 0; i < block->count; ++i) {
        uint8_t txwire[ECLIPSE_TX_MAX_WIRE_SIZE];
        size_t txsize = 0;
        status = eclipse_tx_serialize(block->transactions[i], txwire,
                                       sizeof(txwire), &txsize);
        if (status != ECLIPSE_SUCCESS) return status;
        needed += 4 + txsize;
    }
    if (capacity < needed) return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    memcpy(out, "EBL1", 4);
    status = eclipse_block_header_serialize(&block->header, out + 4,
                                            capacity - 4);
    if (status != ECLIPSE_SUCCESS) return status;
    size_t at = 4 + ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE;
    out[at++] = (uint8_t)block->count;
    at += encode_reward(&block->reward, out + at);
    for (size_t i = 0; i < block->count; ++i) {
        size_t txsize = 0;
        status = eclipse_tx_serialize(block->transactions[i], out + at + 4,
                                       capacity - at - 4, &txsize);
        if (status != ECLIPSE_SUCCESS) return status;
        write_big_endian(out + at, txsize, 4);
        at += 4 + txsize;
    }
    *written = at;
    ECLIPSE_LOG_INFO(5, "block serialized: %zu bytes", at);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_block_deserialize(const uint8_t *wire, size_t length,
                                          eclipse_block_t **out)
{
    if (wire == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (length < 4 + ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE + 1 + 11 ||
        length > ECLIPSE_BLOCK_MAX_WIRE_SIZE || memcmp(wire, "EBL1", 4) != 0)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_block_header_t header;
    eclipse_error_t status = eclipse_block_header_deserialize(
        wire + 4, &header, length - 4);
    if (status != ECLIPSE_SUCCESS) return status;
    if (header.version != ECLIPSE_BLOCK_VERSION)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    size_t at = 4 + ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE;
    size_t count = wire[at++];
    if (count > ECLIPSE_BLOCK_MAX_TRANSACTIONS)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_tx_output_t reward = {0};
    reward.amount = read_big_endian(wire + at, 8);
    reward.scheme = wire_scheme(wire[at + 8]);
    reward.public_key_length = read_big_endian(wire + at + 9, 2);
    at += 11;
    if (reward.public_key_length > ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE ||
        reward.public_key_length > length - at)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    memcpy(reward.public_key, wire + at, reward.public_key_length);
    at += reward.public_key_length;
    eclipse_block_t *block = NULL;
    status = eclipse_block_create(header.prev_block_hash, header.timestamp,
                                   &reward, &block);
    if (status != ECLIPSE_SUCCESS) return status;
    for (size_t i = 0; i < count; ++i) {
        if (length - at < 4) goto malformed;
        size_t txsize = read_big_endian(wire + at, 4);
        at += 4;
        if (txsize == 0 || txsize > ECLIPSE_TX_MAX_WIRE_SIZE ||
            txsize > length - at) goto malformed;
        eclipse_tx_t *tx = malloc(sizeof(*tx));
        if (tx == NULL) { status = ECLIPSE_ERROR_OUT_OF_MEMORY; goto fail; }
        status = eclipse_tx_deserialize(wire + at, txsize, tx);
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_block_add_transaction(block, tx);
        free(tx);
        if (status != ECLIPSE_SUCCESS) goto fail;
        at += txsize;
    }
    if (at != length || memcmp(header.merkle_root,
                               block->header.merkle_root, 32) != 0)
        goto malformed;
    block->header = header;
    *out = block;
    ECLIPSE_LOG_INFO(5, "block deserialized and root checked");
    return ECLIPSE_SUCCESS;
malformed:
    status = ECLIPSE_ERROR_INVALID_ARGUMENT;
    ECLIPSE_LOG_WARNING("malformed developer block rejected");
fail:
    eclipse_block_free(block);
    return status;
}
