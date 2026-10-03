#include "block.h"
#include "../log.h"
#include "../platform.h"

#include <string.h>

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
 * This decodes fields only; block validity and PoW are future responsibilities. */
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
