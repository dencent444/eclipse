#include "../src/core/block/block.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keep checks active even in builds defining NDEBUG, unlike assert(). */
#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n",                        \
                    __FILE__, __LINE__, #condition);                            \
            exit(EXIT_FAILURE);                                                 \
        }                                                                       \
    } while (0)

static void check_headers_equal(const eclipse_block_header_t *left,
                                const eclipse_block_header_t *right)
{
    /* Struct padding is not data, so compare fields instead of whole structs. */
    CHECK(left->version == right->version);
    CHECK(left->timestamp == right->timestamp);
    CHECK(left->difficulty == right->difficulty);
    CHECK(left->nonce == right->nonce);
    CHECK(memcmp(left->prev_block_hash, right->prev_block_hash, 32) == 0);
    CHECK(memcmp(left->merkle_root, right->merkle_root, 32) == 0);
}

static void print_header(const eclipse_block_header_t *header)
{
    /* PRI macros match fixed-width integer types on every supported platform. */
    printf("Version: %" PRIu32 "\n", header->version);
    printf("Timestamp: %" PRIu64 "\n", header->timestamp);
    printf("Difficulty: %" PRIu32 "\n", header->difficulty);
    printf("Nonce: %" PRIu64 "\n", header->nonce);
}

static void test_wire_format(void)
{
    /*
     * An independently written byte vector catches mirrored encoder/decoder
     * mistakes that a round trip alone cannot detect. Distinct, high-bit bytes
     * exercise byte order, field offsets, and unsigned values above INT64_MAX.
     */
    const uint8_t expected[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE] = {
        0x81, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x98, 0xba, 0xdc, 0xfe,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
        0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0
    };
    eclipse_block_header_t original = {
        .version = UINT32_C(0x81234567),
        .timestamp = UINT64_C(0x89abcdef01234567),
        .difficulty = UINT32_C(0x98badcfe),
        .nonce = UINT64_C(0xfedcba9876543210)
    };
    for (size_t i = 0; i < 32; ++i) {
        original.prev_block_hash[i] = (uint8_t)i;
        original.merkle_root[i] = (uint8_t)(255u - i);
    }

    uint8_t buffer[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE + 1];
    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(eclipse_block_header_serialize(&original, buffer, sizeof(buffer)) ==
          ECLIPSE_SUCCESS);
    CHECK(memcmp(buffer, expected, sizeof(expected)) == 0);
    CHECK(buffer[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE] == 0xa5);

    eclipse_block_header_t decoded = {0};
    CHECK(eclipse_block_header_deserialize(expected, &decoded, sizeof(expected)) ==
          ECLIPSE_SUCCESS);
    check_headers_equal(&original, &decoded);
    /* A trailing byte belongs to the caller and must not affect decoding. */
    CHECK(eclipse_block_header_deserialize(buffer, &decoded, sizeof(buffer)) ==
          ECLIPSE_SUCCESS);
    check_headers_equal(&original, &decoded);
}

static void test_uniform_bytes(uint8_t byte)
{
    /* All-zero and all-one vectors exercise zero and maximum integer values. */
    uint8_t input[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    uint8_t output[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    eclipse_block_header_t decoded = {0};
    memset(input, byte, sizeof(input));
    CHECK(eclipse_block_header_deserialize(input, &decoded, sizeof(input)) ==
          ECLIPSE_SUCCESS);
    CHECK(decoded.version == (byte == 0 ? 0 : UINT32_MAX));
    CHECK(decoded.timestamp == (byte == 0 ? 0 : UINT64_MAX));
    CHECK(decoded.difficulty == (byte == 0 ? 0 : UINT32_MAX));
    CHECK(decoded.nonce == (byte == 0 ? 0 : UINT64_MAX));
    CHECK(eclipse_block_header_serialize(&decoded, output, sizeof(output)) ==
          ECLIPSE_SUCCESS);
    CHECK(memcmp(input, output, sizeof(input)) == 0);
}

static void test_invalid_arguments(void)
{
    uint8_t buffer[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    uint8_t saved_buffer[sizeof(buffer)];
    eclipse_block_header_t header = {.version = 42, .nonce = UINT64_MAX};
    unsigned char saved_header[sizeof(header)];
    memset(buffer, 0xa5, sizeof(buffer));
    memcpy(saved_buffer, buffer, sizeof(buffer));
    memcpy(saved_header, &header, sizeof(header));

    CHECK(eclipse_block_header_serialize(NULL, buffer, sizeof(buffer)) ==
          ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_block_header_serialize(&header, NULL, sizeof(buffer)) ==
          ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_block_header_deserialize(NULL, &header, sizeof(buffer)) ==
          ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_block_header_deserialize(buffer, NULL, sizeof(buffer)) ==
          ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_block_header_serialize(NULL, NULL, 0) ==
          ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_block_header_deserialize(NULL, NULL, 0) ==
          ECLIPSE_ERROR_NULL_POINTER);

    /* Every truncated size must be rejected before either output is touched. */
    for (size_t length = 0; length < sizeof(buffer); ++length) {
        CHECK(eclipse_block_header_serialize(&header, buffer, length) ==
              ECLIPSE_ERROR_INVALID_ARGUMENT);
        CHECK(eclipse_block_header_deserialize(buffer, &header, length) ==
              ECLIPSE_ERROR_INVALID_ARGUMENT);
    }
    CHECK(memcmp(buffer, saved_buffer, sizeof(buffer)) == 0);
    /* Here a raw snapshot is intentional: failure must preserve even padding. */
    CHECK(memcmp(&header, saved_header, sizeof(header)) == 0);
}

int main(void)
{
    eclipse_block_header_t block1 = {
        .version = 1,
        .timestamp = 1609459200,
        .difficulty = 10,
        .nonce = 1234567890
    };
    uint8_t buffer[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    eclipse_block_header_t block2 = {0};

    puts("Block header before serialization:");
    print_header(&block1);
    /* The API returns a status; buffer holds the bytes for printing/decoding. */
    CHECK(eclipse_block_header_serialize(&block1, buffer, sizeof(buffer)) ==
          ECLIPSE_SUCCESS);
    puts("Block header serialized successfully.\nSerialized data:");
    for (size_t i = 0; i < sizeof(buffer); ++i) {
        printf("%02x%c", (unsigned int)buffer[i],
               (i + 1) % 16 == 0 || i + 1 == sizeof(buffer) ? '\n' : ' ');
    }
    CHECK(eclipse_block_header_deserialize(buffer, &block2, sizeof(buffer)) ==
          ECLIPSE_SUCCESS);
    check_headers_equal(&block1, &block2);
    puts("Block header after deserialization:");
    print_header(&block2);

    test_wire_format();
    test_uniform_bytes(0x00);
    test_uniform_bytes(0xff);
    test_invalid_arguments();
    puts("All serialization/deserialization tests passed.");
    return EXIT_SUCCESS;
}
