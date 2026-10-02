#include "base92.h"
#include "../log.h"

#include <openssl/crypto.h>

#include <string.h>

/* The published alphabet contains '!', '#'..'_', and 'a'..'}'. It excludes
 * double quote, backtick, and tilde; '~' is reserved for empty input. */
static char base92_char(unsigned value)
{
    if (value == 0) return '!';
    if (value <= 61) return (char)('#' + value - 1);
    return (char)('a' + value - 62);
}

static int base92_value(char ch)
{
    if (ch == '!') return 0;
    if (ch >= '#' && ch <= '_') return ch - '#' + 1;
    if (ch >= 'a' && ch <= '}') return ch - 'a' + 62;
    return -1;
}

size_t eclipse_base92_encoded_capacity(size_t input_length)
{
    if (input_length == 0) return 2; /* "~" and NUL. */
    if (input_length > SIZE_MAX / 8) return 0;
    size_t bits = input_length * 8;
    size_t full_groups = bits / 13;
    size_t remainder = bits % 13;
    if (full_groups > (SIZE_MAX - 3) / 2) return 0;
    return full_groups * 2 + (remainder == 0 ? 0 : remainder < 7 ? 1 : 2) + 1;
}

eclipse_error_t eclipse_base92_encode(const uint8_t *input, size_t input_length,
                                      char *output, size_t capacity,
                                      size_t *written)
{
    if (written == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *written = 0;
    if ((input_length > 0 && input == NULL) || output == NULL) {
        ECLIPSE_LOG_WARNING("Base92 encode rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    size_t needed = eclipse_base92_encoded_capacity(input_length);
    if (needed == 0) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (capacity < needed) return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    if (input_length == 0) {
        output[0] = '~';
        output[1] = '\0';
        *written = 1;
        return ECLIPSE_SUCCESS;
    }

    /* At most 20 bits are live: fewer than 13 before appending a byte. */
    uint32_t bits = 0;
    unsigned bit_count = 0;
    size_t used = 0;
    for (size_t i = 0; i < input_length; ++i) {
        bits = (bits << 8) | input[i];
        bit_count += 8;
        while (bit_count >= 13) {
            unsigned group = (bits >> (bit_count - 13)) & 0x1fffu;
            output[used++] = base92_char(group / 91);
            output[used++] = base92_char(group % 91);
            bit_count -= 13;
            bits &= ((UINT32_C(1) << bit_count) - 1);
        }
    }
    if (bit_count > 0) {
        if (bit_count < 7) {
            output[used++] = base92_char(bits << (6 - bit_count));
        } else {
            unsigned group = bits << (13 - bit_count);
            output[used++] = base92_char(group / 91);
            output[used++] = base92_char(group % 91);
        }
    }
    output[used] = '\0';
    *written = used;
    ECLIPSE_LOG_INFO(5, "bytes encoded as Base92");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_base92_decode(const char *text, size_t text_length,
                                      uint8_t *output, size_t capacity,
                                      size_t *written)
{
    if (written == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *written = 0;
    if (text == NULL || output == NULL) {
        ECLIPSE_LOG_WARNING("Base92 decode rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (text_length == 1 && text[0] == '~') {
        ECLIPSE_LOG_INFO(5, "empty Base92 value decoded");
        return ECLIPSE_SUCCESS;
    }
    if (text_length < 2 || text_length > SIZE_MAX / 13) {
        ECLIPSE_LOG_INFO(4, "Base92 input rejected for invalid length");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }

    /* Decode into a temporary buffer so malformed input cannot leave a
       half-written output. The upper bound is deliberately conservative. */
    size_t max_bytes = (text_length * 13) / 16 + 2;
    uint8_t *decoded = OPENSSL_malloc(max_bytes);
    if (decoded == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    uint32_t bits = 0;
    unsigned bit_count = 0;
    size_t used = 0;
    eclipse_error_t status = ECLIPSE_SUCCESS;
    size_t i = 0;
    for (; i + 1 < text_length; i += 2) {
        int high = base92_value(text[i]);
        int low = base92_value(text[i + 1]);
        int group = high < 0 || low < 0 ? -1 : high * 91 + low;
        if (group < 0 || group >= 8192) {
            status = ECLIPSE_ERROR_INVALID_ARGUMENT;
            break;
        }
        bits = (bits << 13) | (uint32_t)group;
        bit_count += 13;
        while (bit_count >= 8) {
            decoded[used++] = (uint8_t)(bits >> (bit_count - 8));
            bit_count -= 8;
            bits &= ((UINT32_C(1) << bit_count) - 1);
        }
    }
    if (status == ECLIPSE_SUCCESS && i < text_length) {
        int value = base92_value(text[i]);
        if (value < 0 || value >= 64) status = ECLIPSE_ERROR_INVALID_ARGUMENT;
        else {
            bits = (bits << 6) | (uint32_t)value;
            bit_count += 6;
            if (bit_count >= 8)
                decoded[used++] = (uint8_t)(bits >> (bit_count - 8));
        }
    }
    if (status == ECLIPSE_SUCCESS) {
        size_t canonical_capacity = eclipse_base92_encoded_capacity(used);
        char *canonical = OPENSSL_malloc(canonical_capacity);
        size_t canonical_length = 0;
        if (canonical == NULL) status = ECLIPSE_ERROR_OUT_OF_MEMORY;
        else {
            status = eclipse_base92_encode(decoded, used, canonical,
                                           canonical_capacity, &canonical_length);
            if (status == ECLIPSE_SUCCESS &&
                (canonical_length != text_length ||
                 memcmp(canonical, text, text_length) != 0))
                status = ECLIPSE_ERROR_INVALID_ARGUMENT;
        }
        OPENSSL_clear_free(canonical, canonical_capacity);
    }
    if (status == ECLIPSE_SUCCESS) {
        if (used > capacity) status = ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }
    if (status == ECLIPSE_SUCCESS) {
        memcpy(output, decoded, used);
        *written = used;
        ECLIPSE_LOG_INFO(5, "canonical Base92 value decoded");
    } else {
        ECLIPSE_LOG_INFO(4, "Base92 value rejected");
    }
    OPENSSL_clear_free(decoded, max_bytes);
    return status;
}
