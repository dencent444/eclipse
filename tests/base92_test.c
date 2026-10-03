/* Codec contract: known vectors, canonical spelling, invalid input, and
 * output-buffer boundaries must agree for every node using this text format. */
#include "encoding/base92.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

int main(void)
{
    char encoded[256];
    uint8_t decoded[128];
    size_t written = 0;

    /* Published compatibility vector from thenoviceoof/base92. */
    static const uint8_t hello[] = "hello world";
    CHECK(eclipse_base92_encode(hello, sizeof(hello) - 1,
                                encoded, sizeof(encoded), &written) == ECLIPSE_SUCCESS);
    CHECK(written == strlen("Fc_$aOTdKnsM*k"));
    CHECK(strcmp(encoded, "Fc_$aOTdKnsM*k") == 0);
    CHECK(eclipse_base92_decode(encoded, written, decoded, sizeof(decoded),
                                &written) == ECLIPSE_SUCCESS);
    CHECK(written == sizeof(hello) - 1);
    CHECK(memcmp(decoded, hello, written) == 0);

    /* Exercise every remainder modulo 13 and binary zero bytes. */
    uint8_t source[128];
    for (size_t length = 1; length <= sizeof(source); ++length) {
        for (size_t i = 0; i < length; ++i)
            source[i] = (uint8_t)(i * 29u + length);
        CHECK(eclipse_base92_encode(source, length, encoded, sizeof(encoded),
                                    &written) == ECLIPSE_SUCCESS);
        size_t decoded_length = 0;
        CHECK(eclipse_base92_decode(encoded, written, decoded, length,
                                    &decoded_length) == ECLIPSE_SUCCESS);
        CHECK(decoded_length == length);
        CHECK(memcmp(decoded, source, length) == 0);
    }

    CHECK(eclipse_base92_encode(NULL, 0, encoded, sizeof(encoded),
                                &written) == ECLIPSE_SUCCESS);
    CHECK(strcmp(encoded, "~") == 0 && written == 1);
    CHECK(eclipse_base92_decode("~", 1, decoded, sizeof(decoded),
                                &written) == ECLIPSE_SUCCESS && written == 0);
    CHECK(eclipse_base92_decode("!", 1, decoded, sizeof(decoded),
                                &written) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_base92_decode("!#", 2, decoded, sizeof(decoded),
                                &written) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_base92_decode("\"#", 2, decoded, sizeof(decoded),
                                &written) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_base92_decode("!!", 2, decoded, 0,
                                &written) == ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    CHECK(eclipse_base92_encode(hello, sizeof(hello) - 1, encoded, 1,
                                &written) == ECLIPSE_ERROR_BUFFER_TOO_SMALL);

    puts("Base92 tests passed");
    return EXIT_SUCCESS;
}
