/* LibFuzzer entry point for wire bytes accepted from untrusted peers.
 * Valid packets must round-trip to identical canonical bytes; malformed
 * packets must be rejected without an ASan/UBSan finding. The first input
 * byte selects a parser and is not part of the wire packet. */
#include "block/block.h"
#include "log.h"
#include "tx/tx.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* Malformed packets routinely produce warnings; writing those for every
     * fuzz iteration would dominate CPU and fill the log. Sanitizer reports
     * still go to stderr independently of this project logger. */
    FILE *sink = fopen("/dev/null", "w");
    if (sink == NULL || eclipse_log_set_stream(sink) != ECLIPSE_SUCCESS)
        abort();
    (void)eclipse_log_set_info_level(0);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;
    const uint8_t *wire = data + 1;
    size_t length = size - 1;
    if ((data[0] & 1u) == 0) {
        if (length > ECLIPSE_TX_MAX_WIRE_SIZE) return 0;
        eclipse_tx_t *tx = malloc(sizeof(*tx));
        uint8_t *encoded = malloc(ECLIPSE_TX_MAX_WIRE_SIZE);
        if (tx == NULL || encoded == NULL) abort();
        if (eclipse_tx_deserialize(wire, length, tx) == ECLIPSE_SUCCESS) {
            size_t written = 0;
            if (eclipse_tx_serialize(tx, encoded, ECLIPSE_TX_MAX_WIRE_SIZE,
                                     &written) != ECLIPSE_SUCCESS ||
                written != length || memcmp(encoded, wire, length) != 0)
                abort();
        }
        free(encoded);
        free(tx);
    } else {
        if (length > ECLIPSE_BLOCK_MAX_WIRE_SIZE) return 0;
        eclipse_block_t *block = NULL;
        if (eclipse_block_deserialize(wire, length, &block) == ECLIPSE_SUCCESS) {
            uint8_t *encoded = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
            if (encoded == NULL) abort();
            size_t written = 0;
            if (eclipse_block_serialize(block, encoded,
                        ECLIPSE_BLOCK_MAX_WIRE_SIZE, &written) != ECLIPSE_SUCCESS ||
                written != length || memcmp(encoded, wire, length) != 0)
                abort();
            free(encoded);
        }
        eclipse_block_free(block);
    }
    return 0;
}
