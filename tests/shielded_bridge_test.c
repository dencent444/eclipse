#include "../src/core/shielded/shielded.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    assert(argc == 2);
    eclipse_shielded_receipt_t receipt;
    memset(&receipt, 0xa5, sizeof(receipt));
    const uint8_t malformed[] = {'E', 'S', 'X', '1', 0};
    assert(eclipse_shielded_verify_wire(malformed, sizeof(malformed), 44,
                                        &receipt) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    assert(receipt.action_count == 0xa5);
    assert(eclipse_shielded_verify_wire(NULL, 1, 44,
                                        &receipt) == ECLIPSE_ERROR_INVALID_ARGUMENT);

    /* Stable test vector: a real Orchard proof made by esx1_fixture. The
     * private key is a public test constant and has no live-network value. */
    FILE *file = fopen(argv[1], "rb");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size > 0 && size <= ECLIPSE_SHIELDED_MAX_WIRE_SIZE);
    assert(fseek(file, 0, SEEK_SET) == 0);
    uint8_t *wire = malloc((size_t)size);
    assert(wire != NULL);
    assert(fread(wire, 1, (size_t)size, file) == (size_t)size);
    assert(fclose(file) == 0);
    assert(eclipse_shielded_verify_wire(wire, (size_t)size, 44,
                                        &receipt) == ECLIPSE_SUCCESS);
    assert(receipt.network_id == 44 && receipt.public_input == 5000);
    assert(receipt.fee == 0 && receipt.value_balance == -5000);
    assert(receipt.action_count == 2);
    eclipse_shielded_receipt_t accepted = receipt;
    assert(eclipse_shielded_verify_wire(wire, (size_t)size, 45,
                                        &receipt) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    assert(memcmp(&receipt, &accepted, sizeof(receipt)) == 0);
    wire[size - 1] ^= 1; /* Binding signature is the final 64 bytes. */
    assert(eclipse_shielded_verify_wire(wire, (size_t)size, 44,
                                        &receipt) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    assert(memcmp(&receipt, &accepted, sizeof(receipt)) == 0);
    free(wire);
    return 0;
}
