#include "tx/utxo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

int main(void)
{
    uint8_t seed[32] = {9};
    eclipse_ml_dsa_key_t *owner = NULL;
    CHECK(eclipse_ml_dsa_generate_from_seed(ECLIPSE_ML_DSA_44, seed,
                                            sizeof(seed), &owner) == ECLIPSE_SUCCESS);
    eclipse_tx_output_t output = {0};
    output.amount = 100;
    output.scheme = ECLIPSE_ML_DSA_44;
    output.public_key_length = 1312;
    CHECK(eclipse_ml_dsa_export_public(owner, output.public_key,
                                        sizeof(output.public_key)) == ECLIPSE_SUCCESS);
    eclipse_utxo_set_t *set = NULL, *fork = NULL;
    CHECK(eclipse_utxo_set_create(&set) == ECLIPSE_SUCCESS);
    for (uint32_t i = 0; i < 512; ++i) {
        uint8_t id[32] = {0};
        id[0] = (uint8_t)(i >> 8);
        id[1] = (uint8_t)i;
        CHECK(eclipse_utxo_set_seed_dev(set, id, 0, &output) == ECLIPSE_SUCCESS);
    }
    CHECK(eclipse_utxo_set_count(set) == 512);
    CHECK(eclipse_utxo_set_clone(set, &fork) == ECLIPSE_SUCCESS);
    for (uint32_t i = 0; i < 512; ++i) {
        uint8_t id[32] = {0};
        id[0] = (uint8_t)(i >> 8);
        id[1] = (uint8_t)i;
        eclipse_tx_output_t found_output = {0};
        bool found = false;
        CHECK(eclipse_utxo_set_find(fork, id, 0, &found_output, &found) ==
              ECLIPSE_SUCCESS && found && found_output.amount == 100);
    }
    /* Hundreds of spends exercise hash-table growth, tombstones, dense-array
     * compaction, and branch isolation. Live count stays flat at 512. */
    for (uint32_t i = 0; i < 256; ++i) {
        uint8_t old_id[32] = {0}, new_id[32];
        old_id[0] = (uint8_t)(i >> 8);
        old_id[1] = (uint8_t)i;
        eclipse_tx_t tx;
        CHECK(eclipse_tx_init(&tx) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_add_input(&tx, old_id, 0) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_add_output(&tx, 99, output.scheme,
                                    output.public_key, output.public_key_length) ==
              ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_set_fee(&tx, 1) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_sign_input(&tx, 0, owner) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_apply(&tx, set, new_id) == ECLIPSE_SUCCESS);
        CHECK(eclipse_utxo_set_count(set) == 512);
        eclipse_tx_output_t located = {0};
        bool found = true;
        CHECK(eclipse_utxo_set_find(set, old_id, 0, &located, &found) ==
              ECLIPSE_SUCCESS && !found);
        CHECK(eclipse_utxo_set_find(set, new_id, 0, &located, &found) ==
              ECLIPSE_SUCCESS && found && located.amount == 99);
        CHECK(eclipse_utxo_set_find(fork, old_id, 0, &located, &found) ==
              ECLIPSE_SUCCESS && found && located.amount == 100);
    }
    eclipse_utxo_set_free(fork);
    eclipse_utxo_set_free(set);

    /* Repeated replacement of one output must not retain spent history. */
    CHECK(eclipse_utxo_set_create(&set) == ECLIPSE_SUCCESS);
    uint8_t current[32] = {0xa5};
    CHECK(eclipse_utxo_set_seed_dev(set, current, 0, &output) == ECLIPSE_SUCCESS);
    for (unsigned i = 0; i < 300; ++i) {
        eclipse_tx_t tx;
        CHECK(eclipse_tx_init(&tx) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_add_input(&tx, current, 0) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_add_output(&tx, 100, output.scheme,
                                    output.public_key, output.public_key_length) ==
              ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_sign_input(&tx, 0, owner) == ECLIPSE_SUCCESS);
        uint8_t next[32];
        CHECK(eclipse_tx_apply(&tx, set, next) == ECLIPSE_SUCCESS);
        memcpy(current, next, 32);
        CHECK(eclipse_utxo_set_count(set) == 1);
    }
    eclipse_utxo_set_free(set);
    eclipse_ml_dsa_key_free(owner);
    puts("utxo_index_test: OK");
    return EXIT_SUCCESS;
}
