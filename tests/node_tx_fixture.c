/* A deterministic test wallet so the process test can submit a real signed
 * spend of a reward created by another process. No private key is persisted. */
#include "block/chain.h"
#include "encoding/base92.h"
#include "tx/tx.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int digit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static bool reward_id(const char *hex, uint8_t id[32])
{
    if (strlen(hex) != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        int high = digit(hex[2 * i]), low = digit(hex[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        id[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3) return EXIT_FAILURE;
    const uint8_t seed[32] = {42};
    eclipse_ml_dsa_key_t *key = NULL;
    if (eclipse_ml_dsa_generate_from_seed(ECLIPSE_ML_DSA_44, seed,
                                           sizeof(seed), &key) != ECLIPSE_SUCCESS)
        return EXIT_FAILURE;
    eclipse_wallet_public_key_t public = {0};
    public.scheme = ECLIPSE_ML_DSA_44;
    public.length = 1312;
    if (eclipse_ml_dsa_export_public(key, public.bytes, sizeof(public.bytes)) !=
        ECLIPSE_SUCCESS) goto fail;
    if (strcmp(argv[1], "public") == 0 && argc == 2) {
        size_t capacity = eclipse_base92_encoded_capacity(
            eclipse_wallet_public_serialized_size(public.scheme));
        char *text = malloc(capacity);
        size_t written = 0;
        if (text == NULL) goto fail;
        eclipse_error_t status = eclipse_wallet_public_to_base92(
            &public, text, capacity, &written);
        if (status == ECLIPSE_SUCCESS) puts(text);
        free(text);
        eclipse_ml_dsa_key_free(key);
        return status == ECLIPSE_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (strcmp(argv[1], "spend") != 0 || argc != 3) goto fail;
    uint8_t id[32];
    if (!reward_id(argv[2], id)) goto fail;
    eclipse_tx_t *tx = malloc(sizeof(*tx));
    uint8_t *wire = malloc(ECLIPSE_TX_MAX_WIRE_SIZE);
    if (tx == NULL || wire == NULL) { free(tx); free(wire); goto fail; }
    eclipse_error_t status = eclipse_tx_init(tx);
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_add_input(tx, id, 0);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_add_output(tx, ECLIPSE_DEV_INITIAL_SUBSIDY - 1,
                                       public.scheme, public.bytes, public.length);
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_set_fee(tx, 1);
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_sign_input(tx, 0, key);
    size_t length = 0;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_serialize(tx, wire, ECLIPSE_TX_MAX_WIRE_SIZE, &length);
    static const char alphabet[] = "0123456789abcdef";
    if (status == ECLIPSE_SUCCESS) {
        for (size_t i = 0; i < length; ++i) {
            putchar(alphabet[wire[i] >> 4]);
            putchar(alphabet[wire[i] & 15]);
        }
        putchar('\n');
    }
    free(tx);
    free(wire);
    eclipse_ml_dsa_key_free(key);
    return status == ECLIPSE_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
fail:
    eclipse_ml_dsa_key_free(key);
    return EXIT_FAILURE;
}
