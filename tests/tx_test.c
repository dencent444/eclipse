/* Real ML-DSA keys and in-memory UTXO transitions exercise the whole dev v0
 * path. The initial output is a test fixture, not a mining reward. */
#include "tx/tx.h"
#include "tx/utxo.h"
#include "wallet/wallet.h"

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static eclipse_ml_dsa_key_t *key_from_seed(eclipse_ml_dsa_scheme_t scheme,
                                           uint8_t first)
{
    uint8_t seed[32] = {0};
    seed[0] = first;
    eclipse_ml_dsa_key_t *key = NULL;
    CHECK(eclipse_ml_dsa_generate_from_seed(scheme, seed,
                                            sizeof(seed), &key) == ECLIPSE_SUCCESS);
    return key;
}

static eclipse_ml_dsa_key_t *key_from_byte(uint8_t first)
{
    return key_from_seed(ECLIPSE_ML_DSA_44, first);
}

static void key_public(const eclipse_ml_dsa_key_t *key, uint8_t output[1312])
{
    CHECK(eclipse_ml_dsa_export_public(key, output, 1312) == ECLIPSE_SUCCESS);
}

static void add_output(eclipse_tx_t *tx, uint64_t amount,
                       const eclipse_ml_dsa_key_t *key)
{
    uint8_t public_key[1312];
    key_public(key, public_key);
    CHECK(eclipse_tx_add_output(tx, amount, ECLIPSE_ML_DSA_44,
                                public_key, sizeof(public_key)) == ECLIPSE_SUCCESS);
}

static void check_transaction_roundtrip_and_state(void)
{
    eclipse_ml_dsa_key_t *alice = key_from_byte(1);
    eclipse_ml_dsa_key_t *bob = key_from_byte(2);
    eclipse_ml_dsa_key_t *other = key_from_byte(3);
    uint8_t funding_id[32] = {0};
    funding_id[0] = 0xa5;
    eclipse_tx_output_t funding = {0};
    funding.amount = 100;
    funding.scheme = ECLIPSE_ML_DSA_44;
    funding.public_key_length = 1312;
    key_public(alice, funding.public_key);
    eclipse_utxo_set_t *state = NULL;
    CHECK(eclipse_utxo_set_create(&state) == ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_seed_dev(state, funding_id, 0, &funding) ==
          ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_seed_dev(state, funding_id, 0, &funding) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    uint8_t other_funding_id[32] = {0};
    other_funding_id[0] = 0xa6;
    CHECK(eclipse_utxo_set_seed_dev(state, other_funding_id, 0, &funding) ==
          ECLIPSE_SUCCESS);

    eclipse_tx_t tx;
    CHECK(eclipse_tx_init(&tx) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&tx, funding_id, 0) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&tx, funding_id, 0) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    add_output(&tx, 60, bob);
    add_output(&tx, 39, alice);
    CHECK(eclipse_tx_set_fee(&tx, 1) == ECLIPSE_SUCCESS);

    /* The preimage binds the dev network, all outpoints and outputs, fee,
       and the input index. No signature signs its own random bytes. */
    uint8_t message[ECLIPSE_TX_MAX_SIGNING_SIZE];
    size_t message_length = 0;
    CHECK(eclipse_tx_signing_message(&tx, 0, message, sizeof(message),
                                     &message_length) == ECLIPSE_SUCCESS);
    CHECK(message_length > 23 && memcmp(message, "ECLIPSE/DEV/TX/SIGN/V0", 22) == 0);
    CHECK(memcmp(message + 22, "ETX0", 4) == 0);
    /* Independently constructed with Python struct.pack and hashlib.sha3_256
       from the same fixed seeded public keys. This locks the signed layout. */
    static const uint8_t signing_hash[32] = {
        0x06, 0xa9, 0xab, 0x94, 0x72, 0xe0, 0x38, 0x28,
        0x4d, 0x94, 0x02, 0x5b, 0x5b, 0x45, 0xf0, 0xbf,
        0xf7, 0x97, 0x30, 0x91, 0x70, 0x95, 0xfb, 0xee,
        0x01, 0xc2, 0x53, 0x0a, 0x45, 0xc3, 0xee, 0x52
    };
    uint8_t actual_hash[32];
    size_t actual_length = 0;
    CHECK(message_length == 2724);
    CHECK(EVP_Q_digest(NULL, "SHA3-256", NULL, message, message_length,
                       actual_hash, &actual_length) == 1 && actual_length == 32);
    CHECK(memcmp(actual_hash, signing_hash, sizeof(signing_hash)) == 0);

    /* A perfectly formed signature by the wrong key has no authority. */
    bool valid = true;
    CHECK(eclipse_tx_sign_input(&tx, 0, other) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_validate(&tx, state, &valid) == ECLIPSE_SUCCESS && !valid);
    CHECK(eclipse_tx_sign_input(&tx, 0, alice) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_validate(&tx, state, &valid) == ECLIPSE_SUCCESS && valid);

    eclipse_tx_t changed = tx;
    changed.outputs[0].amount = 61;
    changed.outputs[1].amount = 38;
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    changed = tx;
    changed.fee = 2;
    changed.outputs[1].amount = 38;
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    changed = tx;
    changed.outputs[0].public_key[0] ^= 1;
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    changed = tx;
    changed.network_id ^= 1;
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    changed = tx;
    memcpy(changed.inputs[0].txid, other_funding_id, sizeof(other_funding_id));
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    changed = tx;
    changed.output_count = 2;
    changed.outputs[0].amount = UINT64_MAX;
    changed.outputs[1].amount = 1;
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    changed = tx;
    changed.inputs[1] = changed.inputs[0];
    changed.input_count = 2;
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    changed = tx;
    changed.inputs[0].signature[0] ^= 1;
    CHECK(eclipse_tx_validate(&changed, state, &valid) == ECLIPSE_SUCCESS && !valid);
    uint8_t rejected_id[32] = {0};
    CHECK(eclipse_tx_apply(&changed, state, rejected_id) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    eclipse_tx_output_t unchanged_output = {0};
    bool still_unspent = false;
    CHECK(eclipse_utxo_set_find(state, funding_id, 0, &unchanged_output,
                                &still_unspent) == ECLIPSE_SUCCESS &&
          still_unspent && unchanged_output.amount == 100);

    uint8_t wire[ECLIPSE_TX_MAX_WIRE_SIZE + 1];
    size_t wire_length = 0;
    CHECK(eclipse_tx_serialize(&tx, wire, sizeof(wire), &wire_length) ==
          ECLIPSE_SUCCESS);
    CHECK(wire_length < sizeof(wire) && wire[4] == ECLIPSE_TX_VERSION);
    eclipse_tx_t decoded;
    CHECK(eclipse_tx_deserialize(wire, wire_length, &decoded) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_validate(&decoded, state, &valid) == ECLIPSE_SUCCESS && valid);
    uint8_t id_before[32], id_after[32];
    CHECK(eclipse_tx_id(&tx, id_before) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_id(&decoded, id_after) == ECLIPSE_SUCCESS);
    CHECK(memcmp(id_before, id_after, sizeof(id_before)) == 0);

    /* Two independently initialized states must agree on the same transfer. */
    eclipse_utxo_set_t *second_state = NULL;
    CHECK(eclipse_utxo_set_create(&second_state) == ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_seed_dev(second_state, funding_id, 0, &funding) ==
          ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_seed_dev(second_state, other_funding_id, 0,
                                    &funding) == ECLIPSE_SUCCESS);
    uint8_t second_id[32];
    CHECK(eclipse_tx_apply(&decoded, second_state, second_id) == ECLIPSE_SUCCESS);
    CHECK(memcmp(second_id, id_before, sizeof(second_id)) == 0);

    /* Truncation, trailing bytes, wrong header and unsupported network never
       produce a partial transaction object. */
    CHECK(eclipse_tx_deserialize(wire, wire_length - 1, &decoded) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_tx_deserialize(wire, wire_length + 1, &decoded) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    uint8_t original = wire[4];
    wire[4] ^= 1;
    CHECK(eclipse_tx_deserialize(wire, wire_length, &decoded) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[4] = original;
    wire[5] ^= 1;
    CHECK(eclipse_tx_deserialize(wire, wire_length, &decoded) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[5] ^= 1;
    original = wire[19 + 32 + 4];
    wire[19 + 32 + 4] = 0xff; /* Impossible signature byte length. */
    CHECK(eclipse_tx_deserialize(wire, wire_length, &decoded) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[19 + 32 + 4] = original;
    size_t output_at = 19 + 38 + tx.inputs[0].signature_length;
    original = wire[output_at + 8];
    wire[output_at + 8] = 0xff; /* Unknown key scheme. */
    CHECK(eclipse_tx_deserialize(wire, wire_length, &decoded) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[output_at + 8] = original;
    original = wire[output_at + 10];
    wire[output_at + 10] ^= 1; /* Wrong declared public-key length. */
    CHECK(eclipse_tx_deserialize(wire, wire_length, &decoded) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[output_at + 10] = original;
    wire[19 + 38] ^= 1; /* Format valid, cryptographically invalid. */
    CHECK(eclipse_tx_deserialize(wire, wire_length, &decoded) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_validate(&decoded, state, &valid) == ECLIPSE_SUCCESS && !valid);

    uint8_t applied_id[32];
    CHECK(eclipse_tx_apply(&tx, state, applied_id) == ECLIPSE_SUCCESS);
    CHECK(memcmp(id_before, applied_id, sizeof(applied_id)) == 0);
    eclipse_tx_output_t found_output = {0};
    bool found = true;
    CHECK(eclipse_utxo_set_find(state, funding_id, 0, &found_output, &found) ==
          ECLIPSE_SUCCESS && !found);
    CHECK(eclipse_utxo_set_find(state, applied_id, 0, &found_output, &found) ==
          ECLIPSE_SUCCESS && found && found_output.amount == 60);
    eclipse_tx_output_t second_output = {0};
    CHECK(eclipse_utxo_set_find(second_state, id_before, 0,
                                &second_output, &found) == ECLIPSE_SUCCESS &&
          found && second_output.amount == found_output.amount &&
          memcmp(second_output.public_key, found_output.public_key,
                 found_output.public_key_length) == 0);
    CHECK(eclipse_tx_apply(&tx, state, applied_id) == ECLIPSE_ERROR_INVALID_ARGUMENT);

    eclipse_tx_t second;
    CHECK(eclipse_tx_init(&second) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&second, id_before, 0) == ECLIPSE_SUCCESS);
    add_output(&second, 58, other);
    CHECK(eclipse_tx_set_fee(&second, 2) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_sign_input(&second, 0, bob) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_apply(&second, state, applied_id) == ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_find(state, id_before, 0, &found_output, &found) ==
          ECLIPSE_SUCCESS && !found);
    CHECK(eclipse_utxo_set_find(state, applied_id, 0, &found_output, &found) ==
          ECLIPSE_SUCCESS && found && found_output.amount == 58);

    eclipse_utxo_set_free(state);
    eclipse_utxo_set_free(second_state);
    eclipse_ml_dsa_key_free(alice);
    eclipse_ml_dsa_key_free(bob);
    eclipse_ml_dsa_key_free(other);
}

static void check_other_schemes(void)
{
    const eclipse_ml_dsa_scheme_t schemes[] = {ECLIPSE_ML_DSA_65,
                                                ECLIPSE_ML_DSA_87};
    for (size_t s = 0; s < sizeof(schemes) / sizeof(schemes[0]); ++s) {
        eclipse_ml_dsa_scheme_t scheme = schemes[s];
        eclipse_ml_dsa_info_t info;
        CHECK(eclipse_ml_dsa_info(scheme, &info));
        eclipse_ml_dsa_key_t *key = key_from_seed(scheme, (uint8_t)(30 + s));
        uint8_t public_key[ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE];
        CHECK(eclipse_ml_dsa_export_public(key, public_key,
                                           sizeof(public_key)) == ECLIPSE_SUCCESS);
        eclipse_tx_output_t funding = {0};
        funding.amount = 5;
        funding.scheme = scheme;
        funding.public_key_length = info.public_key_size;
        memcpy(funding.public_key, public_key, info.public_key_size);
        uint8_t funding_id[32] = {0};
        funding_id[0] = (uint8_t)(30 + s);
        eclipse_utxo_set_t *state = NULL;
        CHECK(eclipse_utxo_set_create(&state) == ECLIPSE_SUCCESS);
        CHECK(eclipse_utxo_set_seed_dev(state, funding_id, 0, &funding) ==
              ECLIPSE_SUCCESS);
        eclipse_tx_t tx;
        CHECK(eclipse_tx_init(&tx) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_add_input(&tx, funding_id, 0) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_add_output(&tx, 5, scheme, public_key,
                                    info.public_key_size) == ECLIPSE_SUCCESS);
        CHECK(eclipse_tx_sign_input(&tx, 0, key) == ECLIPSE_SUCCESS);
        CHECK(tx.inputs[0].signature_length == info.signature_size);
        uint8_t wire[ECLIPSE_TX_MAX_WIRE_SIZE];
        size_t wire_length = 0;
        CHECK(eclipse_tx_serialize(&tx, wire, sizeof(wire), &wire_length) ==
              ECLIPSE_SUCCESS);
        eclipse_tx_t parsed;
        CHECK(eclipse_tx_deserialize(wire, wire_length, &parsed) == ECLIPSE_SUCCESS);
        uint8_t id[32];
        CHECK(eclipse_tx_apply(&parsed, state, id) == ECLIPSE_SUCCESS);
        eclipse_utxo_set_free(state);
        eclipse_ml_dsa_key_free(key);
    }
}

static void check_two_input_signatures(void)
{
    eclipse_ml_dsa_key_t *owner = key_from_byte(41);
    uint8_t public_key[1312];
    key_public(owner, public_key);
    eclipse_tx_output_t funding = {0};
    funding.amount = 5;
    funding.scheme = ECLIPSE_ML_DSA_44;
    funding.public_key_length = sizeof(public_key);
    memcpy(funding.public_key, public_key, sizeof(public_key));
    uint8_t first_id[32] = {1}, second_id[32] = {2};
    eclipse_utxo_set_t *state = NULL;
    CHECK(eclipse_utxo_set_create(&state) == ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_seed_dev(state, first_id, 0, &funding) ==
          ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_seed_dev(state, second_id, 0, &funding) ==
          ECLIPSE_SUCCESS);
    eclipse_tx_t tx;
    CHECK(eclipse_tx_init(&tx) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&tx, first_id, 0) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&tx, second_id, 0) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_output(&tx, 9, ECLIPSE_ML_DSA_44,
                                public_key, sizeof(public_key)) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_set_fee(&tx, 1) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_sign_input(&tx, 0, owner) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_sign_input(&tx, 1, owner) == ECLIPSE_SUCCESS);
    bool valid = false;
    CHECK(eclipse_tx_validate(&tx, state, &valid) == ECLIPSE_SUCCESS && valid);
    eclipse_tx_t swapped = tx;
    eclipse_tx_input_t saved = swapped.inputs[0];
    swapped.inputs[0].signature_length = swapped.inputs[1].signature_length;
    memcpy(swapped.inputs[0].signature, swapped.inputs[1].signature,
           swapped.inputs[1].signature_length);
    swapped.inputs[1].signature_length = saved.signature_length;
    memcpy(swapped.inputs[1].signature, saved.signature, saved.signature_length);
    CHECK(eclipse_tx_validate(&swapped, state, &valid) == ECLIPSE_SUCCESS && !valid);
    uint8_t id[32];
    CHECK(eclipse_tx_apply(&tx, state, id) == ECLIPSE_SUCCESS);
    eclipse_tx_output_t output;
    bool found = true;
    CHECK(eclipse_utxo_set_find(state, first_id, 0, &output, &found) ==
          ECLIPSE_SUCCESS && !found);
    CHECK(eclipse_utxo_set_find(state, second_id, 0, &output, &found) ==
          ECLIPSE_SUCCESS && !found);
    eclipse_utxo_set_free(state);
    eclipse_ml_dsa_key_free(owner);
}

static void check_wallet_spend_domain(void)
{
    eclipse_wallet_recovery_t *root = NULL;
    eclipse_wallet_t *wallet = NULL;
    CHECK(eclipse_wallet_create(ECLIPSE_ML_DSA_44, &root, &wallet) ==
          ECLIPSE_SUCCESS);
    eclipse_wallet_public_key_t spend_public;
    CHECK(eclipse_wallet_child_public(wallet, ECLIPSE_WALLET_SPEND, 0,
                                      &spend_public) == ECLIPSE_SUCCESS);
    eclipse_tx_output_t funding = {0};
    funding.amount = 10;
    funding.scheme = spend_public.scheme;
    funding.public_key_length = spend_public.length;
    memcpy(funding.public_key, spend_public.bytes, spend_public.length);
    uint8_t funding_id[32] = {0};
    funding_id[0] = 0x73;
    eclipse_utxo_set_t *state = NULL;
    CHECK(eclipse_utxo_set_create(&state) == ECLIPSE_SUCCESS);
    CHECK(eclipse_utxo_set_seed_dev(state, funding_id, 0, &funding) ==
          ECLIPSE_SUCCESS);
    eclipse_tx_t tx;
    CHECK(eclipse_tx_init(&tx) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&tx, funding_id, 0) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_output(&tx, 9, spend_public.scheme,
                                spend_public.bytes, spend_public.length) ==
          ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_set_fee(&tx, 1) == ECLIPSE_SUCCESS);

    eclipse_wallet_domain_t *receive = NULL;
    eclipse_wallet_t *receive_only = NULL;
    CHECK(eclipse_wallet_derive_domain(root, ECLIPSE_WALLET_RECEIVE,
                                       &receive) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_open_domain(receive, &receive_only) == ECLIPSE_SUCCESS);
    CHECK(eclipse_wallet_sign_tx_input(receive_only, 0, &tx, 0) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_wallet_sign_tx_input(wallet, 0, &tx, 0) == ECLIPSE_SUCCESS);
    bool valid = false;
    CHECK(eclipse_tx_validate(&tx, state, &valid) == ECLIPSE_SUCCESS && valid);
    uint8_t applied_id[32];
    CHECK(eclipse_tx_apply(&tx, state, applied_id) == ECLIPSE_SUCCESS);
    eclipse_wallet_free(receive_only);
    eclipse_wallet_domain_free(receive);
    eclipse_wallet_recovery_free(root);
    eclipse_wallet_free(wallet);
    eclipse_utxo_set_free(state);
}

int main(void)
{
    check_transaction_roundtrip_and_state();
    check_other_schemes();
    check_two_input_signatures();
    check_wallet_spend_domain();
    puts("Developer transaction tests passed");
    return EXIT_SUCCESS;
}
