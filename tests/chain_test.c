#include "block/chain.h"
#include "block/miner.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static eclipse_ml_dsa_key_t *seeded_key(uint8_t first)
{
    uint8_t seed[32] = {0};
    seed[0] = first;
    eclipse_ml_dsa_key_t *key = NULL;
    CHECK(eclipse_ml_dsa_generate_from_seed(ECLIPSE_ML_DSA_44,
                                            seed, sizeof(seed), &key) ==
          ECLIPSE_SUCCESS);
    return key;
}

static eclipse_tx_output_t destination(const eclipse_ml_dsa_key_t *key)
{
    eclipse_tx_output_t out = {0};
    out.scheme = ECLIPSE_ML_DSA_44;
    out.public_key_length = 1312;
    CHECK(eclipse_ml_dsa_export_public(key, out.public_key,
                                        sizeof(out.public_key)) == ECLIPSE_SUCCESS);
    return out;
}

static void mine(eclipse_block_t *block)
{
    bool found = false;
    CHECK(eclipse_miner_mine(block, 100000, &found) == ECLIPSE_SUCCESS && found);
    uint8_t hash[32];
    CHECK(eclipse_block_hash(block, hash) == ECLIPSE_SUCCESS);
    CHECK(eclipse_pow_hash_meets_target(hash, ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS));
}

static eclipse_block_t *candidate(eclipse_chain_t *chain, const uint8_t parent[32],
                                  uint64_t time, const eclipse_tx_output_t *miner,
                                  const eclipse_tx_t *const *txs, size_t count)
{
    eclipse_block_t *block = NULL;
    CHECK(eclipse_chain_make_candidate(chain, parent, time, miner,
                                        txs, count, &block) == ECLIPSE_SUCCESS);
    CHECK(block != NULL);
    return block;
}

static void accept(eclipse_chain_t *chain, const eclipse_block_t *block)
{
    bool selected = false;
    CHECK(eclipse_chain_accept(chain, block, &selected) == ECLIPSE_SUCCESS);
}

static void assert_utxo(eclipse_chain_t *chain, const uint8_t id[32],
                        bool expected, uint64_t amount)
{
    eclipse_tx_output_t out = {0};
    bool found = !expected;
    CHECK(eclipse_chain_find_utxo(chain, id, 0, &out, &found) == ECLIPSE_SUCCESS);
    CHECK(found == expected);
    if (expected) CHECK(out.amount == amount);
}

static void hex32(const uint8_t bytes[32], char out[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 15];
    }
    out[64] = '\0';
}

int main(void)
{
    CHECK(eclipse_chain_subsidy(0) == 0);
    CHECK(eclipse_chain_subsidy(1) == ECLIPSE_DEV_INITIAL_SUBSIDY);
    CHECK(eclipse_chain_subsidy(ECLIPSE_DEV_HALVING_INTERVAL) ==
          ECLIPSE_DEV_INITIAL_SUBSIDY);
    CHECK(eclipse_chain_subsidy(ECLIPSE_DEV_HALVING_INTERVAL + 1) ==
          ECLIPSE_DEV_INITIAL_SUBSIDY / 2);
    CHECK(eclipse_chain_subsidy(UINT64_MAX) == 0);

    eclipse_ml_dsa_key_t *alice = seeded_key(1);
    eclipse_ml_dsa_key_t *bob = seeded_key(2);
    eclipse_ml_dsa_key_t *other = seeded_key(3);
    eclipse_tx_output_t alice_dest = destination(alice);
    eclipse_tx_output_t other_dest = destination(other);
    eclipse_chain_t *a = NULL, *b = NULL;
    CHECK(eclipse_chain_create(&a) == ECLIPSE_SUCCESS);
    CHECK(eclipse_chain_create(&b) == ECLIPSE_SUCCESS);
    uint8_t genesis[32], tip[32], block1_hash[32];
    uint64_t height;
    CHECK(eclipse_chain_genesis_hash(genesis) == ECLIPSE_SUCCESS);
    char fixed_hex[65];
    hex32(genesis, fixed_hex);
    CHECK(strcmp(fixed_hex,
          "b0d1787f93b82fbf52777889c17bb15fd52b241fcc2d05047d36b585b4faf20a") == 0);
    CHECK(eclipse_chain_tip(a, tip, &height) == ECLIPSE_SUCCESS);
    CHECK(height == 0 && memcmp(tip, genesis, 32) == 0);

    /* Genesis owns no output. Mining block one creates the first spendable
     * coin, and two independent nodes derive the same chain state. */
    uint8_t nonexistent[32] = {0};
    assert_utxo(a, nonexistent, false, 0);
    eclipse_block_t *rejected_candidate = NULL;
    CHECK(eclipse_chain_make_candidate(a, genesis, 0, &alice_dest, NULL, 0,
                                        &rejected_candidate) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_chain_make_candidate(a, genesis,
                                        ECLIPSE_DEV_MAX_BLOCK_TIME_STEP + 1,
                                        &alice_dest, NULL, 0,
                                        &rejected_candidate) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_chain_make_candidate(a, nonexistent, 1, &alice_dest, NULL, 0,
                                        &rejected_candidate) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    eclipse_block_t *one = candidate(a, genesis, 1, &alice_dest, NULL, 0);
    /* Independently computed with Python hashlib.sha3_256 and the fixed
     * ML-DSA-44 seed 01 || 00*31; locks reward leaf and header byte order. */
    eclipse_block_header_t first_header;
    CHECK(eclipse_block_header(one, &first_header) == ECLIPSE_SUCCESS);
    hex32(first_header.merkle_root, fixed_hex);
    CHECK(strcmp(fixed_hex,
          "f796ed7acf0a489adb15a2d567e6fbbad489b3a21aa78259037ad57fd2fd4648") == 0);
    CHECK(eclipse_block_hash(one, block1_hash) == ECLIPSE_SUCCESS);
    hex32(block1_hash, fixed_hex);
    CHECK(strcmp(fixed_hex,
          "661399fe4e59ce3ccc59357f972c531187152fdcd8d8eb168581e24149de6d29") == 0);
    mine(one);
    /* A correct body and reward still need the advertised PoW. */
    CHECK(eclipse_block_header(one, &first_header) == ECLIPSE_SUCCESS);
    uint64_t mined_nonce = first_header.nonce;
    uint64_t unmined_nonce = mined_nonce + 1;
    for (;;) {
        CHECK(eclipse_block_set_nonce(one, unmined_nonce) == ECLIPSE_SUCCESS);
        CHECK(eclipse_block_hash(one, block1_hash) == ECLIPSE_SUCCESS);
        if (!eclipse_pow_hash_meets_target(block1_hash,
                                            ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS))
            break;
        ++unmined_nonce;
    }
    CHECK(eclipse_chain_accept(a, one, &(bool){false}) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_block_set_nonce(one, mined_nonce) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_hash(one, block1_hash) == ECLIPSE_SUCCESS);
    uint8_t reward1[32];
    CHECK(eclipse_block_reward_id(one, reward1) == ECLIPSE_SUCCESS);
    uint8_t *wire = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE + 1);
    CHECK(wire != NULL);
    size_t wire_length = 0;
    CHECK(eclipse_block_serialize(one, wire, ECLIPSE_BLOCK_MAX_WIRE_SIZE,
                                  &wire_length) == ECLIPSE_SUCCESS);
    eclipse_block_t *decoded = NULL;
    CHECK(eclipse_block_deserialize(wire, wire_length, &decoded) == ECLIPSE_SUCCESS);
    accept(a, one);
    accept(b, decoded);
    CHECK(eclipse_chain_tip(a, tip, &height) == ECLIPSE_SUCCESS);
    CHECK(height == 1 && memcmp(tip, block1_hash, 32) == 0);
    assert_utxo(a, reward1, true, ECLIPSE_DEV_INITIAL_SUBSIDY);
    assert_utxo(b, reward1, true, ECLIPSE_DEV_INITIAL_SUBSIDY);
    CHECK(eclipse_chain_accept(a, one, &(bool){false}) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    eclipse_block_t *scratch = NULL;
    CHECK(eclipse_block_deserialize(wire, wire_length - 1, &scratch) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[wire_length] = 0;
    CHECK(eclipse_block_deserialize(wire, wire_length + 1, &scratch) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    wire[4 + ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE + 1] ^= 1;
    CHECK(eclipse_block_deserialize(wire, wire_length, &scratch) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    free(wire);

    /* A signed spend moves value, and its fee is paid exactly once to the
     * miner in the containing block. The reward cannot be spent inside one. */
    eclipse_tx_t spend;
    CHECK(eclipse_tx_init(&spend) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&spend, reward1, 0) == ECLIPSE_SUCCESS);
    eclipse_tx_output_t bob_dest = destination(bob);
    CHECK(eclipse_tx_add_output(&spend, ECLIPSE_DEV_INITIAL_SUBSIDY - 7,
                                bob_dest.scheme, bob_dest.public_key,
                                bob_dest.public_key_length) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_set_fee(&spend, 7) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_sign_input(&spend, 0, alice) == ECLIPSE_SUCCESS);
    const eclipse_tx_t *txs[] = {&spend};
    eclipse_block_t *two = candidate(a, block1_hash, 2, &alice_dest, txs, 1);
    eclipse_tx_output_t reward_output;
    CHECK(eclipse_block_reward(two, &reward_output) == ECLIPSE_SUCCESS);
    CHECK(reward_output.amount == ECLIPSE_DEV_INITIAL_SUBSIDY + 7);
    mine(two);
    uint8_t spend_id[32], reward2[32];
    CHECK(eclipse_tx_id(&spend, spend_id) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_reward_id(two, reward2) == ECLIPSE_SUCCESS);
    accept(a, two);
    accept(b, two);
    assert_utxo(a, reward1, false, 0);
    assert_utxo(a, spend_id, true, ECLIPSE_DEV_INITIAL_SUBSIDY - 7);
    assert_utxo(a, reward2, true, ECLIPSE_DEV_INITIAL_SUBSIDY + 7);

    /* A block with a valid PoW and an overpaid reward still fails consensus. */
    eclipse_tx_output_t inflated = alice_dest;
    inflated.amount = ECLIPSE_DEV_INITIAL_SUBSIDY + 1;
    eclipse_block_t *bad = NULL;
    CHECK(eclipse_block_create(block1_hash, 3, &inflated, &bad) == ECLIPSE_SUCCESS);
    mine(bad);
    CHECK(eclipse_chain_accept(a, bad, &(bool){false}) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    eclipse_block_free(bad);
    eclipse_tx_t forged = spend;
    forged.inputs[0].signature[0] ^= 1;
    eclipse_tx_output_t fee_claim = alice_dest;
    fee_claim.amount = ECLIPSE_DEV_INITIAL_SUBSIDY + 7;
    CHECK(eclipse_block_create(block1_hash, 3, &fee_claim, &bad) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_add_transaction(bad, &forged) == ECLIPSE_SUCCESS);
    mine(bad);
    CHECK(eclipse_chain_accept(a, bad, &(bool){false}) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    eclipse_block_free(bad);

    /* Competing second blocks are accepted in opposite orders. Deterministic
     * equal-work tie breaking gives both nodes the same tip. A third block on
     * the alternate branch then reorganizes away Bob's transaction. */
    eclipse_block_t *side = candidate(a, block1_hash, 3, &other_dest, NULL, 0);
    mine(side);
    accept(a, side);
    eclipse_chain_t *c = NULL;
    CHECK(eclipse_chain_create(&c) == ECLIPSE_SUCCESS);
    accept(c, one);
    accept(c, side);
    accept(c, two);
    uint8_t a_tip[32], c_tip[32], side_hash[32];
    CHECK(eclipse_chain_tip(a, a_tip, &height) == ECLIPSE_SUCCESS && height == 2);
    CHECK(eclipse_chain_tip(c, c_tip, &height) == ECLIPSE_SUCCESS && height == 2);
    CHECK(memcmp(a_tip, c_tip, 32) == 0);
    CHECK(eclipse_block_hash(side, side_hash) == ECLIPSE_SUCCESS);
    eclipse_block_t *side3 = candidate(a, side_hash, 4, &other_dest, NULL, 0);
    mine(side3);
    accept(a, side3);
    accept(b, side);
    accept(b, side3);
    accept(c, side3);
    uint8_t final_hash[32];
    CHECK(eclipse_block_hash(side3, final_hash) == ECLIPSE_SUCCESS);
    CHECK(eclipse_chain_tip(a, tip, &height) == ECLIPSE_SUCCESS && height == 3 &&
          memcmp(tip, final_hash, 32) == 0);
    CHECK(eclipse_chain_tip(b, tip, &height) == ECLIPSE_SUCCESS &&
          memcmp(tip, final_hash, 32) == 0);
    assert_utxo(a, reward1, true, ECLIPSE_DEV_INITIAL_SUBSIDY);
    assert_utxo(a, spend_id, false, 0);
    assert_utxo(b, spend_id, false, 0);
    uint8_t side_reward[32];
    CHECK(eclipse_block_reward_id(side, side_reward) == ECLIPSE_SUCCESS);
    assert_utxo(a, side_reward, true, ECLIPSE_DEV_INITIAL_SUBSIDY);

    eclipse_block_t *retrieved = NULL;
    CHECK(eclipse_chain_get_block(a, final_hash, &retrieved) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_hash(retrieved, tip) == ECLIPSE_SUCCESS &&
          memcmp(tip, final_hash, 32) == 0);
    eclipse_block_free(retrieved);
    eclipse_block_free(side3);
    eclipse_block_free(side);
    eclipse_block_free(two);
    eclipse_block_free(one);
    eclipse_block_free(decoded);
    eclipse_chain_free(a);
    eclipse_chain_free(b);
    eclipse_chain_free(c);
    eclipse_ml_dsa_key_free(alice);
    eclipse_ml_dsa_key_free(bob);
    eclipse_ml_dsa_key_free(other);
    puts("chain_test: OK");
    return EXIT_SUCCESS;
}
