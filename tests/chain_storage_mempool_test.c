#define _POSIX_C_SOURCE 200809L
#include "block/chain.h"
#include "block/miner.h"
#include "tx/mempool.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static eclipse_ml_dsa_key_t *key(uint8_t first)
{
    uint8_t seed[32] = {0};
    seed[0] = first;
    eclipse_ml_dsa_key_t *result = NULL;
    CHECK(eclipse_ml_dsa_generate_from_seed(ECLIPSE_ML_DSA_44,
                                            seed, sizeof(seed), &result) ==
          ECLIPSE_SUCCESS);
    return result;
}

static eclipse_tx_output_t destination(const eclipse_ml_dsa_key_t *keypair)
{
    eclipse_tx_output_t out = {0};
    out.scheme = ECLIPSE_ML_DSA_44;
    out.public_key_length = 1312;
    CHECK(eclipse_ml_dsa_export_public(keypair, out.public_key,
                                        sizeof(out.public_key)) == ECLIPSE_SUCCESS);
    return out;
}

static eclipse_block_t *candidate(eclipse_chain_t *chain, const uint8_t parent[32],
    uint64_t timestamp, const eclipse_tx_output_t *destination,
    const eclipse_tx_t *const *txs, size_t count)
{
    eclipse_block_t *block = NULL;
    CHECK(eclipse_chain_make_candidate(chain, parent, timestamp, destination,
                                        txs, count, &block) == ECLIPSE_SUCCESS);
    return block;
}

static void mine_accept(eclipse_chain_t *chain, eclipse_block_t *block)
{
    bool found = false, selected = false;
    CHECK(eclipse_miner_mine(block, 100000, &found) == ECLIPSE_SUCCESS && found);
    CHECK(eclipse_chain_accept(chain, block, &selected) == ECLIPSE_SUCCESS);
}

static void check_output(eclipse_chain_t *chain, const uint8_t id[32],
                         bool expected, uint64_t amount)
{
    eclipse_tx_output_t output = {0};
    bool found = !expected;
    CHECK(eclipse_chain_find_utxo(chain, id, 0, &output, &found) == ECLIPSE_SUCCESS);
    CHECK(found == expected);
    if (expected) CHECK(output.amount == amount);
}

int main(void)
{
    char path[] = "eclipse-chain-test-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    eclipse_ml_dsa_key_t *alice = key(11), *bob = key(12), *carol = key(13);
    eclipse_tx_output_t alice_dest = destination(alice);
    eclipse_tx_output_t bob_dest = destination(bob);
    eclipse_tx_output_t carol_dest = destination(carol);
    eclipse_chain_t *chain = NULL, *second_writer = NULL;
    CHECK(eclipse_chain_open(path, &chain) == ECLIPSE_SUCCESS);
    CHECK(eclipse_chain_open(path, &second_writer) == ECLIPSE_ERROR_IO);
    CHECK(second_writer == NULL);
    uint8_t genesis[32], first_hash[32], first_reward[32];
    uint64_t height = 0;
    CHECK(eclipse_chain_tip(chain, genesis, &height) == ECLIPSE_SUCCESS && height == 0);
    eclipse_block_t *first = candidate(chain, genesis, 1, &alice_dest, NULL, 0);
    mine_accept(chain, first);
    CHECK(eclipse_block_hash(first, first_hash) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_reward_id(first, first_reward) == ECLIPSE_SUCCESS);
    eclipse_mempool_t *pool = NULL;
    CHECK(eclipse_mempool_create(chain, &pool) == ECLIPSE_SUCCESS);

    /* Parent and child can coexist in the volatile pool. Exact tx bytes and
     * signatures are validated against the tip plus earlier pending spends. */
    eclipse_tx_t to_bob, to_carol, conflict;
    CHECK(eclipse_tx_init(&to_bob) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&to_bob, first_reward, 0) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_output(&to_bob, ECLIPSE_DEV_INITIAL_SUBSIDY - 2,
                                bob_dest.scheme, bob_dest.public_key,
                                bob_dest.public_key_length) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_set_fee(&to_bob, 2) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_sign_input(&to_bob, 0, alice) == ECLIPSE_SUCCESS);
    uint8_t bob_id[32], carol_id[32];
    CHECK(eclipse_tx_id(&to_bob, bob_id) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_init(&to_carol) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_input(&to_carol, bob_id, 0) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_add_output(&to_carol, ECLIPSE_DEV_INITIAL_SUBSIDY - 3,
                                carol_dest.scheme, carol_dest.public_key,
                                carol_dest.public_key_length) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_set_fee(&to_carol, 1) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_sign_input(&to_carol, 0, bob) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tx_id(&to_carol, carol_id) == ECLIPSE_SUCCESS);
    bool accepted = false;
    CHECK(eclipse_mempool_submit(pool, chain, &to_carol, &accepted) ==
          ECLIPSE_SUCCESS && !accepted); /* Parent not present yet. */
    CHECK(eclipse_mempool_submit(pool, chain, &to_bob, &accepted) ==
          ECLIPSE_SUCCESS && accepted);
    CHECK(eclipse_mempool_submit(pool, chain, &to_bob, &accepted) ==
          ECLIPSE_SUCCESS && !accepted);
    CHECK(eclipse_mempool_submit(pool, chain, &to_carol, &accepted) ==
          ECLIPSE_SUCCESS && accepted);
    CHECK(eclipse_mempool_count(pool) == 2);
    conflict = to_bob;
    conflict.outputs[0].amount--;
    conflict.fee++;
    CHECK(eclipse_tx_sign_input(&conflict, 0, alice) == ECLIPSE_SUCCESS);
    CHECK(eclipse_mempool_submit(pool, chain, &conflict, &accepted) ==
          ECLIPSE_SUCCESS && !accepted); /* Same confirmed input reserved. */
    eclipse_tx_t forged = to_bob;
    forged.inputs[0].signature[0] ^= 1;
    CHECK(eclipse_mempool_submit(pool, chain, &forged, &accepted) ==
          ECLIPSE_SUCCESS && !accepted);

    eclipse_block_t *second = NULL;
    CHECK(eclipse_mempool_make_candidate(pool, chain, 2, &alice_dest, &second) ==
          ECLIPSE_SUCCESS);
    CHECK(eclipse_block_transaction_count(second) == 2);
    eclipse_tx_output_t payout;
    CHECK(eclipse_block_reward(second, &payout) == ECLIPSE_SUCCESS);
    CHECK(payout.amount == ECLIPSE_DEV_INITIAL_SUBSIDY + 3);
    mine_accept(chain, second);
    CHECK(eclipse_mempool_sync(pool, chain) == ECLIPSE_SUCCESS);
    CHECK(eclipse_mempool_count(pool) == 0);
    check_output(chain, carol_id, true, ECLIPSE_DEV_INITIAL_SUBSIDY - 3);

    /* A longer alternate branch restores both disconnected transactions in
     * parent-before-child order, then a conflicting spend removes both. */
    eclipse_block_t *side2 = candidate(chain, first_hash, 3,
                                        &bob_dest, NULL, 0);
    mine_accept(chain, side2);
    uint8_t side2_hash[32];
    CHECK(eclipse_block_hash(side2, side2_hash) == ECLIPSE_SUCCESS);
    eclipse_block_t *side3 = candidate(chain, side2_hash, 4,
                                        &bob_dest, NULL, 0);
    mine_accept(chain, side3);
    CHECK(eclipse_mempool_sync(pool, chain) == ECLIPSE_SUCCESS);
    CHECK(eclipse_mempool_count(pool) == 2);
    check_output(chain, carol_id, false, 0);
    check_output(chain, first_reward, true, ECLIPSE_DEV_INITIAL_SUBSIDY);
    eclipse_block_t *restored_candidate = NULL;
    CHECK(eclipse_mempool_make_candidate(pool, chain, 5, &alice_dest,
                                         &restored_candidate) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_transaction_count(restored_candidate) == 2);
    eclipse_block_free(restored_candidate);

    uint8_t side3_hash[32];
    CHECK(eclipse_block_hash(side3, side3_hash) == ECLIPSE_SUCCESS);
    const eclipse_tx_t *conflict_tx[] = {&conflict};
    eclipse_block_t *side4 = candidate(chain, side3_hash, 5,
                                        &bob_dest, conflict_tx, 1);
    mine_accept(chain, side4);
    CHECK(eclipse_mempool_sync(pool, chain) == ECLIPSE_SUCCESS);
    CHECK(eclipse_mempool_count(pool) == 0);
    uint8_t final_hash[32];
    CHECK(eclipse_block_hash(side4, final_hash) == ECLIPSE_SUCCESS);
    CHECK(eclipse_chain_tip(chain, side3_hash, &height) == ECLIPSE_SUCCESS &&
          height == 4 && memcmp(side3_hash, final_hash, 32) == 0);

    eclipse_mempool_free(pool);
    eclipse_block_free(side4);
    eclipse_block_free(side3);
    eclipse_block_free(side2);
    eclipse_block_free(second);
    eclipse_block_free(first);
    eclipse_chain_free(chain);

    /* Reopening validates all branch records and reconstructs the same tip.
     * An incomplete final append is discarded, while complete corruption is
     * an error and cannot silently become a different chain. */
    struct stat original;
    CHECK(stat(path, &original) == 0);
    CHECK(eclipse_chain_open(path, &chain) == ECLIPSE_SUCCESS);
    uint8_t reopened_tip[32];
    CHECK(eclipse_chain_tip(chain, reopened_tip, &height) == ECLIPSE_SUCCESS &&
          height == 4 && memcmp(reopened_tip, final_hash, 32) == 0);
    check_output(chain, carol_id, false, 0);
    eclipse_block_t *side_copy = NULL;
    CHECK(eclipse_chain_get_block(chain, first_hash, &side_copy) == ECLIPSE_SUCCESS);
    eclipse_block_free(side_copy);
    CHECK(eclipse_mempool_create(chain, &pool) == ECLIPSE_SUCCESS);
    CHECK(eclipse_mempool_count(pool) == 0); /* Pool is intentionally volatile. */
    eclipse_mempool_free(pool);
    eclipse_chain_free(chain);

    fd = open(path, O_WRONLY | O_APPEND);
    CHECK(fd >= 0);
    const uint8_t torn_prefix[3] = {0, 0, 0};
    CHECK(write(fd, torn_prefix, sizeof(torn_prefix)) ==
          (ssize_t)sizeof(torn_prefix));
    CHECK(close(fd) == 0);
    CHECK(eclipse_chain_open(path, &chain) == ECLIPSE_SUCCESS);
    eclipse_chain_free(chain);
    struct stat recovered;
    CHECK(stat(path, &recovered) == 0 && recovered.st_size == original.st_size);

    fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    uint8_t original_byte;
    CHECK(pread(fd, &original_byte, 1, 50) == 1);
    uint8_t damaged = original_byte ^ 1;
    CHECK(pwrite(fd, &damaged, 1, 50) == 1);
    CHECK(close(fd) == 0);
    CHECK(eclipse_chain_open(path, &chain) == ECLIPSE_ERROR_IO);
    CHECK(chain == NULL);
    fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    CHECK(pwrite(fd, &original_byte, 1, 50) == 1);
    CHECK(close(fd) == 0);
    CHECK(eclipse_chain_open(path, &chain) == ECLIPSE_SUCCESS);
    eclipse_chain_free(chain);
    CHECK(unlink(path) == 0);
    eclipse_ml_dsa_key_free(alice);
    eclipse_ml_dsa_key_free(bob);
    eclipse_ml_dsa_key_free(carol);
    puts("chain_storage_mempool_test: OK");
    return EXIT_SUCCESS;
}
