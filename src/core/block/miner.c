#include "miner.h"
#include "../log.h"

#include <string.h>

bool eclipse_pow_hash_meets_target(const uint8_t hash[32], uint32_t bits)
{
    if (hash == NULL || bits == 0 || bits > 256) return false;
    uint32_t whole = bits / 8;
    uint32_t rest = bits % 8;
    for (uint32_t i = 0; i < whole; ++i)
        if (hash[i] != 0) return false;
    if (rest != 0 && (hash[whole] >> (8 - rest)) != 0) return false;
    return true;
}

eclipse_error_t eclipse_miner_mine(eclipse_block_t *block,
                                   uint64_t max_attempts, bool *found)
{
    if (block == NULL || found == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *found = false;
    if (max_attempts == 0) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_block_header_t header;
    eclipse_error_t status = eclipse_block_header(block, &header);
    if (status != ECLIPSE_SUCCESS) return status;
    uint8_t root[32];
    status = eclipse_block_compute_root(block, root);
    if (status != ECLIPSE_SUCCESS) return status;
    if (header.version != ECLIPSE_BLOCK_VERSION ||
        header.difficulty != ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS ||
        memcmp(root, header.merkle_root, 32) != 0)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    uint64_t nonce = header.nonce;
    for (uint64_t remaining = max_attempts; remaining != 0; --remaining) {
        status = eclipse_block_set_nonce(block, nonce);
        if (status != ECLIPSE_SUCCESS) return status;
        uint8_t hash[32];
        status = eclipse_block_hash(block, hash);
        if (status != ECLIPSE_SUCCESS) return status;
        if (eclipse_pow_hash_meets_target(hash, header.difficulty)) {
            *found = true;
            ECLIPSE_LOG_INFO(2, "miner found dev block nonce=%llu",
                             (unsigned long long)nonce);
            return ECLIPSE_SUCCESS;
        }
        if (nonce == UINT64_MAX) break;
        ++nonce;
    }
    (void)eclipse_block_set_nonce(block, nonce);
    ECLIPSE_LOG_INFO(4, "miner exhausted nonce search range");
    return ECLIPSE_SUCCESS;
}
