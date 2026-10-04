#ifndef ECLIPSE_BLOCK_CHAIN_STORE_H
#define ECLIPSE_BLOCK_CHAIN_STORE_H

#include <stdbool.h>
#include <stdint.h>
#include "block.h"

/* Private append-only journal. Its checksum detects torn/corrupt records;
 * chain replay still performs full consensus validation. */
typedef struct eclipse_chain_store eclipse_chain_store_t;
eclipse_error_t eclipse_chain_store_open(const char *path,
    const uint8_t genesis[32], eclipse_chain_store_t **out);
void eclipse_chain_store_close(eclipse_chain_store_t *store);
eclipse_error_t eclipse_chain_store_next(eclipse_chain_store_t *store,
    eclipse_block_t **out, bool *end);
eclipse_error_t eclipse_chain_store_append(eclipse_chain_store_t *store,
    const eclipse_block_t *block);

#endif
