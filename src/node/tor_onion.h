#ifndef ECLIPSE_NODE_TOR_ONION_H
#define ECLIPSE_NODE_TOR_ONION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "error.h"

typedef struct {
    bool enabled;
    uint16_t control_port;
    uint16_t virtual_port;
    char cookie_path[4096];
} eclipse_tor_config_t;

typedef struct eclipse_tor_onion eclipse_tor_onion_t;

/* Registers a v3 onion service through the local Tor control port. The
 * controller connection stays open for the service lifetime. Its private key
 * is stored in the node's mode-0700 data directory, never in the chain. */
eclipse_error_t eclipse_tor_onion_start(const eclipse_tor_config_t *config,
                                        const char *data_dir,
                                        uint16_t target_port,
                                        atomic_bool *node_stopping,
                                        eclipse_tor_onion_t **out);
/* Returns "none", "offline", or the public .onion address. */
void eclipse_tor_onion_status(eclipse_tor_onion_t *onion, char *out,
                              size_t capacity);
void eclipse_tor_onion_stop(eclipse_tor_onion_t *onion);

#endif
