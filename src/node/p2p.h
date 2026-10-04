#ifndef ECLIPSE_NODE_P2P_H
#define ECLIPSE_NODE_P2P_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "block/chain.h"
#include "tx/mempool.h"

/* Static peer configuration for the developer network. An onion peer requires
 * a Tor SOCKS5 proxy; the P2P listener normally binds only to loopback and
 * Tor's HiddenServicePort forwards its virtual TCP port to that listener. */
typedef struct {
    bool listen_enabled;
    char listen_host[256];
    uint16_t listen_port;
    bool peer_enabled;
    char peer_host[256];
    uint16_t peer_port;
    bool socks_enabled;
    char socks_host[256];
    uint16_t socks_port;
} eclipse_p2p_config_t;

typedef struct eclipse_p2p eclipse_p2p_t;

/* chain and pool remain owned by the caller. Every access from P2P threads
 * takes state_lock; local node commands must use the same mutex. */
eclipse_error_t eclipse_p2p_start(const eclipse_p2p_config_t *config,
                                  eclipse_chain_t *chain,
                                  eclipse_mempool_t *pool,
                                  pthread_mutex_t *state_lock,
                                  atomic_bool *node_stopping,
                                  eclipse_p2p_t **out);
uint16_t eclipse_p2p_listen_port(const eclipse_p2p_t *p2p);
void eclipse_p2p_stop(eclipse_p2p_t *p2p);

#endif
