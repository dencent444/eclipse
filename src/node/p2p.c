#define _POSIX_C_SOURCE 200809L

/* EPN1 is a deliberately small developer protocol. Sessions are short lived:
 * exchange handshakes, synchronize at most 128 canonical blocks in each
 * direction, then exchange pending transactions. Reconnects continue sync.
 * All bytes received here are untrusted until core validation succeeds. */
#include "p2p.h"

#include "log.h"
#include "net/tcp.h"

#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define P2P_VERSION 1u
#define P2P_HELLO_SIZE 96u
#define P2P_MAX_LOCATORS 32u
#define P2P_MAX_BLOCKS_PER_SESSION 128u
#define P2P_SESSION_SECONDS 20u
#define P2P_IO_TIMEOUT_MS 3000
#define P2P_CONNECT_TIMEOUT_MS 3000
#define P2P_RECONNECT_MS 2000

enum {
    P2P_HELLO = 1,
    P2P_LOCATORS = 2,
    P2P_BLOCK = 3,
    P2P_TRANSACTION = 4,
    P2P_END = 5,
};

struct eclipse_p2p {
    eclipse_p2p_config_t config;
    eclipse_chain_t *chain;
    eclipse_mempool_t *pool;
    pthread_mutex_t *state_lock;
    atomic_bool *node_stopping;
    atomic_bool shutdown;
    uint8_t instance_id[16];
    uint8_t download_cursor[32];
    uint64_t download_height;
    bool download_cursor_valid; /* Guarded by state_lock. */
    eclipse_tcp_socket_t *listener;
    uint16_t listen_port;
    pthread_t inbound_thread;
    pthread_t outbound_thread;
    bool inbound_started;
    bool outbound_started;
};

static bool stopping(const eclipse_p2p_t *p2p)
{
    return atomic_load(&p2p->shutdown) || atomic_load(p2p->node_stopping);
}

static void put_u32(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void put_u64(uint8_t out[8], uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)value;
        value >>= 8;
    }
}

static uint32_t get_u32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t get_u64(const uint8_t in[8])
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | in[i];
    return value;
}

static bool before_deadline(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return false;
    return now.tv_sec < deadline->tv_sec ||
           (now.tv_sec == deadline->tv_sec && now.tv_nsec <= deadline->tv_nsec);
}

static bool recv_exact(eclipse_tcp_socket_t *socket, uint8_t *out, size_t length,
                       const struct timespec *deadline)
{
    size_t at = 0;
    while (at < length && before_deadline(deadline)) {
        size_t count = 0;
        if (eclipse_tcp_recv(socket, out + at, length - at, &count) !=
            ECLIPSE_SUCCESS || count == 0) return false;
        at += count;
    }
    return at == length && before_deadline(deadline);
}

/* Frame: ASCII EPN1 | type:u8 | length:u32be | payload. Never allocate
 * according to a peer-supplied length: callers provide one fixed cap. */
static bool send_frame(eclipse_tcp_socket_t *socket, uint8_t type,
                       const uint8_t *data, size_t length,
                       const struct timespec *deadline)
{
    if (length > ECLIPSE_BLOCK_MAX_WIRE_SIZE || !before_deadline(deadline))
        return false;
    uint8_t header[9] = {'E', 'P', 'N', '1', type, 0, 0, 0, 0};
    put_u32(header + 5, (uint32_t)length);
    if (eclipse_tcp_send_all(socket, header, sizeof(header)) != ECLIPSE_SUCCESS)
        return false;
    return length == 0 || (data != NULL &&
        eclipse_tcp_send_all(socket, data, length) == ECLIPSE_SUCCESS &&
        before_deadline(deadline));
}

static bool recv_frame(eclipse_tcp_socket_t *socket, uint8_t *type,
                       uint8_t *data, size_t capacity, size_t *length,
                       const struct timespec *deadline)
{
    uint8_t header[9];
    if (!recv_exact(socket, header, sizeof(header), deadline) ||
        memcmp(header, "EPN1", 4) != 0) return false;
    uint32_t size = get_u32(header + 5);
    if (size > capacity) return false;
    if (size != 0 && !recv_exact(socket, data, size, deadline)) return false;
    *type = header[4];
    *length = size;
    return true;
}

static bool send_hello(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                       const struct timespec *deadline)
{
    uint8_t payload[P2P_HELLO_SIZE] = {0};
    put_u32(payload, P2P_VERSION);
    put_u32(payload + 4, ECLIPSE_TX_DEV_NETWORK_ID);
    if (eclipse_chain_genesis_hash(payload + 8) != ECLIPSE_SUCCESS)
        return false;
    uint64_t height = 0;
    pthread_mutex_lock(p2p->state_lock);
    eclipse_error_t status = eclipse_chain_tip(p2p->chain, payload + 48, &height);
    pthread_mutex_unlock(p2p->state_lock);
    if (status != ECLIPSE_SUCCESS) return false;
    put_u64(payload + 40, height);
    memcpy(payload + 80, p2p->instance_id, 16);
    return send_frame(socket, P2P_HELLO, payload, sizeof(payload), deadline);
}

static bool recv_hello(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                       uint8_t *buffer, const struct timespec *deadline)
{
    uint8_t type = 0;
    size_t length = 0;
    if (!recv_frame(socket, &type, buffer, ECLIPSE_BLOCK_MAX_WIRE_SIZE,
                    &length, deadline) || type != P2P_HELLO ||
        length != P2P_HELLO_SIZE || get_u32(buffer) != P2P_VERSION ||
        get_u32(buffer + 4) != ECLIPSE_TX_DEV_NETWORK_ID ||
        memcmp(buffer + 80, p2p->instance_id, 16) == 0)
        return false;
    uint8_t genesis[32];
    if (eclipse_chain_genesis_hash(genesis) != ECLIPSE_SUCCESS ||
        memcmp(buffer + 8, genesis, 32) != 0) return false;
    ECLIPSE_LOG_INFO(3, "P2P peer handshake accepted, advertised height=%llu",
                     (unsigned long long)get_u64(buffer + 40));
    return true;
}

/* Include nearby ancestors and exponentially older ones. A deep fork still
 * finds genesis, while a reconnect after a partial batch finds its new tip. */
static bool send_locators(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                          const struct timespec *deadline)
{
    uint8_t payload[1 + P2P_MAX_LOCATORS * 40] = {0};
    uint8_t tip[32];
    uint64_t height = 0, cursor = 0, step = 1;
    pthread_mutex_lock(p2p->state_lock);
    bool good = eclipse_chain_tip(p2p->chain, tip, &height) == ECLIPSE_SUCCESS;
    size_t prefix = 0;
    if (good && p2p->download_cursor_valid &&
        eclipse_chain_has_block(p2p->chain, p2p->download_cursor) &&
        memcmp(tip, p2p->download_cursor, 32) != 0) {
        put_u64(payload + 1, p2p->download_height);
        memcpy(payload + 9, p2p->download_cursor, 32);
        payload[0] = 1;
        prefix = 1;
    }
    cursor = height;
    size_t canonical_slots = P2P_MAX_LOCATORS - prefix;
    for (size_t i = 0; good && i < canonical_slots; ++i) {
        size_t at = 1 + (prefix + i) * 40;
        put_u64(payload + at, cursor);
        good = eclipse_chain_canonical_hash_at_height(
            p2p->chain, cursor, payload + at + 8) == ECLIPSE_SUCCESS;
        payload[0] = (uint8_t)(prefix + i + 1);
        if (cursor == 0) break;
        if (i == canonical_slots - 2) cursor = 0;
        else {
            if (i >= 7 && step <= UINT64_MAX / 2) step *= 2;
            cursor = step >= cursor ? 0 : cursor - step;
        }
    }
    pthread_mutex_unlock(p2p->state_lock);
    if (!good) return false;
    return send_frame(socket, P2P_LOCATORS, payload,
                      1u + (size_t)payload[0] * 40u, deadline);
}

static bool receive_locators(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                             uint8_t *buffer, const struct timespec *deadline,
                             uint64_t *common_height)
{
    uint8_t type = 0;
    size_t length = 0;
    if (!recv_frame(socket, &type, buffer, ECLIPSE_BLOCK_MAX_WIRE_SIZE,
                    &length, deadline) || type != P2P_LOCATORS ||
        length < 41 || buffer[0] == 0 || buffer[0] > P2P_MAX_LOCATORS ||
        length != 1u + (size_t)buffer[0] * 40u) return false;
    bool matched = false;
    pthread_mutex_lock(p2p->state_lock);
    for (size_t i = 0; i < buffer[0]; ++i) {
        const uint8_t *entry = buffer + 1 + i * 40;
        uint64_t height = get_u64(entry);
        uint8_t canonical[32];
        if (eclipse_chain_canonical_hash_at_height(p2p->chain, height,
                                                    canonical) == ECLIPSE_SUCCESS &&
            memcmp(canonical, entry + 8, 32) == 0) {
            *common_height = height;
            matched = true;
            break;
        }
    }
    pthread_mutex_unlock(p2p->state_lock);
    /* An honest locator always includes the fixed genesis anchor. */
    return matched;
}

static bool send_blocks(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                        uint64_t common_height, const struct timespec *deadline)
{
    uint8_t hashes[P2P_MAX_BLOCKS_PER_SESSION][32];
    size_t count = 0;
    uint8_t tip[32];
    uint64_t tip_height = 0;
    pthread_mutex_lock(p2p->state_lock);
    bool good = eclipse_chain_tip(p2p->chain, tip, &tip_height) == ECLIPSE_SUCCESS;
    if (good && common_height < tip_height) {
        uint64_t available = tip_height - common_height;
        count = available < P2P_MAX_BLOCKS_PER_SESSION ?
                (size_t)available : P2P_MAX_BLOCKS_PER_SESSION;
        for (size_t i = 0; good && i < count; ++i)
            good = eclipse_chain_canonical_hash_at_height(
                p2p->chain, common_height + 1 + i, hashes[i]) == ECLIPSE_SUCCESS;
    }
    pthread_mutex_unlock(p2p->state_lock);
    if (!good) return false;
    uint8_t *wire = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
    if (wire == NULL) return false;
    for (size_t i = 0; good && i < count && !stopping(p2p); ++i) {
        eclipse_block_t *block = NULL;
        pthread_mutex_lock(p2p->state_lock);
        eclipse_error_t status = eclipse_chain_get_block(p2p->chain, hashes[i],
                                                          &block);
        pthread_mutex_unlock(p2p->state_lock);
        size_t length = 0;
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_block_serialize(block, wire,
                                              ECLIPSE_BLOCK_MAX_WIRE_SIZE, &length);
        eclipse_block_free(block);
        good = status == ECLIPSE_SUCCESS &&
               send_frame(socket, P2P_BLOCK, wire, length, deadline);
    }
    free(wire);
    if (good && !stopping(p2p)) good = send_frame(socket, P2P_END, NULL, 0, deadline);
    if (good && count != 0)
        ECLIPSE_LOG_INFO(2, "P2P sent %zu canonical dev blocks", count);
    return good && !stopping(p2p);
}

static bool receive_blocks(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                           uint8_t *buffer, const struct timespec *deadline)
{
    size_t received = 0, accepted = 0;
    for (;;) {
        uint8_t type = 0;
        size_t length = 0;
        if (stopping(p2p) || !recv_frame(socket, &type, buffer,
            ECLIPSE_BLOCK_MAX_WIRE_SIZE, &length, deadline)) return false;
        if (type == P2P_END) {
            if (length != 0) return false;
            if (accepted != 0)
                ECLIPSE_LOG_INFO(1, "P2P accepted %zu independently validated blocks",
                                 accepted);
            return true;
        }
        if (type != P2P_BLOCK || length == 0 ||
            ++received > P2P_MAX_BLOCKS_PER_SESSION) return false;
        eclipse_block_t *block = NULL;
        if (eclipse_block_deserialize(buffer, length, &block) != ECLIPSE_SUCCESS)
            return false;
        uint8_t hash[32];
        eclipse_error_t status = eclipse_block_hash(block, hash);
        if (status != ECLIPSE_SUCCESS) { eclipse_block_free(block); return false; }
        pthread_mutex_lock(p2p->state_lock);
        if (!eclipse_chain_has_block(p2p->chain, hash)) {
            bool became_tip = false;
            status = eclipse_chain_accept(p2p->chain, block, &became_tip);
            if (status == ECLIPSE_SUCCESS && became_tip)
                status = eclipse_mempool_sync(p2p->pool, p2p->chain);
            if (status == ECLIPSE_SUCCESS) ++accepted;
        }
        if (status == ECLIPSE_SUCCESS) {
            status = eclipse_chain_block_height(p2p->chain, hash,
                                                &p2p->download_height);
            if (status == ECLIPSE_SUCCESS) {
                memcpy(p2p->download_cursor, hash, 32);
                p2p->download_cursor_valid = true;
            }
        }
        pthread_mutex_unlock(p2p->state_lock);
        eclipse_block_free(block);
        if (status != ECLIPSE_SUCCESS) {
            ECLIPSE_LOG_WARNING("P2P rejected invalid or unprocessable block");
            return false;
        }
    }
}

static bool send_transactions(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                              const struct timespec *deadline)
{
    uint8_t *wire = malloc(ECLIPSE_TX_MAX_WIRE_SIZE);
    eclipse_tx_t *tx = malloc(sizeof(*tx));
    if (wire == NULL || tx == NULL) { free(wire); free(tx); return false; }
    pthread_mutex_lock(p2p->state_lock);
    size_t count = eclipse_mempool_count(p2p->pool);
    pthread_mutex_unlock(p2p->state_lock);
    bool good = true;
    size_t sent = 0;
    for (size_t i = 0; good && i < count && !stopping(p2p); ++i) {
        pthread_mutex_lock(p2p->state_lock);
        eclipse_error_t status = eclipse_mempool_transaction(p2p->pool, i, tx);
        pthread_mutex_unlock(p2p->state_lock);
        if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) break; /* Pool changed. */
        size_t length = 0;
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_tx_serialize(tx, wire, ECLIPSE_TX_MAX_WIRE_SIZE,
                                           &length);
        good = status == ECLIPSE_SUCCESS &&
               send_frame(socket, P2P_TRANSACTION, wire, length, deadline);
        if (good) ++sent;
    }
    free(wire);
    free(tx);
    if (good && !stopping(p2p)) good = send_frame(socket, P2P_END, NULL, 0, deadline);
    if (good && sent != 0)
        ECLIPSE_LOG_INFO(3, "P2P relayed %zu pending transactions", sent);
    return good && !stopping(p2p);
}

static bool receive_transactions(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                                 uint8_t *buffer, const struct timespec *deadline)
{
    eclipse_tx_t *tx = malloc(sizeof(*tx));
    if (tx == NULL) return false;
    bool good = true;
    size_t received = 0, accepted = 0;
    for (;;) {
        uint8_t type = 0;
        size_t length = 0;
        if (stopping(p2p) || !recv_frame(socket, &type, buffer,
            ECLIPSE_TX_MAX_WIRE_SIZE, &length, deadline)) { good = false; break; }
        if (type == P2P_END) {
            good = length == 0;
            break;
        }
        if (type != P2P_TRANSACTION || length == 0 ||
            ++received > ECLIPSE_MEMPOOL_MAX_TRANSACTIONS ||
            eclipse_tx_deserialize(buffer, length, tx) != ECLIPSE_SUCCESS) {
            good = false;
            break;
        }
        bool admitted = false;
        pthread_mutex_lock(p2p->state_lock);
        eclipse_error_t status = eclipse_mempool_submit(p2p->pool, p2p->chain,
                                                         tx, &admitted);
        pthread_mutex_unlock(p2p->state_lock);
        if (status != ECLIPSE_SUCCESS) { good = false; break; }
        if (admitted) ++accepted;
    }
    free(tx);
    if (good && accepted != 0)
        ECLIPSE_LOG_INFO(2, "P2P admitted %zu independently validated transactions",
                         accepted);
    return good;
}

static bool session(eclipse_p2p_t *p2p, eclipse_tcp_socket_t *socket,
                    bool initiator)
{
    if (eclipse_tcp_set_timeout(socket, P2P_IO_TIMEOUT_MS) != ECLIPSE_SUCCESS)
        return false;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) return false;
    deadline.tv_sec += P2P_SESSION_SECONDS;
    uint8_t *buffer = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
    if (buffer == NULL) return false;
    bool good;
    uint64_t common = 0;
    if (initiator) {
        good = send_hello(p2p, socket, &deadline) &&
               recv_hello(p2p, socket, buffer, &deadline) &&
               send_locators(p2p, socket, &deadline) &&
               receive_blocks(p2p, socket, buffer, &deadline) &&
               receive_locators(p2p, socket, buffer, &deadline, &common) &&
               send_blocks(p2p, socket, common, &deadline) &&
               send_transactions(p2p, socket, &deadline) &&
               receive_transactions(p2p, socket, buffer, &deadline);
    } else {
        good = recv_hello(p2p, socket, buffer, &deadline) &&
               send_hello(p2p, socket, &deadline) &&
               receive_locators(p2p, socket, buffer, &deadline, &common) &&
               send_blocks(p2p, socket, common, &deadline) &&
               send_locators(p2p, socket, &deadline) &&
               receive_blocks(p2p, socket, buffer, &deadline) &&
               receive_transactions(p2p, socket, buffer, &deadline) &&
               send_transactions(p2p, socket, &deadline);
    }
    free(buffer);
    if (good) ECLIPSE_LOG_INFO(2, "P2P sync session completed");
    return good;
}

static bool onion_name(const char *host)
{
    size_t length = strlen(host);
    if (length != 0 && host[length - 1] == '.') --length;
    return length >= 6 && strncasecmp(host + length - 6, ".onion", 6) == 0;
}

/* SOCKS5 sends the onion hostname to Tor as a domain name. Passing it to the
 * ordinary DNS-based TCP connector would leak or fail name resolution. */
static eclipse_error_t connect_peer(eclipse_p2p_t *p2p,
                                    eclipse_tcp_socket_t **out)
{
    *out = NULL;
    if (!p2p->config.socks_enabled)
        return eclipse_tcp_connect(p2p->config.peer_host,
                                   p2p->config.peer_port,
                                   P2P_CONNECT_TIMEOUT_MS, out);
    eclipse_tcp_socket_t *proxy = NULL;
    eclipse_error_t status = eclipse_tcp_connect(p2p->config.socks_host,
        p2p->config.socks_port, P2P_CONNECT_TIMEOUT_MS, &proxy);
    if (status != ECLIPSE_SUCCESS) return status;
    if (eclipse_tcp_set_timeout(proxy, P2P_IO_TIMEOUT_MS) != ECLIPSE_SUCCESS)
        goto fail;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) goto fail;
    deadline.tv_sec += 10;
    const uint8_t greeting[] = {5, 1, 0};
    uint8_t answer[260];
    if (eclipse_tcp_send_all(proxy, greeting, sizeof(greeting)) !=
        ECLIPSE_SUCCESS || !recv_exact(proxy, answer, 2, &deadline) ||
        answer[0] != 5 || answer[1] != 0) goto fail;
    size_t host_length = strlen(p2p->config.peer_host);
    if (host_length == 0 || host_length > 255) goto fail;
    uint8_t request[4 + 1 + 255 + 2] = {5, 1, 0, 3};
    request[4] = (uint8_t)host_length;
    memcpy(request + 5, p2p->config.peer_host, host_length);
    request[5 + host_length] = (uint8_t)(p2p->config.peer_port >> 8);
    request[6 + host_length] = (uint8_t)p2p->config.peer_port;
    if (eclipse_tcp_send_all(proxy, request, 7 + host_length) !=
        ECLIPSE_SUCCESS || !recv_exact(proxy, answer, 4, &deadline) ||
        answer[0] != 5 || answer[1] != 0 || answer[2] != 0) goto fail;
    size_t address_length = 0;
    if (answer[3] == 1) address_length = 4;
    else if (answer[3] == 4) address_length = 16;
    else if (answer[3] == 3) {
        if (!recv_exact(proxy, answer, 1, &deadline)) goto fail;
        address_length = answer[0];
    } else goto fail;
    if (!recv_exact(proxy, answer, address_length + 2, &deadline)) goto fail;
    *out = proxy;
    ECLIPSE_LOG_INFO(2, "P2P outbound connection established through SOCKS5");
    return ECLIPSE_SUCCESS;
fail:
    eclipse_tcp_close(proxy);
    ECLIPSE_LOG_WARNING("P2P SOCKS5 connection failed");
    return ECLIPSE_ERROR_IO;
}

static void *inbound_worker(void *argument)
{
    eclipse_p2p_t *p2p = argument;
    while (!stopping(p2p)) {
        bool ready = false;
        if (eclipse_tcp_wait_readable(p2p->listener, 250, &ready) !=
            ECLIPSE_SUCCESS) break;
        if (!ready || stopping(p2p)) continue;
        eclipse_tcp_socket_t *peer = NULL;
        if (eclipse_tcp_accept(p2p->listener, &peer) != ECLIPSE_SUCCESS) continue;
        bool okay = session(p2p, peer, false);
        eclipse_tcp_close(peer);
        if (!okay && !stopping(p2p))
            ECLIPSE_LOG_WARNING("P2P inbound session rejected or interrupted");
    }
    return NULL;
}

static void reconnect_pause(eclipse_p2p_t *p2p)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
    for (int elapsed = 0; elapsed < P2P_RECONNECT_MS && !stopping(p2p);
         elapsed += 100)
        (void)nanosleep(&delay, NULL);
}

static void *outbound_worker(void *argument)
{
    eclipse_p2p_t *p2p = argument;
    while (!stopping(p2p)) {
        eclipse_tcp_socket_t *peer = NULL;
        eclipse_error_t status = connect_peer(p2p, &peer);
        if (status == ECLIPSE_SUCCESS) {
            bool okay = session(p2p, peer, true);
            eclipse_tcp_close(peer);
            if (!okay && !stopping(p2p))
                ECLIPSE_LOG_WARNING("P2P outbound session rejected or interrupted");
        }
        reconnect_pause(p2p);
    }
    return NULL;
}

eclipse_error_t eclipse_p2p_start(const eclipse_p2p_config_t *config,
                                  eclipse_chain_t *chain,
                                  eclipse_mempool_t *pool,
                                  pthread_mutex_t *state_lock,
                                  atomic_bool *node_stopping,
                                  eclipse_p2p_t **out)
{
    if (config == NULL || chain == NULL || pool == NULL || state_lock == NULL ||
        node_stopping == NULL || out == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (!config->listen_enabled && !config->peer_enabled)
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (config->listen_enabled && onion_name(config->listen_host)) {
        ECLIPSE_LOG_WARNING("P2P listener must bind a local address, not an onion name");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    if (config->peer_enabled &&
        (config->peer_port == 0 || config->peer_host[0] == '\0' ||
         (onion_name(config->peer_host) && !config->socks_enabled))) {
        ECLIPSE_LOG_WARNING("onion peer requires a configured SOCKS5 proxy");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    eclipse_p2p_t *p2p = calloc(1, sizeof(*p2p));
    if (p2p == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    p2p->config = *config;
    p2p->chain = chain;
    p2p->pool = pool;
    p2p->state_lock = state_lock;
    p2p->node_stopping = node_stopping;
    atomic_init(&p2p->shutdown, false);
    if (RAND_bytes(p2p->instance_id, sizeof(p2p->instance_id)) != 1) goto fail;
    if (eclipse_chain_last_accepted(chain, p2p->download_cursor,
                                    &p2p->download_height) == ECLIPSE_SUCCESS)
        p2p->download_cursor_valid = true;
    if (config->listen_enabled) {
        if (eclipse_tcp_listen(config->listen_host, config->listen_port, 8,
                               &p2p->listener) != ECLIPSE_SUCCESS ||
            eclipse_tcp_local_port(p2p->listener, &p2p->listen_port) !=
            ECLIPSE_SUCCESS) goto fail;
        if (pthread_create(&p2p->inbound_thread, NULL, inbound_worker, p2p) != 0)
            goto fail;
        p2p->inbound_started = true;
    }
    if (config->peer_enabled) {
        if (pthread_create(&p2p->outbound_thread, NULL, outbound_worker, p2p) != 0)
            goto fail;
        p2p->outbound_started = true;
    }
    *out = p2p;
    ECLIPSE_LOG_INFO(1, "P2P dev transport started, listen_port=%u",
                     (unsigned)p2p->listen_port);
    return ECLIPSE_SUCCESS;
fail:
    eclipse_p2p_stop(p2p);
    return ECLIPSE_ERROR_IO;
}

uint16_t eclipse_p2p_listen_port(const eclipse_p2p_t *p2p)
{
    return p2p == NULL ? 0 : p2p->listen_port;
}

void eclipse_p2p_stop(eclipse_p2p_t *p2p)
{
    if (p2p == NULL) return;
    atomic_store(&p2p->shutdown, true);
    if (p2p->outbound_started) (void)pthread_join(p2p->outbound_thread, NULL);
    if (p2p->inbound_started) (void)pthread_join(p2p->inbound_thread, NULL);
    eclipse_tcp_close(p2p->listener);
    free(p2p);
    ECLIPSE_LOG_INFO(1, "P2P dev transport stopped");
}
