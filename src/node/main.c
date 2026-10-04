#define _POSIX_C_SOURCE 200809L

/* Local developer node. Its Unix socket is control-only; P2P uses a separate
 * TCP listener. All chain and pool access shares one mutex with P2P workers. */
#include "p2p.h"
#include "block/chain.h"
#include "block/miner.h"
#include "log.h"
#include "tx/mempool.h"
#include "wallet/wallet.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define NODE_MAX_LINE (2u * ECLIPSE_BLOCK_MAX_WIRE_SIZE + 128u)
#define NODE_IO_TIMEOUT_SECONDS 5

typedef struct {
    eclipse_chain_t *chain;
    eclipse_mempool_t *pool;
    pthread_mutex_t state_lock;
    atomic_bool stopping;
    eclipse_p2p_t *p2p;
} node_t;

static volatile sig_atomic_t interrupted = 0;

static void on_signal(int number)
{
    (void)number;
    interrupted = 1;
}

static void print_usage(void)
{
    fputs("Usage:\n"
          "  eclipse-node run DATA_DIR [--log-level 0..5]\n"
          "      [--p2p-listen HOST PORT] [--peer HOST PORT]\n"
          "      [--tor-socks HOST PORT]\n"
          "  eclipse-node ctl DATA_DIR status|mempool|stop\n"
          "  eclipse-node ctl DATA_DIR mine PUBLIC_BASE92\n"
          "  eclipse-node ctl DATA_DIR submit-tx TX_HEX\n"
          "  eclipse-node ctl DATA_DIR submit-block BLOCK_HEX\n"
          "  eclipse-node ctl DATA_DIR get-block BLOCK_HASH_HEX\n"
          "  eclipse-node ctl DATA_DIR utxo TXID_HEX INDEX\n", stderr);
}

static bool paths_for(const char *directory, char *journal, size_t journal_size,
                      char *socket_path, size_t socket_size)
{
    if (directory == NULL || *directory == '\0') return false;
    int a = snprintf(journal, journal_size, "%s/chain.dat", directory);
    int b = snprintf(socket_path, socket_size, "%s/node.sock", directory);
    return a > 0 && (size_t)a < journal_size &&
           b > 0 && (size_t)b < socket_size;
}

/* The socket and journal live in a directory accessible only to its owner.
 * Reject symlinked directories so the displayed path is the actual location. */
static bool prepare_directory(const char *path)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
    struct stat info;
    return lstat(path, &info) == 0 && S_ISDIR(info.st_mode) &&
           info.st_uid == geteuid() && (info.st_mode & 077) == 0;
}

static int digit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static bool decode_hex(const char *text, uint8_t *out, size_t capacity,
                       size_t *length)
{
    size_t size = strlen(text);
    if ((size & 1u) != 0 || size / 2 > capacity) return false;
    for (size_t i = 0; i < size / 2; ++i) {
        int high = digit(text[2 * i]), low = digit(text[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = (uint8_t)((high << 4) | low);
    }
    *length = size / 2;
    return true;
}

static void encode_hex(const uint8_t *input, size_t length, char *out)
{
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        out[2 * i] = alphabet[input[i] >> 4];
        out[2 * i + 1] = alphabet[input[i] & 15];
    }
    out[2 * length] = '\0';
}

static bool parse_u32(const char *text, uint32_t *out)
{
    if (text == NULL || *text == '\0' || *text == '-') return false;
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value > UINT32_MAX) return false;
    *out = (uint32_t)value;
    return true;
}

/* A client may send a large block, but never an unbounded line. A read
 * timeout keeps one stalled local client from freezing the single-thread loop. */
static bool read_line(int fd, char *buffer, size_t capacity)
{
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t got = recv(fd, buffer + used, capacity - used - 1, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        for (ssize_t i = 0; i < got; ++i) {
            if (buffer[used + (size_t)i] == '\n') {
                if ((size_t)i + 1 != (size_t)got) return false;
                buffer[used + (size_t)i] = '\0';
                return memchr(buffer, '\0', used + (size_t)i) == NULL;
            }
        }
        used += (size_t)got;
    }
    return false;
}

static bool send_all(int fd, const char *data, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
#ifdef MSG_NOSIGNAL
        ssize_t count = send(fd, data + sent, length - sent, MSG_NOSIGNAL);
#else
        ssize_t count = send(fd, data + sent, length - sent, 0);
#endif
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        sent += (size_t)count;
    }
    return true;
}

static void set_timeout(int fd)
{
    struct timeval timeout = {.tv_sec = NODE_IO_TIMEOUT_SECONDS};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

/* Outputs are public consensus data; do not log supplied packets, wallet
 * material, or the control request. The response is one bounded line. */
static bool handle_command_locked(node_t *node, char *request, char *response,
                                  size_t capacity)
{
    char *command = strtok(request, " ");
    char *first = strtok(NULL, " ");
    char *second = strtok(NULL, " ");
    char *extra = strtok(NULL, " ");
    if (command == NULL || extra != NULL) goto usage;

    if (strcmp(command, "status") == 0 && first == NULL) {
        uint8_t tip[32];
        uint64_t height = 0;
        if (eclipse_chain_tip(node->chain, tip, &height) != ECLIPSE_SUCCESS)
            goto internal;
        char hex[65];
        encode_hex(tip, sizeof(tip), hex);
        (void)snprintf(response, capacity, "OK height=%" PRIu64
                       " tip=%s mempool=%zu p2p_port=%u\n", height, hex,
                       eclipse_mempool_count(node->pool),
                       (unsigned)eclipse_p2p_listen_port(node->p2p));
        ECLIPSE_LOG_INFO(3, "local node status read at height %" PRIu64, height);
        return true;
    }
    if (strcmp(command, "mempool") == 0 && first == NULL) {
        (void)snprintf(response, capacity, "OK count=%zu\n",
                       eclipse_mempool_count(node->pool));
        ECLIPSE_LOG_INFO(3, "local node mempool count read");
        return true;
    }
    if (strcmp(command, "stop") == 0 && first == NULL) {
        atomic_store(&node->stopping, true);
        (void)snprintf(response, capacity, "OK stopping\n");
        ECLIPSE_LOG_INFO(1, "local node shutdown requested");
        return true;
    }
    if (strcmp(command, "utxo") == 0 && first != NULL && second != NULL) {
        uint8_t id[32];
        size_t length = 0;
        uint32_t index = 0;
        if (!decode_hex(first, id, sizeof(id), &length) || length != 32 ||
            !parse_u32(second, &index)) goto usage;
        eclipse_tx_output_t output = {0};
        bool found = false;
        if (eclipse_chain_find_utxo(node->chain, id, index, &output, &found) !=
            ECLIPSE_SUCCESS) goto internal;
        if (!found) { (void)snprintf(response, capacity, "OK found=0\n"); return true; }
        char key[2 * ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE + 1];
        encode_hex(output.public_key, output.public_key_length, key);
        (void)snprintf(response, capacity,
                       "OK found=1 amount=%" PRIu64 " scheme=%u public_key=%s\n",
                       output.amount, (unsigned)output.scheme, key);
        ECLIPSE_LOG_INFO(3, "local node UTXO query completed");
        return true;
    }
    if (strcmp(command, "mine") == 0 && first != NULL && second == NULL) {
        eclipse_wallet_public_key_t key = {0};
        if (eclipse_wallet_public_from_base92(first, strlen(first), &key) !=
            ECLIPSE_SUCCESS || key.length > ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE) {
            (void)snprintf(response, capacity,
                           "ERR invalid_public_key: expected an EWPK Base92 packet\n");
            ECLIPSE_LOG_WARNING("local node rejected an invalid mining public key");
            return false;
        }
        eclipse_tx_output_t payout = {0};
        payout.scheme = key.scheme;
        payout.public_key_length = key.length;
        memcpy(payout.public_key, key.bytes, key.length);
        uint8_t parent[32];
        uint64_t height = 0, timestamp = 1;
        if (eclipse_chain_tip(node->chain, parent, &height) != ECLIPSE_SUCCESS)
            goto internal;
        if (height != 0) {
            eclipse_block_t *previous = NULL;
            eclipse_block_header_t header;
            eclipse_error_t status = eclipse_chain_get_block(node->chain, parent,
                                                              &previous);
            if (status == ECLIPSE_SUCCESS)
                status = eclipse_block_header(previous, &header);
            eclipse_block_free(previous);
            if (status != ECLIPSE_SUCCESS || header.timestamp == UINT64_MAX)
                goto internal;
            timestamp = header.timestamp + 1;
        }
        eclipse_block_t *candidate = NULL;
        eclipse_error_t status = eclipse_mempool_make_candidate(node->pool,
            node->chain, timestamp, &payout, &candidate);
        bool found = false, became_tip = false;
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_miner_mine(candidate, 100000, &found);
        if (status == ECLIPSE_SUCCESS && found)
            status = eclipse_chain_accept(node->chain, candidate, &became_tip);
        uint8_t reward_id[32], tip[32];
        if (status == ECLIPSE_SUCCESS && found)
            status = eclipse_block_reward_id(candidate, reward_id);
        if (status == ECLIPSE_SUCCESS && found)
            status = eclipse_chain_tip(node->chain, tip, &height);
        if (status == ECLIPSE_SUCCESS && found && became_tip)
            status = eclipse_mempool_sync(node->pool, node->chain);
        eclipse_block_free(candidate);
        if (status != ECLIPSE_SUCCESS || !found || !became_tip) goto internal;
        char hash_text[65], reward_text[65];
        encode_hex(tip, sizeof(tip), hash_text);
        encode_hex(reward_id, sizeof(reward_id), reward_text);
        (void)snprintf(response, capacity,
                       "OK height=%" PRIu64 " tip=%s reward_outpoint=%s:0\n",
                       height, hash_text, reward_text);
        ECLIPSE_LOG_INFO(1, "local node mined and committed a dev block at height %" PRIu64,
                         height);
        return true;
    }
    if (strcmp(command, "submit-tx") == 0 && first != NULL && second == NULL) {
        uint8_t *wire = malloc(ECLIPSE_TX_MAX_WIRE_SIZE);
        eclipse_tx_t *tx = malloc(sizeof(*tx));
        if (wire == NULL || tx == NULL) { free(wire); free(tx); goto internal; }
        size_t length = 0;
        if (!decode_hex(first, wire, ECLIPSE_TX_MAX_WIRE_SIZE, &length)) {
            free(wire); free(tx); goto usage;
        }
        eclipse_error_t status = eclipse_tx_deserialize(wire, length, tx);
        bool accepted = false;
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_mempool_submit(node->pool, node->chain, tx, &accepted);
        uint8_t id[32];
        if (status == ECLIPSE_SUCCESS && accepted)
            status = eclipse_tx_id(tx, id);
        free(wire);
        free(tx);
        if (status == ECLIPSE_ERROR_INVALID_ARGUMENT ||
            (status == ECLIPSE_SUCCESS && !accepted)) {
            (void)snprintf(response, capacity, "ERR rejected_transaction\n");
            return false;
        }
        if (status != ECLIPSE_SUCCESS) goto internal;
        char hex[65];
        encode_hex(id, sizeof(id), hex);
        (void)snprintf(response, capacity, "OK txid=%s mempool=%zu\n",
                       hex, eclipse_mempool_count(node->pool));
        ECLIPSE_LOG_INFO(2, "local node admitted a validated transaction");
        return true;
    }
    if (strcmp(command, "submit-block") == 0 && first != NULL && second == NULL) {
        uint8_t *wire = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
        if (wire == NULL) goto internal;
        size_t length = 0;
        if (!decode_hex(first, wire, ECLIPSE_BLOCK_MAX_WIRE_SIZE, &length)) {
            free(wire);
            goto usage;
        }
        eclipse_block_t *block = NULL;
        eclipse_error_t status = eclipse_block_deserialize(wire, length, &block);
        free(wire);
        bool became_tip = false;
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_chain_accept(node->chain, block, &became_tip);
        eclipse_block_free(block);
        if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) {
            (void)snprintf(response, capacity, "ERR rejected_block\n");
            return false;
        }
        if (status != ECLIPSE_SUCCESS) goto internal;
        if (became_tip && eclipse_mempool_sync(node->pool, node->chain) !=
            ECLIPSE_SUCCESS) goto internal;
        uint8_t tip[32];
        uint64_t height = 0;
        if (eclipse_chain_tip(node->chain, tip, &height) != ECLIPSE_SUCCESS)
            goto internal;
        char hex[65];
        encode_hex(tip, sizeof(tip), hex);
        (void)snprintf(response, capacity, "OK canonical=%u height=%" PRIu64
                       " tip=%s\n", became_tip ? 1u : 0u, height, hex);
        ECLIPSE_LOG_INFO(2, "local node accepted a validated block");
        return true;
    }
    if (strcmp(command, "get-block") == 0 && first != NULL && second == NULL) {
        uint8_t hash[32];
        size_t length = 0;
        if (!decode_hex(first, hash, sizeof(hash), &length) || length != 32)
            goto usage;
        eclipse_block_t *block = NULL;
        eclipse_error_t status = eclipse_chain_get_block(node->chain, hash, &block);
        if (status == ECLIPSE_ERROR_INVALID_ARGUMENT) {
            (void)snprintf(response, capacity, "ERR unknown_block\n");
            return false;
        }
        if (status != ECLIPSE_SUCCESS) goto internal;
        uint8_t *wire = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
        if (wire == NULL) { eclipse_block_free(block); goto internal; }
        status = eclipse_block_serialize(block, wire, ECLIPSE_BLOCK_MAX_WIRE_SIZE,
                                         &length);
        eclipse_block_free(block);
        if (status != ECLIPSE_SUCCESS || 2 * length + 5 > capacity) {
            free(wire);
            goto internal;
        }
        memcpy(response, "OK ", 3);
        encode_hex(wire, length, response + 3);
        response[3 + 2 * length] = '\n';
        response[4 + 2 * length] = '\0';
        free(wire);
        ECLIPSE_LOG_INFO(3, "local node returned a validated block packet");
        return true;
    }
usage:
    (void)snprintf(response, capacity, "ERR bad_request\n");
    ECLIPSE_LOG_WARNING("local node rejected malformed control request");
    return false;
internal:
    (void)snprintf(response, capacity, "ERR internal_failure\n");
    ECLIPSE_LOG_ERROR("local node command failed after validation");
    return false;
}

static bool handle_command(node_t *node, char *request, char *response,
                           size_t capacity)
{
    pthread_mutex_lock(&node->state_lock);
    bool good = handle_command_locked(node, request, response, capacity);
    pthread_mutex_unlock(&node->state_lock);
    return good;
}

static int run_node(const char *directory, const eclipse_p2p_config_t *p2p_config)
{
    umask(077);
    if (!prepare_directory(directory)) {
        fputs("Data directory must exist or be creatable, owned by this user, and mode 0700.\n", stderr);
        return EXIT_FAILURE;
    }
    char journal[4096], socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    if (!paths_for(directory, journal, sizeof(journal), socket_path,
                   sizeof(socket_path))) {
        fputs("Data directory path is too long.\n", stderr);
        return EXIT_FAILURE;
    }
    node_t node = {0};
    if (pthread_mutex_init(&node.state_lock, NULL) != 0) return EXIT_FAILURE;
    atomic_init(&node.stopping, false);
    eclipse_error_t status = eclipse_chain_open(journal, &node.chain);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_mempool_create(node.chain, &node.pool);
    if (status != ECLIPSE_SUCCESS) {
        ECLIPSE_LOG_ERROR("node startup failed while opening local state: %d", status);
        eclipse_chain_free(node.chain);
        (void)pthread_mutex_destroy(&node.state_lock);
        return EXIT_FAILURE;
    }

    /* Journal lock is held before replacing a stale socket. It prevents a
     * second process for this data directory from taking over the endpoint. */
    struct stat existing;
    if (lstat(socket_path, &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid != geteuid() ||
            unlink(socket_path) != 0) {
            ECLIPSE_LOG_ERROR("local control socket path is occupied");
            goto fail;
        }
    } else if (errno != ENOENT) goto fail;

    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) goto fail;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(socket_path, 0600) != 0 || listen(listener, 8) != 0) {
        ECLIPSE_LOG_ERROR("local control socket bind/listen failed: errno=%d", errno);
        close(listener);
        (void)unlink(socket_path);
        goto fail;
    }
    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)signal(SIGPIPE, SIG_IGN);
    char *request = malloc(NODE_MAX_LINE);
    char *response = malloc(NODE_MAX_LINE);
    if (request == NULL || response == NULL) {
        free(request); free(response);
        close(listener);
        (void)unlink(socket_path);
        goto fail;
    }
    if (p2p_config->listen_enabled || p2p_config->peer_enabled) {
        status = eclipse_p2p_start(p2p_config, node.chain, node.pool,
                                   &node.state_lock, &node.stopping, &node.p2p);
        if (status != ECLIPSE_SUCCESS) {
            ECLIPSE_LOG_ERROR("P2P startup failed: %d", status);
            free(request); free(response);
            close(listener);
            (void)unlink(socket_path);
            goto fail;
        }
    }
    ECLIPSE_LOG_INFO(1, "local developer node ready");
    bool loop_failed = false;
    while (!interrupted && !atomic_load(&node.stopping)) {
        struct pollfd watch = {.fd = listener, .events = POLLIN};
        int ready = poll(&watch, 1, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            ECLIPSE_LOG_ERROR("local node socket poll failed: errno=%d", errno);
            loop_failed = true;
            break;
        }
        if (ready == 0) continue;
        int client = accept(listener, NULL, NULL);
        if (client < 0 && errno == EINTR) continue;
        if (client < 0) {
            ECLIPSE_LOG_ERROR("local node socket accept failed: errno=%d", errno);
            loop_failed = true;
            break;
        }
        set_timeout(client);
        if (read_line(client, request, NODE_MAX_LINE)) {
            (void)handle_command(&node, request, response, NODE_MAX_LINE);
            (void)send_all(client, response, strlen(response));
        } else {
            ECLIPSE_LOG_WARNING("local node dropped oversized or incomplete request");
            (void)send_all(client, "ERR bad_request\n", 16);
        }
        close(client);
    }
    free(request);
    free(response);
    atomic_store(&node.stopping, true);
    eclipse_p2p_stop(node.p2p);
    close(listener);
    (void)unlink(socket_path);
    eclipse_mempool_free(node.pool);
    eclipse_chain_free(node.chain);
    (void)pthread_mutex_destroy(&node.state_lock);
    if (!loop_failed) ECLIPSE_LOG_INFO(1, "local developer node stopped cleanly");
    return loop_failed ? EXIT_FAILURE : EXIT_SUCCESS;
fail:
    atomic_store(&node.stopping, true);
    eclipse_p2p_stop(node.p2p);
    eclipse_mempool_free(node.pool);
    eclipse_chain_free(node.chain);
    (void)pthread_mutex_destroy(&node.state_lock);
    return EXIT_FAILURE;
}

static int run_client(const char *directory, int count, char **words)
{
    if (count < 1 || count > 3) { print_usage(); return EXIT_FAILURE; }
    char journal[4096], socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    if (!paths_for(directory, journal, sizeof(journal), socket_path,
                   sizeof(socket_path))) return EXIT_FAILURE;
    size_t length = 1;
    for (int i = 0; i < count; ++i) {
        size_t part = strlen(words[i]);
        if (part > NODE_MAX_LINE - length - 2) return EXIT_FAILURE;
        length += part + (i != 0 ? 1u : 0u);
    }
    char *line = malloc(NODE_MAX_LINE);
    if (line == NULL) return EXIT_FAILURE;
    size_t at = 0;
    for (int i = 0; i < count; ++i) {
        if (i != 0) line[at++] = ' ';
        size_t size = strlen(words[i]);
        memcpy(line + at, words[i], size);
        at += size;
    }
    line[at++] = '\n';
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { free(line); return EXIT_FAILURE; }
    set_timeout(fd);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        !send_all(fd, line, at)) {
        fputs("Cannot contact local node. Is it running?\n", stderr);
        close(fd); free(line); return EXIT_FAILURE;
    }
    free(line);
    char *answer = malloc(NODE_MAX_LINE);
    if (answer == NULL) { close(fd); return EXIT_FAILURE; }
    bool received = read_line(fd, answer, NODE_MAX_LINE);
    close(fd);
    if (!received) {
        fputs("Local node returned no complete response.\n", stderr);
        free(answer); return EXIT_FAILURE;
    }
    bool success = strncmp(answer, "OK ", 3) == 0;
    FILE *destination = success ? stdout : stderr;
    (void)fprintf(destination, "%s\n", answer);
    free(answer);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "run") == 0) {
        eclipse_p2p_config_t config = {0};
        for (int i = 3; i < argc;) {
            uint32_t number = 0;
            if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc &&
                parse_u32(argv[i + 1], &number) && number <= 5 &&
                eclipse_log_set_info_level(number) == ECLIPSE_SUCCESS) {
                i += 2;
                continue;
            }
            if (i + 2 < argc && parse_u32(argv[i + 2], &number) &&
                number <= UINT16_MAX) {
                if (strcmp(argv[i], "--p2p-listen") == 0 &&
                    strlen(argv[i + 1]) < sizeof(config.listen_host) &&
                    argv[i + 1][0] != '\0') {
                    config.listen_enabled = true;
                    memcpy(config.listen_host, argv[i + 1], strlen(argv[i + 1]) + 1);
                    config.listen_port = (uint16_t)number;
                    i += 3;
                    continue;
                }
                if (number != 0 && strcmp(argv[i], "--peer") == 0 &&
                    strlen(argv[i + 1]) < sizeof(config.peer_host) &&
                    argv[i + 1][0] != '\0') {
                    config.peer_enabled = true;
                    memcpy(config.peer_host, argv[i + 1], strlen(argv[i + 1]) + 1);
                    config.peer_port = (uint16_t)number;
                    i += 3;
                    continue;
                }
                if (number != 0 && strcmp(argv[i], "--tor-socks") == 0 &&
                    strlen(argv[i + 1]) < sizeof(config.socks_host) &&
                    argv[i + 1][0] != '\0') {
                    config.socks_enabled = true;
                    memcpy(config.socks_host, argv[i + 1], strlen(argv[i + 1]) + 1);
                    config.socks_port = (uint16_t)number;
                    i += 3;
                    continue;
                }
            }
            print_usage();
            return EXIT_FAILURE;
        }
        return run_node(argv[2], &config);
    }
    if (argc >= 4 && strcmp(argv[1], "ctl") == 0)
        return run_client(argv[2], argc - 3, argv + 3);
    print_usage();
    return EXIT_FAILURE;
}
