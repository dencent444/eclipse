#define _POSIX_C_SOURCE 200809L

/* Tor control client for an ephemeral v3 onion service. "Ephemeral" describes
 * Tor's control-connection lifetime; we persist its key to retain the address.
 * Only the loopback control port is used, with mutual SAFECOOKIE validation. */
#include "tor_onion.h"

#include "log.h"
#include "net/tcp.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define TOR_LINE_MAX 512u
#define TOR_KEY_MAX 160u
#define TOR_IO_TIMEOUT_MS 3000

struct eclipse_tor_onion {
    eclipse_tor_config_t config;
    char key_path[4096];
    uint16_t target_port;
    atomic_bool *node_stopping;
    atomic_bool shutdown;
    pthread_t worker;
    bool worker_started;
    pthread_mutex_t status_lock;
    char address[64];
    bool active;
    eclipse_tcp_socket_t *control; /* Owned by the worker after startup. */
};

static bool stopped(const eclipse_tor_onion_t *onion)
{
    return atomic_load(&onion->shutdown) || atomic_load(onion->node_stopping);
}

static void hex_encode(const uint8_t *bytes, size_t count, char *out)
{
    static const char digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < count; ++i) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 15];
    }
    out[2 * count] = '\0';
}

static int hex_digit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static bool hex_decode_32(const char *text, uint8_t out[32])
{
    if (strlen(text) != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        int a = hex_digit(text[2 * i]), b = hex_digit(text[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return true;
}

/* Read exactly one bounded CRLF line. Byte-at-a-time keeps a later Tor reply
 * on the socket instead of accidentally consuming multiple control messages. */
static bool read_line(eclipse_tcp_socket_t *socket, char out[TOR_LINE_MAX])
{
    for (size_t i = 0; i < TOR_LINE_MAX - 1; ++i) {
        uint8_t byte = 0;
        size_t got = 0;
        if (eclipse_tcp_recv(socket, &byte, 1, &got) != ECLIPSE_SUCCESS ||
            got != 1) return false;
        if (byte == '\n') {
            if (i == 0 || out[i - 1] != '\r') return false;
            out[i - 1] = '\0';
            return true;
        }
        if (byte == 0 || byte > 0x7e || (byte < 0x20 && byte != '\r'))
            return false;
        out[i] = (char)byte;
    }
    return false;
}

static bool send_command(eclipse_tcp_socket_t *socket, const char *command)
{
    return eclipse_tcp_send_all(socket, (const uint8_t *)command,
                                strlen(command)) == ECLIPSE_SUCCESS;
}

static bool read_ok(eclipse_tcp_socket_t *socket)
{
    char line[TOR_LINE_MAX];
    return read_line(socket, line) && strcmp(line, "250 OK") == 0;
}

/* Reject a substituted cookie path and malformed contents. SAFECOOKIE does
 * not transmit the cookie itself, but its secrecy still matters. */
static bool read_cookie(const char *path, uint8_t cookie[32])
{
    int flags = O_RDONLY;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags);
    if (fd < 0) return false;
    struct stat info;
    bool good = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                info.st_size == 32 && (info.st_mode & 0007) == 0;
    size_t at = 0;
    while (good && at < 32) {
        ssize_t count = read(fd, cookie + at, 32 - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { good = false; break; }
        at += (size_t)count;
    }
    close(fd);
    if (!good) OPENSSL_cleanse(cookie, 32);
    return good;
}

static bool mac(const char *label, const uint8_t material[96], uint8_t out[32])
{
    unsigned int count = 0;
    return HMAC(EVP_sha256(), label, (int)strlen(label), material, 96,
                out, &count) != NULL && count == 32;
}

static bool authenticate(eclipse_tcp_socket_t *socket, const char *cookie_path)
{
    static const char server_label[] =
        "Tor safe cookie authentication server-to-controller hash";
    static const char client_label[] =
        "Tor safe cookie authentication controller-to-server hash";
    uint8_t material[96] = {0}, expected[32] = {0}, actual[32] = {0};
    char nonce_hex[65], command[128], line[TOR_LINE_MAX];
    bool good = read_cookie(cookie_path, material) &&
                RAND_bytes(material + 32, 32) == 1;
    if (!good) goto done;
    hex_encode(material + 32, 32, nonce_hex);
    (void)snprintf(command, sizeof(command), "AUTHCHALLENGE SAFECOOKIE %s\r\n",
                   nonce_hex);
    if (!send_command(socket, command) || !read_line(socket, line)) {
        good = false;
        goto done;
    }
    const char *prefix = "250 AUTHCHALLENGE SERVERHASH=";
    const char *separator = " SERVERNONCE=";
    if (strncmp(line, prefix, strlen(prefix)) != 0) { good = false; goto done; }
    char *nonce = strstr(line + strlen(prefix), separator);
    if (nonce == NULL) { good = false; goto done; }
    *nonce = '\0';
    nonce += strlen(separator);
    if (!hex_decode_32(line + strlen(prefix), actual) ||
        !hex_decode_32(nonce, material + 64) ||
        !mac(server_label, material, expected) ||
        CRYPTO_memcmp(expected, actual, 32) != 0 ||
        !mac(client_label, material, expected)) { good = false; goto done; }
    hex_encode(expected, 32, nonce_hex);
    (void)snprintf(command, sizeof(command), "AUTHENTICATE %s\r\n", nonce_hex);
    good = send_command(socket, command) && read_ok(socket);
done:
    OPENSSL_cleanse(material, sizeof(material));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(nonce_hex, sizeof(nonce_hex));
    OPENSSL_cleanse(command, sizeof(command));
    return good;
}

static bool valid_key(const char *key)
{
    static const char prefix[] = "ED25519-V3:";
    size_t length = strlen(key);
    if (strncmp(key, prefix, sizeof(prefix) - 1) != 0 ||
        length < 80 || length >= TOR_KEY_MAX) return false;
    for (const char *at = key + sizeof(prefix) - 1; *at != '\0'; ++at)
        if (!((*at >= 'A' && *at <= 'Z') || (*at >= 'a' && *at <= 'z') ||
              (*at >= '0' && *at <= '9') || *at == '+' || *at == '/' ||
              *at == '=')) return false;
    return true;
}

static bool load_key(const char *path, char key[TOR_KEY_MAX], bool *exists)
{
    *exists = false;
    struct stat path_info;
    if (lstat(path, &path_info) != 0) return errno == ENOENT;
    *exists = true;
    if (!S_ISREG(path_info.st_mode) || path_info.st_uid != geteuid() ||
        (path_info.st_mode & 077) != 0 || path_info.st_size < 80 ||
        path_info.st_size >= TOR_KEY_MAX) return false;
    int flags = O_RDONLY;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags);
    if (fd < 0) return false;
    struct stat info;
    bool good = fstat(fd, &info) == 0 && info.st_dev == path_info.st_dev &&
                info.st_ino == path_info.st_ino && info.st_size == path_info.st_size;
    size_t at = 0;
    while (good && at < (size_t)info.st_size) {
        ssize_t count = read(fd, key + at, (size_t)info.st_size - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { good = false; break; }
        at += (size_t)count;
    }
    close(fd);
    if (good) {
        if (key[at - 1] == '\n') --at;
        key[at] = '\0';
        good = valid_key(key);
    }
    if (!good) OPENSSL_cleanse(key, TOR_KEY_MAX);
    return good;
}

static bool save_key(const char *path, const char *key)
{
    char temporary[4096];
    int size = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", path);
    if (size <= 0 || (size_t)size >= sizeof(temporary)) return false;
    int fd = mkstemp(temporary);
    if (fd < 0) return false;
    size_t length = strlen(key), at = 0;
    bool good = fchmod(fd, 0600) == 0;
    while (good && at < length) {
        ssize_t count = write(fd, key + at, length - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { good = false; break; }
        at += (size_t)count;
    }
    if (good) good = fsync(fd) == 0;
    if (close(fd) != 0) good = false;
    if (good) good = rename(temporary, path) == 0;
    if (!good) (void)unlink(temporary);
    return good;
}

static bool valid_service_id(const char *id)
{
    if (strlen(id) != 56) return false;
    for (size_t i = 0; i < 56; ++i)
        if (!((id[i] >= 'a' && id[i] <= 'z') ||
              (id[i] >= '2' && id[i] <= '7'))) return false;
    return true;
}

static bool register_service(eclipse_tor_onion_t *onion,
                             eclipse_tcp_socket_t *socket)
{
    char key[TOR_KEY_MAX] = {0}, returned_key[TOR_KEY_MAX] = {0};
    char id[57] = {0}, command[TOR_LINE_MAX], line[TOR_LINE_MAX];
    bool exists = false, good = false;
    if (!load_key(onion->key_path, key, &exists)) goto done;
    int size = snprintf(command, sizeof(command), "ADD_ONION %s Port=%u,127.0.0.1:%u\r\n",
                        exists ? key : "NEW:ED25519-V3",
                        (unsigned)onion->config.virtual_port,
                        (unsigned)onion->target_port);
    if (size <= 0 || (size_t)size >= sizeof(command) ||
        !send_command(socket, command)) goto done;
    for (unsigned i = 0; i < 4; ++i) {
        if (!read_line(socket, line)) goto done;
        if (strncmp(line, "250-ServiceID=", 14) == 0) {
            if (id[0] || strlen(line + 14) != 56) goto done;
            memcpy(id, line + 14, 57);
        } else if (strncmp(line, "250-PrivateKey=", 15) == 0) {
            if (returned_key[0] || strlen(line + 15) >= TOR_KEY_MAX) goto done;
            memcpy(returned_key, line + 15, strlen(line + 15) + 1);
        } else if (strcmp(line, "250 OK") == 0) {
            good = valid_service_id(id) && (exists || valid_key(returned_key));
            break;
        } else goto done;
    }
    if (!good) goto done;
    if (!exists && !save_key(onion->key_path, returned_key)) { good = false; goto done; }
    (void)pthread_mutex_lock(&onion->status_lock);
    (void)snprintf(onion->address, sizeof(onion->address), "%s.onion", id);
    onion->active = true;
    (void)pthread_mutex_unlock(&onion->status_lock);
    ECLIPSE_LOG_INFO(1, "Tor onion service active at %s.onion:%u", id,
                     (unsigned)onion->config.virtual_port);
done:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(returned_key, sizeof(returned_key));
    OPENSSL_cleanse(command, sizeof(command));
    return good;
}

static bool connect_and_register(eclipse_tor_onion_t *onion)
{
    eclipse_tcp_socket_t *socket = NULL;
    if (eclipse_tcp_connect("127.0.0.1", onion->config.control_port,
                            TOR_IO_TIMEOUT_MS, &socket) != ECLIPSE_SUCCESS)
        return false;
    bool good = eclipse_tcp_set_timeout(socket, TOR_IO_TIMEOUT_MS) ==
                ECLIPSE_SUCCESS &&
                authenticate(socket, onion->config.cookie_path) &&
                register_service(onion, socket);
    if (good) onion->control = socket;
    else eclipse_tcp_close(socket);
    return good;
}

static bool ping_control(eclipse_tcp_socket_t *socket)
{
    char line[TOR_LINE_MAX];
    return send_command(socket, "GETINFO version\r\n") &&
           read_line(socket, line) && strncmp(line, "250-version=", 12) == 0 &&
           read_ok(socket);
}

static void *onion_worker(void *argument)
{
    eclipse_tor_onion_t *onion = argument;
    while (!stopped(onion)) {
        /* Short sleeps keep stop responsive while still checking Tor often. */
        for (unsigned i = 0; i < 20 && !stopped(onion); ++i) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000L};
            (void)nanosleep(&pause, NULL);
        }
        if (stopped(onion)) break;
        if (onion->control != NULL && ping_control(onion->control)) continue;
        eclipse_tcp_close(onion->control);
        onion->control = NULL;
        (void)pthread_mutex_lock(&onion->status_lock);
        onion->active = false;
        (void)pthread_mutex_unlock(&onion->status_lock);
        ECLIPSE_LOG_WARNING("Tor control connection lost; restoring onion service");
        if (!connect_and_register(onion))
            ECLIPSE_LOG_WARNING("Tor onion service unavailable; retrying");
    }
    eclipse_tcp_close(onion->control);
    onion->control = NULL;
    return NULL;
}

eclipse_error_t eclipse_tor_onion_start(const eclipse_tor_config_t *config,
                                        const char *data_dir,
                                        uint16_t target_port,
                                        atomic_bool *node_stopping,
                                        eclipse_tor_onion_t **out)
{
    if (config == NULL || data_dir == NULL || node_stopping == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (!config->enabled || config->control_port == 0 ||
        config->virtual_port == 0 || target_port == 0 ||
        config->cookie_path[0] == '\0') return ECLIPSE_ERROR_INVALID_ARGUMENT;
    eclipse_tor_onion_t *onion = calloc(1, sizeof(*onion));
    if (onion == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    onion->config = *config;
    onion->target_port = target_port;
    onion->node_stopping = node_stopping;
    atomic_init(&onion->shutdown, false);
    int size = snprintf(onion->key_path, sizeof(onion->key_path),
                        "%s/onion.key", data_dir);
    if (size <= 0 || (size_t)size >= sizeof(onion->key_path) ||
        pthread_mutex_init(&onion->status_lock, NULL) != 0) {
        free(onion);
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    if (!connect_and_register(onion) ||
        pthread_create(&onion->worker, NULL, onion_worker, onion) != 0) {
        eclipse_tcp_close(onion->control);
        (void)pthread_mutex_destroy(&onion->status_lock);
        free(onion);
        ECLIPSE_LOG_ERROR("Tor onion startup failed; check ControlPort and SAFECOOKIE path");
        return ECLIPSE_ERROR_IO;
    }
    onion->worker_started = true;
    *out = onion;
    return ECLIPSE_SUCCESS;
}

void eclipse_tor_onion_status(eclipse_tor_onion_t *onion, char *out,
                              size_t capacity)
{
    if (out == NULL || capacity == 0) return;
    if (onion == NULL) { (void)snprintf(out, capacity, "none"); return; }
    (void)pthread_mutex_lock(&onion->status_lock);
    (void)snprintf(out, capacity, "%s", onion->active ? onion->address : "offline");
    (void)pthread_mutex_unlock(&onion->status_lock);
}

void eclipse_tor_onion_stop(eclipse_tor_onion_t *onion)
{
    if (onion == NULL) return;
    atomic_store(&onion->shutdown, true);
    if (onion->worker_started) (void)pthread_join(onion->worker, NULL);
    else eclipse_tcp_close(onion->control);
    (void)pthread_mutex_destroy(&onion->status_lock);
    free(onion);
    ECLIPSE_LOG_INFO(1, "Tor onion service stopped");
}
