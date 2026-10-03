/* Loopback tests exercise real POSIX sockets and a minimal RFC 6455 test
 * peer. The production WebSocket parser and handshake remain in libcurl. */
#include "net/tcp.h"
#include "net/udp.h"
#include "net/websocket.h"

#include <openssl/evp.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static void read_exact(eclipse_tcp_socket_t *socket, uint8_t *output, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        size_t count = 0;
        CHECK(eclipse_tcp_recv(socket, output + offset, length - offset,
                               &count) == ECLIPSE_SUCCESS);
        CHECK(count > 0);
        offset += count;
    }
}

static void check_tcp(void)
{
    eclipse_tcp_socket_t *listener = NULL, *client = NULL, *server = NULL;
    CHECK(eclipse_tcp_listen("127.0.0.1", 0, 1, &listener) == ECLIPSE_SUCCESS);
    uint16_t port = 0;
    CHECK(eclipse_tcp_local_port(listener, &port) == ECLIPSE_SUCCESS && port != 0);
    CHECK(eclipse_tcp_connect("127.0.0.1", port, 1000, &client) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tcp_accept(listener, &server) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tcp_set_timeout(client, 1000) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tcp_set_timeout(server, 1000) == ECLIPSE_SUCCESS);
    const uint8_t request[] = {0, 1, 2, 3, 4};
    CHECK(eclipse_tcp_send_all(client, request, sizeof(request)) == ECLIPSE_SUCCESS);
    uint8_t received[sizeof(request)] = {0};
    read_exact(server, received, sizeof(received));
    CHECK(memcmp(request, received, sizeof(request)) == 0);
    CHECK(eclipse_tcp_send_all(server, request, 0) == ECLIPSE_SUCCESS);
    eclipse_tcp_close(client);
    size_t count = 99;
    CHECK(eclipse_tcp_recv(server, received, sizeof(received), &count) ==
          ECLIPSE_SUCCESS && count == 0);
    eclipse_tcp_close(server);
    eclipse_tcp_close(listener);
}

static void check_udp(void)
{
    eclipse_udp_socket_t *sender = NULL, *receiver = NULL;
    CHECK(eclipse_udp_bind("127.0.0.1", 0, &sender) == ECLIPSE_SUCCESS);
    CHECK(eclipse_udp_bind("127.0.0.1", 0, &receiver) == ECLIPSE_SUCCESS);
    CHECK(eclipse_udp_set_timeout(receiver, 1000) == ECLIPSE_SUCCESS);
    uint16_t sender_port = 0, receiver_port = 0, peer_port = 0;
    CHECK(eclipse_udp_local_port(sender, &sender_port) == ECLIPSE_SUCCESS);
    CHECK(eclipse_udp_local_port(receiver, &receiver_port) == ECLIPSE_SUCCESS);
    const uint8_t message[] = {0, 1, 2, 3, 4};
    CHECK(eclipse_udp_send_to(sender, "127.0.0.1", receiver_port,
                              message, sizeof(message)) == ECLIPSE_SUCCESS);
    uint8_t received[sizeof(message)] = {0};
    char peer_host[64] = {0};
    size_t count = 0;
    CHECK(eclipse_udp_recv_from(receiver, received, sizeof(received), &count,
                                peer_host, sizeof(peer_host), &peer_port) ==
          ECLIPSE_SUCCESS);
    CHECK(count == sizeof(message) && memcmp(message, received, count) == 0);
    CHECK(strcmp(peer_host, "127.0.0.1") == 0 && peer_port == sender_port);
    CHECK(eclipse_udp_send_to(sender, "127.0.0.1", receiver_port,
                              message, sizeof(message)) == ECLIPSE_SUCCESS);
    CHECK(eclipse_udp_recv_from(receiver, received, 2, &count,
                                peer_host, sizeof(peer_host), &peer_port) ==
          ECLIPSE_ERROR_BUFFER_TOO_SMALL);
    CHECK(count == 0);
    eclipse_udp_close(sender);
    eclipse_udp_close(receiver);
}

typedef struct { eclipse_tcp_socket_t *listener; } ws_server_args_t;

static void *ws_server(void *arg)
{
    ws_server_args_t *args = arg;
    eclipse_tcp_socket_t *socket = NULL;
    CHECK(eclipse_tcp_accept(args->listener, &socket) == ECLIPSE_SUCCESS);
    CHECK(eclipse_tcp_set_timeout(socket, 2000) == ECLIPSE_SUCCESS);
    char request[4096] = {0};
    size_t used = 0;
    while (strstr(request, "\r\n\r\n") == NULL) {
        CHECK(used + 1 < sizeof(request));
        read_exact(socket, (uint8_t *)request + used, 1);
        ++used;
    }
    const char *key_header = strstr(request, "Sec-WebSocket-Key: ");
    CHECK(key_header != NULL);
    key_header += strlen("Sec-WebSocket-Key: ");
    const char *end = strstr(key_header, "\r\n");
    CHECK(end != NULL && (size_t)(end - key_header) < 64);
    static const char suffix[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char source[128] = {0};
    size_t key_length = (size_t)(end - key_header);
    memcpy(source, key_header, key_length);
    memcpy(source + key_length, suffix, sizeof(suffix) - 1);
    uint8_t digest[20];
    size_t digest_length = 0;
    CHECK(EVP_Q_digest(NULL, "SHA1", NULL, source,
                       key_length + sizeof(suffix) - 1,
                       digest, &digest_length) == 1 && digest_length == 20);
    char accept[32] = {0};
    CHECK(EVP_EncodeBlock((unsigned char *)accept, digest,
                          (int)sizeof(digest)) == 28);
    char response[256];
    int response_length = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    CHECK(response_length > 0 && (size_t)response_length < sizeof(response));
    CHECK(eclipse_tcp_send_all(socket, (const uint8_t *)response,
                               (size_t)response_length) == ECLIPSE_SUCCESS);

    /* Confirm libcurl masks outgoing client frames and preserves payload. */
    uint8_t header[2], mask[4], payload[5];
    read_exact(socket, header, sizeof(header));
    CHECK(header[0] == 0x82 && header[1] == (0x80 | sizeof(payload)));
    read_exact(socket, mask, sizeof(mask));
    read_exact(socket, payload, sizeof(payload));
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] ^= mask[i % 4];
    CHECK(memcmp(payload, "hello", sizeof(payload)) == 0);
    static const uint8_t reply[] = {0x82, 5, 'w', 'o', 'r', 'l', 'd'};
    CHECK(eclipse_tcp_send_all(socket, reply, sizeof(reply)) == ECLIPSE_SUCCESS);
    eclipse_tcp_close(socket);
    return NULL;
}

static void check_websocket(void)
{
    eclipse_ws_client_t *client = NULL;
    CHECK(eclipse_ws_connect("https://example.invalid", 1000, &client) ==
          ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(client == NULL);
    eclipse_tcp_socket_t *listener = NULL;
    CHECK(eclipse_tcp_listen("127.0.0.1", 0, 1, &listener) == ECLIPSE_SUCCESS);
    uint16_t port = 0;
    CHECK(eclipse_tcp_local_port(listener, &port) == ECLIPSE_SUCCESS);
    pthread_t server_thread;
    ws_server_args_t args = {.listener = listener};
    CHECK(pthread_create(&server_thread, NULL, ws_server, &args) == 0);
    char url[64];
    (void)snprintf(url, sizeof(url), "ws://127.0.0.1:%u/", (unsigned)port);
    CHECK(eclipse_ws_connect(url, 2000, &client) == ECLIPSE_SUCCESS);
    CHECK(eclipse_ws_send_binary(client, (const uint8_t *)"hello", 5) == ECLIPSE_SUCCESS);
    uint8_t response[8] = {0};
    size_t count = 0, bytes_left = 0;
    unsigned flags = 0;
    CHECK(eclipse_ws_recv_chunk(client, response, sizeof(response), &count,
                                &flags, &bytes_left) == ECLIPSE_SUCCESS);
    CHECK(count == 5 && bytes_left == 0 && flags == ECLIPSE_WS_BINARY);
    CHECK(memcmp(response, "world", 5) == 0);
    eclipse_ws_close(client);
    CHECK(pthread_join(server_thread, NULL) == 0);
    eclipse_tcp_close(listener);
}

int main(void)
{
    check_tcp();
    check_udp();
    check_websocket();
    puts("Network wrapper tests passed");
    return EXIT_SUCCESS;
}
