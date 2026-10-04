#ifndef ECLIPSE_NET_TCP_H
#define ECLIPSE_NET_TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eclipse_tcp_socket eclipse_tcp_socket_t;

/* Resolve a host and connect within timeout_ms for each candidate address.
 * The caller owns *out. DNS resolution itself can take longer than this limit. */
eclipse_error_t eclipse_tcp_connect(const char *host, uint16_t port,
                                    int timeout_ms, eclipse_tcp_socket_t **out);
/* Bind/listen on host; port 0 asks the OS for an ephemeral port. The returned
 * listener only accepts connections; use eclipse_tcp_accept for a data socket. */
eclipse_error_t eclipse_tcp_listen(const char *host, uint16_t port, int backlog,
                                   eclipse_tcp_socket_t **out);
eclipse_error_t eclipse_tcp_accept(const eclipse_tcp_socket_t *listener,
                                   eclipse_tcp_socket_t **out);
/* Poll a listener without exposing its native descriptor to callers. */
eclipse_error_t eclipse_tcp_wait_readable(const eclipse_tcp_socket_t *listener,
                                         int timeout_ms, bool *ready);
eclipse_error_t eclipse_tcp_local_port(const eclipse_tcp_socket_t *socket,
                                       uint16_t *port);
/* Sets both send and receive timeouts; zero restores blocking behavior. */
eclipse_error_t eclipse_tcp_set_timeout(eclipse_tcp_socket_t *socket,
                                        int timeout_ms);
/* send_all writes exactly length bytes or returns IO; an error can occur after
 * some bytes have already been sent. A zero length succeeds.
 * recv reads up to capacity; success with *received == 0 means clean EOF. */
eclipse_error_t eclipse_tcp_send_all(eclipse_tcp_socket_t *socket,
                                     const uint8_t *data, size_t length);
eclipse_error_t eclipse_tcp_recv(eclipse_tcp_socket_t *socket, uint8_t *buffer,
                                 size_t capacity, size_t *received);
void eclipse_tcp_close(eclipse_tcp_socket_t *socket);

#ifdef __cplusplus
}
#endif

#endif
