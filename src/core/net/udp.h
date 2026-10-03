#ifndef ECLIPSE_NET_UDP_H
#define ECLIPSE_NET_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "../error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eclipse_udp_socket eclipse_udp_socket_t;

/* Bind one IPv4 or IPv6 UDP socket. Port 0 chooses an ephemeral local port.
 * The socket can both send and receive datagrams of its address family. */
eclipse_error_t eclipse_udp_bind(const char *host, uint16_t port,
                                 eclipse_udp_socket_t **out);
eclipse_error_t eclipse_udp_local_port(const eclipse_udp_socket_t *socket,
                                       uint16_t *port);
/* A timeout of zero restores blocking receive behavior. */
eclipse_error_t eclipse_udp_set_timeout(eclipse_udp_socket_t *socket,
                                        int timeout_ms);
/* One call sends exactly one datagram. A failed send never retries part of it. */
eclipse_error_t eclipse_udp_send_to(eclipse_udp_socket_t *socket,
                                    const char *host, uint16_t port,
                                    const uint8_t *data, size_t length);
/* Caller supplies storage for the datagram and numeric peer address. A
 * truncated datagram is rejected with BUFFER_TOO_SMALL, never returned as a
 * valid shorter packet. Empty datagrams are valid and return received == 0. */
eclipse_error_t eclipse_udp_recv_from(eclipse_udp_socket_t *socket,
                                      uint8_t *buffer, size_t capacity,
                                      size_t *received, char *peer_host,
                                      size_t peer_host_capacity,
                                      uint16_t *peer_port);
void eclipse_udp_close(eclipse_udp_socket_t *socket);

#ifdef __cplusplus
}
#endif

#endif
