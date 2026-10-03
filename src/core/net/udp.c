#define _POSIX_C_SOURCE 200809L
#include "udp.h"
#include "../log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct eclipse_udp_socket {
    int fd;
    int family;
};

eclipse_error_t eclipse_udp_bind(const char *host, uint16_t port,
                                 eclipse_udp_socket_t **out)
{
    if (out == NULL || host == NULL) {
        ECLIPSE_LOG_WARNING("UDP bind rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    if (host[0] == '\0') {
        ECLIPSE_LOG_WARNING("UDP bind rejected an empty host");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM,
                             .ai_flags = AI_PASSIVE};
    struct addrinfo *addresses = NULL;
    int lookup = getaddrinfo(host, service, &hints, &addresses);
    if (lookup != 0) {
        ECLIPSE_LOG_WARNING("UDP bind address resolution failed: %s", gai_strerror(lookup));
        return ECLIPSE_ERROR_IO;
    }
    int fd = -1;
    int family = AF_UNSPEC;
    for (const struct addrinfo *item = addresses; item != NULL; item = item->ai_next) {
        fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (fd < 0) continue;
        if (bind(fd, item->ai_addr, (socklen_t)item->ai_addrlen) == 0) {
            family = item->ai_family;
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) {
        ECLIPSE_LOG_WARNING("UDP bind failed");
        return ECLIPSE_ERROR_IO;
    }
    eclipse_udp_socket_t *socket = malloc(sizeof(*socket));
    if (socket == NULL) {
        close(fd);
        ECLIPSE_LOG_ERROR("UDP handle allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    socket->fd = fd;
    socket->family = family;
    *out = socket;
    ECLIPSE_LOG_INFO(2, "UDP socket bound");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_udp_local_port(const eclipse_udp_socket_t *socket,
                                       uint16_t *port)
{
    if (socket == NULL || port == NULL) {
        ECLIPSE_LOG_WARNING("UDP local-port query rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    if (getsockname(socket->fd, (struct sockaddr *)&address, &length) < 0)
        return ECLIPSE_ERROR_IO;
    if (address.ss_family == AF_INET)
        *port = ntohs(((struct sockaddr_in *)&address)->sin_port);
    else if (address.ss_family == AF_INET6)
        *port = ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    else return ECLIPSE_ERROR_IO;
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_udp_set_timeout(eclipse_udp_socket_t *socket,
                                        int timeout_ms)
{
    if (socket == NULL) {
        ECLIPSE_LOG_WARNING("UDP timeout setup rejected a null socket");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (timeout_ms < 0) {
        ECLIPSE_LOG_WARNING("UDP timeout setup rejected a negative timeout");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    struct timeval timeout = {.tv_sec = timeout_ms / 1000,
                              .tv_usec = (timeout_ms % 1000) * 1000};
    if (setsockopt(socket->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) < 0) {
        ECLIPSE_LOG_WARNING("UDP receive timeout setup failed: errno=%d", errno);
        return ECLIPSE_ERROR_IO;
    }
    ECLIPSE_LOG_INFO(4, "UDP receive timeout configured");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_udp_send_to(eclipse_udp_socket_t *socket,
                                    const char *host, uint16_t port,
                                    const uint8_t *data, size_t length)
{
    if (socket == NULL || host == NULL || (data == NULL && length != 0)) {
        ECLIPSE_LOG_WARNING("UDP send rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (host[0] == '\0' || port == 0 || length > (size_t)SSIZE_MAX) {
        ECLIPSE_LOG_WARNING("UDP send rejected host, port, or datagram size");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo hints = {.ai_family = socket->family, .ai_socktype = SOCK_DGRAM};
    struct addrinfo *addresses = NULL;
    int lookup = getaddrinfo(host, service, &hints, &addresses);
    if (lookup != 0) {
        ECLIPSE_LOG_WARNING("UDP destination resolution failed: %s", gai_strerror(lookup));
        return ECLIPSE_ERROR_IO;
    }
    /* Some sendto implementations require a non-NULL pointer for an empty
       datagram even though they will read zero bytes from it. */
    static const uint8_t empty = 0;
    ssize_t sent = -1;
    for (const struct addrinfo *item = addresses; item != NULL; item = item->ai_next) {
        do {
            sent = sendto(socket->fd, data == NULL ? &empty : data, length, 0,
                          item->ai_addr, (socklen_t)item->ai_addrlen);
        } while (sent < 0 && errno == EINTR);
        if (sent >= 0) break;
    }
    freeaddrinfo(addresses);
    if (sent != (ssize_t)length) {
        ECLIPSE_LOG_WARNING("UDP datagram send failed: errno=%d", errno);
        return ECLIPSE_ERROR_IO;
    }
    ECLIPSE_LOG_INFO(5, "UDP datagram sent: %zu bytes", length);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_udp_recv_from(eclipse_udp_socket_t *socket,
                                      uint8_t *buffer, size_t capacity,
                                      size_t *received, char *peer_host,
                                      size_t peer_host_capacity,
                                      uint16_t *peer_port)
{
    if (socket == NULL || buffer == NULL || received == NULL ||
        peer_host == NULL || peer_port == NULL) {
        ECLIPSE_LOG_WARNING("UDP receive rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *received = 0;
    if (capacity == 0 || capacity > (size_t)SSIZE_MAX || peer_host_capacity == 0) {
        ECLIPSE_LOG_WARNING("UDP receive rejected a buffer size");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    struct sockaddr_storage address;
    struct iovec payload = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr message = {.msg_name = &address, .msg_namelen = sizeof(address),
                             .msg_iov = &payload, .msg_iovlen = 1};
    ssize_t count;
    do { count = recvmsg(socket->fd, &message, 0); } while (count < 0 && errno == EINTR);
    if (count < 0) {
        ECLIPSE_LOG_WARNING("UDP receive failed: errno=%d", errno);
        return ECLIPSE_ERROR_IO;
    }
    if ((message.msg_flags & MSG_TRUNC) != 0) {
        ECLIPSE_LOG_WARNING("UDP datagram rejected: receive buffer too small");
        return ECLIPSE_ERROR_BUFFER_TOO_SMALL;
    }
    char numeric_service[6];
    int status = getnameinfo((struct sockaddr *)&address, message.msg_namelen,
                             peer_host, (socklen_t)peer_host_capacity,
                             numeric_service, sizeof(numeric_service),
                             NI_NUMERICHOST | NI_NUMERICSERV);
    if (status != 0) {
        ECLIPSE_LOG_WARNING("UDP source address conversion failed: %s", gai_strerror(status));
        return ECLIPSE_ERROR_IO;
    }
    unsigned long parsed = strtoul(numeric_service, NULL, 10);
    if (parsed > UINT16_MAX) return ECLIPSE_ERROR_IO;
    *peer_port = (uint16_t)parsed;
    *received = (size_t)count;
    ECLIPSE_LOG_INFO(5, "UDP datagram received: %zu bytes", *received);
    return ECLIPSE_SUCCESS;
}

void eclipse_udp_close(eclipse_udp_socket_t *socket)
{
    if (socket == NULL) return;
    close(socket->fd);
    free(socket);
    ECLIPSE_LOG_INFO(3, "UDP socket closed");
}
