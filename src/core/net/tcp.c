#define _POSIX_C_SOURCE 200809L
#include "tcp.h"
#include "../log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct eclipse_tcp_socket {
    int fd;
    int listening;
};

/* Keep a closed TCP peer from raising SIGPIPE on platforms that support a
 * per-socket switch. Linux uses MSG_NOSIGNAL on each send below instead. */
static int configure_no_sigpipe(int fd)
{
#ifdef SO_NOSIGPIPE
    int enabled = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#else
    (void)fd;
    return 0;
#endif
}

static eclipse_error_t wrap_fd(int fd, int listening, eclipse_tcp_socket_t **out)
{
    eclipse_tcp_socket_t *socket = malloc(sizeof(*socket));
    if (socket == NULL) {
        close(fd);
        ECLIPSE_LOG_ERROR("TCP socket handle allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    socket->fd = fd;
    socket->listening = listening;
    *out = socket;
    return ECLIPSE_SUCCESS;
}

/* poll avoids an unbounded blocking connect. Restore the original flags so
 * ordinary send/recv have familiar blocking semantics after connection. */
static int connect_with_timeout(int fd, const struct sockaddr *address,
                                socklen_t address_length, int timeout_ms)
{
    int old_flags = fcntl(fd, F_GETFL, 0);
    if (old_flags < 0 || fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0)
        return -1;
    int result = connect(fd, address, address_length);
    if (result < 0 && errno == EINPROGRESS) {
        struct pollfd watch = {.fd = fd, .events = POLLOUT};
        do { result = poll(&watch, 1, timeout_ms); } while (result < 0 && errno == EINTR);
        if (result > 0) {
            int socket_error = 0;
            socklen_t error_length = sizeof(socket_error);
            result = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                                &error_length);
            if (result == 0 && socket_error != 0) {
                errno = socket_error;
                result = -1;
            }
        } else if (result == 0) {
            errno = ETIMEDOUT;
            result = -1;
        }
    }
    int saved_errno = errno;
    if (fcntl(fd, F_SETFL, old_flags) < 0) result = -1;
    else errno = saved_errno;
    return result;
}

eclipse_error_t eclipse_tcp_connect(const char *host, uint16_t port,
                                    int timeout_ms, eclipse_tcp_socket_t **out)
{
    if (out == NULL || host == NULL) {
        ECLIPSE_LOG_WARNING("TCP connect rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    if (host[0] == '\0' || port == 0 || timeout_ms <= 0) {
        ECLIPSE_LOG_WARNING("TCP connect rejected host, port, or timeout");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    int lookup = getaddrinfo(host, service, &hints, &addresses);
    if (lookup != 0) {
        ECLIPSE_LOG_WARNING("TCP address resolution failed: %s", gai_strerror(lookup));
        return ECLIPSE_ERROR_IO;
    }
    int fd = -1;
    for (const struct addrinfo *item = addresses; item != NULL; item = item->ai_next) {
        fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (fd < 0) continue;
        if (configure_no_sigpipe(fd) == 0 &&
            connect_with_timeout(fd, item->ai_addr,
                                 (socklen_t)item->ai_addrlen, timeout_ms) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) {
        ECLIPSE_LOG_WARNING("TCP connection failed");
        return ECLIPSE_ERROR_IO;
    }
    eclipse_error_t status = wrap_fd(fd, 0, out);
    if (status == ECLIPSE_SUCCESS) ECLIPSE_LOG_INFO(2, "TCP connection established");
    return status;
}

eclipse_error_t eclipse_tcp_listen(const char *host, uint16_t port, int backlog,
                                   eclipse_tcp_socket_t **out)
{
    if (out == NULL || host == NULL) {
        ECLIPSE_LOG_WARNING("TCP listen rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    if (host[0] == '\0' || backlog <= 0) {
        ECLIPSE_LOG_WARNING("TCP listen rejected host or backlog");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM,
                             .ai_flags = AI_PASSIVE};
    struct addrinfo *addresses = NULL;
    int lookup = getaddrinfo(host, service, &hints, &addresses);
    if (lookup != 0) {
        ECLIPSE_LOG_WARNING("TCP bind address resolution failed: %s", gai_strerror(lookup));
        return ECLIPSE_ERROR_IO;
    }
    int fd = -1;
    for (const struct addrinfo *item = addresses; item != NULL; item = item->ai_next) {
        fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (fd < 0) continue;
        int reuse = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (configure_no_sigpipe(fd) == 0 &&
            bind(fd, item->ai_addr, (socklen_t)item->ai_addrlen) == 0 &&
            listen(fd, backlog) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) {
        ECLIPSE_LOG_WARNING("TCP listener setup failed");
        return ECLIPSE_ERROR_IO;
    }
    eclipse_error_t status = wrap_fd(fd, 1, out);
    if (status == ECLIPSE_SUCCESS) ECLIPSE_LOG_INFO(2, "TCP listener started");
    return status;
}

eclipse_error_t eclipse_tcp_accept(const eclipse_tcp_socket_t *listener,
                                   eclipse_tcp_socket_t **out)
{
    if (out == NULL || listener == NULL) {
        ECLIPSE_LOG_WARNING("TCP accept rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    if (!listener->listening) {
        ECLIPSE_LOG_WARNING("TCP accept requires a listener");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    int fd;
    do { fd = accept(listener->fd, NULL, NULL); } while (fd < 0 && errno == EINTR);
    if (fd < 0 || configure_no_sigpipe(fd) < 0) {
        if (fd >= 0) close(fd);
        ECLIPSE_LOG_WARNING("TCP accept failed: errno=%d", errno);
        return ECLIPSE_ERROR_IO;
    }
    eclipse_error_t status = wrap_fd(fd, 0, out);
    if (status == ECLIPSE_SUCCESS) ECLIPSE_LOG_INFO(3, "TCP peer accepted");
    return status;
}

eclipse_error_t eclipse_tcp_local_port(const eclipse_tcp_socket_t *socket,
                                       uint16_t *port)
{
    if (socket == NULL || port == NULL) {
        ECLIPSE_LOG_WARNING("TCP local-port query rejected a null argument");
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

eclipse_error_t eclipse_tcp_set_timeout(eclipse_tcp_socket_t *socket,
                                        int timeout_ms)
{
    if (socket == NULL) {
        ECLIPSE_LOG_WARNING("TCP timeout setup rejected a null socket");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (socket->listening || timeout_ms < 0) {
        ECLIPSE_LOG_WARNING("TCP timeout setup rejected listener or negative timeout");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    struct timeval timeout = {.tv_sec = timeout_ms / 1000,
                              .tv_usec = (timeout_ms % 1000) * 1000};
    if (setsockopt(socket->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) < 0 ||
        setsockopt(socket->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) < 0) {
        ECLIPSE_LOG_WARNING("TCP timeout setup failed: errno=%d", errno);
        return ECLIPSE_ERROR_IO;
    }
    ECLIPSE_LOG_INFO(4, "TCP I/O timeout configured");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tcp_send_all(eclipse_tcp_socket_t *socket,
                                     const uint8_t *data, size_t length)
{
    if (socket == NULL || (data == NULL && length != 0)) {
        ECLIPSE_LOG_WARNING("TCP send rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    if (socket->listening) {
        ECLIPSE_LOG_WARNING("TCP send requires a connected socket");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    size_t offset = 0;
    while (offset < length) {
        size_t chunk = length - offset > (size_t)SSIZE_MAX ?
                       (size_t)SSIZE_MAX : length - offset;
#ifdef MSG_NOSIGNAL
        ssize_t sent = send(socket->fd, data + offset, chunk, MSG_NOSIGNAL);
#else
        ssize_t sent = send(socket->fd, data + offset, chunk, 0);
#endif
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) {
            ECLIPSE_LOG_WARNING("TCP send failed: errno=%d", errno);
            return ECLIPSE_ERROR_IO;
        }
        offset += (size_t)sent;
    }
    ECLIPSE_LOG_INFO(5, "TCP send completed: %zu bytes", length);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_tcp_recv(eclipse_tcp_socket_t *socket, uint8_t *buffer,
                                 size_t capacity, size_t *received)
{
    if (received == NULL || socket == NULL || buffer == NULL) {
        ECLIPSE_LOG_WARNING("TCP receive rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *received = 0;
    if (socket->listening || capacity == 0) {
        ECLIPSE_LOG_WARNING("TCP receive rejected listener or empty buffer");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    size_t chunk = capacity > (size_t)SSIZE_MAX ? (size_t)SSIZE_MAX : capacity;
    ssize_t count;
    do { count = recv(socket->fd, buffer, chunk, 0); } while (count < 0 && errno == EINTR);
    if (count < 0) {
        ECLIPSE_LOG_WARNING("TCP receive failed: errno=%d", errno);
        return ECLIPSE_ERROR_IO;
    }
    *received = (size_t)count;
    if (count == 0) ECLIPSE_LOG_INFO(4, "TCP peer closed the connection");
    else ECLIPSE_LOG_INFO(5, "TCP received %zu bytes", *received);
    return ECLIPSE_SUCCESS;
}

void eclipse_tcp_close(eclipse_tcp_socket_t *socket)
{
    if (socket == NULL) return;
    close(socket->fd);
    free(socket);
    ECLIPSE_LOG_INFO(3, "TCP socket closed");
}
