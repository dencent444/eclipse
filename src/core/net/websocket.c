#define _POSIX_C_SOURCE 200809L
#include "websocket.h"
#include "../log.h"

#include <curl/curl.h>
#include <curl/websockets.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct eclipse_ws_client {
    CURL *curl;
    int timeout_ms;
};

/* libcurl global initialization must finish before any thread creates an
 * easy handle. Keep it process-wide; applications using libcurl elsewhere can
 * continue using it after individual WebSocket handles are closed. */
static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_start_status = CURLE_FAILED_INIT;

static void curl_start(void)
{
    curl_start_status = curl_global_init(CURL_GLOBAL_DEFAULT);
}

/* CONNECT_ONLY WebSockets can report CURLE_AGAIN. poll the active socket and
 * retry; the positive timeout prevents a stalled peer from blocking forever. */
static eclipse_error_t wait_socket(eclipse_ws_client_t *client, short events)
{
    curl_socket_t fd = CURL_SOCKET_BAD;
    if (curl_easy_getinfo(client->curl, CURLINFO_ACTIVESOCKET, &fd) != CURLE_OK ||
        fd == CURL_SOCKET_BAD) {
        ECLIPSE_LOG_WARNING("WebSocket has no active socket");
        return ECLIPSE_ERROR_IO;
    }
    struct pollfd watch = {.fd = (int)fd, .events = events};
    int result;
    do { result = poll(&watch, 1, client->timeout_ms); }
    while (result < 0 && errno == EINTR);
    if (result <= 0 || (watch.revents & events) == 0 ||
        (watch.revents & (POLLERR | POLLNVAL)) != 0) {
        ECLIPSE_LOG_WARNING("WebSocket wait failed or timed out");
        return ECLIPSE_ERROR_IO;
    }
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ws_connect(const char *url, int timeout_ms,
                                   eclipse_ws_client_t **out)
{
    if (out == NULL || url == NULL) {
        ECLIPSE_LOG_WARNING("WebSocket connect rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *out = NULL;
    if ((strncmp(url, "ws://", 5) != 0 && strncmp(url, "wss://", 6) != 0) ||
        timeout_ms <= 0) {
        ECLIPSE_LOG_WARNING("WebSocket connect rejected URL scheme or timeout");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    if (pthread_once(&curl_once, curl_start) != 0 || curl_start_status != CURLE_OK) {
        ECLIPSE_LOG_ERROR("libcurl global initialization failed");
        return ECLIPSE_ERROR_IO;
    }
    eclipse_ws_client_t *client = malloc(sizeof(*client));
    if (client == NULL) {
        ECLIPSE_LOG_ERROR("WebSocket client allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    client->curl = curl_easy_init();
    client->timeout_ms = timeout_ms;
    if (client->curl == NULL) {
        free(client);
        ECLIPSE_LOG_ERROR("WebSocket handle allocation failed");
        return ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    /* Restrict schemes and redirects. TLS verification stays enabled: no
       insecure fallback for wss:// and no logging of URL credentials. */
    CURLcode code = curl_easy_setopt(client->curl, CURLOPT_URL, url);
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_PROTOCOLS_STR, "ws,wss");
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_CONNECT_ONLY, 2L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_CONNECTTIMEOUT_MS,
                                (long)timeout_ms);
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_TIMEOUT_MS,
                                (long)timeout_ms);
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_NOSIGNAL, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(client->curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (code == CURLE_OK) code = curl_easy_perform(client->curl);
    if (code != CURLE_OK) {
        ECLIPSE_LOG_WARNING("WebSocket upgrade failed: %s", curl_easy_strerror(code));
        curl_easy_cleanup(client->curl);
        free(client);
        return ECLIPSE_ERROR_IO;
    }
    *out = client;
    ECLIPSE_LOG_INFO(2, "WebSocket client connected");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ws_send_binary(eclipse_ws_client_t *client,
                                       const uint8_t *data, size_t length)
{
    if (client == NULL || (data == NULL && length != 0)) {
        ECLIPSE_LOG_WARNING("WebSocket send rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    static const uint8_t empty = 0;
    size_t offset = 0;
    do {
        size_t sent = 0;
        CURLcode code = curl_ws_send(client->curl,
                                     data == NULL ? &empty : data + offset,
                                     length - offset, &sent, 0, CURLWS_BINARY);
        if (code == CURLE_AGAIN) {
            /* libcurl can consume a prefix before reporting backpressure. */
            offset += sent;
            eclipse_error_t status = wait_socket(client, POLLOUT);
            if (status != ECLIPSE_SUCCESS) return status;
            continue;
        }
        if (code != CURLE_OK || (sent == 0 && length != 0)) {
            ECLIPSE_LOG_WARNING("WebSocket binary send failed: %s",
                                curl_easy_strerror(code));
            return ECLIPSE_ERROR_IO;
        }
        offset += sent;
    } while (offset < length);
    ECLIPSE_LOG_INFO(5, "WebSocket binary frame sent: %zu bytes", length);
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_ws_recv_chunk(eclipse_ws_client_t *client,
                                      uint8_t *buffer, size_t capacity,
                                      size_t *received, unsigned *flags,
                                      size_t *bytes_left)
{
    if (client == NULL || buffer == NULL || received == NULL ||
        flags == NULL || bytes_left == NULL) {
        ECLIPSE_LOG_WARNING("WebSocket receive rejected a null argument");
        return ECLIPSE_ERROR_NULL_POINTER;
    }
    *received = 0;
    *flags = 0;
    *bytes_left = 0;
    if (capacity == 0) {
        ECLIPSE_LOG_WARNING("WebSocket receive rejected an empty buffer");
        return ECLIPSE_ERROR_INVALID_ARGUMENT;
    }
    for (;;) {
        size_t count = 0;
        const struct curl_ws_frame *meta = NULL;
        CURLcode code = curl_ws_recv(client->curl, buffer, capacity, &count, &meta);
        if (code == CURLE_AGAIN) {
            eclipse_error_t status = wait_socket(client, POLLIN);
            if (status != ECLIPSE_SUCCESS) return status;
            continue;
        }
        if (code != CURLE_OK || meta == NULL || meta->bytesleft < 0 ||
            (uintmax_t)meta->bytesleft > SIZE_MAX) {
            ECLIPSE_LOG_WARNING("WebSocket receive or frame metadata failed: %s",
                                curl_easy_strerror(code));
            return ECLIPSE_ERROR_IO;
        }
        /* Copy metadata before the next libcurl call invalidates meta. */
        unsigned result_flags = 0;
        if ((meta->flags & CURLWS_TEXT) != 0) result_flags |= ECLIPSE_WS_TEXT;
        if ((meta->flags & CURLWS_BINARY) != 0) result_flags |= ECLIPSE_WS_BINARY;
        if ((meta->flags & CURLWS_CLOSE) != 0) result_flags |= ECLIPSE_WS_CLOSE;
        if ((meta->flags & CURLWS_PING) != 0) result_flags |= ECLIPSE_WS_PING;
        if ((meta->flags & CURLWS_PONG) != 0) result_flags |= ECLIPSE_WS_PONG;
        if ((meta->flags & CURLWS_CONT) != 0) result_flags |= ECLIPSE_WS_MORE_FRAMES;
        *received = count;
        *flags = result_flags;
        *bytes_left = (size_t)meta->bytesleft;
        ECLIPSE_LOG_INFO(5, "WebSocket chunk received: %zu bytes", count);
        return ECLIPSE_SUCCESS;
    }
}

void eclipse_ws_close(eclipse_ws_client_t *client)
{
    if (client == NULL) return;
    size_t sent = 0;
    /* Best effort close frame; cleanup also works after a broken connection. */
    (void)curl_ws_send(client->curl, "", 0, &sent, 0, CURLWS_CLOSE);
    curl_easy_cleanup(client->curl);
    free(client);
    ECLIPSE_LOG_INFO(3, "WebSocket client closed");
}
