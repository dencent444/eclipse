#ifndef ECLIPSE_NET_WEBSOCKET_H
#define ECLIPSE_NET_WEBSOCKET_H

#include <stddef.h>
#include <stdint.h>

#include "../error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eclipse_ws_client eclipse_ws_client_t;

typedef enum {
    ECLIPSE_WS_TEXT = 1u << 0,
    ECLIPSE_WS_BINARY = 1u << 1,
    ECLIPSE_WS_CLOSE = 1u << 2,
    ECLIPSE_WS_PING = 1u << 3,
    ECLIPSE_WS_PONG = 1u << 4,
    ECLIPSE_WS_MORE_FRAMES = 1u << 5,
} eclipse_ws_flags_t;

/* Client-only WebSocket wrapper. libcurl performs the HTTP upgrade and TLS
 * certificate/hostname verification for wss://. Each handle is single-thread
 * use; callers must not send and receive concurrently on the same handle. */
eclipse_error_t eclipse_ws_connect(const char *url, int timeout_ms,
                                   eclipse_ws_client_t **out);
/* Send one binary frame; zero-byte frames are allowed. Partial writes and
 * temporary socket backpressure are handled within timeout_ms per wait. An
 * error can occur after part of a frame has been sent; callers should close
 * that connection rather than replaying the message blindly. */
eclipse_error_t eclipse_ws_send_binary(eclipse_ws_client_t *client,
                                       const uint8_t *data, size_t length);
/* Read one chunk, not necessarily a whole frame or message. bytes_left is the
 * remaining payload in this frame. MORE_FRAMES says a later frame continues
 * the same message. The caller must reassemble before parsing protocol data.
 * A CLOSE chunk means the peer is closing; it is not an empty data message. */
eclipse_error_t eclipse_ws_recv_chunk(eclipse_ws_client_t *client,
                                      uint8_t *buffer, size_t capacity,
                                      size_t *received, unsigned *flags,
                                      size_t *bytes_left);
void eclipse_ws_close(eclipse_ws_client_t *client);

#ifdef __cplusplus
}
#endif

#endif
