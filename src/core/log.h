#ifndef ECLIPSE_LOG_H
#define ECLIPSE_LOG_H

#include <stdbool.h>
#include <stdio.h>

#include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ECLIPSE_LOG_LEVEL_ERROR,
    ECLIPSE_LOG_LEVEL_WARNING,
    ECLIPSE_LOG_LEVEL_SECURITY,
    ECLIPSE_LOG_LEVEL_INFO,
} eclipse_log_level_t;

/* INFO 1 is most important; INFO 5 is most detailed. 0 disables INFO. */
eclipse_error_t eclipse_log_set_info_level(unsigned level);
unsigned eclipse_log_get_info_level(void);
bool eclipse_log_info_enabled(unsigned level);

/* The default destination is stderr. A supplied stream remains caller-owned. */
eclipse_error_t eclipse_log_set_stream(FILE *stream);
/* Opens a file in append mode. The logger owns and closes it on replacement. */
eclipse_error_t eclipse_log_set_file(const char *path);
/* Flushes and closes a logger-owned file; restores stderr and INFO 1. */
void eclipse_log_shutdown(void);

#if defined(__GNUC__) || defined(__clang__)
#define ECLIPSE_LOG_PRINTF_FORMAT(format_index, first_argument) \
    __attribute__((format(printf, format_index, first_argument)))
#else
#define ECLIPSE_LOG_PRINTF_FORMAT(format_index, first_argument)
#endif

/* Prefer the macros below: they insert the actual caller's location. */
eclipse_error_t eclipse_log_write(eclipse_log_level_t level, unsigned info_level,
                                  const char *file, int line, const char *function,
                                  const char *format, ...)
    ECLIPSE_LOG_PRINTF_FORMAT(6, 7);

#define ECLIPSE_LOG_ERROR(...) \
    ((void)eclipse_log_write(ECLIPSE_LOG_LEVEL_ERROR, 0, __FILE__, __LINE__, \
                             __func__, __VA_ARGS__))
#define ECLIPSE_LOG_WARNING(...) \
    ((void)eclipse_log_write(ECLIPSE_LOG_LEVEL_WARNING, 0, __FILE__, __LINE__, \
                             __func__, __VA_ARGS__))
#define ECLIPSE_LOG_SECURITY(...) \
    ((void)eclipse_log_write(ECLIPSE_LOG_LEVEL_SECURITY, 0, __FILE__, __LINE__, \
                             __func__, __VA_ARGS__))
#define ECLIPSE_LOG_INFO(level, ...) do { \
    unsigned eclipse_log_requested_level_ = (unsigned)(level); \
    if (eclipse_log_info_enabled(eclipse_log_requested_level_)) \
        (void)eclipse_log_write(ECLIPSE_LOG_LEVEL_INFO, \
                                eclipse_log_requested_level_, __FILE__, __LINE__, \
                                __func__, __VA_ARGS__); \
} while (0)

#ifdef __cplusplus
}
#endif

#endif
