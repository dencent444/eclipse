#define _POSIX_C_SOURCE 200809L
#include "log.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ECLIPSE_LOG_MESSAGE_CAPACITY 4096u

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *log_stream = NULL; /* NULL means stderr. */
static FILE *owned_stream = NULL;
static unsigned info_verbosity = 1;

/* INFO is a volume filter only. Severity WARNING/ERROR/SECURITY is never
 * suppressed by this setting, and consensus behavior must not depend on it. */
eclipse_error_t eclipse_log_set_info_level(unsigned level)
{
    if (level > 5) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    pthread_mutex_lock(&log_mutex);
    info_verbosity = level;
    pthread_mutex_unlock(&log_mutex);
    return ECLIPSE_SUCCESS;
}

/* Read the current volume setting under the same mutex used by writers. */
unsigned eclipse_log_get_info_level(void)
{
    pthread_mutex_lock(&log_mutex);
    unsigned level = info_verbosity;
    pthread_mutex_unlock(&log_mutex);
    return level;
}

/* Cheap caller-side INFO check; it does not replace write-time filtering. */
bool eclipse_log_info_enabled(unsigned level)
{
    if (level < 1 || level > 5) return false;
    pthread_mutex_lock(&log_mutex);
    bool enabled = level <= info_verbosity;
    pthread_mutex_unlock(&log_mutex);
    return enabled;
}

/* Switch to a caller-owned stream. If a previous log file was opened by this
 * module, close that owned file before replacing the destination. */
eclipse_error_t eclipse_log_set_stream(FILE *stream)
{
    if (stream == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    pthread_mutex_lock(&log_mutex);
    if (stream == owned_stream) {
        pthread_mutex_unlock(&log_mutex);
        return ECLIPSE_SUCCESS;
    }
    if (owned_stream != NULL) fclose(owned_stream);
    owned_stream = NULL;
    log_stream = stream;
    pthread_mutex_unlock(&log_mutex);
    return ECLIPSE_SUCCESS;
}

/* Open an append-only log destination with mode 0600 for newly created files.
 * Keep the old destination if open/fdopen fails; never log the file contents. */
eclipse_error_t eclipse_log_set_file(const char *path)
{
    if (path == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    if (*path == '\0') return ECLIPSE_ERROR_INVALID_ARGUMENT;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return ECLIPSE_ERROR_IO;
    FILE *stream = fdopen(fd, "a");
    if (stream == NULL) {
        close(fd);
        return ECLIPSE_ERROR_IO;
    }
    pthread_mutex_lock(&log_mutex);
    if (owned_stream != NULL) fclose(owned_stream);
    owned_stream = stream;
    log_stream = stream;
    pthread_mutex_unlock(&log_mutex);
    return ECLIPSE_SUCCESS;
}

/* Restore defaults and close only a destination opened by this logger. */
void eclipse_log_shutdown(void)
{
    pthread_mutex_lock(&log_mutex);
    if (owned_stream != NULL) fclose(owned_stream);
    owned_stream = NULL;
    log_stream = NULL;
    info_verbosity = 1;
    pthread_mutex_unlock(&log_mutex);
}

/* Severity names are fixed text, never built from untrusted messages. */
static const char *level_label(eclipse_log_level_t level)
{
    switch (level) {
    case ECLIPSE_LOG_LEVEL_ERROR: return "ERROR";
    case ECLIPSE_LOG_LEVEL_WARNING: return "WARNING";
    case ECLIPSE_LOG_LEVEL_SECURITY: return "SECURITY";
    case ECLIPSE_LOG_LEVEL_INFO: return "INFO";
    default: return NULL;
    }
}

/* Keep control characters from turning one event into forged extra lines. */
static void sanitize_message(char *message)
{
    /* Keep one event on one line, even if a peer supplies line breaks. */
    for (unsigned char *p = (unsigned char *)message; *p != '\0'; ++p) {
        if (*p < 0x20 || *p == 0x7f) *p = ' ';
    }
}

/* Format one event with UTC time, severity, source location, and a bounded
 * message. The mutex protects both the destination and uninterrupted lines. */
eclipse_error_t eclipse_log_write(eclipse_log_level_t level, unsigned info_level,
                                  const char *file, int line, const char *function,
                                  const char *format, ...)
{
    if (file == NULL || function == NULL || format == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    const char *label = level_label(level);
    if (label == NULL || line < 0 ||
        (level == ECLIPSE_LOG_LEVEL_INFO && (info_level < 1 || info_level > 5)))
        return ECLIPSE_ERROR_INVALID_ARGUMENT;

    char message[ECLIPSE_LOG_MESSAGE_CAPACITY];
    va_list args;
    va_start(args, format);
    int needed = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (needed < 0) return ECLIPSE_ERROR_INVALID_ARGUMENT;
    if ((size_t)needed >= sizeof(message)) {
        static const char marker[] = " [truncated]";
        size_t marker_size = sizeof(marker) - 1;
        memcpy(message + sizeof(message) - marker_size - 1, marker, marker_size + 1);
    }
    sanitize_message(message);

    pthread_mutex_lock(&log_mutex);
    if (level == ECLIPSE_LOG_LEVEL_INFO && info_level > info_verbosity) {
        pthread_mutex_unlock(&log_mutex);
        return ECLIPSE_SUCCESS;
    }

    struct timespec now;
    struct tm utc;
    char timestamp[40];
    if (clock_gettime(CLOCK_REALTIME, &now) == 0 &&
        gmtime_r(&now.tv_sec, &utc) != NULL) {
        size_t used = strftime(timestamp, sizeof(timestamp),
                               "%Y-%m-%dT%H:%M:%S", &utc);
        if (used == 0) {
            (void)snprintf(timestamp, sizeof(timestamp), "time-unavailable");
        } else {
            unsigned milliseconds = (unsigned)(now.tv_nsec / 1000000L);
            if (milliseconds > 999) milliseconds = 0;
            (void)snprintf(timestamp + used, sizeof(timestamp) - used,
                           ".%03uZ", milliseconds);
        }
    } else {
        (void)snprintf(timestamp, sizeof(timestamp), "time-unavailable");
    }

    FILE *stream = log_stream != NULL ? log_stream : stderr;
    int written;
    if (level == ECLIPSE_LOG_LEVEL_INFO)
        written = fprintf(stream, "%s [INFO:%u] %s:%d %s: %s\n",
                          timestamp, info_level, file, line, function, message);
    else
        written = fprintf(stream, "%s [%s] %s:%d %s: %s\n",
                          timestamp, label, file, line, function, message);
    int flushed = fflush(stream);
    pthread_mutex_unlock(&log_mutex);
    return written < 0 || flushed != 0 ? ECLIPSE_ERROR_IO : ECLIPSE_SUCCESS;
}
