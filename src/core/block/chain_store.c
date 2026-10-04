#define _POSIX_C_SOURCE 200809L
#include "chain_store.h"
#include "../log.h"

#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define STORE_HEADER_SIZE 36u
#define STORE_CHECKSUM_SIZE 32u

struct eclipse_chain_store {
    int fd;
    off_t offset; /* First unread record while replaying. */
};

static uint32_t read_u32(const uint8_t bytes[4])
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void write_u32(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static eclipse_error_t checksum(const uint8_t *wire, size_t length,
                                uint8_t output[STORE_CHECKSUM_SIZE])
{
    size_t written = 0;
    if (EVP_Q_digest(NULL, "SHA3-256", NULL, wire, length,
                     output, &written) != 1 || written != STORE_CHECKSUM_SIZE)
        return ECLIPSE_ERROR_CRYPTO_FAILURE;
    return ECLIPSE_SUCCESS;
}

/* POSIX read/write calls may complete only part of a record or be interrupted.
 * Offset-based I/O keeps the journal position independent of other code. */
static bool read_exact(int fd, uint8_t *out, size_t length, off_t offset)
{
    size_t done = 0;
    while (done < length) {
        ssize_t got = pread(fd, out + done, length - done, offset + (off_t)done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        done += (size_t)got;
    }
    return true;
}

static bool write_exact(int fd, const uint8_t *data, size_t length, off_t offset)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pwrite(fd, data + done, length - done,
                               offset + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        done += (size_t)count;
    }
    return true;
}

static eclipse_error_t truncate_tail(eclipse_chain_store_t *store)
{
    if (ftruncate(store->fd, store->offset) != 0 || fsync(store->fd) != 0) {
        ECLIPSE_LOG_ERROR("cannot remove incomplete chain journal tail");
        return ECLIPSE_ERROR_IO;
    }
    ECLIPSE_LOG_WARNING("incomplete final chain record discarded after crash");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_chain_store_open(const char *path,
    const uint8_t genesis[32], eclipse_chain_store_t **out)
{
    if (path == NULL || genesis == NULL || out == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    if (*path == '\0') return ECLIPSE_ERROR_INVALID_ARGUMENT;
    int flags = O_RDWR | O_CREAT;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags, 0600);
    if (fd < 0) {
        ECLIPSE_LOG_ERROR("chain journal open failed: errno=%d", errno);
        return ECLIPSE_ERROR_IO;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        ECLIPSE_LOG_WARNING("chain journal already has a writer or lock failed");
        close(fd);
        return ECLIPSE_ERROR_IO;
    }
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        close(fd);
        return ECLIPSE_ERROR_IO;
    }
    uint8_t header[STORE_HEADER_SIZE];
    memcpy(header, "ECS1", 4);
    memcpy(header + 4, genesis, 32);
    if (info.st_size == 0) {
        if (!write_exact(fd, header, sizeof(header), 0) || fsync(fd) != 0) {
            ECLIPSE_LOG_ERROR("chain journal header write failed");
            close(fd);
            return ECLIPSE_ERROR_IO;
        }
    } else {
        uint8_t existing[STORE_HEADER_SIZE];
        if (info.st_size < STORE_HEADER_SIZE ||
            !read_exact(fd, existing, sizeof(existing), 0) ||
            memcmp(header, existing, sizeof(header)) != 0) {
            ECLIPSE_LOG_WARNING("chain journal header or genesis mismatch");
            close(fd);
            return ECLIPSE_ERROR_IO;
        }
    }
    eclipse_chain_store_t *store = calloc(1, sizeof(*store));
    if (store == NULL) { close(fd); return ECLIPSE_ERROR_OUT_OF_MEMORY; }
    store->fd = fd;
    store->offset = STORE_HEADER_SIZE;
    *out = store;
    ECLIPSE_LOG_INFO(2, "chain journal opened for validated replay");
    return ECLIPSE_SUCCESS;
}

void eclipse_chain_store_close(eclipse_chain_store_t *store)
{
    if (store == NULL) return;
    close(store->fd);
    free(store);
    ECLIPSE_LOG_INFO(3, "chain journal closed");
}

eclipse_error_t eclipse_chain_store_next(eclipse_chain_store_t *store,
    eclipse_block_t **out, bool *end)
{
    if (store == NULL || out == NULL || end == NULL)
        return ECLIPSE_ERROR_NULL_POINTER;
    *out = NULL;
    *end = false;
    struct stat info;
    if (fstat(store->fd, &info) != 0 || info.st_size < store->offset)
        return ECLIPSE_ERROR_IO;
    off_t remaining = info.st_size - store->offset;
    if (remaining == 0) { *end = true; return ECLIPSE_SUCCESS; }
    if (remaining < 4) {
        eclipse_error_t status = truncate_tail(store);
        if (status == ECLIPSE_SUCCESS) *end = true;
        return status;
    }
    uint8_t prefix[4];
    if (!read_exact(store->fd, prefix, sizeof(prefix), store->offset))
        return ECLIPSE_ERROR_IO;
    uint32_t length = read_u32(prefix);
    if (length == 0 || length > ECLIPSE_BLOCK_MAX_WIRE_SIZE) {
        ECLIPSE_LOG_WARNING("chain journal record length is invalid");
        return ECLIPSE_ERROR_IO;
    }
    if (remaining < (off_t)(4u + length + STORE_CHECKSUM_SIZE)) {
        eclipse_error_t status = truncate_tail(store);
        if (status == ECLIPSE_SUCCESS) *end = true;
        return status;
    }
    uint8_t *wire = malloc(length);
    if (wire == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    uint8_t stored[STORE_CHECKSUM_SIZE], computed[STORE_CHECKSUM_SIZE];
    eclipse_error_t status = ECLIPSE_SUCCESS;
    if (!read_exact(store->fd, wire, length, store->offset + 4) ||
        !read_exact(store->fd, stored, sizeof(stored),
                    store->offset + 4 + (off_t)length))
        status = ECLIPSE_ERROR_IO;
    if (status == ECLIPSE_SUCCESS) status = checksum(wire, length, computed);
    if (status == ECLIPSE_SUCCESS && memcmp(stored, computed, 32) != 0)
        status = ECLIPSE_ERROR_IO;
    if (status == ECLIPSE_SUCCESS) {
        status = eclipse_block_deserialize(wire, length, out);
        if (status == ECLIPSE_ERROR_INVALID_ARGUMENT)
            status = ECLIPSE_ERROR_IO;
    }
    free(wire);
    if (status != ECLIPSE_SUCCESS) {
        ECLIPSE_LOG_WARNING("chain journal record failed integrity or format check");
        return status;
    }
    store->offset += (off_t)(4u + length + STORE_CHECKSUM_SIZE);
    ECLIPSE_LOG_INFO(5, "chain journal record integrity and format checked");
    return ECLIPSE_SUCCESS;
}

eclipse_error_t eclipse_chain_store_append(eclipse_chain_store_t *store,
    const eclipse_block_t *block)
{
    if (store == NULL || block == NULL) return ECLIPSE_ERROR_NULL_POINTER;
    uint8_t *record = malloc(4u + ECLIPSE_BLOCK_MAX_WIRE_SIZE +
                             STORE_CHECKSUM_SIZE);
    if (record == NULL) return ECLIPSE_ERROR_OUT_OF_MEMORY;
    size_t length = 0;
    eclipse_error_t status = eclipse_block_serialize(
        block, record + 4, ECLIPSE_BLOCK_MAX_WIRE_SIZE, &length);
    if (status == ECLIPSE_SUCCESS)
        status = checksum(record + 4, length, record + 4 + length);
    if (status != ECLIPSE_SUCCESS) { free(record); return status; }
    write_u32(record, (uint32_t)length);
    struct stat info;
    if (fstat(store->fd, &info) != 0 || info.st_size != store->offset) {
        free(record);
        ECLIPSE_LOG_ERROR("chain journal offset changed unexpectedly");
        return ECLIPSE_ERROR_IO;
    }
    size_t record_size = 4u + length + STORE_CHECKSUM_SIZE;
    bool written = write_exact(store->fd, record, record_size, store->offset);
    free(record);
    if (!written || fsync(store->fd) != 0) {
        (void)ftruncate(store->fd, store->offset);
        (void)fsync(store->fd);
        ECLIPSE_LOG_ERROR("chain journal append failed");
        return ECLIPSE_ERROR_IO;
    }
    store->offset += (off_t)record_size;
    ECLIPSE_LOG_INFO(3, "validated block durably appended to chain journal");
    return ECLIPSE_SUCCESS;
}
