#define _POSIX_C_SOURCE 200809L
/* Logger contract: severity filtering, source locations, concurrent writes,
 * and file permissions must work without exposing sensitive input. */
#include "log.h"
#include "block/block.h"
#include "crypto/ml_dsa.h"
#include "crypto/ml_dsa_math.h"

#include <pthread.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #test); \
    exit(EXIT_FAILURE); \
} } while (0)

static void emit_warning(void)
{
    ECLIPSE_LOG_WARNING("peer said: %s", "bad\nblock");
}

static void *write_from_thread(void *argument)
{
    unsigned id = *(unsigned *)argument;
    for (unsigned i = 0; i < 20; ++i)
        ECLIPSE_LOG_INFO(1, "worker %u event %u", id, i);
    return NULL;
}

static int count_lines(FILE *stream, const char *required)
{
    rewind(stream);
    char line[8192];
    int count = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        CHECK(strchr(line, '\n') != NULL);
        if (required == NULL || strstr(line, required) != NULL) ++count;
    }
    return count;
}

int main(void)
{
    FILE *capture = tmpfile();
    CHECK(capture != NULL);
    CHECK(eclipse_log_set_stream(capture) == ECLIPSE_SUCCESS);
    CHECK(eclipse_log_set_info_level(0) == ECLIPSE_SUCCESS);
    int evaluated = 0;
    ECLIPSE_LOG_INFO(5, "filtered %d", ++evaluated);
    CHECK(evaluated == 0);
    ECLIPSE_LOG_ERROR("disk error %d", 7);
    emit_warning();
    ECLIPSE_LOG_SECURITY("reserved event");
    CHECK(eclipse_log_set_info_level(2) == ECLIPSE_SUCCESS);
    CHECK(eclipse_log_get_info_level() == 2);
    ECLIPSE_LOG_INFO(1, "essential");
    ECLIPSE_LOG_INFO(2, "details");
    ECLIPSE_LOG_INFO(3, "hidden");
    CHECK(eclipse_log_set_info_level(6) == ECLIPSE_ERROR_INVALID_ARGUMENT);
    CHECK(eclipse_log_get_info_level() == 2);

    CHECK(count_lines(capture, NULL) == 5);
    CHECK(count_lines(capture, "[ERROR]") == 1);
    CHECK(count_lines(capture, "[WARNING]") == 1);
    CHECK(count_lines(capture, "[SECURITY]") == 1);
    CHECK(count_lines(capture, "[INFO:1]") == 1);
    CHECK(count_lines(capture, "[INFO:2]") == 1);
    CHECK(count_lines(capture, "emit_warning: peer said: bad block") == 1);
    CHECK(count_lines(capture, "log_test.c:") == 5);
    CHECK(count_lines(capture, "hidden") == 0);
    CHECK(eclipse_log_set_stream(NULL) == ECLIPSE_ERROR_NULL_POINTER);
    CHECK(eclipse_log_set_info_level(5) == ECLIPSE_SUCCESS);
    ECLIPSE_LOG_INFO(3, "level three");
    ECLIPSE_LOG_INFO(4, "level four");
    ECLIPSE_LOG_INFO(5, "level five");
    CHECK(count_lines(capture, "[INFO:3]") == 1);
    CHECK(count_lines(capture, "[INFO:4]") == 1);
    CHECK(count_lines(capture, "[INFO:5]") == 1);

    pthread_t threads[4];
    unsigned ids[4] = {0, 1, 2, 3};
    for (size_t i = 0; i < 4; ++i)
        CHECK(pthread_create(&threads[i], NULL, write_from_thread, &ids[i]) == 0);
    for (size_t i = 0; i < 4; ++i)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(count_lines(capture, NULL) == 88);
    CHECK(count_lines(capture, "write_from_thread: worker") == 80);

    char long_message[5000];
    memset(long_message, 'x', sizeof(long_message) - 1);
    long_message[sizeof(long_message) - 1] = '\0';
    ECLIPSE_LOG_WARNING("%s", long_message);
    CHECK(count_lines(capture, "[truncated]") == 1);

    eclipse_block_header_t header = {.version = 1};
    eclipse_block_header_t decoded = {0};
    uint8_t wire[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    CHECK(eclipse_block_header_serialize(&header, wire, sizeof(wire)) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_header_deserialize(wire, &decoded, sizeof(wire)) == ECLIPSE_SUCCESS);
    CHECK(eclipse_block_header_deserialize(wire, &decoded, 1) == ECLIPSE_ERROR_INVALID_ARGUMENT);

    eclipse_ml_dsa_poly_t left = {0};
    eclipse_ml_dsa_poly_t right = {0};
    eclipse_ml_dsa_poly_t sum = {0};
    left.coefficient[0] = 1;
    right.coefficient[0] = 2;
    CHECK(eclipse_ml_dsa_poly_add(&left, &right, &sum) == ECLIPSE_SUCCESS);

    eclipse_ml_dsa_key_t *key = NULL;
    eclipse_ml_dsa_info_t info;
    CHECK(eclipse_ml_dsa_generate(ECLIPSE_ML_DSA_44, &key) == ECLIPSE_SUCCESS);
    CHECK(eclipse_ml_dsa_info(ECLIPSE_ML_DSA_44, &info));
    uint8_t *signature = malloc(info.signature_size);
    CHECK(signature != NULL);
    static const uint8_t message[] = "secret-text-for-log-test";
    size_t signature_length = 0;
    CHECK(eclipse_ml_dsa_sign(key, message, sizeof(message), NULL, 0,
                              signature, info.signature_size,
                              &signature_length) == ECLIPSE_SUCCESS);
    bool valid = false;
    CHECK(eclipse_ml_dsa_verify(key, message, sizeof(message), NULL, 0,
                                signature, signature_length, &valid) == ECLIPSE_SUCCESS);
    CHECK(valid);
    free(signature);
    eclipse_ml_dsa_key_free(key);

    CHECK(count_lines(capture, "eclipse_block_header_serialize: block header serialized") == 1);
    CHECK(count_lines(capture, "eclipse_block_header_deserialize: block header deserialized") == 1);
    CHECK(count_lines(capture, "eclipse_block_header_deserialize: truncated block header rejected") == 1);
    CHECK(count_lines(capture, "eclipse_ml_dsa_poly_add: polynomial addition completed") == 1);
    CHECK(count_lines(capture, "eclipse_ml_dsa_generate: ML-DSA key pair generated") == 1);
    CHECK(count_lines(capture, "eclipse_ml_dsa_sign: ML-DSA message signed") == 1);
    CHECK(count_lines(capture, "eclipse_ml_dsa_verify: ML-DSA signature accepted") == 1);
    CHECK(count_lines(capture, "secret-text-for-log-test") == 0);

    char path[] = "/tmp/eclipse-log-test-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(write(fd, "existing\n", 9) == 9);
    CHECK(close(fd) == 0);
    CHECK(eclipse_log_set_file(path) == ECLIPSE_SUCCESS);
    ECLIPSE_LOG_INFO(1, "file destination");
    eclipse_log_shutdown();
    FILE *from_file = fopen(path, "r");
    CHECK(from_file != NULL);
    CHECK(count_lines(from_file, "existing") == 1);
    CHECK(count_lines(from_file, "file destination") == 1);
    CHECK(fclose(from_file) == 0);
    CHECK(unlink(path) == 0);

    char new_path[] = "/tmp/eclipse-log-new-XXXXXX";
    fd = mkstemp(new_path);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    CHECK(unlink(new_path) == 0);
    CHECK(eclipse_log_set_file(new_path) == ECLIPSE_SUCCESS);
    struct stat log_stat;
    CHECK(stat(new_path, &log_stat) == 0);
    CHECK((log_stat.st_mode & 0077) == 0);
    eclipse_log_shutdown();
    CHECK(unlink(new_path) == 0);
    CHECK(fclose(capture) == 0);
    puts("Logger tests passed");
    return EXIT_SUCCESS;
}
