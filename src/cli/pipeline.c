#define _POSIX_C_SOURCE 200809L
#include "pipeline.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/crypto.h>

#define MAX_STAGES 16u
#define MAX_WORDS 32u
#define MAX_LINE 16384u

typedef struct {
    char *words[MAX_WORDS + 1u];
    size_t count;
    bool external;
} pipeline_stage_t;

static char *trim(char *text)
{
    while (isspace((unsigned char)*text)) ++text;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return text;
}

static bool split_stages(char *line, char **parts, size_t *count)
{
    *count = 0;
    char quote = 0;
    unsigned depth = 0;
    bool escaped = false;
    parts[(*count)++] = line;
    for (char *at = line; *at != '\0'; ++at) {
        if (escaped) { escaped = false; continue; }
        if (*at == '\\') { escaped = true; continue; }
        if (quote != 0) {
            if (*at == quote) quote = 0;
            continue;
        }
        if (*at == '\'' || *at == '"') { quote = *at; continue; }
        if (*at == '(') { ++depth; continue; }
        if (*at == ')') {
            if (depth == 0) return false;
            --depth;
            continue;
        }
        if (*at == '/' && at[1] == '/' && depth == 0) {
            if (*count >= MAX_STAGES) return false;
            *at = '\0';
            parts[(*count)++] = at + 2;
            ++at;
        }
    }
    if (quote != 0 || depth != 0 || escaped) return false;
    for (size_t i = 0; i < *count; ++i) {
        parts[i] = trim(parts[i]);
        if (*parts[i] == '\0') return false;
    }
    return true;
}

static bool parse_words(char *text, pipeline_stage_t *stage)
{
    stage->count = 0;
    stage->external = false;
    text = trim(text);
    if (*text == '!') {
        stage->external = true;
        text = trim(text + 1);
    }
    if (*text == '\0') return false;

    /* Parenthesized API calls may contain spaces between commas. Keep the
       entire expression as one argument for the existing command parser. */
    size_t length = strlen(text);
    if (!stage->external &&
        (strncmp(text, "serialize(", 10) == 0 ||
         strncmp(text, "deserialize(", 12) == 0) &&
        text[length - 1] == ')') {
        stage->words[0] = text;
        stage->words[1] = NULL;
        stage->count = 1;
        return true;
    }

    char *read = text, *write = text;
    while (*read != '\0') {
        while (isspace((unsigned char)*read)) ++read;
        if (*read == '\0') break;
        if (stage->count >= MAX_WORDS) return false;
        stage->words[stage->count++] = write;
        char quote = 0;
        while (*read != '\0' && (quote != 0 || !isspace((unsigned char)*read))) {
            char ch = *read++;
            if (ch == '\\' && *read != '\0') { *write++ = *read++; continue; }
            if (quote != 0) {
                if (ch == quote) quote = 0;
                else *write++ = ch;
            } else if (ch == '\'' || ch == '"') quote = ch;
            else *write++ = ch;
        }
        if (quote != 0) return false;
        /* Advance before placing NUL: read and write can point at the same
           separating space when no quotes or escapes were present. */
        while (isspace((unsigned char)*read)) ++read;
        *write++ = '\0';
    }
    stage->words[stage->count] = NULL;
    return stage->count > 0;
}

static void run_child(const pipeline_stage_t *stage,
                      const eclipse_cli_pipeline_options_t *options)
{
    if (stage->external) {
        execvp(stage->words[0], stage->words);
    } else {
        char level[2] = {(char)('0' + options->log_level), '\0'};
        char *argv[MAX_WORDS + 7u];
        size_t at = 0;
        argv[at++] = (char *)options->program;
        argv[at++] = "--log-level";
        argv[at++] = level;
        if (options->log_file != NULL) {
            argv[at++] = "--log-file";
            argv[at++] = (char *)options->log_file;
        }
        for (size_t i = 0; i < stage->count; ++i)
            argv[at++] = stage->words[i];
        argv[at] = NULL;
        execvp(options->program, argv);
    }
    /* Command data might be a secret, so never echo argv on exec failure. */
    fprintf(stderr, "Pipeline stage could not start: %s\n", strerror(errno));
    _exit(127);
}

int eclipse_cli_run_pipeline(const char *line,
                             const eclipse_cli_pipeline_options_t *options)
{
    if (line == NULL || options == NULL || options->program == NULL ||
        strlen(line) >= MAX_LINE || options->log_level > 5) {
        ECLIPSE_LOG_WARNING("pipeline rejected invalid input or options");
        return 2;
    }
    char *storage = strdup(line);
    if (storage == NULL) return 1;
    char *parts[MAX_STAGES];
    pipeline_stage_t stages[MAX_STAGES] = {0};
    size_t count = 0;
    if (!split_stages(storage, parts, &count)) {
        ECLIPSE_LOG_WARNING("pipeline syntax rejected");
        OPENSSL_cleanse(storage, strlen(line) + 1);
        free(storage);
        return 2;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!parse_words(parts[i], &stages[i])) {
            ECLIPSE_LOG_WARNING("pipeline stage syntax rejected");
            OPENSSL_cleanse(storage, strlen(line) + 1);
            free(storage);
            return 2;
        }
    }

    ECLIPSE_LOG_INFO(2, "pipeline executing %zu stage(s)", count);
    pid_t children[MAX_STAGES];
    size_t launched = 0;
    int previous_read = -1;
    int result = 0;
    for (size_t i = 0; i < count; ++i) {
        int next_pipe[2] = {-1, -1};
        if (i + 1 < count && pipe(next_pipe) != 0) {
            ECLIPSE_LOG_ERROR("pipeline pipe creation failed");
            result = 1;
            break;
        }
        pid_t child = fork();
        if (child == 0) {
            if (previous_read >= 0 && dup2(previous_read, STDIN_FILENO) < 0)
                _exit(127);
            if (next_pipe[1] >= 0 && dup2(next_pipe[1], STDOUT_FILENO) < 0)
                _exit(127);
            if (previous_read >= 0) close(previous_read);
            if (next_pipe[0] >= 0) close(next_pipe[0]);
            if (next_pipe[1] >= 0) close(next_pipe[1]);
            run_child(&stages[i], options);
        }
        if (child < 0) {
            ECLIPSE_LOG_ERROR("pipeline process creation failed");
            if (next_pipe[0] >= 0) close(next_pipe[0]);
            if (next_pipe[1] >= 0) close(next_pipe[1]);
            result = 1;
            break;
        }
        children[launched++] = child;
        if (previous_read >= 0) close(previous_read);
        if (next_pipe[1] >= 0) close(next_pipe[1]);
        previous_read = next_pipe[0];
    }
    if (previous_read >= 0) close(previous_read);
    for (size_t i = 0; i < launched; ++i) {
        int status = 0;
        pid_t waited;
        do { waited = waitpid(children[i], &status, 0); }
        while (waited < 0 && errno == EINTR);
        if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            if (result == 0)
                result = waited >= 0 && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            ECLIPSE_LOG_WARNING("pipeline stage %zu failed", i + 1);
        }
    }
    OPENSSL_cleanse(storage, strlen(line) + 1);
    free(storage);
    if (result == 0) ECLIPSE_LOG_INFO(2, "pipeline completed");
    return result;
}

int eclipse_cli_shell(const eclipse_cli_pipeline_options_t *options)
{
    if (options == NULL) return 2;
    char line[MAX_LINE];
    bool interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    int last_status = 0;
    ECLIPSE_LOG_INFO(1, "developer pipeline shell started");
    for (;;) {
        if (interactive) { fputs("eclipse> ", stdout); fflush(stdout); }
        if (fgets(line, sizeof(line), stdin) == NULL) break;
        size_t length = strlen(line);
        if (length > 0 && line[length - 1] != '\n' && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {}
            fputs("Input line is too long.\n", stderr);
            last_status = 2;
            OPENSSL_cleanse(line, sizeof(line));
            continue;
        }
        char *command = trim(line);
        if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
            OPENSSL_cleanse(line, sizeof(line));
            break;
        }
        if (*command != '\0') {
            last_status = eclipse_cli_run_pipeline(command, options);
            if (last_status != 0 && interactive)
                fprintf(stderr, "Command exited with status %d.\n", last_status);
        }
        OPENSSL_cleanse(line, sizeof(line));
    }
    ECLIPSE_LOG_INFO(1, "developer pipeline shell stopped");
    return last_status;
}
