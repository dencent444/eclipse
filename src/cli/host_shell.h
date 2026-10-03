#ifndef ECLIPSE_CLI_HOST_SHELL_H
#define ECLIPSE_CLI_HOST_SHELL_H

#include <stdio.h>

typedef enum {
    ECLIPSE_HOST_SHELL_UNKNOWN,
    ECLIPSE_HOST_SHELL_POSIX,
    ECLIPSE_HOST_SHELL_BASH,
    ECLIPSE_HOST_SHELL_ZSH,
    ECLIPSE_HOST_SHELL_FISH,
    ECLIPSE_HOST_SHELL_POWERSHELL
} eclipse_host_shell_kind_t;

typedef struct {
    eclipse_host_shell_kind_t kind;
    const char *name;
    const char *source;
} eclipse_host_shell_t;

/* Inspect the direct parent on Linux, then fall back to the configured SHELL.
 * SHELL alone may describe a login shell rather than the invoking process. */
eclipse_host_shell_t eclipse_host_shell_detect(void);
eclipse_host_shell_kind_t eclipse_host_shell_classify(const char *name);
void eclipse_host_shell_print_guide(FILE *stream, eclipse_host_shell_t shell);

#endif
