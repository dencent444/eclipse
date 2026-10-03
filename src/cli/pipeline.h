#ifndef ECLIPSE_CLI_PIPELINE_H
#define ECLIPSE_CLI_PIPELINE_H

typedef struct {
    const char *program;
    unsigned log_level;
    const char *log_file;
    const char *host_shell_name;
} eclipse_cli_pipeline_options_t;

/* A developer-only REPL and explicit // pipeline. External stages require !.
 * Stage words support simple quotes and backslash escapes, but no shell
 * expansion. Data goes over OS pipes; logs remain on stderr or in the file. */
int eclipse_cli_run_pipeline(const char *line,
                             const eclipse_cli_pipeline_options_t *options);
int eclipse_cli_pipeline_from_stdin(const eclipse_cli_pipeline_options_t *options);
int eclipse_cli_shell(const eclipse_cli_pipeline_options_t *options);

#endif
