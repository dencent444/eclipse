#include "host_shell.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *name = slash == NULL ? path : slash + 1;
    /* Login shells may prefix argv[0] with '-'. */
    return *name == '-' ? name + 1 : name;
}

eclipse_host_shell_kind_t eclipse_host_shell_classify(const char *path)
{
    if (path == NULL || *path == '\0') return ECLIPSE_HOST_SHELL_UNKNOWN;
    const char *name = basename_of(path);
    if (strcmp(name, "bash") == 0) return ECLIPSE_HOST_SHELL_BASH;
    if (strcmp(name, "zsh") == 0) return ECLIPSE_HOST_SHELL_ZSH;
    if (strcmp(name, "fish") == 0) return ECLIPSE_HOST_SHELL_FISH;
    if (strcmp(name, "pwsh") == 0 || strcmp(name, "powershell") == 0)
        return ECLIPSE_HOST_SHELL_POWERSHELL;
    if (strcmp(name, "sh") == 0 || strcmp(name, "dash") == 0 ||
        strcmp(name, "ash") == 0 || strcmp(name, "ksh") == 0 ||
        strcmp(name, "mksh") == 0)
        return ECLIPSE_HOST_SHELL_POSIX;
    return ECLIPSE_HOST_SHELL_UNKNOWN;
}

static const char *shell_name(eclipse_host_shell_kind_t kind)
{
    switch (kind) {
    case ECLIPSE_HOST_SHELL_BASH: return "bash";
    case ECLIPSE_HOST_SHELL_ZSH: return "zsh";
    case ECLIPSE_HOST_SHELL_FISH: return "fish";
    case ECLIPSE_HOST_SHELL_POWERSHELL: return "PowerShell";
    case ECLIPSE_HOST_SHELL_POSIX: return "POSIX shell";
    default: return "unknown";
    }
}

eclipse_host_shell_t eclipse_host_shell_detect(void)
{
    eclipse_host_shell_t result = {ECLIPSE_HOST_SHELL_UNKNOWN, "unknown", "none"};
#ifdef __linux__
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%ld/comm", (long)getppid()) > 0) {
        FILE *parent = fopen(path, "r");
        if (parent != NULL) {
            char name[64];
            if (fgets(name, sizeof(name), parent) != NULL) {
                name[strcspn(name, "\r\n")] = '\0';
                result.kind = eclipse_host_shell_classify(name);
                if (result.kind != ECLIPSE_HOST_SHELL_UNKNOWN) {
                    result.name = shell_name(result.kind);
                    result.source = "parent process";
                }
            }
            fclose(parent);
        }
    }
#endif
    if (result.kind == ECLIPSE_HOST_SHELL_UNKNOWN) {
        result.kind = eclipse_host_shell_classify(getenv("SHELL"));
        if (result.kind != ECLIPSE_HOST_SHELL_UNKNOWN) {
            result.name = shell_name(result.kind);
            result.source = "SHELL environment hint";
        }
    }
    return result;
}

void eclipse_host_shell_print_guide(FILE *stream, eclipse_host_shell_t shell)
{
    fprintf(stream, "Detected outer shell: %s (%s).\n", shell.name, shell.source);
    switch (shell.kind) {
    case ECLIPSE_HOST_SHELL_BASH:
    case ECLIPSE_HOST_SHELL_ZSH:
        fputs("For bash/zsh, single-quote a full pipe expression so !, () and // reach Eclipse unchanged.\n", stream);
        break;
    case ECLIPSE_HOST_SHELL_FISH:
        fputs("For fish, single-quote a full pipe expression so parentheses and wildcards reach Eclipse unchanged.\n", stream);
        break;
    case ECLIPSE_HOST_SHELL_POWERSHELL:
        fputs("For PowerShell, pass a full pipe expression as one single-quoted argument.\n", stream);
        break;
    case ECLIPSE_HOST_SHELL_POSIX:
        fputs("For this shell, single-quote a full pipe expression to preserve punctuation.\n", stream);
        break;
    default:
        fputs("Shell-specific quoting is unknown; use the Eclipse shell for raw expressions.\n", stream);
        break;
    }
    fputs("Example: eclipse-cli pipe 'math mod -1 // !cat'\n"
          "For arbitrary or secret text, run eclipse-cli shell, or pass one line to eclipse-cli pipe -.\n"
          "The outer shell parses its command line before Eclipse starts; Eclipse cannot recover altered arguments.\n",
          stream);
}
