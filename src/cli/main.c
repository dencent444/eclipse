/* Developer interface for APIs that already exist in eclipse_core.
 * Parsing and display live here; consensus serialization stays in block.c.
 * Never log raw CLI arguments: a later command may carry private material.
 */
#include "block/block.h"
#include "block/chain.h"
#include "block/miner.h"
#include "crypto/ml_dsa.h"
#include "crypto/ml_dsa_math.h"
#include "encoding/base92.h"
#include "log.h"
#include "particle/particle.h"
#include "platform.h"
#include "tx/tx.h"
#include "tx/utxo.h"
#include "wallet/wallet.h"
#include "wallet/keypair.h"
#include "pipeline.h"
#include "host_shell.h"

#include <openssl/crypto.h>

#include <curses.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { CLI_OK = 0, CLI_ERROR = 1, CLI_USAGE = 2 };
static eclipse_cli_pipeline_options_t pipeline_options;
static eclipse_host_shell_t host_shell;

/* Print the implemented command surface and guidance for the detected outer
 * shell. Help is output only; it never executes a command or exposes keys. */
static void usage(FILE *stream)
{
    fputs("Usage: eclipse-cli [--log-level 0..5] [--log-file PATH] [COMMAND]\n"
          "\n"
          "With no command, open the ncurses menu.\n"
          "Commands:\n"
          "  serialize                         Prompt for six block-header fields\n"
          "  serialize VERSION TIMESTAMP DIFFICULTY NONCE PREV_HASH MERKLE_ROOT\n"
          "  'serialize(VERSION,TIMESTAMP,DIFFICULTY,NONCE,PREV_HASH,MERKLE_ROOT)'\n"
          "  deserialize                       Prompt for a serialized header\n"
          "  deserialize HEX                   Decode exactly 88 bytes of hex\n"
          "  'deserialize(HEX)'\n"
          "  math mod SIGNED_INTEGER\n"
          "  math add|sub|mul LEFT RIGHT\n"
          "  ml-dsa self-test 44|65|87 MESSAGE [CONTEXT]\n"
          "  ml-dsa derive-public 44|65|87 SEED_HEX32\n"
          "  keypair generate 44|65|87\n"
          "  base92 encode HEX | base92 decode TEXT\n"
          "  particle create AMOUNT RECEIVE_HEX32 SPEND_HEX32\n"
          "  particle commit AMOUNT RECEIVE_HEX32 SPEND_HEX32 RANDOM_HEX32\n"
          "  particle verify AMOUNT RECEIVE_HEX32 SPEND_HEX32 RANDOM_HEX32 COMMIT_HEX32\n"
          "  tx demo                           Build one local signed dev transfer\n"
          "  tx decode HEX|-                   Inspect one signed dev transaction\n"
          "  block demo                        Mine and emit one dev block as hex\n"
          "  block decode HEX|-                Inspect a canonical dev block\n"
          "  chain demo                        Mine, transfer, and validate on two nodes\n"
          "  wallet create 44|65|87\n"
          "  wallet domain ROOT_BASE92 receive|spend\n"
          "  wallet public ROOT_BASE92 receive|spend master|INDEX\n"
          "  wallet role-public DOMAIN_BASE92 receive|spend master|INDEX\n"
          "  wallet public-decode PUBLIC_BASE92\n"
          "  wallet verify ROOT_BASE92 receive|spend INDEX\n"
          "  shell                             Line-oriented developer shell\n"
          "  shell-info                        Show detected shell and input guidance\n"
          "  build-info                        Show compiled target OS and architecture\n"
          "  pipe 'COMMAND // COMMAND // !FILTER ARGS'\n"
          "  pipe                             Prompt for one raw pipeline line\n"
          "  pipe -                           Read one raw pipeline line from stdin\n"
          "\n"
          "Integers are decimal or 0x-prefixed hex, except math mod (decimal).\n"
          "Hashes are exactly 32 bytes (64 hex digits), without a 0x prefix.\n"
          "The serialized header is exactly 88 bytes (176 hex digits).\n"
          "Use - in place of a single input value to read one line from stdin.\n"
          "In the developer shell, // pipes stdout into the next stage.\n"
          "A stage beginning with ! runs an external program (no shell expansion).\n"
          "Wallet create/domain output unencrypted secrets; protect stdout.\n"
          "Quote the parenthesized form in a shell. Logs go to stderr by default.\n",
          stream);
    eclipse_host_shell_print_guide(stream, host_shell);
}

/* Trim a mutable field in place and return a pointer inside its buffer. */
static char *trim(char *text)
{
    while (isspace((unsigned char)*text)) ++text;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return text;
}

/* Parse a whole unsigned number and enforce the field's maximum. Decimal is
 * the default, and only an explicit 0x prefix selects hexadecimal. */
static bool parse_unsigned(const char *text, uint64_t maximum, uint64_t *out)
{
    /* Base 10 by default avoids strtoull's surprising leading-zero octal
       interpretation. The only alternate spelling is an explicit 0x prefix. */
    if (*text == '\0' || *text == '-' || *text == '+') return false;
    int base = text[0] == '0' && (text[1] == 'x' || text[1] == 'X') ? 16 : 10;
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, base);
    if (errno == ERANGE || end == text || *end != '\0' || value > maximum)
        return false;
    *out = (uint64_t)value;
    return true;
}

/* Signed decimal parser used by the educational modular-arithmetic command. */
static bool parse_signed(const char *text, int64_t *out)
{
    if (*text == '\0') return false;
    errno = 0;
    char *end;
    long long value = strtoll(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0') return false;
    *out = (int64_t)value;
    return true;
}

/* Map one ASCII hex character to 0..15, or -1 for invalid input. */
static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Decode exactly bytes*2 hex characters. A field with a suffix or missing
 * digits is rejected rather than silently accepted. */
static bool parse_hex(const char *hex, uint8_t *out, size_t bytes)
{
    /* Exact length matters: silently accepting a suffix would conceal a
       caller mistake while testing the wire format. */
    if (strlen(hex) != bytes * 2) return false;
    for (size_t i = 0; i < bytes; ++i) {
        int high = hex_digit(hex[2 * i]);
        int low = hex_digit(hex[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

/* Read one piped value, trim it, and reject extra non-whitespace stdin.
 * This keeps a secret root or packet from accidentally swallowing a second
 * value that the receiving command would otherwise ignore. */
static bool read_stream_token(char *buffer, size_t capacity)
{
    if (capacity < 2 || fgets(buffer, (int)capacity, stdin) == NULL) return false;
    size_t length = strlen(buffer);
    if (length == capacity - 1 && buffer[length - 1] != '\n') return false;
    char *value = trim(buffer);
    if (*value == '\0') return false;
    if (value != buffer) memmove(buffer, value, strlen(value) + 1);
    /* A piped command consumes exactly one value. Extra nonblank lines are a
       likely mistake, especially when the value is a secret root. */
    int ch;
    while ((ch = getchar()) != EOF)
        if (!isspace((unsigned char)ch)) return false;
    return true;
}

/* A literal '-' means one value should come from stdin. The returned pointer
 * is borrowed from argv or buffer; the caller must cleanse buffer afterward. */
static const char *resolve_input(const char *argument, char *buffer, size_t capacity)
{
    if (strcmp(argument, "-") != 0) return argument;
    if (isatty(STDIN_FILENO) || !read_stream_token(buffer, capacity)) {
        ECLIPSE_LOG_WARNING("piped command input is missing or malformed");
        return NULL;
    }
    return buffer;
}

/* Give field-specific feedback before the user leaves the ncurses form. */
static bool valid_serialize_field(size_t index, const char *text)
{
    /* Immediate TUI feedback is separate from serialize_fields' final check:
       positional and parenthesized calls must obey the same constraints. */
    char copy[256];
    (void)snprintf(copy, sizeof(copy), "%s", text);
    char *value = trim(copy);
    uint64_t parsed;
    uint8_t hash[32];
    if (index == 0 || index == 2)
        return parse_unsigned(value, UINT32_MAX, &parsed);
    if (index == 1 || index == 3)
        return parse_unsigned(value, UINT64_MAX, &parsed);
    return parse_hex(value, hash, sizeof(hash));
}

/* The interactive deserializer expects one complete 88-byte header in hex. */
static bool valid_deserialize_field(size_t index, const char *text)
{
    (void)index;
    char copy[256];
    (void)snprintf(copy, sizeof(copy), "%s", text);
    uint8_t header[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    return parse_hex(trim(copy), header, sizeof(header));
}

/* The binary header remains the source of truth; this is presentation only.
 * The caller allocates at least 2*length+1 bytes for output. */
static void format_hex(const uint8_t *bytes, size_t length, char *output)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        output[2 * i] = digits[bytes[i] >> 4];
        output[2 * i + 1] = digits[bytes[i] & 15];
    }
    output[2 * length] = '\0';
}

/* Start ncurses only for genuine terminals. Positional commands keep stdout
 * free of terminal control sequences so they can be used in pipelines. */
static bool tui_begin(void)
{
    /* Keep scriptable commands free of ncurses control sequences. */
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fputs("Interactive mode requires a terminal; pass arguments for scripts.\n", stderr);
        return false;
    }
    const char *term = getenv("TERM");
    if (term == NULL || *term == '\0' || strcmp(term, "dumb") == 0) {
        fputs("Interactive mode requires a terminal with TERM set.\n", stderr);
        return false;
    }
    if (initscr() == NULL) {
        fputs("Could not initialize ncurses.\n", stderr);
        return false;
    }
    if (LINES < 8 || COLS < 60) {
        endwin();
        fputs("Terminal must be at least 60 columns by 8 rows.\n", stderr);
        return false;
    }
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    (void)curs_set(1);
    return true;
}

/* Pause an active form until the terminal is large enough or Esc cancels. */
static bool tui_wait_for_resize(void)
{
    if (LINES >= 8 && COLS >= 60) return true;
    erase();
    mvaddstr(0, 0, "Resize to 60x8, or press Esc to cancel");
    refresh();
    return getch() != 27;
}

/* Walk through form fields one at a time. Invalid input stays on screen for
 * correction, while Esc cancels the form without calling any core API. */
static bool tui_collect(const char *title, const char **labels,
                        char fields[][256], size_t count,
                        bool (*valid_field)(size_t, const char *))
{
    if (!tui_begin()) return false;
    unsigned rejected = 0;
    for (size_t field = 0; field < count; ++field) {
        size_t used = 0;
        bool invalid = false;
        fields[field][0] = '\0';
        for (;;) {
            if (LINES < 8 || COLS < 60) {
                if (!tui_wait_for_resize()) {
                    endwin();
                    return false;
                }
                continue;
            }
            erase();
            mvprintw(1, 2, "%s", title);
            mvprintw(3, 2, "Field %zu/%zu: %s", field + 1, count, labels[field]);
            mvprintw(4, 2, "Enter: next | Backspace: edit | Esc: cancel");
            if (invalid) mvprintw(5, 2, "Invalid value; check its length and format");
            /* Keep the tail of long hex input visible on narrow terminals. */
            size_t visible = (size_t)(COLS - 5);
            size_t start = used > visible ? used - visible : 0;
            mvprintw(6, 2, "> %s", fields[field] + start);
            move(6, (int)(4 + used - start));
            refresh();
            int ch = getch();
            if (ch == 27 || ch == 4) {
                endwin();
                if (rejected > 0)
                    ECLIPSE_LOG_INFO(4, "%u invalid interactive field entries", rejected);
                return false;
            }
            if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                if (used != 0 && valid_field(field, fields[field])) break;
                invalid = true;
                ++rejected;
                beep();
            } else if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
                if (used > 0) fields[field][--used] = '\0';
                invalid = false;
            } else if (ch >= 32 && ch <= 126 && used + 1 < 256) {
                fields[field][used++] = (char)ch;
                fields[field][used] = '\0';
                invalid = false;
            } else {
                beep();
            }
        }
    }
    endwin();
    if (rejected > 0)
        ECLIPSE_LOG_INFO(4, "%u invalid interactive field entries corrected", rejected);
    return true;
}

/* Show a potentially long result in a scrollable ncurses viewport. The
 * caller also prints the same result to stdout after the UI closes. */
static void tui_result(const char *title, const char *result)
{
    if (!tui_begin()) return;
    size_t first_row = 0;
    for (;;) {
        if (LINES < 8 || COLS < 60) {
            if (!tui_wait_for_resize()) break;
            continue;
        }
        erase();
        mvprintw(1, 2, "%s", title);
        size_t width = (size_t)(COLS - 4);
        size_t available = (size_t)(LINES - 6);
        size_t physical_row = 0;
        const char *cursor = result;
        /* Wrap logical lines and render a scrollable viewport. The 176-byte
           header hex can occupy several rows on a small terminal. */
        while (*cursor != '\0') {
            const char *newline = strchr(cursor, '\n');
            size_t length = newline == NULL ? strlen(cursor) : (size_t)(newline - cursor);
            do {
                size_t chunk = length < width ? length : width;
                if (physical_row >= first_row && physical_row < first_row + available)
                    mvprintw((int)(3 + physical_row - first_row), 2,
                             "%.*s", (int)chunk, cursor);
                ++physical_row;
                cursor += chunk;
                length -= chunk;
            } while (length > 0);
            if (newline == NULL) break;
            cursor = newline + 1;
        }
        mvprintw(LINES - 2, 2, "Up/Down: scroll | Enter/Esc: close");
        refresh();
        int ch = getch();
        if (ch == KEY_UP && first_row > 0) --first_row;
        else if (ch == KEY_DOWN && first_row + available < physical_row) ++first_row;
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER || ch == 27) break;
    }
    endwin();
}

/* Parse the convenient name(a,b,...) form into a bounded, mutable copy.
 * Only the expected number of nonempty fields is accepted. */
static bool parse_call(const char *command, const char *name,
                       char *storage, size_t capacity, char **parts,
                       size_t expected)
{
    /* A shell passes the quoted name(...) form as one argv element. Split a
       bounded copy so argv itself remains untouched. Nested calls do not
       exist in this CLI's input grammar. */
    size_t name_length = strlen(name);
    size_t length = strlen(command);
    if (length < name_length + 2 ||
        strncmp(command, name, name_length) != 0 ||
        command[name_length] != '(' || command[length - 1] != ')' ||
        length - name_length - 2 >= capacity)
        return false;

    size_t inner_length = length - name_length - 2;
    memcpy(storage, command + name_length + 1, inner_length);
    storage[inner_length] = '\0';
    char *cursor = storage;
    for (size_t i = 0; i < expected; ++i) {
        char *comma = strchr(cursor, ',');
        if ((i + 1 < expected && comma == NULL) ||
            (i + 1 == expected && comma != NULL))
            return false;
        if (comma != NULL) *comma = '\0';
        parts[i] = trim(cursor);
        if (*parts[i] == '\0') return false;
        if (comma != NULL) cursor = comma + 1;
    }
    return true;
}

/* Validate six text fields, build a header object, then call the real binary
 * serializer. The CLI owns presentation, while block.c owns wire bytes. */
static int serialize_fields(char **fields, char output[177])
{
    /* Validate every field before calling the protocol serializer. */
    ECLIPSE_LOG_INFO(3, "validating block header fields for serialization");
    uint64_t values[4];
    static const uint64_t limits[4] = {UINT32_MAX, UINT64_MAX, UINT32_MAX, UINT64_MAX};
    static const char *names[4] = {"version", "timestamp", "difficulty", "nonce"};
    for (size_t i = 0; i < 4; ++i) {
        if (!parse_unsigned(fields[i], limits[i], &values[i])) {
            fprintf(stderr, "Invalid %s; expected an unsigned integer in range.\n", names[i]);
            ECLIPSE_LOG_WARNING("serialize rejected invalid %s", names[i]);
            return CLI_USAGE;
        }
    }

    eclipse_block_header_t header = {0};
    header.version = (uint32_t)values[0];
    header.timestamp = values[1];
    header.difficulty = (uint32_t)values[2];
    header.nonce = values[3];
    if (!parse_hex(fields[4], header.prev_block_hash, sizeof(header.prev_block_hash)) ||
        !parse_hex(fields[5], header.merkle_root, sizeof(header.merkle_root))) {
        fputs("Hashes must each contain exactly 64 hex digits.\n", stderr);
        ECLIPSE_LOG_WARNING("serialize rejected an invalid hash field");
        return CLI_USAGE;
    }

    uint8_t wire[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    eclipse_error_t status = eclipse_block_header_serialize(&header, wire, sizeof(wire));
    if (status != ECLIPSE_SUCCESS) {
        fprintf(stderr, "Header serialization failed (code %d).\n", status);
        ECLIPSE_LOG_ERROR("header serialization failed with code %d", status);
        return CLI_ERROR;
    }
    format_hex(wire, sizeof(wire), output);
    ECLIPSE_LOG_INFO(2, "block header serialized by CLI");
    return CLI_OK;
}

/* Choose positional fields or a six-step ncurses form, then use the same
 * serializer in either path so their validation rules cannot diverge. */
static int serialize_command(int count, char **args)
{
    if (count != 0 && count != 6) {
        fputs("serialize needs exactly six fields.\n", stderr);
        return CLI_USAGE;
    }
    static const char *labels[6] = {
        "version", "timestamp", "difficulty", "nonce",
        "prev_block_hash (64 hex digits)", "merkle_root (64 hex digits)"
    };
    char input[6][256];
    char *fields[6];
    if (count == 0) {
        ECLIPSE_LOG_INFO(2, "opening interactive block header serializer");
        if (!tui_collect("Serialize block header", labels, input, 6,
                         valid_serialize_field)) {
            ECLIPSE_LOG_INFO(2, "interactive block header serializer cancelled");
            return CLI_USAGE;
        }
        for (size_t i = 0; i < 6; ++i) fields[i] = trim(input[i]);
    } else {
        for (size_t i = 0; i < 6; ++i) fields[i] = args[i];
    }
    char output[177];
    int status = serialize_fields(fields, output);
    if (status == CLI_OK) {
        if (count == 0) tui_result("Serialized block header", output);
        puts(output);
    }
    return status;
}

/* Decode a complete hex header through block.c, then format named fields for
 * humans. This function does not decide whether the block is consensus-valid. */
static int deserialize_field(const char *hex, char output[320])
{
    ECLIPSE_LOG_INFO(3, "validating serialized block header input");
    uint8_t wire[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    if (!parse_hex(hex, wire, sizeof(wire))) {
        fputs("Header must contain exactly 176 hex digits.\n", stderr);
        ECLIPSE_LOG_WARNING("deserialize rejected invalid header hex");
        return CLI_USAGE;
    }
    eclipse_block_header_t header = {0};
    eclipse_error_t status = eclipse_block_header_deserialize(wire, &header, sizeof(wire));
    if (status != ECLIPSE_SUCCESS) {
        fprintf(stderr, "Header deserialization failed (code %d).\n", status);
        ECLIPSE_LOG_ERROR("header deserialization failed with code %d", status);
        return CLI_ERROR;
    }
    char previous[65];
    char merkle[65];
    format_hex(header.prev_block_hash, sizeof(header.prev_block_hash), previous);
    format_hex(header.merkle_root, sizeof(header.merkle_root), merkle);
    int written = snprintf(output, 320,
                           "version=%" PRIu32 "\ntimestamp=%" PRIu64
                           "\ndifficulty=%" PRIu32 "\nnonce=%" PRIu64
                           "\nprev_block_hash=%s\nmerkle_root=%s",
                           header.version, header.timestamp, header.difficulty,
                           header.nonce, previous, merkle);
    if (written < 0 || written >= 320) {
        ECLIPSE_LOG_ERROR("CLI header output formatting failed");
        return CLI_ERROR;
    }
    ECLIPSE_LOG_INFO(2, "block header deserialized by CLI");
    return CLI_OK;
}

/* Accept one positional hex value, a piped line, or an interactive form.
 * The piped path never initializes ncurses or adds control bytes to stdout. */
static int deserialize_command(int count, char **args)
{
    if (count != 0 && count != 1) {
        fputs("deserialize accepts one header hex value.\n", stderr);
        return CLI_USAGE;
    }
    const char *hex;
    char input[1][256];
    if (count == 0) {
        if (!isatty(STDIN_FILENO)) {
            if (!read_stream_token(input[0], sizeof(input[0]))) {
                ECLIPSE_LOG_WARNING("deserializer pipe input is missing or malformed");
                OPENSSL_cleanse(input, sizeof(input));
                return CLI_USAGE;
            }
        } else {
            const char *label = "serialized header (176 hex digits)";
            ECLIPSE_LOG_INFO(2, "opening interactive block header deserializer");
            if (!tui_collect("Deserialize block header", &label, input, 1,
                             valid_deserialize_field)) {
                ECLIPSE_LOG_INFO(2, "interactive block header deserializer cancelled");
                return CLI_USAGE;
            }
        }
        hex = trim(input[0]);
    } else {
        hex = args[0];
    }
    char output[320];
    int status = deserialize_field(hex, output);
    if (status == CLI_OK) {
        if (count == 0 && isatty(STDIN_FILENO))
            tui_result("Deserialized block header", output);
        puts(output);
    }
    OPENSSL_cleanse(input, sizeof(input));
    return status;
}

/* Small inspection surface for the project's existing ML-DSA ring helpers.
 * It handles integers only; polynomial routines remain covered by C tests. */
static int math_command(int count, char **args)
{
    ECLIPSE_LOG_INFO(2, "modular arithmetic command selected");
    if (count == 2 && strcmp(args[0], "mod") == 0) {
        int64_t value;
        if (!parse_signed(args[1], &value)) {
            fputs("math mod requires a signed 64-bit decimal integer.\n", stderr);
            return CLI_USAGE;
        }
        printf("%" PRIu32 "\n", eclipse_ml_dsa_mod_q(value));
        ECLIPSE_LOG_INFO(3, "modular reduction completed");
        return CLI_OK;
    }
    if (count == 3 && (strcmp(args[0], "add") == 0 ||
                       strcmp(args[0], "sub") == 0 ||
                       strcmp(args[0], "mul") == 0)) {
        uint64_t left, right;
        if (!parse_unsigned(args[1], UINT32_MAX, &left) ||
            !parse_unsigned(args[2], UINT32_MAX, &right)) {
            fputs("math operands must be unsigned 32-bit integers.\n", stderr);
            return CLI_USAGE;
        }
        uint32_t result;
        if (strcmp(args[0], "add") == 0)
            result = eclipse_ml_dsa_add_q((uint32_t)left, (uint32_t)right);
        else if (strcmp(args[0], "sub") == 0)
            result = eclipse_ml_dsa_sub_q((uint32_t)left, (uint32_t)right);
        else
            result = eclipse_ml_dsa_mul_q((uint32_t)left, (uint32_t)right);
        printf("%" PRIu32 "\n", result);
        ECLIPSE_LOG_INFO(3, "binary modular arithmetic completed");
        return CLI_OK;
    }
    fputs("Use math mod VALUE or math add|sub|mul LEFT RIGHT.\n", stderr);
    return CLI_USAGE;
}

/* Map user-facing 44/65/87 names to the local API enum. */
static bool parse_scheme(const char *text, eclipse_ml_dsa_scheme_t *out)
{
    if (strcmp(text, "44") == 0) *out = ECLIPSE_ML_DSA_44;
    else if (strcmp(text, "65") == 0) *out = ECLIPSE_ML_DSA_65;
    else if (strcmp(text, "87") == 0) *out = ECLIPSE_ML_DSA_87;
    else return false;
    return true;
}

/* Only the two currently implemented wallet domains are user-selectable. */
static bool parse_role(const char *text, eclipse_wallet_role_t *out)
{
    if (strcmp(text, "receive") == 0) *out = ECLIPSE_WALLET_RECEIVE;
    else if (strcmp(text, "spend") == 0) *out = ECLIPSE_WALLET_SPEND;
    else return false;
    return true;
}

/* Deterministically derive a public key from an explicit 32-byte test seed.
 * The seed is never logged and its parsed stack copy is wiped before return. */
static int ml_dsa_derive_public(int count, char **args)
{
    if (count != 3) return CLI_USAGE;
    eclipse_ml_dsa_scheme_t scheme;
    uint8_t seed[32];
    if (!parse_scheme(args[1], &scheme) || !parse_hex(args[2], seed, sizeof(seed))) {
        OPENSSL_cleanse(seed, sizeof(seed));
        fputs("Use ml-dsa derive-public 44|65|87 SEED_HEX32.\n", stderr);
        return CLI_USAGE;
    }
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(scheme, &info)) {
        OPENSSL_cleanse(seed, sizeof(seed));
        return CLI_ERROR;
    }
    uint8_t *public_key = malloc(info.public_key_size);
    char *hex = malloc(info.public_key_size * 2 + 1);
    eclipse_ml_dsa_key_t *key = NULL;
    eclipse_error_t status = public_key == NULL || hex == NULL ?
                             ECLIPSE_ERROR_OUT_OF_MEMORY :
                             eclipse_ml_dsa_generate_from_seed(scheme, seed,
                                                                sizeof(seed), &key);
    OPENSSL_cleanse(seed, sizeof(seed));
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_export_public(key, public_key, info.public_key_size);
    if (status == ECLIPSE_SUCCESS) {
        format_hex(public_key, info.public_key_size, hex);
        puts(hex);
        ECLIPSE_LOG_INFO(2, "seeded ML-DSA public key derived by CLI");
    } else {
        ECLIPSE_LOG_ERROR("seeded ML-DSA CLI derivation failed with code %d", status);
    }
    eclipse_ml_dsa_key_free(key);
    free(public_key);
    free(hex);
    return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
}

/* Exercise the ML-DSA wrappers end to end: generate, export/import public,
 * sign with the private key, then verify with the imported public handle. */
static int ml_dsa_command(int count, char **args)
{
    if (count > 0 && strcmp(args[0], "derive-public") == 0)
        return ml_dsa_derive_public(count, args);
    ECLIPSE_LOG_INFO(2, "ML-DSA self-test command selected");
    if ((count != 3 && count != 4) || strcmp(args[0], "self-test") != 0) {
        fputs("Use ml-dsa self-test 44|65|87 MESSAGE [CONTEXT].\n", stderr);
        return CLI_USAGE;
    }
    eclipse_ml_dsa_scheme_t scheme;
    if (!parse_scheme(args[1], &scheme)) {
        fputs("Scheme must be 44, 65, or 87.\n", stderr);
        return CLI_USAGE;
    }
    const uint8_t *message = (const uint8_t *)args[2];
    const uint8_t *context = count == 4 ? (const uint8_t *)args[3] : NULL;
    size_t context_length = count == 4 ? strlen(args[3]) : 0;
    if (context_length > 255) {
        fputs("Context cannot exceed 255 bytes.\n", stderr);
        return CLI_USAGE;
    }

    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(scheme, &info)) return CLI_ERROR;
    uint8_t *public_bytes = malloc(info.public_key_size);
    uint8_t *signature = malloc(info.signature_size);
    if (public_bytes == NULL || signature == NULL) {
        free(public_bytes);
        free(signature);
        ECLIPSE_LOG_ERROR("ML-DSA CLI buffer allocation failed");
        fputs("Out of memory.\n", stderr);
        return CLI_ERROR;
    }

    eclipse_ml_dsa_key_t *private_key = NULL;
    eclipse_ml_dsa_key_t *public_key = NULL;
    /* One ephemeral key is enough to exercise every public-key wrapper.
       The self-test verifies with an imported public key, not the private
       handle, so export/import failures cannot be hidden by signing. */
    eclipse_error_t status = eclipse_ml_dsa_generate(scheme, &private_key);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_export_public(private_key, public_bytes,
                                              info.public_key_size);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_import_public(scheme, public_bytes,
                                              info.public_key_size, &public_key);
    size_t signature_length = 0;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_sign(private_key, message, strlen(args[2]),
                                     context, context_length, signature,
                                     info.signature_size, &signature_length);
    bool valid = false;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_verify(public_key, message, strlen(args[2]),
                                       context, context_length, signature,
                                       signature_length, &valid);
    eclipse_ml_dsa_key_free(public_key);
    eclipse_ml_dsa_key_free(private_key);
    free(signature);
    free(public_bytes);
    if (status != ECLIPSE_SUCCESS || !valid) {
        fprintf(stderr, "ML-DSA self-test failed (code %d).\n", status);
        ECLIPSE_LOG_ERROR("ML-DSA CLI self-test failed with code %d", status);
        return CLI_ERROR;
    }
    printf("ML-DSA-%s: valid\n", args[1]);
    ECLIPSE_LOG_INFO(2, "ML-DSA CLI self-test passed");
    return CLI_OK;
}

/* Generate the standalone wallet-keypair wrapper and print only public bytes.
 * The opaque private handle is released before this CLI process exits. */
static int keypair_command(int count, char **args)
{
    eclipse_ml_dsa_scheme_t scheme;
    if (count != 2 || strcmp(args[0], "generate") != 0 ||
        !parse_scheme(args[1], &scheme)) {
        fputs("Use keypair generate 44|65|87.\n", stderr);
        return CLI_USAGE;
    }
    eclipse_wallet_keypair_t *pair = NULL;
    eclipse_error_t status = eclipse_wallet_generate_keypair(scheme, &pair);
    const uint8_t *bytes = NULL;
    size_t length = 0;
    eclipse_ml_dsa_scheme_t actual_scheme;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_wallet_keypair_public(pair, &actual_scheme, &bytes,
                                               &length);
    if (status == ECLIPSE_SUCCESS && actual_scheme != scheme)
        status = ECLIPSE_ERROR_CRYPTO_FAILURE;
    char *hex = status == ECLIPSE_SUCCESS ? malloc(length * 2 + 1) : NULL;
    if (status == ECLIPSE_SUCCESS && hex == NULL)
        status = ECLIPSE_ERROR_OUT_OF_MEMORY;
    if (status == ECLIPSE_SUCCESS) {
        format_hex(bytes, length, hex);
        puts(hex);
        ECLIPSE_LOG_INFO(2, "standalone wallet keypair generated");
    } else {
        ECLIPSE_LOG_ERROR("standalone wallet keypair generation failed with code %d",
                          status);
    }
    free(hex);
    eclipse_wallet_keypair_free(pair);
    return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
}

/* Convert explicit hex or Base92 text through the core codec. A '-' argument
 * accepts piped data, and temporary decoded bytes are cleared on exit. */
static int base92_command(int count, char **args)
{
    if (count != 2 || (strcmp(args[0], "encode") != 0 &&
                       strcmp(args[0], "decode") != 0)) {
        fputs("Use base92 encode HEX or base92 decode TEXT.\n", stderr);
        return CLI_USAGE;
    }
    char piped[8192] = {0};
    const char *input = resolve_input(args[1], piped, sizeof(piped));
    if (input == NULL || strlen(input) >= sizeof(piped)) {
        OPENSSL_cleanse(piped, sizeof(piped));
        return CLI_USAGE;
    }
    size_t length = strlen(input);
    size_t bytes_capacity = length + 2;
    uint8_t *bytes = OPENSSL_malloc(bytes_capacity);
    char *result = malloc(bytes_capacity * 2 + 2);
    if (bytes == NULL || result == NULL) {
        OPENSSL_clear_free(bytes, bytes_capacity);
        free(result);
        OPENSSL_cleanse(piped, sizeof(piped));
        ECLIPSE_LOG_ERROR("Base92 CLI allocation failed");
        return CLI_ERROR;
    }
    eclipse_error_t status;
    if (strcmp(args[0], "encode") == 0) {
        size_t byte_count = length / 2;
        if (length % 2 != 0 || !parse_hex(input, bytes, byte_count)) {
            fputs("Base92 encode requires even-length hex.\n", stderr);
            status = ECLIPSE_ERROR_INVALID_ARGUMENT;
        } else {
            size_t written = 0;
            status = eclipse_base92_encode(bytes, byte_count, result,
                                            bytes_capacity * 2 + 2, &written);
            if (status == ECLIPSE_SUCCESS) puts(result);
        }
    } else {
        size_t written = 0;
        status = eclipse_base92_decode(input, length, bytes, bytes_capacity,
                                       &written);
        if (status == ECLIPSE_SUCCESS) {
            format_hex(bytes, written, result);
            puts(result);
        }
    }
    OPENSSL_clear_free(bytes, bytes_capacity);
    OPENSSL_cleanse(result, bytes_capacity * 2 + 2);
    free(result);
    OPENSSL_cleanse(piped, sizeof(piped));
    if (status != ECLIPSE_SUCCESS) {
        ECLIPSE_LOG_WARNING("Base92 CLI operation rejected with code %d", status);
        return CLI_USAGE;
    }
    ECLIPSE_LOG_INFO(2, "Base92 CLI operation completed");
    return CLI_OK;
}

/* Expose particle create/commit/verify without inventing transactions.
 * `create` intentionally prints the private opening for development tests;
 * no secret field is included in logger messages. */
static int particle_command(int count, char **args)
{
    bool create = count == 4 && strcmp(args[0], "create") == 0;
    bool commit = count == 5 && strcmp(args[0], "commit") == 0;
    bool verify = count == 6 && strcmp(args[0], "verify") == 0;
    if (!create && !commit && !verify) {
        fputs("Use particle create|commit|verify with amount and 32-byte hex fields.\n",
              stderr);
        return CLI_USAGE;
    }
    uint64_t amount;
    eclipse_particle_t particle = {0};
    uint8_t supplied[ECLIPSE_PARTICLE_COMMITMENT_SIZE] = {0};
    if (!parse_unsigned(args[1], UINT64_MAX, &amount) ||
        !parse_hex(args[2], particle.receive_material,
                   ECLIPSE_PARTICLE_MATERIAL_SIZE) ||
        !parse_hex(args[3], particle.spend_authority,
                   ECLIPSE_PARTICLE_MATERIAL_SIZE) ||
        (!create && !parse_hex(args[4], particle.randomness,
                               ECLIPSE_PARTICLE_RANDOMNESS_SIZE)) ||
        (verify && !parse_hex(args[5], supplied,
                               ECLIPSE_PARTICLE_COMMITMENT_SIZE))) {
        eclipse_particle_clear(&particle);
        ECLIPSE_LOG_WARNING("particle CLI rejected amount or hex field");
        return CLI_USAGE;
    }
    particle.amount = amount;
    eclipse_error_t status = ECLIPSE_SUCCESS;
    /* `create` obtains new randomness; `commit`/`verify` use the exact opening
     * supplied by the developer, which makes fixed vectors reproducible. */
    if (create)
        status = eclipse_particle_create(amount, particle.receive_material,
                                         particle.spend_authority, &particle);
    uint8_t digest[ECLIPSE_PARTICLE_COMMITMENT_SIZE] = {0};
    bool valid = false;
    if (status == ECLIPSE_SUCCESS && verify)
        status = eclipse_particle_verify_commitment(&particle, supplied,
                                                     sizeof(supplied), &valid);
    else if (status == ECLIPSE_SUCCESS)
        status = eclipse_particle_commitment(&particle, digest, sizeof(digest));
    if (status == ECLIPSE_SUCCESS) {
        if (verify) {
            printf("valid=%s\n", valid ? "true" : "false");
        } else {
            char commitment_hex[65];
            format_hex(digest, sizeof(digest), commitment_hex);
            if (create) {
                char receive_hex[65], spend_hex[65], randomness_hex[65];
                format_hex(particle.receive_material, 32, receive_hex);
                format_hex(particle.spend_authority, 32, spend_hex);
                format_hex(particle.randomness, 32, randomness_hex);
                printf("amount=%" PRIu64 "\nreceive_material=%s\n"
                       "spend_authority=%s\nrandomness=%s\n",
                       particle.amount, receive_hex, spend_hex, randomness_hex);
                OPENSSL_cleanse(receive_hex, sizeof(receive_hex));
                OPENSSL_cleanse(spend_hex, sizeof(spend_hex));
                OPENSSL_cleanse(randomness_hex, sizeof(randomness_hex));
            }
            printf("commitment=%s\n", commitment_hex);
            OPENSSL_cleanse(commitment_hex, sizeof(commitment_hex));
        }
        ECLIPSE_LOG_INFO(2, "particle CLI %s completed", args[0]);
    } else {
        ECLIPSE_LOG_ERROR("particle CLI %s failed with code %d", args[0], status);
    }
    eclipse_particle_clear(&particle);
    OPENSSL_cleanse(supplied, sizeof(supplied));
    OPENSSL_cleanse(digest, sizeof(digest));
    return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
}

/* Stable display names for the supported ML-DSA schemes. */
static const char *scheme_name(eclipse_ml_dsa_scheme_t scheme)
{
    if (scheme == ECLIPSE_ML_DSA_44) return "44";
    if (scheme == ECLIPSE_ML_DSA_65) return "65";
    if (scheme == ECLIPSE_ML_DSA_87) return "87";
    return "unknown";
}

/* Encode one standalone public key as the existing EWPK Base92 packet. */
static int print_wallet_public(const eclipse_wallet_public_key_t *key)
{
    size_t wire_size = eclipse_wallet_public_serialized_size(key->scheme);
    size_t capacity = eclipse_base92_encoded_capacity(wire_size);
    char *text = malloc(capacity);
    if (text == NULL) return CLI_ERROR;
    size_t written = 0;
    eclipse_error_t status = eclipse_wallet_public_to_base92(
        key, text, capacity, &written);
    if (status == ECLIPSE_SUCCESS) puts(text);
    free(text);
    if (status != ECLIPSE_SUCCESS)
        ECLIPSE_LOG_ERROR("wallet CLI public-key encoding failed with code %d", status);
    return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
}

/* Select the role master or one of the fixed 24 child indices. */
static bool parse_wallet_slot(const char *text, bool *master, size_t *index)
{
    if (strcmp(text, "master") == 0) {
        *master = true;
        *index = 0;
        return true;
    }
    uint64_t parsed;
    if (!parse_unsigned(text, ECLIPSE_WALLET_POOL_SIZE - 1u, &parsed))
        return false;
    *master = false;
    *index = (size_t)parsed;
    return true;
}

/* Developer entry points for recovery, role, and public-key APIs. Root and
 * domain exports are explicit plaintext results on stdout; imported secrets
 * may arrive through '-' stdin and are cleansed from local scratch buffers. */
/* Build a disposable, fully signed transparent transfer. The fixture UTXO
 * exists only in this process and the temporary keypairs are freed before
 * return; stdout carries public wire bytes for `tx decode -`. */
static int tx_demo(void)
{
    eclipse_ml_dsa_key_t *sender = NULL;
    eclipse_ml_dsa_key_t *receiver = NULL;
    eclipse_utxo_set_t *state = NULL;
    eclipse_error_t status = eclipse_ml_dsa_generate(ECLIPSE_ML_DSA_44, &sender);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_generate(ECLIPSE_ML_DSA_44, &receiver);
    if (status == ECLIPSE_SUCCESS) status = eclipse_utxo_set_create(&state);
    if (status != ECLIPSE_SUCCESS) goto done;
    eclipse_ml_dsa_info_t info;
    if (!eclipse_ml_dsa_info(ECLIPSE_ML_DSA_44, &info)) {
        status = ECLIPSE_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    eclipse_tx_output_t funding = {0};
    funding.amount = 30;
    funding.scheme = ECLIPSE_ML_DSA_44;
    funding.public_key_length = info.public_key_size;
    status = eclipse_ml_dsa_export_public(sender, funding.public_key,
                                           sizeof(funding.public_key));
    if (status != ECLIPSE_SUCCESS) goto done;
    uint8_t funding_id[ECLIPSE_TX_ID_SIZE] = {0};
    funding_id[0] = 0xd0; /* Only a local fixture identifier. */
    status = eclipse_utxo_set_seed_dev(state, funding_id, 0, &funding);
    if (status != ECLIPSE_SUCCESS) goto done;
    uint8_t receiver_public[ECLIPSE_TX_MAX_PUBLIC_KEY_SIZE];
    status = eclipse_ml_dsa_export_public(receiver, receiver_public,
                                           sizeof(receiver_public));
    if (status != ECLIPSE_SUCCESS) goto done;
    eclipse_tx_t tx;
    status = eclipse_tx_init(&tx);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_add_input(&tx, funding_id, 0);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_add_output(&tx, 29, ECLIPSE_ML_DSA_44,
                                       receiver_public, info.public_key_size);
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_set_fee(&tx, 1);
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_sign_input(&tx, 0, sender);
    bool valid = false;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_validate(&tx, state, &valid);
    if (status == ECLIPSE_SUCCESS && !valid)
        status = ECLIPSE_ERROR_INVALID_ARGUMENT;
    uint8_t id[ECLIPSE_TX_ID_SIZE];
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_apply(&tx, state, id);
    uint8_t wire[ECLIPSE_TX_MAX_WIRE_SIZE];
    size_t wire_length = 0;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_serialize(&tx, wire, sizeof(wire), &wire_length);
    char *hex = NULL;
    if (status == ECLIPSE_SUCCESS) {
        hex = malloc(wire_length * 2 + 1);
        if (hex == NULL) status = ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    if (status == ECLIPSE_SUCCESS) {
        format_hex(wire, wire_length, hex);
        puts(hex);
        ECLIPSE_LOG_INFO(1, "local signed developer transaction emitted by CLI");
    }
    free(hex);
done:
    eclipse_utxo_set_free(state);
    eclipse_ml_dsa_key_free(sender);
    eclipse_ml_dsa_key_free(receiver);
    if (status != ECLIPSE_SUCCESS)
        ECLIPSE_LOG_ERROR("transaction demo failed with code %d", status);
    return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
}

/* Decode canonical bytes and show their public fields. Without the UTXO set
 * this command reports format only; it cannot authenticate inputs or value. */
static int tx_decode(const char *argument)
{
    const size_t text_capacity = ECLIPSE_TX_MAX_WIRE_SIZE * 2u + 2u;
    char *piped = malloc(text_capacity);
    uint8_t *wire = malloc(ECLIPSE_TX_MAX_WIRE_SIZE);
    if (piped == NULL || wire == NULL) {
        free(piped);
        free(wire);
        return CLI_ERROR;
    }
    const char *hex = resolve_input(argument, piped, text_capacity);
    size_t hex_length = hex == NULL ? 0 : strlen(hex);
    int result = CLI_USAGE;
    if (hex_length == 0 || (hex_length & 1u) != 0 ||
        hex_length / 2 > ECLIPSE_TX_MAX_WIRE_SIZE ||
        !parse_hex(hex, wire, hex_length / 2)) {
        fputs("Expected one canonical transaction as even-length hex.\n", stderr);
        goto done;
    }
    eclipse_tx_t tx;
    eclipse_error_t status = eclipse_tx_deserialize(wire, hex_length / 2, &tx);
    if (status != ECLIPSE_SUCCESS) {
        ECLIPSE_LOG_WARNING("transaction CLI decode rejected packet");
        goto done;
    }
    uint8_t id[ECLIPSE_TX_ID_SIZE];
    status = eclipse_tx_id(&tx, id);
    if (status != ECLIPSE_SUCCESS) {
        result = CLI_ERROR;
        goto done;
    }
    char id_hex[ECLIPSE_TX_ID_SIZE * 2u + 1u];
    format_hex(id, sizeof(id), id_hex);
    printf("format_valid=true\ntxid=%s\nnetwork_id=EVD1\ninputs=%u\noutputs=%u\nfee=%" PRIu64 "\n",
           id_hex, (unsigned)tx.input_count, (unsigned)tx.output_count, tx.fee);
    for (size_t i = 0; i < tx.output_count; ++i)
        printf("output[%zu].amount=%" PRIu64 "\noutput[%zu].scheme=%s\n",
               i, tx.outputs[i].amount, i, scheme_name(tx.outputs[i].scheme));
    result = CLI_OK;
done:
    /* The wire bytes are public in this transparent experiment, but avoid
       retaining any stale pipe contents across command invocations. */
    OPENSSL_cleanse(piped, text_capacity);
    free(piped);
    free(wire);
    return result;
}

static int tx_command(int count, char **args)
{
    if (count == 1 && strcmp(args[0], "demo") == 0) return tx_demo();
    if (count == 2 && strcmp(args[0], "decode") == 0)
        return tx_decode(args[1]);
    fputs("Use tx demo or tx decode HEX|-.\n", stderr);
    return CLI_USAGE;
}

/* The block demo uses a fresh disposable miner key. Its output is one full
 * canonical block packet, ready for `block decode -`; no secret is printed. */
static int block_demo(void)
{
    eclipse_chain_t *chain = NULL;
    eclipse_ml_dsa_key_t *miner = NULL;
    eclipse_block_t *block = NULL;
    uint8_t *wire = NULL;
    char *hex = NULL;
    eclipse_error_t status = eclipse_chain_create(&chain);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_generate(ECLIPSE_ML_DSA_44, &miner);
    uint8_t parent[32];
    uint64_t height = 0;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_tip(chain, parent, &height);
    eclipse_tx_output_t destination = {0};
    destination.scheme = ECLIPSE_ML_DSA_44;
    destination.public_key_length = 1312;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_export_public(miner, destination.public_key,
                                              sizeof(destination.public_key));
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_make_candidate(chain, parent, 1, &destination,
                                               NULL, 0, &block);
    bool found = false;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_miner_mine(block, 100000, &found);
    if (status == ECLIPSE_SUCCESS && !found)
        status = ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (status == ECLIPSE_SUCCESS) {
        wire = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
        if (wire == NULL) status = ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    size_t length = 0;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_block_serialize(block, wire,
                                         ECLIPSE_BLOCK_MAX_WIRE_SIZE, &length);
    if (status == ECLIPSE_SUCCESS) {
        hex = malloc(length * 2 + 1);
        if (hex == NULL) status = ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    if (status == ECLIPSE_SUCCESS) {
        format_hex(wire, length, hex);
        puts(hex);
        ECLIPSE_LOG_INFO(1, "CLI mined a disposable developer block");
    }
    free(hex);
    free(wire);
    eclipse_block_free(block);
    eclipse_ml_dsa_key_free(miner);
    eclipse_chain_free(chain);
    if (status != ECLIPSE_SUCCESS)
        ECLIPSE_LOG_ERROR("block demo failed with code %d", status);
    return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
}

/* Decoder authenticates canonical bytes and Merkle root. It cannot decide
 * whether the block belongs to a valid chain without that chain's UTXOs. */
static int block_decode(const char *argument)
{
    const size_t text_capacity = ECLIPSE_BLOCK_MAX_WIRE_SIZE * 2u + 2u;
    char *piped = malloc(text_capacity);
    uint8_t *wire = malloc(ECLIPSE_BLOCK_MAX_WIRE_SIZE);
    if (piped == NULL || wire == NULL) {
        free(piped);
        free(wire);
        return CLI_ERROR;
    }
    const char *hex = resolve_input(argument, piped, text_capacity);
    size_t text_length = hex == NULL ? 0 : strlen(hex);
    int result = CLI_USAGE;
    if (text_length == 0 || (text_length & 1u) != 0 ||
        text_length / 2 > ECLIPSE_BLOCK_MAX_WIRE_SIZE ||
        !parse_hex(hex, wire, text_length / 2)) {
        fputs("Expected one canonical block as even-length hex.\n", stderr);
        goto done;
    }
    eclipse_block_t *block = NULL;
    eclipse_error_t status = eclipse_block_deserialize(wire, text_length / 2,
                                                       &block);
    if (status != ECLIPSE_SUCCESS) goto done;
    eclipse_block_header_t header;
    eclipse_tx_output_t reward;
    uint8_t hash[32];
    status = eclipse_block_header(block, &header);
    if (status == ECLIPSE_SUCCESS) status = eclipse_block_reward(block, &reward);
    if (status == ECLIPSE_SUCCESS) status = eclipse_block_hash(block, hash);
    if (status == ECLIPSE_SUCCESS) {
        char hash_hex[65];
        format_hex(hash, sizeof(hash), hash_hex);
        printf("format_valid=true\nblock_hash=%s\npow_valid=%s\n"
               "timestamp=%" PRIu64 "\ndifficulty_bits=%" PRIu32 "\n"
               "transactions=%zu\nreward=%" PRIu64 "\nstate_valid=unknown\n",
               hash_hex, (header.difficulty == ECLIPSE_BLOCK_DEV_DIFFICULTY_BITS &&
               eclipse_pow_hash_meets_target(hash, header.difficulty)) ?
               "true" : "false", header.timestamp, header.difficulty,
               eclipse_block_transaction_count(block), reward.amount);
        result = CLI_OK;
    } else result = CLI_ERROR;
    eclipse_block_free(block);
done:
    OPENSSL_cleanse(piped, text_capacity);
    free(piped);
    free(wire);
    return result;
}

static int block_command(int count, char **args)
{
    if (count == 1 && strcmp(args[0], "demo") == 0) return block_demo();
    if (count == 2 && strcmp(args[0], "decode") == 0)
        return block_decode(args[1]);
    fputs("Use block demo or block decode HEX|-.\n", stderr);
    return CLI_USAGE;
}

/* Mine a first reward, spend it in a second block, and independently validate
 * both blocks on two fresh nodes. This is deliberately all local process state. */
static int chain_demo(void)
{
    eclipse_chain_t *first = NULL, *second = NULL;
    eclipse_ml_dsa_key_t *miner = NULL, *receiver = NULL;
    eclipse_block_t *one = NULL, *two = NULL;
    eclipse_error_t status = eclipse_chain_create(&first);
    if (status == ECLIPSE_SUCCESS) status = eclipse_chain_create(&second);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_generate(ECLIPSE_ML_DSA_44, &miner);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_generate(ECLIPSE_ML_DSA_44, &receiver);
    uint8_t genesis[32], one_hash[32], reward_id[32], txid[32];
    uint64_t height = 0;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_tip(first, genesis, &height);
    eclipse_tx_output_t destination = {0};
    destination.scheme = ECLIPSE_ML_DSA_44;
    destination.public_key_length = 1312;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_export_public(miner, destination.public_key,
                                              sizeof(destination.public_key));
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_make_candidate(first, genesis, 1, &destination,
                                               NULL, 0, &one);
    bool found = false, selected = false;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_miner_mine(one, 100000, &found);
    if (status == ECLIPSE_SUCCESS && !found)
        status = ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_accept(first, one, &selected);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_accept(second, one, &selected);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_block_hash(one, one_hash);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_block_reward_id(one, reward_id);
    eclipse_tx_t *tx = NULL;
    if (status == ECLIPSE_SUCCESS) {
        tx = malloc(sizeof(*tx));
        if (tx == NULL) status = ECLIPSE_ERROR_OUT_OF_MEMORY;
    }
    uint8_t receiver_public[1312];
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_ml_dsa_export_public(receiver, receiver_public,
                                              sizeof(receiver_public));
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_init(tx);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_add_input(tx, reward_id, 0);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_tx_add_output(tx, ECLIPSE_DEV_INITIAL_SUBSIDY - 1,
                                       ECLIPSE_ML_DSA_44, receiver_public,
                                       sizeof(receiver_public));
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_set_fee(tx, 1);
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_sign_input(tx, 0, miner);
    const eclipse_tx_t *transactions[] = {tx};
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_make_candidate(first, one_hash, 2,
                                               &destination, transactions, 1, &two);
    found = false;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_miner_mine(two, 100000, &found);
    if (status == ECLIPSE_SUCCESS && !found)
        status = ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_accept(first, two, &selected);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_accept(second, two, &selected);
    if (status == ECLIPSE_SUCCESS) status = eclipse_tx_id(tx, txid);
    uint8_t first_tip[32], second_tip[32];
    uint64_t second_height = 0;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_tip(first, first_tip, &height);
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_tip(second, second_tip, &second_height);
    eclipse_tx_output_t received = {0};
    bool owned = false;
    if (status == ECLIPSE_SUCCESS)
        status = eclipse_chain_find_utxo(second, txid, 0, &received, &owned);
    if (status == ECLIPSE_SUCCESS && (!owned || height != 2 ||
        second_height != height || memcmp(first_tip, second_tip, 32) != 0))
        status = ECLIPSE_ERROR_INVALID_ARGUMENT;
    if (status == ECLIPSE_SUCCESS) {
        char tip_hex[65];
        format_hex(first_tip, sizeof(first_tip), tip_hex);
        printf("height=%" PRIu64 "\ntip=%s\n"
               "receiver_amount=%" PRIu64 "\nnodes_agree=true\n",
               height, tip_hex, received.amount);
        ECLIPSE_LOG_INFO(1, "CLI mined and independently validated two dev blocks");
    }
    free(tx);
    eclipse_block_free(two);
    eclipse_block_free(one);
    eclipse_ml_dsa_key_free(receiver);
    eclipse_ml_dsa_key_free(miner);
    eclipse_chain_free(second);
    eclipse_chain_free(first);
    if (status != ECLIPSE_SUCCESS)
        ECLIPSE_LOG_ERROR("chain demo failed with code %d", status);
    return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
}

static int wallet_command(int count, char **args)
{
    /* Only this branch creates a new root. Other branches import an existing
     * root or role secret and never regenerate it behind the user's back. */
    if (count == 2 && strcmp(args[0], "create") == 0) {
        eclipse_ml_dsa_scheme_t scheme;
        if (!parse_scheme(args[1], &scheme)) return CLI_USAGE;
        eclipse_wallet_recovery_t *root = NULL;
        eclipse_wallet_t *wallet = NULL;
        eclipse_error_t status = eclipse_wallet_create(scheme, &root, &wallet);
        size_t capacity = eclipse_wallet_recovery_export_capacity();
        char *text = status == ECLIPSE_SUCCESS ? malloc(capacity) : NULL;
        if (status == ECLIPSE_SUCCESS && text == NULL)
            status = ECLIPSE_ERROR_OUT_OF_MEMORY;
        size_t written = 0;
        if (status == ECLIPSE_SUCCESS)
            status = eclipse_wallet_recovery_export_base92(root, text, capacity,
                                                            &written);
        if (status == ECLIPSE_SUCCESS) puts(text);
        if (text != NULL) { OPENSSL_cleanse(text, capacity); free(text); }
        eclipse_wallet_free(wallet);
        eclipse_wallet_recovery_free(root);
        if (status != ECLIPSE_SUCCESS)
            ECLIPSE_LOG_ERROR("wallet CLI creation failed with code %d", status);
        else ECLIPSE_LOG_INFO(1, "wallet CLI created and explicitly printed a root");
        return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_ERROR;
    }

    /* A public packet can be inspected without importing any secret. */
    if (count == 2 && strcmp(args[0], "public-decode") == 0) {
        char piped[8192] = {0};
        const char *text = resolve_input(args[1], piped, sizeof(piped));
        eclipse_wallet_public_key_t key = {0};
        eclipse_error_t status = text == NULL ? ECLIPSE_ERROR_INVALID_ARGUMENT :
                                 eclipse_wallet_public_from_base92(text,
                                                                    strlen(text), &key);
        if (status == ECLIPSE_SUCCESS) {
            char *hex = malloc(key.length * 2 + 1);
            if (hex == NULL) status = ECLIPSE_ERROR_OUT_OF_MEMORY;
            else {
                format_hex(key.bytes, key.length, hex);
                printf("scheme=%s\nlength=%zu\npublic_key=%s\n",
                       scheme_name(key.scheme), key.length, hex);
                free(hex);
            }
        }
        OPENSSL_cleanse(piped, sizeof(piped));
        if (status != ECLIPSE_SUCCESS)
            ECLIPSE_LOG_WARNING("wallet CLI public decode rejected with code %d", status);
        return status == ECLIPSE_SUCCESS ? CLI_OK : CLI_USAGE;
    }

    bool derive = count == 3 && strcmp(args[0], "domain") == 0;
    bool public_from_root = count == 4 && strcmp(args[0], "public") == 0;
    bool public_from_domain = count == 4 && strcmp(args[0], "role-public") == 0;
    bool verify = count == 4 && strcmp(args[0], "verify") == 0;
    if (!derive && !public_from_root && !public_from_domain && !verify) {
        fputs("Use wallet create|domain|public|role-public|public-decode|verify.\n",
              stderr);
        return CLI_USAGE;
    }

    eclipse_wallet_role_t role;
    if (!parse_role(args[2], &role)) return CLI_USAGE;
    char piped[8192] = {0};
    const char *secret = resolve_input(args[1], piped, sizeof(piped));
    if (secret == NULL) {
        OPENSSL_cleanse(piped, sizeof(piped));
        return CLI_USAGE;
    }
    eclipse_wallet_recovery_t *root = NULL;
    eclipse_wallet_domain_t *domain = NULL;
    eclipse_wallet_t *wallet = NULL;
    eclipse_error_t status;
    /* Domain-only commands have no recovery root; every other command below
     * starts from the root and may derive either role. */
    if (public_from_domain)
        status = eclipse_wallet_domain_import_base92(secret, strlen(secret), &domain);
    else
        status = eclipse_wallet_recovery_import_base92(secret, strlen(secret), &root);

    int result = CLI_ERROR;
    if (status != ECLIPSE_SUCCESS) goto done;
    if (derive) {
        /* Export exactly one role secret. The Base92 text is intentionally
         * printed only because the developer requested this command. */
        status = eclipse_wallet_derive_domain(root, role, &domain);
        if (status != ECLIPSE_SUCCESS) goto done;
        size_t capacity = eclipse_wallet_domain_export_capacity();
        char *text = malloc(capacity);
        if (text == NULL) { status = ECLIPSE_ERROR_OUT_OF_MEMORY; goto done; }
        size_t written = 0;
        status = eclipse_wallet_domain_export_base92(domain, text, capacity,
                                                      &written);
        if (status == ECLIPSE_SUCCESS) puts(text);
        OPENSSL_cleanse(text, capacity);
        free(text);
        if (status == ECLIPSE_SUCCESS) result = CLI_OK;
        goto done;
    }

    if (public_from_domain) status = eclipse_wallet_open_domain(domain, &wallet);
    else status = eclipse_wallet_open(root, &wallet);
    if (status != ECLIPSE_SUCCESS) goto done;
    if (verify) {
        uint64_t index;
        if (!parse_unsigned(args[3], ECLIPSE_WALLET_POOL_SIZE - 1u, &index)) {
            result = CLI_USAGE;
            goto done;
        }
        bool valid = false;
        status = eclipse_wallet_verify_child_binding(wallet, role, (size_t)index,
                                                      &valid);
        if (status == ECLIPSE_SUCCESS) {
            printf("valid=%s\n", valid ? "true" : "false");
            result = CLI_OK;
        }
    } else {
        bool master;
        size_t index;
        if (!parse_wallet_slot(args[3], &master, &index)) {
            result = CLI_USAGE;
            goto done;
        }
        eclipse_wallet_public_key_t key;
        status = master ? eclipse_wallet_master_public(wallet, role, &key) :
                          eclipse_wallet_child_public(wallet, role, index, &key);
        if (status == ECLIPSE_SUCCESS) result = print_wallet_public(&key);
    }
done:
    /* All secret object owners are released on every branch. The command
     * string itself is argv-owned, so only the local piped copy is wiped. */
    eclipse_wallet_free(wallet);
    eclipse_wallet_domain_free(domain);
    eclipse_wallet_recovery_free(root);
    OPENSSL_cleanse(piped, sizeof(piped));
    if (result == CLI_OK) ECLIPSE_LOG_INFO(2, "wallet CLI %s completed", args[0]);
    else ECLIPSE_LOG_WARNING("wallet CLI %s rejected or failed", args[0]);
    return result;
}

/* Small ncurses launcher for the available forms and the raw Eclipse shell. */
static int tui_menu(void)
{
    if (!tui_begin()) return CLI_USAGE;
    for (;;) {
        if (LINES < 8 || COLS < 60) {
            if (!tui_wait_for_resize()) {
                endwin();
                return CLI_OK;
            }
            continue;
        }
        erase();
        mvprintw(1, 2, "Eclipse developer CLI (%s)", host_shell.name);
        mvprintw(3, 2, "1  Serialize a block header");
        mvprintw(4, 2, "2  Deserialize a block header");
        mvprintw(5, 2, "3  Build a local signed dev transaction");
        mvprintw(6, 2, "4 Chain demo  s Shell  i Info  h Help  q Quit");
        refresh();
        int choice = getch();
        if (choice == '1' || choice == '2' || choice == '3' || choice == '4' || choice == 's' ||
            choice == 'i' || choice == 'h' ||
            choice == 'q' || choice == 27) {
            endwin();
            if (choice == '1') return serialize_command(0, NULL);
            if (choice == '2') return deserialize_command(0, NULL);
            if (choice == '3') return tx_demo();
            if (choice == '4') return chain_demo();
            if (choice == 's') return eclipse_cli_shell(&pipeline_options);
            if (choice == 'i') eclipse_host_shell_print_guide(stdout, host_shell);
            if (choice == 'h') usage(stdout);
            return CLI_OK;
        }
        beep();
    }
}

/* Route a parsed command to an implemented API. Parenthesized calls remain
 * convenience syntax for the existing block-header operations only. */
static int run_command(int count, char **args)
{
    if (count == 0) return tui_menu();
    const char *command = args[0];
    if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0) {
        usage(stdout);
        return CLI_OK;
    }
    if (strcmp(command, "serialize") == 0) {
        ECLIPSE_LOG_INFO(1, "serialize command selected");
        return serialize_command(count - 1, args + 1);
    }
    if (strcmp(command, "deserialize") == 0) {
        ECLIPSE_LOG_INFO(1, "deserialize command selected");
        return deserialize_command(count - 1, args + 1);
    }
    if (strcmp(command, "math") == 0) {
        ECLIPSE_LOG_INFO(1, "math command selected");
        return math_command(count - 1, args + 1);
    }
    if (strcmp(command, "ml-dsa") == 0) {
        ECLIPSE_LOG_INFO(1, "ML-DSA command selected");
        return ml_dsa_command(count - 1, args + 1);
    }
    if (strcmp(command, "keypair") == 0)
        return keypair_command(count - 1, args + 1);
    if (strcmp(command, "base92") == 0)
        return base92_command(count - 1, args + 1);
    if (strcmp(command, "particle") == 0)
        return particle_command(count - 1, args + 1);
    if (strcmp(command, "tx") == 0)
        return tx_command(count - 1, args + 1);
    if (strcmp(command, "block") == 0)
        return block_command(count - 1, args + 1);
    if (strcmp(command, "chain") == 0 && count == 2 &&
        strcmp(args[1], "demo") == 0)
        return chain_demo();
    if (strcmp(command, "wallet") == 0)
        return wallet_command(count - 1, args + 1);
    if (strcmp(command, "shell") == 0 && count == 1)
        return eclipse_cli_shell(&pipeline_options);
    if (strcmp(command, "shell-info") == 0 && count == 1) {
        eclipse_host_shell_print_guide(stdout, host_shell);
        return CLI_OK;
    }
    if (strcmp(command, "build-info") == 0 && count == 1) {
        printf("os=%s\narchitecture=%s\npointer_bits=%zu\nbyte_order=%s\n",
               ECLIPSE_TARGET_OS, ECLIPSE_TARGET_ARCH,
               (size_t)ECLIPSE_TARGET_POINTER_BITS, ECLIPSE_TARGET_BYTE_ORDER);
        ECLIPSE_LOG_INFO(2, "compiled target information shown");
        return CLI_OK;
    }
    if (strcmp(command, "pipe") == 0) {
        if (count == 1 || (count == 2 && strcmp(args[1], "-") == 0))
            return eclipse_cli_pipeline_from_stdin(&pipeline_options);
        if (count == 2)
            return eclipse_cli_run_pipeline(args[1], &pipeline_options);
        return CLI_USAGE;
    }

    char storage[1024];
    char *parts[6];
    if (count == 1 && strncmp(command, "serialize(", 10) == 0) {
        ECLIPSE_LOG_INFO(1, "parenthesized serialize command selected");
        if (!parse_call(command, "serialize", storage, sizeof(storage), parts, 6)) {
            fputs("Invalid serialize(...) call; expected six comma-separated fields.\n", stderr);
            ECLIPSE_LOG_WARNING("malformed parenthesized serialize call");
            return CLI_USAGE;
        }
        char output[177];
        int status = serialize_fields(parts, output);
        if (status == CLI_OK) puts(output);
        return status;
    }
    if (count == 1 && strncmp(command, "deserialize(", 12) == 0) {
        ECLIPSE_LOG_INFO(1, "parenthesized deserialize command selected");
        if (!parse_call(command, "deserialize", storage, sizeof(storage), parts, 1)) {
            fputs("Invalid deserialize(...) call; expected one hex value.\n", stderr);
            ECLIPSE_LOG_WARNING("malformed parenthesized deserialize call");
            return CLI_USAGE;
        }
        char output[320];
        int status = deserialize_field(parts[0], output);
        if (status == CLI_OK) puts(output);
        return status;
    }
    fputs("Unknown command. Use eclipse-cli help.\n", stderr);
    return CLI_USAGE;
}

/* Detect shell guidance, configure logging, then run one command. A standalone
 * `//` argv element or one quoted expression with ` // ` selects pipeline
 * mode after the outer shell has already parsed its own syntax. */
int main(int argc, char **argv)
{
    host_shell = eclipse_host_shell_detect();
    int index = 1;
    pipeline_options.program = argv[0];
    pipeline_options.host_shell_name = host_shell.name;
    while (index < argc) {
        if (strcmp(argv[index], "--log-level") == 0) {
            uint64_t level;
            if (++index >= argc || !parse_unsigned(argv[index], 5, &level)) {
                fputs("--log-level requires a value from 0 to 5.\n", stderr);
                return CLI_USAGE;
            }
            (void)eclipse_log_set_info_level((unsigned)level);
        } else if (strcmp(argv[index], "--log-file") == 0) {
            if (++index >= argc || eclipse_log_set_file(argv[index]) != ECLIPSE_SUCCESS) {
                fputs("--log-file requires a writable file path.\n", stderr);
                eclipse_log_shutdown();
                return CLI_USAGE;
            }
            pipeline_options.log_file = argv[index];
        } else {
            break;
        }
        ++index;
    }
    pipeline_options.log_level = eclipse_log_get_info_level();
    ECLIPSE_LOG_INFO(2, "CLI outer shell detected: %s (%s)",
                     host_shell.name, host_shell.source);
    ECLIPSE_LOG_INFO(1, "CLI command started");
    int result;
    bool direct_pipeline = false;
    for (int i = index; i < argc; ++i)
        if (strcmp(argv[i], "//") == 0 ||
            (argc - index == 1 && strstr(argv[i], " // ") != NULL))
            direct_pipeline = true;
    if (direct_pipeline) {
        size_t length = 1;
        for (int i = index; i < argc; ++i) length += strlen(argv[i]) + 1;
        char *expression = malloc(length);
        if (expression == NULL) {
            result = CLI_ERROR;
        } else {
            expression[0] = '\0';
            for (int i = index; i < argc; ++i) {
                if (i != index) strcat(expression, " ");
                strcat(expression, argv[i]);
            }
            result = eclipse_cli_run_pipeline(expression, &pipeline_options);
            OPENSSL_cleanse(expression, length);
            free(expression);
        }
    } else {
        result = run_command(argc - index, argv + index);
    }
    if (result == CLI_OK) ECLIPSE_LOG_INFO(1, "CLI command completed");
    else ECLIPSE_LOG_WARNING("CLI command failed with exit code %d", result);
    eclipse_log_shutdown();
    return result;
}
