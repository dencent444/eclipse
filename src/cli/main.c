/* Developer interface for APIs that already exist in eclipse_core.
 * Parsing and display live here; consensus serialization stays in block.c.
 * Never log raw CLI arguments: a later command may carry private material.
 */
#include "block/block.h"
#include "crypto/ml_dsa.h"
#include "crypto/ml_dsa_math.h"
#include "log.h"

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
          "\n"
          "Integers are decimal or 0x-prefixed hex, except math mod (decimal).\n"
          "Hashes are exactly 32 bytes (64 hex digits), without a 0x prefix.\n"
          "The serialized header is exactly 88 bytes (176 hex digits).\n"
          "Quote the parenthesized form in a shell. Logs go to stderr by default.\n",
          stream);
}

static char *trim(char *text)
{
    while (isspace((unsigned char)*text)) ++text;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return text;
}

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

static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

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

static bool valid_deserialize_field(size_t index, const char *text)
{
    (void)index;
    char copy[256];
    (void)snprintf(copy, sizeof(copy), "%s", text);
    uint8_t header[ECLIPSE_BLOCK_HEADER_SERIALIZED_SIZE];
    return parse_hex(trim(copy), header, sizeof(header));
}

/* The binary header remains the source of truth; this is presentation only. */
static void format_hex(const uint8_t *bytes, size_t length, char *output)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        output[2 * i] = digits[bytes[i] >> 4];
        output[2 * i + 1] = digits[bytes[i] & 15];
    }
    output[2 * length] = '\0';
}

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

static bool tui_wait_for_resize(void)
{
    if (LINES >= 8 && COLS >= 60) return true;
    erase();
    mvaddstr(0, 0, "Resize to 60x8, or press Esc to cancel");
    refresh();
    return getch() != 27;
}

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

static int deserialize_command(int count, char **args)
{
    if (count != 0 && count != 1) {
        fputs("deserialize accepts one header hex value.\n", stderr);
        return CLI_USAGE;
    }
    const char *hex;
    char input[1][256];
    if (count == 0) {
        const char *label = "serialized header (176 hex digits)";
        ECLIPSE_LOG_INFO(2, "opening interactive block header deserializer");
        if (!tui_collect("Deserialize block header", &label, input, 1,
                         valid_deserialize_field)) {
            ECLIPSE_LOG_INFO(2, "interactive block header deserializer cancelled");
            return CLI_USAGE;
        }
        hex = trim(input[0]);
    } else {
        hex = args[0];
    }
    char output[320];
    int status = deserialize_field(hex, output);
    if (status == CLI_OK) {
        if (count == 0) tui_result("Deserialized block header", output);
        puts(output);
    }
    return status;
}

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

static int ml_dsa_command(int count, char **args)
{
    ECLIPSE_LOG_INFO(2, "ML-DSA self-test command selected");
    if ((count != 3 && count != 4) || strcmp(args[0], "self-test") != 0) {
        fputs("Use ml-dsa self-test 44|65|87 MESSAGE [CONTEXT].\n", stderr);
        return CLI_USAGE;
    }
    eclipse_ml_dsa_scheme_t scheme;
    if (strcmp(args[1], "44") == 0) scheme = ECLIPSE_ML_DSA_44;
    else if (strcmp(args[1], "65") == 0) scheme = ECLIPSE_ML_DSA_65;
    else if (strcmp(args[1], "87") == 0) scheme = ECLIPSE_ML_DSA_87;
    else {
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
        mvprintw(1, 2, "Eclipse developer CLI");
        mvprintw(3, 2, "1  Serialize a block header");
        mvprintw(4, 2, "2  Deserialize a block header");
        mvprintw(6, 2, "h  Show all commands    q  Quit");
        refresh();
        int choice = getch();
        if (choice == '1' || choice == '2' || choice == 'h' ||
            choice == 'q' || choice == 27) {
            endwin();
            if (choice == '1') return serialize_command(0, NULL);
            if (choice == '2') return deserialize_command(0, NULL);
            if (choice == 'h') usage(stdout);
            return CLI_OK;
        }
        beep();
    }
}

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

int main(int argc, char **argv)
{
    int index = 1;
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
        } else {
            break;
        }
        ++index;
    }
    ECLIPSE_LOG_INFO(1, "CLI command started");
    int result = run_command(argc - index, argv + index);
    if (result == CLI_OK) ECLIPSE_LOG_INFO(1, "CLI command completed");
    else ECLIPSE_LOG_WARNING("CLI command failed with exit code %d", result);
    eclipse_log_shutdown();
    return result;
}
