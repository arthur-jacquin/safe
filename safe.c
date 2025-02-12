// See LICENSE file for copyright and license details.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"


#define BUFFER_CHUNK_SIZE               128
#define DEFAULT_PASSWORD_CHARACTER_SET  PRINTABLE
#define DEFAULT_PASSWORD_LENGTH         20
#define DEFAULT_USERNAME_CHARACTER_SET  PRINTABLE
#define DEFAULT_USERNAME_LENGTH         20

#define EXPECT_ARGUMENT()               do{if(!*++arg) goto invalid_usage;}while(0)
#define HEX(C)                          ((C) < 10 ? '0' + (C) : 'a' + (C) - 10)
#define IS(A, B)                        (!strcmp(A, B))
#define IS_EITHER(STR, SHORT, LONG)     (IS(STR, SHORT) || IS(STR, LONG))


enum character_set {
    DIGITS,
    LOWERCASE,
    PRINTABLE,
};
enum decode_mode {
    ANY_SIZE_BUFFER,
    FIXED_SIZE_BUFFER,
    STREAM,
};
struct definition {
    enum mode {
        INTERACTIVE_PROMPT,
        FILENAME,
        NONE,
        RANDOMLY_GENERATED,
        STDIN,
        STDOUT,
        STRING,
    } mode;
    enum character_set character_set;
    int length;
    const char *value;
};


static void bufferize_stream(FILE *stream, const uint8_t **buffer,
    size_t *length);
static void die(int exit_status, const char *msg);

static enum character_set parse_character_set(const char *identifier);
static void parse_definition(struct definition definition,
    enum decode_mode decode_mode, const char *open_mode, int *valid,
    const uint8_t **any_size_buffer, uint8_t fixed_size_buffer[32],
    size_t *length, FILE **stream);
static int parse_hex(char c);
static int parse_text(FILE *in, struct text *dest);

static void put(int ch);
static void put_bytes_as_hex(const uint8_t bytes[], size_t length);
static void put_formatted_output(const char *format, struct text password,
    struct text username, int valid_username);
static void put_text(const struct text text);

static void random_bytes(uint8_t dest[], size_t length, uint8_t max_bound);

static void randomized_encryption(struct text plaintext, const uint8_t key[],
    size_t key_length, struct text *ciphertext);
static void create_password_entry(struct definition key_def,
    struct definition password_def, struct definition username_def,
    const char *notes);
static void query_password_entry(struct definition entry_def,
    struct definition key_def, const char *output_format);
static void generate_noise(void);


static const char *CHARACTER_SETS[] = {
    [DIGITS] = "0123456789",
    [LOWERCASE] = "abcdefghijklmnopqrstuvwxyz",
    [PRINTABLE] = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ["
        "\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
};
static const char USAGE[] =
    "safe " VERSION " - simple symmetric-key password encrypter\n"
    "\n"
    "safe c|create [OPTIONS]        create password entry\n"
    "safe q|query [OPTIONS] [FILE]  query password entry\n"
    "safe n|noise                   generate noise (can be used to clear clipboard)\n"
    "\n"
    "OPTIONS:\n"
    "-o|--output <file>\n"
    "KEY (default: interactive prompt):\n"
    "-k|--key <key>\n"
    "-K|--key-file <file>\n"
    "PASSWORD (create subcommand only, default: random generation):\n"
    "-p|--password <password>\n"
    "-c|--password-character-set <generated-password-character-set-id> (default: p)\n"
    "-l|--password-length <generated-password-length> (default: 20)\n"
    "USERNAME (create subcommand only, default: none):\n"
    "-u|--username <username>\n"
    "-U|--random-username\n"
    "-C|--username-character-set <generated-username-character-set-id> (default: p)\n"
    "-L|--username-length <generated-username-length> (default: 20)\n"
    "NOTES (create subcommand only, default: none):\n"
    "-n|--notes <notes>\n"
    "QUERY OUTPUT (query subcommand only, default: password):\n"
    "-f|--format <output-format>\n"
    "-p|--password                  short for: --format %p\n"
    "-u|--username                  short for: --format %u\n"
    "-s|--separator <separator>     short for: --format %u<separator>%p\n"
    "\n"
    "CHARACTER SETS:\n"
    "d|digits                       0 to 9\n"
    "l|lowercase                    a to z\n"
    "p|printable                    alphanumeric and special characters";

static FILE *out = NULL;


static void
bufferize_stream(FILE *stream, const uint8_t **buffer, size_t *length)
{
    char *buffer_ = NULL, c;
    size_t capacity = 0, length_ = 0;

    while ((c = fgetc(stream)) != EOF) {
        if (c == '\n') continue; // ignore newline characters
        if (length_ == capacity)
            buffer_ = realloc(buffer_, capacity += BUFFER_CHUNK_SIZE);
        buffer_[length_++] = c;
    }
    *buffer = (uint8_t *) buffer_; *length = length_;
    printf("Length: %ld\n", length_);
}

static void
die(int exit_status, const char *msg)
{
    if (msg)
        fprintf((exit_status) ? stderr : stdout, "%s\n", msg);
    exit(exit_status);
}

static enum character_set
parse_character_set(const char *identifier)
{
         if (IS_EITHER(identifier, "d", "digits"   )) return DIGITS;
    else if (IS_EITHER(identifier, "l", "lowercase")) return LOWERCASE;
    else if (IS_EITHER(identifier, "p", "printable")) return PRINTABLE;
    else die(EXIT_FAILURE, "Invalid character set identifier");
    return 0; // unreachable
}

static void
parse_definition(struct definition definition, enum decode_mode decode_mode,
    const char *open_mode, int *valid, const uint8_t **any_size_buffer,
    uint8_t fixed_size_buffer[32], size_t *length, FILE **stream)
{
    const char *possible_characters;
    uint8_t random[32];
    FILE *to_be_decoded_stream;

    if (valid)
        *valid = definition.mode != NONE;
    switch (definition.mode) {
    case INTERACTIVE_PROMPT:
        goto TODO;
    case NONE:
        break;
    case RANDOMLY_GENERATED:
        if (decode_mode != FIXED_SIZE_BUFFER) goto unsupported;
        *length = definition.length;
        if (!(0 <= *length && *length < 32)) goto invalid_length;
        possible_characters = CHARACTER_SETS[definition.character_set];
        random_bytes(random, *length, strlen(possible_characters));
        for (size_t i = 0; i < *length; i++)
            fixed_size_buffer[i] = possible_characters[random[i]];
        break;
    case FILENAME:
        if ((to_be_decoded_stream = fopen(definition.value, open_mode)) == NULL)
            die(EXIT_FAILURE, "Cannot open file");
        goto decode_stream;
    case STDIN:
        to_be_decoded_stream = stdin;
        goto decode_stream;
    case STDOUT:
        to_be_decoded_stream = stdout;
        goto decode_stream;
    decode_stream:
        switch (decode_mode) {
        case ANY_SIZE_BUFFER:
            bufferize_stream(to_be_decoded_stream, any_size_buffer, length);
            break;
        case FIXED_SIZE_BUFFER:
            for (*length = 0; *length < 32; (*length)++) {
                if ((fixed_size_buffer[*length] = fgetc(to_be_decoded_stream)) == '\n')
                    goto eof_found;
            }
            goto invalid_length;
        eof_found:
            break;
        case STREAM:
            *stream = to_be_decoded_stream;
            break;
        }
        break;
    case STRING:
        switch (decode_mode) {
        case ANY_SIZE_BUFFER:
            *length = strlen(definition.value);
            *any_size_buffer = (uint8_t *) definition.value;
            break;
        case FIXED_SIZE_BUFFER:
            *length = strlen(definition.value);
            if (!(0 <= *length && *length < 32)) goto invalid_length;
            strncpy((char *) fixed_size_buffer, definition.value, *length);
            break;
        case STREAM: goto unsupported;
        }
        break;
    }
    return;

invalid_length: die(EXIT_FAILURE, "Invalid length");
unsupported: exit(EXIT_FAILURE);
TODO: die(EXIT_FAILURE, "Not implemented");
}

static int
parse_hex(char c)
{
    int res;

    if (0 <= (res = c - '0') && res < 10) return res;
    if (10 <= (res = c - 'a' + 10) && res < 16) return res;
    if (10 <= (res = c - 'A' + 10) && res < 16) return res;
    return -1;
}

static int
parse_text(FILE *in, struct text *dest)
{
    char buffer[1 + 2*16 + 2*32 + 2] = {0};
    int high_nibble, low_nibble;

    if (fgets(buffer, sizeof(buffer), in) == NULL || buffer[0] == '\n') goto no_input;
    if (buffer[1 + 2*16 + 2*32] != '\n') goto invalid_input;
    dest->length = (size_t) (buffer[0] - 64);
    if (!(0 <= dest->length && dest->length < 32)) goto invalid_input;
    for (size_t i = 0; i < 16; i++) {
        if ((high_nibble = parse_hex(buffer[1 + 2*i + 0])) < 0) goto invalid_input;
        if ((low_nibble = parse_hex(buffer[1 + 2*i + 1])) < 0) goto invalid_input;
        dest->init_vector[i] = (uint8_t) ((high_nibble << 4) | low_nibble);
    }
    for (size_t i = 0; i < 32; i++) {
        if ((high_nibble = parse_hex(buffer[1 + 2*16 + 2*i + 0])) < 0) goto invalid_input;
        if ((low_nibble = parse_hex(buffer[1 + 2*16 + 2*i + 1])) < 0) goto invalid_input;
        dest->text[i] = (uint8_t) ((high_nibble << 4) | low_nibble);
    }
    return 0;

invalid_input: die(EXIT_FAILURE, "Invalid input");
no_input: return -1;
}

static void
put(int ch)
{
    if (putc(ch, out) == EOF) die(EXIT_FAILURE, "Cannot write output");
}

static void
put_bytes_as_hex(const uint8_t bytes[], size_t length)
{
    for (size_t i = 0; i < length; i++) {
        put(HEX(bytes[i] >> 4));
        put(HEX(bytes[i] & 0xf));
    }
}

static void
put_formatted_output(const char *format, struct text password,
    struct text username, int valid_username)
{
    for (const char *s = format; *s; s++) {
        switch (*s) {
        case '%':
            switch (*++s) {
            case 'p':
                for (size_t i = 0; i < password.length; i++)
                    put(password.text[i]);
                break;
            case 'u':
                if (!valid_username) die(EXIT_FAILURE, "No username available");
                for (size_t i = 0; i < username.length; i++)
                    put(username.text[i]);
                break;
            case '%': put('%'); break;
            default: goto invalid_format;
            } break;
        case '\\':
            switch (*++s) {
            case 't': put('\t'); break;
            case 'n': put('\n'); break;
            default: goto invalid_format;
            } break;
        default: put(*s); break;
        }
    }
    put('\n');
    return;

invalid_format: die(EXIT_FAILURE, "Invalid output format");
}

static void
put_text(const struct text text)
{
    put(64 + text.length);
    put_bytes_as_hex(text.init_vector, sizeof(text.init_vector));
    put_bytes_as_hex(text.text, sizeof(text.text));
    put('\n');
}

static void
random_bytes(uint8_t dest[], size_t length, uint8_t max_bound)
{
    // use operating system pseudorandom number generator
    // max_bound is an optional exclusive upper bound

    FILE *random = fopen("/dev/random", "r");
    if (!random) goto failure;
    if (max_bound == 0) {
        if (fread(dest, 1, length, random) < length) goto failure;
    } else {
        uint8_t threshold = max_bound * (256 / max_bound);
        for (size_t i = 0; i < length; i++) {
            do {
                if (fread(dest + i, 1, 1, random) < 1) goto failure;
            } while (dest[i] >= threshold);
            dest[i] %= max_bound;
        }
    }
    if (fclose(random) == EOF) goto failure;
    return;

failure: die(EXIT_FAILURE, "Cannot generate random values");
}

static void
randomized_encryption(struct text plaintext, const uint8_t key[],
    size_t key_length, struct text *ciphertext)
{
    // only the first plaintext.length bytes of plaintext.text are considered
    // meaningful

    random_bytes(plaintext.text + plaintext.length, sizeof(plaintext.text) -
        plaintext.length, 0);
    random_bytes(plaintext.init_vector, sizeof(plaintext.init_vector), 0);
    text_symmetric_encryption(plaintext, 1, key, key_length, ciphertext);
}

static void
create_password_entry(struct definition key_def, struct definition password_def,
    struct definition username_def, const char *notes)
{
    const uint8_t *key;
    size_t key_length;
    struct text plaintext, password, username;
    int valid_username;

    parse_definition(key_def, ANY_SIZE_BUFFER, "r", NULL, &key, NULL,
        &key_length, NULL);

    parse_definition(password_def, FIXED_SIZE_BUFFER, "r", NULL, NULL,
        plaintext.text, &plaintext.length, NULL);
    randomized_encryption(plaintext, key, key_length, &password);
    put_text(password);

    parse_definition(username_def, FIXED_SIZE_BUFFER, "r", &valid_username,
        NULL, plaintext.text, &plaintext.length, NULL);
    if (valid_username) {
        randomized_encryption(plaintext, key, key_length, &username);
        put_text(username);
    } else put('\n');

    if (notes) {
        while (*notes)
            put(*notes++);
        put('\n');
    }
}

static void
query_password_entry(struct definition entry_def, struct definition key_def,
    const char *output_format)
{
    FILE *in;
    const uint8_t *key;
    size_t key_length;
    struct text ciphertext, password, username;
    int valid_username;

    parse_definition(entry_def, STREAM, "r", NULL, NULL, NULL, NULL, &in);
    parse_definition(key_def, ANY_SIZE_BUFFER, "r", NULL, &key, NULL,
        &key_length, NULL);

    if (parse_text(in, &ciphertext) < 0) die(EXIT_FAILURE, "No password available");
    text_symmetric_encryption(ciphertext, 0, key, key_length, &password);
    if ((valid_username = parse_text(in, &ciphertext) >= 0))
        text_symmetric_encryption(ciphertext, 0, key, key_length, &username);

    put_formatted_output(output_format, password, username, valid_username);
}

static void
generate_noise(void)
{
    uint8_t bytes[16];

    random_bytes(bytes, sizeof(bytes), 0);
    put_bytes_as_hex(bytes, sizeof(bytes));
    put('\n');
}


int
main(int argc, const char *argv[])
{
    const char **arg, *notes = NULL, *output_format = "%p";
    struct definition
        output_def = (struct definition) {.mode = STDOUT,},
        key_def = (struct definition) {.mode = INTERACTIVE_PROMPT,},
        password_def = (struct definition) {
            .mode = RANDOMLY_GENERATED,
            .length = DEFAULT_PASSWORD_LENGTH,
            .character_set = DEFAULT_PASSWORD_CHARACTER_SET,
        },
        username_def = (struct definition) {
            .mode = NONE,
            .length = DEFAULT_USERNAME_LENGTH,
            .character_set = DEFAULT_USERNAME_CHARACTER_SET,
        },
        entry_def = (struct definition) {.mode = STDIN,};
    enum subcommand {
        CREATE,
        QUERY,
        NOISE,
    } subcommand;

    // parse subcommand
    if (argc < 2) goto invalid_usage;
    else if (IS_EITHER(argv[1], "-h", "--help")) die(EXIT_SUCCESS, USAGE);
    else if (IS_EITHER(argv[1], "-v", "--version")) die(EXIT_SUCCESS, VERSION);
    else if (IS_EITHER(argv[1], "c", "create")) subcommand = CREATE;
    else if (IS_EITHER(argv[1], "q", "query")) subcommand = QUERY;
    else if (IS_EITHER(argv[1], "n", "noise")) subcommand = NOISE;
    else goto invalid_usage;

    // parse optional arguments
    for (arg = argv + 2; *arg; arg++) {
        if (IS_EITHER(*arg, "-o", "--output")) {
            EXPECT_ARGUMENT();
            if (IS(*arg, "-")) {
                output_def.mode = STDOUT;
            } else {
                output_def.mode = FILENAME;
                output_def.value = *arg;
            }
        } else if (IS_EITHER(*arg, "-k", "--key") && subcommand != NOISE) {
            EXPECT_ARGUMENT();
            if (IS(*arg, "?")) {
                key_def.mode = INTERACTIVE_PROMPT;
            } else if (IS(*arg, "-")) {
                key_def.mode = STDIN;
            } else {
                key_def.mode = STRING;
                key_def.value = *arg;
            }
        } else if (IS_EITHER(*arg, "-K", "--key-file") && subcommand != NOISE) {
            EXPECT_ARGUMENT();
            key_def.mode = FILENAME;
            key_def.value = *arg;
        } else if (IS_EITHER(*arg, "-p", "--password") && subcommand == CREATE) {
            EXPECT_ARGUMENT();
            if (IS(*arg, "?")) {
                password_def.mode = INTERACTIVE_PROMPT;
            } else if (IS(*arg, "-")) {
                password_def.mode = STDIN;
            } else {
                password_def.mode = STRING;
                password_def.value = *arg;
            }
        } else if (IS_EITHER(*arg, "-l", "--password-length") && subcommand == CREATE) {
            EXPECT_ARGUMENT();
            char *remaining;
            password_def.length = strtol(*arg, &remaining, 10);
            if (*remaining) goto invalid_usage;
        } else if (IS_EITHER(*arg, "-c", "--password-character-set") && subcommand == CREATE) {
            EXPECT_ARGUMENT();
            password_def.character_set = parse_character_set(*arg);
        } else if (IS_EITHER(*arg, "-u", "--username") && subcommand == CREATE) {
            EXPECT_ARGUMENT();
            if (IS(*arg, "?")) {
                username_def.mode = INTERACTIVE_PROMPT;
            } else if (IS(*arg, "-")) {
                username_def.mode = STDIN;
            } else {
                username_def.mode = STRING;
                username_def.value = *arg;
            }
        } else if (IS_EITHER(*arg, "-U", "--random-username") && subcommand == CREATE) {
            username_def.mode = RANDOMLY_GENERATED;
        } else if (IS_EITHER(*arg, "-L", "--username-length") && subcommand == CREATE) {
            EXPECT_ARGUMENT();
            char *remaining;
            username_def.length = strtol(*arg, &remaining, 10);
            if (*remaining) goto invalid_usage;
        } else if (IS_EITHER(*arg, "-C", "--username-character-set") && subcommand == CREATE) {
            EXPECT_ARGUMENT();
            username_def.character_set = parse_character_set(*arg);
        } else if (IS_EITHER(*arg, "-n", "--notes") && subcommand == CREATE) {
            EXPECT_ARGUMENT();
            notes = *arg;
        } else if (IS_EITHER(*arg, "-f", "--format") && subcommand == QUERY) {
            EXPECT_ARGUMENT();
            output_format = *arg;
        } else if (IS_EITHER(*arg, "-p", "--password") && subcommand == QUERY) {
            output_format = "%p";
        } else if (IS_EITHER(*arg, "-u", "--username") && subcommand == QUERY) {
            output_format = "%u";
        } else if (IS_EITHER(*arg, "-s", "--separator") && subcommand == QUERY) {
            EXPECT_ARGUMENT();
            char *format = malloc(strlen(*arg) + 5);
            sprintf(format, "%%u%s%%p", *arg);
            output_format = format;
        } else break;
    }

    // parse positional arguments
    if (subcommand == QUERY && *arg) {
        if (IS(*arg, "--")) EXPECT_ARGUMENT();
        if (IS(*arg, "-")) {
            entry_def.mode = STDIN;
        } else {
            entry_def.mode = FILENAME;
            entry_def.value = *arg;
        }
        arg++;
    }
    if (*arg) goto invalid_usage;

    // check number of definition using stdin
    if ((key_def.mode == STDIN && subcommand != NOISE) +
        (password_def.mode == STDIN && subcommand == CREATE) +
        (username_def.mode == STDIN && subcommand == CREATE) +
        (entry_def.mode == STDIN && subcommand == QUERY) > 1)
        die(EXIT_FAILURE, "Cannot use stdin for several inputs");

    // actual subcommand execution
    parse_definition(output_def, STREAM, "w", NULL, NULL, NULL, NULL, &out);
    switch (subcommand) {
    case CREATE:
        create_password_entry(key_def, password_def, username_def, notes);
        break;
    case QUERY:
        query_password_entry(entry_def, key_def, output_format);
        break;
    case NOISE:
        generate_noise();
        break;
    }

    return 0;

invalid_usage: die(EXIT_FAILURE, "Invalid usage, see safe --help");
}
