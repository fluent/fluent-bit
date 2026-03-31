/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <msgpack.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_utf8.h>
#include <fluent-bit/flb_simd.h>

#include <fluent-bit/calyptia/calyptia_constants.h>

#ifdef FLB_HAVE_AWS_ERROR_REPORTER
#include <fluent-bit/aws/flb_aws_error_reporter.h>

extern struct flb_aws_error_reporter *error_reporter;
#endif

#ifdef FLB_HAVE_OPENSSL
#include <openssl/rand.h>
#endif

#ifdef FLB_SYSTEM_MACOS
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <AvailabilityMacros.h>
#if MAC_OS_X_VERSION_MIN_REQUIRED < 120000
#define kIOMainPortDefault kIOMasterPortDefault
#endif
#endif

/*
 * The following block descriptor describes the private use unicode character range
 * used for denoting invalid utf-8 fragments. Invalid fragment 0xCE would become
 * utf-8 codepoint U+E0CE if FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR is set to
 * E0 since U+E0CE = U+<FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR><HEX_FRAGMENT>
 */
#define FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR 0xE0

void flb_utils_error(int err)
{
    char *msg = NULL;

    switch (err) {
    case FLB_ERR_CFG_FILE:
        msg = "could not open configuration file";
        break;
    case FLB_ERR_CFG_FILE_FORMAT:
        msg = "configuration file contains format errors";
        break;
    case FLB_ERR_CFG_FILE_STOP:
        msg = "configuration file contains errors";
        break;
    case FLB_ERR_CFG_FLUSH:
        msg = "invalid flush value";
        break;
    case FLB_ERR_CFG_FLUSH_CREATE:
        msg = "could not create timer for flushing";
        break;
    case FLB_ERR_CFG_FLUSH_REGISTER:
        msg = "could not register timer for flushing";
        break;
    case FLB_ERR_INPUT_INVALID:
        msg = "invalid input type";
        break;
    case FLB_ERR_INPUT_UNDEF:
        msg = "no input(s) have been defined";
        break;
    case FLB_ERR_INPUT_UNSUP:
        msg = "unsupported Input";
        break;
    case FLB_ERR_OUTPUT_UNDEF:
        msg = "you must specify an output target";
        break;
    case FLB_ERR_OUTPUT_INVALID:
        msg = "invalid output target";
        break;
    case FLB_ERR_OUTPUT_UNIQ:
        msg = "just one output type is supported";
        break;
    case FLB_ERR_FILTER_INVALID:
        msg = "invalid filter plugin";
        break;
    case FLB_ERR_CFG_PARSER_FILE:
        msg = "could not open parser configuration file";
        break;
    case FLB_ERR_JSON_INVAL:
        msg = "invalid JSON string";
        break;
    case FLB_ERR_JSON_PART:
        msg = "truncated JSON string";
        break;
    case FLB_ERR_CORO_STACK_SIZE:
        msg = "invalid coroutine stack size";
        break;
    case FLB_ERR_CFG_PLUGIN_FILE:
        msg = "plugins_file not found";
        break;
    case FLB_ERR_RELOADING_IN_PROGRESS:
        msg = "reloading in progress";
        break;
    default:
        flb_error("(error message is not defined. err=%d)", err);
    }

    if (!msg) {
        fprintf(stderr,
                "%sError%s: undefined. Aborting",
                ANSI_BOLD ANSI_RED, ANSI_RESET);
        #ifdef FLB_HAVE_AWS_ERROR_REPORTER
        if (is_error_reporting_enabled()) {
            flb_aws_error_reporter_write(error_reporter, "Error: undefined. Aborting\n");
        }
        #endif

    }
    else {
        flb_error("%s, aborting.", msg);
        #ifdef FLB_HAVE_AWS_ERROR_REPORTER
        if (is_error_reporting_enabled()) {
            flb_aws_error_reporter_write(error_reporter, msg);
        }
        #endif
    }

    if (err <= FLB_ERR_FILTER_INVALID) {
        exit(EXIT_FAILURE);
    }
}

/* Custom error */
void flb_utils_error_c(const char *msg)
{
    fprintf(stderr,
            "%sError%s: %s. Aborting\n\n",
            ANSI_BOLD ANSI_RED, ANSI_RESET, msg);
    exit(EXIT_FAILURE);
}

void flb_utils_warn_c(const char *msg)
{
    fprintf(stderr,
            "%sWarning%s: %s",
            ANSI_BOLD ANSI_YELLOW, ANSI_RESET, msg);
}

#ifdef FLB_HAVE_FORK
/* Run current process in background mode */
int flb_utils_set_daemon(struct flb_config *config)
{
    pid_t pid;

    if ((pid = fork()) < 0){
        flb_error("Failed creating to switch to daemon mode (fork failed)");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) { /* parent */
        exit(EXIT_SUCCESS);
    }

    /* set files mask */
    umask(0);

    /* Create new session */
    setsid();

    if (chdir("/") < 0) { /* make sure we can unmount the inherited filesystem */
        flb_error("Unable to unmount the inherited filesystem");
        exit(EXIT_FAILURE);
    }

    /* Our last STDOUT messages */
    flb_info("switching to background mode (PID=%ld)", (long) getpid());

    fclose(stderr);
    fclose(stdout);

    return 0;
}
#endif

void flb_utils_print_setup(struct flb_config *config)
{
    struct mk_list *head;
    struct mk_list *head_tmp;
    struct flb_input_plugin *plugin;
    struct flb_input_collector *collector;
    struct flb_input_instance *in;
    struct flb_filter_instance *f;
    struct flb_output_instance *out;

    flb_info("Configuration:");

    /* general */
    flb_info(" flush time     | %f seconds", config->flush);
    flb_info(" grace          | %i seconds", config->grace);
    flb_info(" daemon         | %i", config->daemon);

    /* Inputs */
    flb_info("___________");
    flb_info(" inputs:");
    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        flb_info("     %s", in->p->name);
    }

    /* Filters */
    flb_info("___________");
    flb_info(" filters:");
    mk_list_foreach(head, &config->filters) {
        f = mk_list_entry(head, struct flb_filter_instance, _head);
        flb_info("     %s", f->name);
    }

    /* Outputs */
    flb_info("___________");
    flb_info(" outputs:");
    mk_list_foreach(head, &config->outputs) {
        out = mk_list_entry(head, struct flb_output_instance, _head);
        flb_info("     %s", out->name);
    }

    /* Collectors */
    flb_info("___________");
    flb_info(" collectors:");
    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        mk_list_foreach(head_tmp, &in->collectors) {
            collector = mk_list_entry(head_tmp, struct flb_input_collector, _head);
            plugin = collector->instance->p;

            if (collector->seconds > 0) {
                flb_info("[%s %lus,%luns] ",
                          plugin->name,
                          collector->seconds,
                          collector->nanoseconds);
            }
            else {
                flb_info("     [%s] ", plugin->name);
            }
        }
    }
}

/*
 * quoted_string_len returns the length of a quoted string, not including the quotes.
 */
static int quoted_string_len(const char *str)
{
    int len = 0;
    char quote = *str++; /* Consume the quote character. */

    while (quote != 0) {
        char c = *str++;
        switch (c) {
            case '\0':
                /* Error: string ends before end-quote was seen. */
                return -1;
            case '\\':
                /* Skip escaped quote or \\. */
                if (*str == quote || *str == '\\') {
                    str++;
                }
                break;
            case '\'':
            case '"':
                /* End-quote seen: stop iterating. */
                if (c == quote) {
                    quote = 0;
                }
                break;
            default:
                break;
        }
        len++;
    }

    /* Go back one character to ignore end-quote */
    len--;

    return len;
}

/*
 * next_token returns the next token in the string 'str' delimited by 'separator'.
 * 'out' is set to the beginning of the token.
 * 'out_len' is set to the length of the token.
 * 'parse_quotes' is set to FLB_TRUE when quotes shall be considered when tokenizing the 'str'.
 * The function returns offset to next token in the string.
 */
static int next_token(const char *str, int separator, char **out, int *out_len, int parse_quotes) {
    const char *token_in = str;
    char *token_out;
    int next_separator = 0;
    int quote = 0; /* Parser state: 0 not inside quoted string, or '"' or '\'' when inside quoted string. */
    int len = 0;
    int i;

    /* Skip leading separators. */
    while (*token_in == separator) {
        token_in++;
    }

    /* Should quotes be parsed? Or is token quoted? If not, copy until separator or the end of string. */
    if (parse_quotes == FLB_FALSE || (*token_in != '"' && *token_in != '\'')) {
        len = (int)strlen(token_in);
        next_separator = mk_string_char_search(token_in, separator, len);
        if (next_separator > 0) {
            len = next_separator;
        }
        *out_len = len;
        *out = mk_string_copy_substr(token_in, 0, len);
        if (*out == NULL) {
            return -1;
        }

        return (int)(token_in - str) + len;
    }

    /* Token is quoted. */

    len = quoted_string_len(token_in);
    if (len < 0) {
        return -1;
    }

    /* Consume the quote character. */
    quote = *token_in++;

    token_out = flb_malloc(len + 1);
    if (!token_out) {
        return -1;
    }

    /* Copy the token */
    for (i = 0; i < len; i++) {
        /* Handle escapes when inside quoted token:
         *   \" -> "
         *   \' -> '
         *   \\ -> \
         */
        if (*token_in == '\\' && (token_in[1] == quote || token_in[1] == '\\')) {
            token_in++;
        }
        token_out[i] = *token_in++;
    }
    token_out[i] = '\0';

    *out = token_out;
    *out_len = len;

    return (int)(token_in - str);
}


static struct mk_list *split(const char *line, int separator, int max_split, int quoted)
{
    int i = 0;
    int count = 0;
    int val_len;
    int len;
    int end;
    char *val;
    struct mk_list *list;
    struct flb_split_entry *new;

    if (!line) {
        return NULL;
    }

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    len = strlen(line);
    while (i < len) {
        end = next_token(line + i, separator, &val, &val_len, quoted);
        if (end == -1) {
            flb_error("Parsing failed: %s", line);
            flb_utils_split_free(list);
            return NULL;
        }

        /* Update last position */
        i += end;

        /* Create new entry */
        new = flb_malloc(sizeof(struct flb_split_entry));
        if (!new) {
            flb_errno();
            flb_free(val);
            flb_utils_split_free(list);
            return NULL;
        }
        new->value = val;
        new->len = val_len;
        new->last_pos = i;
        mk_list_add(&new->_head, list);
        count++;

        /* Update index for next loop */
        i++;

        /*
         * If the counter exceeded the maximum specified and there
         * are still remaining bytes, append those bytes in a new
         * and last entry.
         */
        if (count >= max_split && max_split > 0 && i < len) {
            new = flb_malloc(sizeof(struct flb_split_entry));
            if (!new) {
                flb_errno();
                flb_utils_split_free(list);
                return NULL;
            }
            new->value = mk_string_copy_substr(line, i, len);
            new->len   = len - i;
            mk_list_add(&new->_head, list);
            break;
        }
    }

    return list;
}

struct mk_list *flb_utils_split_quoted(const char *line, int separator, int max_split)
{
    return split(line, separator, max_split, FLB_TRUE);
}

struct mk_list *flb_utils_split(const char *line, int separator, int max_split)
{
    return split(line, separator, max_split, FLB_FALSE);
}


void flb_utils_split_free_entry(struct flb_split_entry *entry)
{
    mk_list_del(&entry->_head);
    flb_free(entry->value);
    flb_free(entry);
}

void flb_utils_split_free(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_split_entry *entry;

    mk_list_foreach_safe(head, tmp, list) {
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        flb_utils_split_free_entry(entry);
    }

    flb_free(list);
}

/* When a timer expires, it needs some handling */
int flb_utils_timer_consume(flb_pipefd_t fd)
{
    int ret;
    uint64_t val;

    ret = flb_pipe_r(fd, &val, sizeof(val));
    if (ret == -1) {
        flb_pipe_error();
        return -1;
    }

#ifdef __linux__
    /* A timer on linux must return an unisgned 64 bit number */
    if (ret == 0) {
        return -1;
    }
#endif

    return 0;
}

int flb_utils_pipe_byte_consume(flb_pipefd_t fd)
{
    int ret;
    uint64_t val;

    ret = flb_pipe_r(fd, &val, sizeof(val));
    if (ret == -1) {
        flb_pipe_error();
        return -1;
    }

    return 0;
}

int64_t flb_utils_size_to_bytes(const char *size)
{
    int i;
    int len;
    int plen = 0;
    double val;
    char c;
    char tmp[3] = {0};
    int64_t KB = 1000;
    int64_t MB = 1000 * KB;
    int64_t GB = 1000 * MB;

    if (!size) {
        return -1;
    }

    if (strcasecmp(size, "false") == 0) {
        return 0;
    }

    len = strlen(size);
    val = atof(size);

    if (len == 0) {
        return -1;
    }

    for (i = len - 1; i > 0; i--) {
        if (isdigit(size[i])) {
            break;
        }
        else {
            plen++;
        }
    }

    if (plen == 0) {
        return (int64_t)val;
    }
    else if (plen > 2) {
        return -1;
    }

    for (i = 0; i < plen; i++) {
        c = size[(len - plen) + i];
        tmp[i] = toupper(c);
    }

    if (plen == 2) {
        if (tmp[1] != 'B') {
            return -1;
        }
    }

    if (tmp[0] == 'K') {
        /* set upper bound (2**64/KB)/2 to avoid overflows */
        if (val >= 9223372036854775.0 || val <= -9223372036854774.0)
        {
            return -1;
        }
        return (int64_t)(val * KB);
    }
    else if (tmp[0] == 'M') {
        /* set upper bound (2**64/MB)/2 to avoid overflows */
        if (val >= 9223372036854 || val <= -9223372036853) {
            return -1;
        }
        return (int64_t)(val * MB);
    }
    else if (tmp[0] == 'G') {
        /* set upper bound (2**64/GB)/2 to avoid overflows */
        if (val >= 9223372036 || val <= -9223372035) {
            return -1;
        }
        return (int64_t)(val * GB);
    }
    else {
        return -1;
    }

    return (int64_t)val;
}

int64_t flb_utils_size_to_binary_bytes(const char *size)
{
    int i;
    int len;
    int plen = 0;
    double val;
    char tmp[4] = {0};
    int64_t KiB = 1024;
    int64_t MiB = 1024 * KiB;
    int64_t GiB = 1024 * MiB;

    if (!size) {
        return -1;
    }

    if (strcasecmp(size, "false") == 0) {
        return 0;
    }

    len = strlen(size);
    val = atof(size);

    if (len == 0) {
        return -1;
    }

    for (i = len - 1; i >= 0; i--) {
        if (isalpha(size[i])) {
            plen++;
        }
        else {
            break;
        }
    }

    if (plen == 0) {
        return (int64_t)val;
    }
    else if (plen > 3) {
        return -1;
    }

    for (i = 0; i < plen; i++) {
        tmp[i] = toupper(size[len - plen + i]);
    }

    if (plen == 2) {
        if (tmp[1] != 'B') {
            return -1;
        }
    }
    if (plen == 3) {
        if (tmp[1] != 'I' || tmp[2] != 'B') {
            return -1;
        }
    }

    if (tmp[0] == 'K') {
        /* set upper bound (2**64/KiB)/2 to avoid overflows */
        if (val >= 9223372036854775.0 || val <= -9223372036854774.0)
        {
            return -1;
        }
        return (int64_t)(val * KiB);
    }
    else if (tmp[0] == 'M') {
        /* set upper bound (2**64/MiB)/2 to avoid overflows */
        if (val >= 9223372036854.0 || val <= -9223372036853.0) {
            return -1;
        }
        return (int64_t)(val * MiB);
    }
    else if (tmp[0] == 'G') {
        /* set upper bound (2**64/GiB)/2 to avoid overflows */
        if (val >= 9223372036.0 || val <= -9223372035.0) {
            return -1;
        }
        return (int64_t)(val * GiB);
    }
    else {
        return -1;
    }

    return (int64_t)val;
}

int64_t flb_utils_hex2int(char *hex, int len)
{
    int i = 0;
    int64_t res = 0;
    char c;

    while ((c = *hex++) && i < len) {
        /* Ensure no overflow */
        if (res >= (int64_t)((INT64_MAX/0x10) - 0xff)) {
            return -1;
        }

        res *= 0x10;

        if (c >= 'a' && c <= 'f') {
            res += (c - 0x57);
        }
        else if (c >= 'A' && c <= 'F') {
            res += (c - 0x37);
        }
        else if (c >= '0' && c <= '9') {
            res += (c - 0x30);
        }
        else {
            return -1;
        }
        i++;
    }

    if (res < 0) {
        return -1;
    }

    return res;
}

int flb_utils_time_to_seconds(const char *time)
{
    int len;
    size_t val;

    len = strlen(time);
    if (len == 0) {
        return 0;
    }
    val = atoi(time);

    /* String time to seconds */
    if (time[len - 1] == 'D' || time[len - 1] == 'd') {
        val *= 86400;
    }
    if (time[len - 1] == 'H' || time[len - 1] == 'h') {
        val *= 3600;
    }
    else if (time[len - 1] == 'M' || time[len - 1] == 'm') {
        val *= 60;
    }

    return val;
}

int flb_utils_bool(const char *val)
{
    if (strcasecmp(val, "true") == 0 ||
        strcasecmp(val, "on") == 0 ||
        strcasecmp(val, "yes") == 0) {
        return FLB_TRUE;
    }
    else if (strcasecmp(val, "false") == 0 ||
             strcasecmp(val, "off") == 0 ||
             strcasecmp(val, "no") == 0) {
        return FLB_FALSE;
    }

    return -1;
}

/* Convert a 'string' time seconds.nanoseconds to int and long values */
int flb_utils_time_split(const char *time, int *sec, long *nsec)
{
    char *p;
    char *end;
    long val = 0;

    errno = 0;
    val = strtol(time, &end, 10);
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
        || (errno != 0 && val == 0)) {
        flb_errno();
        return -1;
    }
    if (end == time) {
        return -1;
    }
    *sec = (int) val;

    /* Try to find subseconds */
    *nsec = 0;
    p = strchr(time, '.');
    if (p) {
        p += 1;
        val = strtol(p, &end, 10);
        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
            || (errno != 0 && val == 0)) {
            flb_errno();
            return -1;
        }
        if (end == p) {
            return -1;
        }
        *nsec = val;
    }

    return 0;
}

void flb_utils_bytes_to_human_readable_size(size_t bytes,
                                            char *out_buf, size_t size)
{
    unsigned long i;
    unsigned long u = 1024;
    static const char *__units[] = {
        "b", "K", "M", "G",
        "T", "P", "E", "Z", "Y", NULL
    };

    for (i = 0; __units[i] != NULL; i++) {
        if ((bytes / u) == 0) {
            break;
        }
        u *= 1024;
    }
    if (!i) {
        snprintf(out_buf, size, "%lu%s", (long unsigned int) bytes, __units[0]);
    }
    else {
        float fsize = (float) ((double) bytes / (u / 1024));
        snprintf(out_buf, size, "%.1f%s", fsize, __units[i]);
    }
}


static inline void encoded_to_buf(char *out, const char *in, int len)
{
    int i;
    char *p = out;

    for (i = 0; i < len; i++) {
        *p++ = in[i];
    }
}

/* Structure to hold escape sequence */
struct escape_seq {
    const char *seq;
};

/* Lookup table for escape sequences */
static const struct escape_seq json_escape_table[128] = {
    ['\"'] = {"\\\""},
    ['\\'] = {"\\\\"},
    ['\n'] = {"\\n"},
    ['\r'] = {"\\r"},
    ['\t'] = {"\\t"},
    ['\b'] = {"\\b"},
    ['\f'] = {"\\f"},
    [0x00] = {"\\u0000"}, [0x01] = {"\\u0001"}, [0x02] = {"\\u0002"}, [0x03] = {"\\u0003"},
    [0x04] = {"\\u0004"}, [0x05] = {"\\u0005"}, [0x06] = {"\\u0006"}, [0x07] = {"\\u0007"},
    [0x0B] = {"\\u000b"}, [0x0E] = {"\\u000e"}, [0x0F] = {"\\u000f"},
    [0x10] = {"\\u0010"}, [0x11] = {"\\u0011"}, [0x12] = {"\\u0012"}, [0x13] = {"\\u0013"},
    [0x14] = {"\\u0014"}, [0x15] = {"\\u0015"}, [0x16] = {"\\u0016"}, [0x17] = {"\\u0017"},
    [0x18] = {"\\u0018"}, [0x19] = {"\\u0019"}, [0x1A] = {"\\u001a"}, [0x1B] = {"\\u001b"},
    [0x1C] = {"\\u001c"}, [0x1D] = {"\\u001d"}, [0x1E] = {"\\u001e"}, [0x1F] = {"\\u001f"},
    [0x7F] = {"\\u007f"}
};

/*
 * Write string pointed by 'str' to the destination buffer 'buf'. It's make sure
 * to escape special characters and convert utf-8 byte characters to string
 * representation.
 */
static int flb_utils_write_str_escaped(char *buf, int *off, size_t size, const char *str, size_t str_len)
{
    int i, b, ret, len, hex_bytes, utf_sequence_length, utf_sequence_number;
    int processed_bytes = 0;
    int is_valid, copypos = 0, vlen;
    uint32_t c;
    uint32_t codepoint = 0;
    uint32_t state = 0;
    size_t available;
    uint8_t *s;
    off_t offset = 0;
    char tmp[16];
    char *p;
    const size_t inst_len = FLB_SIMD_VEC8_INST_LEN;

    /* to encode codepoints > 0xFFFF */
    uint16_t high;
    uint16_t low;

    available = size - *off;

    /* Ensure we have some minimum space in the buffer */
    if (available < str_len) {
        return FLB_FALSE;
    }

    p = buf + *off;

    /* align length to the nearest multiple of the vector size for safe SIMD processing */
    vlen = str_len & ~(inst_len - 1);
    for (i = 0;;) {
        /* SIMD optimization: Process chunk of input string */
        for (; i < vlen; i += inst_len) {
            flb_vector8 chunk;
            flb_vector8_load(&chunk, (const uint8_t *)&str[i]);

            /*
             * Look for the special characters we are interested in,
             * if they are found we break the loop and escape them
             * in a char-by-char basis. Otherwise the do a bulk copy
             */
            if (flb_vector8_has_le(chunk, (unsigned char) 0x1F) ||
                flb_vector8_has(chunk, (unsigned char) '"')    ||
                flb_vector8_has(chunk, (unsigned char) '\\')  ||
                flb_vector8_is_highbit_set(chunk)) {
                break;

            }
        }

        /* Copy the chunk processed so far */
        if (copypos < i) {
            /* check if we have enough space */
            if (available < i - copypos) {
                return FLB_FALSE;
            }

            /* copy and adjust pointers */
            memcpy(p, &str[copypos], i - copypos);
            p += i - copypos;
            offset += i - copypos;
            available -= (i - copypos);
            copypos = i;
        }

        /* Process remaining characters one by one */
        for (b = 0; b < inst_len; b++) {
            if (i >= str_len) {
                /* all characters has been processed */
                goto done;
            }

            c = (uint32_t) str[i];

            /* Use lookup table for escaping known sequences */
            if (c < 128 && json_escape_table[c].seq) {
                /*
                 * All characters in the table have a lenght of 2 or 6 bytes,
                 * just check if the second byte starts with 'u' so we know
                 * it's unicode and needs 6 bytes of space.
                 */
                if (json_escape_table[c].seq[1] == 'u') {
                    len = 6;
                }
                else {
                    len = 2;
                }

                /* check if we have anough space */
                if (available < len) {
                    return FLB_FALSE;
                }

                /* copy the escape sequence */
                memcpy(p, json_escape_table[c].seq, len);
                p += len;
                offset += len;
                available -= len;
            }
            /* Handle UTF-8 sequences from 0x80 to 0xFFFF */
            else if (c >= 0x80 && c <= 0xFFFF) {
                hex_bytes = flb_utf8_len(&str[i]);

                /* Handle invalid or truncated sequence */
                if (hex_bytes == 0 || i + hex_bytes > str_len) {
                    /* check for the minimum space required */
                    if (available < 3) {
                        return FLB_FALSE;
                    }

                    /* insert replacement character (U+FFFD) */
                    p[0] = 0xEF;
                    p[1] = 0xBF;
                    p[2] = 0xBD;
                    p += 3;
                    offset += 3;
                    available -= 3;

                    /* skip the original byte */
                    i++;
                    continue;
                }

                /* decode UTF-8 sequence */
                state = FLB_UTF8_ACCEPT;
                codepoint = 0;
                processed_bytes = 0;

                for (b = 0; b < hex_bytes; b++) {
                    s = (unsigned char *) &str[i + b];
                    ret = flb_utf8_decode(&state, &codepoint, *s);
                    processed_bytes++;

                    if (ret == FLB_UTF8_ACCEPT) {
                        /* check if all required bytes for the sequence are processed */
                        if (processed_bytes == hex_bytes) {
                            break;
                        }
                    }
                    else if (ret == FLB_UTF8_REJECT) {
                        flb_warn("[pack] Invalid UTF-8 bytes found, skipping.");
                        break;
                    }
                }

                if (state == FLB_UTF8_ACCEPT) {
                    len = snprintf(tmp, sizeof(tmp), "\\u%.4x", codepoint);
                    if (available < len) {
                        return FLB_FALSE;
                    }
                    memcpy(p, tmp, len);
                    p += len;
                    offset += len;
                    available -= len;
                }
                else {
                    flb_warn("[pack] Invalid UTF-8 bytes found, skipping.");
                }

                i += processed_bytes;
            }
            /* Handle sequences beyond 0xFFFF */
            else if (c > 0xFFFF) {
                utf_sequence_length = flb_utf8_len(str + i);

                /* skip truncated UTF-8 ? */
                if (i + utf_sequence_length > str_len) {
                    i++;
                    break;
                }

                state = FLB_UTF8_ACCEPT;
                codepoint = 0;
                is_valid = FLB_TRUE;

                /* Decode the sequence */
                for (utf_sequence_number = 0; utf_sequence_number < utf_sequence_length; utf_sequence_number++) {
                    ret = flb_utf8_decode(&state, &codepoint, (uint8_t) str[i]);

                    if (ret == FLB_UTF8_REJECT) {
                        /* Handle invalid leading byte */
                        if (utf_sequence_number == 0) {
                            flb_debug("[pack] unexpected UTF-8 leading byte, substituting character");
                            tmp[utf_sequence_number] = str[i];
                            utf_sequence_length = utf_sequence_number + 1; /* Process only this invalid byte */
                            i++; /* Consume invalid byte */
                        }
                        /* Handle invalid continuation byte */
                        else {
                            flb_debug("[pack] unexpected UTF-8 continuation byte, substituting character");
                            utf_sequence_length = utf_sequence_number; /* Adjust length */
                        }
                        is_valid = FLB_FALSE;
                        break;
                    }

                    tmp[utf_sequence_number] = str[i];
                    ++i;
                }

                --i;

                if (is_valid) {
                    if (available < utf_sequence_length) {
                        /* not enough space */
                        return FLB_FALSE;
                    }

                    /* Handle codepoints beyond BMP (requires surrogate pairs in UTF-16) */
                    if (codepoint > 0xFFFF) {
                        high = 0xD800 + ((codepoint - 0x10000) >> 10);
                        low = 0xDC00 + ((codepoint - 0x10000) & 0x3FF);

                        len = snprintf(tmp, sizeof(tmp), "\\u%.4x\\u%.4x", high, low);
                    }
                    else {
                        len = snprintf(tmp, sizeof(tmp), "\\u%.4x", codepoint);
                    }

                    if (available < len) {
                        /* not enough space */
                        return FLB_FALSE;
                    }
                    memcpy(p, tmp, len);
                    p += len;
                    offset += len;
                    available -= len;
                }
                else {
                    if (available < utf_sequence_length * 3) {
                        return FLB_FALSE;
                    }

                    /*
                    * Utf-8 sequence is invalid. Map fragments to private use area
                    * codepoints in range:
                    * 0x<FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR>00 to
                    * 0x<FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR>FF
                    */
                    for (b = 0; b < utf_sequence_length; ++b) {
                        /*
                        * Utf-8 private block invalid hex mapping. Format unicode charpoint
                        * in the following format:
                        *
                        *      +--------+--------+--------+
                        *      |1110PPPP|10PPPPHH|10HHHHHH|
                        *      +--------+--------+--------+
                        *
                        * Where:
                        *   P is FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR bits (1 byte)
                        *   H is Utf-8 fragment hex bits (1 byte)
                        *   1 is bit 1
                        *   0 is bit 0
                        */

                        /* unicode codepoint start */
                        *p = 0xE0;

                        /* print unicode private block header first 4 bits */
                        *p |= FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR >> 4;
                        ++p;

                        /* unicode codepoint middle */
                        *p = 0x80;

                        /* print end of unicode private block header last 4 bits */
                        *p |= ((FLB_UTILS_FRAGMENT_PRIVATE_BLOCK_DESCRIPTOR << 2) & 0x3f);

                        /* print hex fragment first 2 bits */
                        *p |= (tmp[b] >> 6) & 0x03;
                        ++p;

                        /* unicode codepoint middle */
                        *p = 0x80;

                        /* print hex fragment last 6 bits */
                        *p |= tmp[b] & 0x3f;
                        ++p;

                        offset += 3;
                        available -= 3;
                    }
                }

            }
             else {
                if (available < 1) {
                    /*  no space for a single byte */
                    return FLB_FALSE;
                }
                *p++ = c;
                offset++;
                available--;
            }

            i++;
        }

        copypos = i;
    }

done:
    /* update the buffer offset */
    *off += offset;

    return FLB_TRUE;
}

static inline int flb_utf8_validate_char(const unsigned char *str, int max_len)
{
    unsigned char c = str[0];
    int len = 0;
    int i;

    if (max_len < 1) {
        return 0;
    }

    /* 1-byte sequence (ASCII) */
    if (c <= 0x7F) {
        return 1;
    }
    /* 2-byte sequence */
    else if ((c & 0xE0) == 0xC0) {
        if (c < 0xC2) return 0; /* Overlong encoding */
        len = 2;
    }
    /* 3-byte sequence */
    else if ((c & 0xF0) == 0xE0) {
        if (max_len > 1 && c == 0xE0 && (unsigned char)str[1] < 0xA0) {
            return 0; /* Overlong */
        }
        if (max_len > 1 && c == 0xED && (unsigned char)str[1] >= 0xA0) {
            return 0; /* Surrogates */
        }
        len = 3;
    }
    /* 4-byte sequence */
    else if ((c & 0xF8) == 0xF0) {
        if (max_len > 1 && c == 0xF0 && (unsigned char)str[1] < 0x90) {
            return 0; /* Overlong */
        }
        if (c > 0xF4) {
            return 0; /* Outside of Unicode range */
        }
        if (max_len > 1 && c == 0xF4 && (unsigned char)str[1] > 0x8F) {
            return 0; /* Outside of Unicode range */
        }
        len = 4;
    }
    else {
        return 0; /* Invalid starting byte */
    }

    if (max_len < len) {
        return 0; /* Truncated sequence */
    }

    for (i = 1; i < len; i++) {
        if ((str[i] & 0xC0) != 0x80) {
            return 0; /* Invalid continuation byte */
        }
    }

    return len;
}

/* Safely copies raw UTF-8 strings, only escaping essential characters.
 * This version correctly implements the repeating SIMD fast path for performance.
 */
static int flb_utils_write_str_raw(char *buf, int *off, size_t size,
                                   const char *str, size_t str_len)
{
    int i, b, vlen, len, utf_len, copypos = 0;
    size_t available;
    char *p;
    off_t offset = 0;
    const size_t inst_len = FLB_SIMD_VEC8_INST_LEN;
    uint32_t c;
    char *seq = NULL;

    available = size - *off;
    p = buf + *off;

    /* align length to the nearest multiple of the vector size for safe SIMD processing */
    vlen = str_len & ~(inst_len - 1);

    for (i = 0;;) {
        /*
         * Process chunks of the input string using SIMD instructions.
         * This loop continues as long as it finds "safe" ASCII characters.
         */
        for (; i < vlen; i += inst_len) {
            flb_vector8 chunk;
            flb_vector8_load(&chunk, (const uint8_t *)&str[i]);

            /* If a special character is found, break and switch to the slow path */
            if (flb_vector8_has_le(chunk, (unsigned char) 0x1F) ||
                flb_vector8_has(chunk, (unsigned char) '"')    ||
                flb_vector8_has(chunk, (unsigned char) '\\')   ||
                flb_vector8_is_highbit_set(chunk)) {
                break;
            }
        }

        /* Copy the 'safe' chunk processed by the SIMD loop so far */
        if (copypos < i) {
            if (available < i - copypos) {
                return FLB_FALSE;
            }
            memcpy(p, &str[copypos], i - copypos);
            p += i - copypos;
            offset += i - copypos;
            available -= (i - copypos);
            copypos = i;
        }

        /*
         * Process the next 16-byte chunk character by character.
         * This loop runs only for a chunk that contains special characters.
         */
        for (b = 0; b < inst_len; b++) {
            if (i >= str_len) {
                goto done;
            }

            c = (uint32_t) str[i];
            len = 0;
            seq = NULL;

            /* Handle essential escapes for JSON validity */
            if (c < 128 && json_escape_table[c].seq) {
                seq = json_escape_table[c].seq;
                len = json_escape_table[c].seq[1] == 'u' ? 6 : 2;
                if (available < len) {
                    return FLB_FALSE;
                }
                memcpy(p, seq, len);
                p += len;
                offset += len;
                available -= len;
            }
            else if (c < 0x80) { /* Regular ASCII */
                if (available < 1) {
                    return FLB_FALSE;
                }
                *p++ = c;
                offset++;
                available--;
            }
            else { /* Multibyte UTF-8 sequence */
                utf_len = flb_utf8_validate_char((const unsigned char *)&str[i], str_len - i);

                if (utf_len == 0 || i + utf_len > str_len) { /* Invalid/truncated */
                    if (available < 3) {
                        return FLB_FALSE;
                    }
                    memcpy(p, "\xEF\xBF\xBD", 3); /* Standard replacement character */
                    p += 3;
                    offset += 3;
                    available -= 3;
                }
                else { /* Valid sequence, copy raw */
                    if (available < utf_len) {
                        return FLB_FALSE;
                    }
                    memcpy(p, &str[i], utf_len);
                    p += utf_len;
                    offset += utf_len;
                    available -= utf_len;
                    i += utf_len - 1; /* Advance loop counter by extra bytes */
                }
            }
            i++;
        }
        copypos = i;
    }

done:
    *off += offset;
    return FLB_TRUE;
}

/*
 * This is the wrapper public function for acting as a wrapper and calls the
 * appropriate specialized function based on the escape_unicode flag.
 */
int flb_utils_write_str(char *buf, int *off, size_t size, const char *str, size_t str_len,
                        int escape_unicode)
{
    if (escape_unicode == FLB_TRUE) {
        return flb_utils_write_str_escaped(buf, off, size, str, str_len);
    }
    else {
        return flb_utils_write_str_raw(buf, off, size, str, str_len);
    }
}

int flb_utils_write_str_buf(const char *str, size_t str_len, char **out, size_t *out_size,
                            int escape_unicode)
{
    int ret;
    int off;
    char *tmp;
    char *buf;
    size_t s;

    s = str_len + 1;
    buf = flb_malloc(s);
    if (!buf) {
        flb_errno();
        return -1;
    }

    while (1) {
        off = 0;
        ret = flb_utils_write_str(buf, &off, s, str, str_len, escape_unicode);
        if (ret == FLB_FALSE) {
            s += 256;
            tmp = flb_realloc(buf, s);
            if (!tmp) {
                flb_errno();
                flb_free(buf);
                return -1;
            }
            buf = tmp;
        }
        else {
            /* done */
            break;
        }
    }

    *out = buf;
    *out_size = off;
    return 0;
}

static char *flb_copy_host(const char *string, int pos_init, int pos_end)
{
    if (string[pos_init] == '[') {            /* IPv6 */
        if (string[pos_end-1] != ']') {
            return NULL;
        }
        return mk_string_copy_substr(string, pos_init + 1, pos_end - 1);
    }
    else {
        return mk_string_copy_substr(string, pos_init, pos_end);
    }
}

static char *flb_utils_copy_host_sds(const char *string, int pos_init, int pos_end)
{
    if (string[pos_init] == '[') {            /* IPv6 */
        if (string[pos_end-1] != ']') {
            return NULL;
        }
        return flb_sds_create_len(string + pos_init + 1, pos_end - pos_init - 2);
    }
    else {
        return flb_sds_create_len(string + pos_init, pos_end - pos_init);
    }
}

/* Validate IPv6 bracket syntax in URL host part */
static int validate_ipv6_brackets(const char *p, const char **out_bracket)
{
    const char *host_end;
    const char *bracket = NULL;
    const char *closing;
    const char *query_or_fragment;

    /* Only inspect the host portion (up to the first '/', '?', or '#') */
    host_end = strchr(p, '/');
    query_or_fragment = strpbrk(p, "?#");
    
    /* Use the earliest delimiter found */
    if (query_or_fragment && (!host_end || query_or_fragment < host_end)) {
        host_end = query_or_fragment;
    }
    
    if (!host_end) {
        host_end = p + strlen(p);
    }

    if (p[0] == '[') {
        closing = memchr(p, ']', host_end - p);
        if (!closing || closing == p + 1) {
            /* Missing closing bracket or empty brackets [] */
            return -1;
        }
        bracket = closing;
    }
    else {
        /* Non-bracketed hosts must not contain ']' before the first '/' */
        closing = memchr(p, ']', host_end - p);
        if (closing) {
            return -1;
        }
    }

    if (out_bracket) {
        *out_bracket = bracket;
    }
    return 0;
}

/* Helper to create URI with prepended '/' if it starts with '?' or '#' */
static char *create_uri_with_slash(const char *uri_part)
{
    char *uri;
    size_t uri_part_len;

    if (!uri_part || *uri_part == '\0') {
        return flb_strdup("/");
    }

    /* If URI starts with '?' or '#', prepend '/' */
    if (*uri_part == '?' || *uri_part == '#') {
        uri_part_len = strlen(uri_part);
        /* Allocate space for '/' + uri_part + '\0' */
        uri = flb_malloc(uri_part_len + 2);
        if (!uri) {
            return NULL;
        }
        uri[0] = '/';
        /* +1 to include '\0' */
        memcpy(uri + 1, uri_part, uri_part_len + 1);
        return uri;
    }

    /* URI already starts with '/' or is a normal path */
    return flb_strdup(uri_part);
}

/* SDS version: Helper to create URI with prepended '/' if it starts with '?' or '#' */
static flb_sds_t create_uri_with_slash_sds(const char *uri_part)
{
    char *result;
    flb_sds_t uri;

    /* Use the regular version to create the string */
    result = create_uri_with_slash(uri_part);
    if (!result) {
        return NULL;
    }

    /* Convert to SDS */
    uri = flb_sds_create(result);
    flb_free(result);

    return uri;
}

int flb_utils_url_split(const char *in_url, char **out_protocol,
                        char **out_host, char **out_port, char **out_uri)
{
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    char *p;
    char *tmp;
    char *sep;
    const char *bracket = NULL;

    /* Protocol */
    p = strstr(in_url, "://");
    if (!p) {
        return -1;
    }
    if (p == in_url) {
        return -1;
    }

    protocol = mk_string_copy_substr(in_url, 0, p - in_url);
    if (!protocol) {
        flb_errno();
        return -1;
    }

    /* Advance position after protocol */
    p += 3;

    /* Validate IPv6 brackets */
    sep = strchr(p, '/');
    if (validate_ipv6_brackets(p, &bracket) < 0) {
        flb_errno();
        goto error;
    }

    /* Compute end of host segment (before '/', '?', or '#') */
    const char *host_end = sep;
    const char *qf = strpbrk(p, "?#");

    if (!host_end || (qf && qf < host_end)) {
        host_end = qf;
    }
    if (!host_end) {
        host_end = p + strlen(p);
    }

    if (bracket) {
        /* For bracketed IPv6, only ports after ']' and before URI delimiters are valid */
        tmp = memchr(bracket, ':', host_end - bracket);
    }
    else {
        /* Non-IPv6: limit ':' search to the host portion */
        tmp = memchr(p, ':', host_end - p);
    }

    /* Extract host if port separator was found */
    if (tmp) {
        host = flb_copy_host(p, 0, tmp - p);
        if (!host) {
            flb_errno();
            goto error;
        }
        p = tmp + 1;
    }

    /* Find URI delimiter (/, ?, or #) */
    tmp = strpbrk(p, "/?#");
    
    if (!host) {
        /* No port: extract host */
        if (tmp) {
            host = flb_copy_host(p, 0, tmp - p);
        }
        else {
            host = flb_copy_host(p, 0, strlen(p));
        }
        if (!host) {
            flb_errno();
            goto error;
        }
    }
    else {
        /* Port exists: extract port */
        if (tmp) {
            port = mk_string_copy_substr(p, 0, tmp - p);
        }
        else {
            port = flb_strdup(p);
        }
    }

    /* Extract URI */
    if (tmp) {
        uri = create_uri_with_slash(tmp);
        if (!uri) {
            flb_errno();
            goto error;
        }
    }
    else {
        uri = flb_strdup("/");
    }

    if (!port) {
        if (strcmp(protocol, "http") == 0) {
            port = flb_strdup("80");
        }
        else if (strcmp(protocol, "https") == 0) {
            port = flb_strdup("443");
        }
    }

    *out_protocol = protocol;
    *out_host = host;
    *out_port = port;
    *out_uri = uri;

    return 0;

 error:
    if (protocol) {
        flb_free(protocol);
    }
    if (host) {
        flb_free(host);
    }
    if (port) {
        flb_free(port);
    }
    if (uri) {
        flb_free(uri);
    }

    return -1;
}

int flb_utils_url_split_sds(const flb_sds_t in_url, flb_sds_t *out_protocol,
                            flb_sds_t *out_host, flb_sds_t *out_port, flb_sds_t *out_uri)
{
    int i;
    flb_sds_t protocol = NULL;
    flb_sds_t host = NULL;
    flb_sds_t port = NULL;
    flb_sds_t uri = NULL;
    char *p = NULL;
    char *tmp = NULL;
    char *sep = NULL;
    const char *bracket = NULL;

    /* Protocol */
    p = strstr(in_url, "://");
    if (!p) {
        return -1;
    }
    if (p == in_url) {
        return -1;
    }

    protocol = flb_sds_create_len(in_url, p - in_url);
    if (!protocol) {
        flb_errno();
        return -1;
    }

    /* Advance position after protocol */
    p += 3;

    /* Validate IPv6 brackets */
    sep = strchr(p, '/');
    if (validate_ipv6_brackets(p, &bracket) < 0) {
        flb_errno();
        goto error;
    }

    /* Compute end of host segment (before '/', '?', or '#') */
    const char *host_end = sep;
    const char *qf = strpbrk(p, "?#");

    if (!host_end || (qf && qf < host_end)) {
        host_end = qf;
    }
    if (!host_end) {
        host_end = p + strlen(p);
    }

    if (bracket) {
        /* For bracketed IPv6, only ports after ']' and before URI delimiters are valid */
        tmp = memchr(bracket, ':', host_end - bracket);
    }
    else {
        /* Non-IPv6: limit ':' search to the host portion */
        tmp = memchr(p, ':', host_end - p);
    }

    /* Extract host if port separator was found */
    if (tmp) {
        host = flb_utils_copy_host_sds(p, 0, tmp - p);
        if (!host) {
            flb_errno();
            goto error;
        }
        p = tmp + 1;
    }

    /* Find URI delimiter (/, ?, or #) */
    tmp = strpbrk(p, "/?#");
    
    if (!host) {
        /* No port: extract host */
        if (tmp) {
            host = flb_utils_copy_host_sds(p, 0, tmp - p);
        }
        else {
            host = flb_utils_copy_host_sds(p, 0, strlen(p));
        }
        if (!host) {
            flb_errno();
            goto error;
        }
    }
    else {
        /* Port exists: extract port */
        if (tmp) {
            port = flb_sds_create_len(p, tmp - p);
        }
        else {
            port = flb_sds_create_len(p, strlen(p));
        }
    }

    /* Extract URI */
    if (tmp) {
        uri = create_uri_with_slash_sds(tmp);
        if (!uri) {
            flb_errno();
            goto error;
        }
    }
    else {
        uri = flb_sds_create("/");
    }

    if (!port) {
        if (strcmp(protocol, "http") == 0) {
            port = flb_sds_create("80");
        }
        else if (strcmp(protocol, "https") == 0) {
            port = flb_sds_create("443");
        }
    }

    if (!host) {
        flb_errno();
        goto error;
    }

    if (!port) {
        flb_errno();
        goto error;
    }
    else {
        /* check that port is a number */
        for (i = 0; i < flb_sds_len(port); i++) {
            if (!isdigit(port[i])) {
                goto error;
            }
        }

    }

    if (!uri) {
        flb_errno();
        goto error;
    }

    *out_protocol = protocol;
    *out_host = host;
    *out_port = port;
    *out_uri = uri;

    return 0;

 error:
    if (protocol) {
        flb_sds_destroy(protocol);
    }
    if (host) {
        flb_sds_destroy(host);
    }
    if (port) {
        flb_sds_destroy(port);
    }
    if (uri) {
        flb_sds_destroy(uri);
    }

    return -1;
}


/*
 * flb_utils_proxy_url_split parses a proxy's information from a http_proxy URL.
 * The URL is in the form like `http://[username:password@]myproxy.com:8080`.
 * Note: currently only HTTP is supported.
 */
int flb_utils_proxy_url_split(const char *in_url, char **out_protocol,
                              char **out_username, char **out_password,
                              char **out_host, char **out_port)
{
    const char *at_sep;
    const char *tmp;
    const char *port_start;
    const char *end;
    const char *authority;
    char *protocol = NULL;
    char *username = NULL;
    char *password = NULL;
    char *host = NULL;
    char *port = NULL;

    if (!in_url || *in_url == '\0') {
        flb_error("HTTP_PROXY variable must specify a proxy host");
        return -1;
    }

    /*  Parse protocol */
    tmp = strstr(in_url, "://");
    if (tmp) {
        if (tmp == in_url) {
            flb_error("HTTP_PROXY variable must be set in the form of '[http://][username:password@]host:port'");
            return -1;
        }

        protocol = mk_string_copy_substr(in_url, 0, tmp - in_url);
        if (!protocol) {
            flb_errno();
            return -1;
        }

        /* Only HTTP proxy is supported for now. */
        if (strcmp(protocol, "http") != 0) {
            flb_error("only HTTP proxy is supported.");
            goto error;
        }

        authority = tmp + 3;
    }
    else {
        protocol = flb_strdup("http");
        if (!protocol) {
            flb_errno();
            return -1;
        }

        authority = in_url;
    }

    if (!authority || *authority == '\0') {
        flb_error("HTTP_PROXY variable must include a host");
        goto error;
    }

    /* Separate `username:password` and `host:port` */
    at_sep = strrchr(authority, '@');
    if (at_sep) {
        tmp = strchr(authority, ':');
        if (!tmp || tmp > at_sep) {
            flb_error("invalid HTTP proxy credentials");
            goto error;
        }

        username = mk_string_copy_substr(authority, 0, tmp - authority);
        if (!username) {
            flb_errno();
            goto error;
        }

        tmp += 1;
        password = mk_string_copy_substr(tmp, 0, at_sep - tmp);
        if (!password) {
            flb_errno();
            goto error;
        }

        authority = at_sep + 1;
    }

    if (!authority || *authority == '\0') {
        flb_error("HTTP proxy host is missing");
        goto error;
    }

    if (*authority == '[') {
        end = strchr(authority, ']');
        if (!end) {
            flb_error("invalid HTTP proxy host");
            goto error;
        }

        host = flb_copy_host(authority, 0, end - authority + 1);
        if (!host) {
            flb_error("invalid HTTP proxy host");
            goto error;
        }

        if (*(end + 1) == ':') {
            port_start = end + 2;
            if (*port_start == '\0') {
                flb_error("invalid HTTP proxy port");
                goto error;
            }

            port = flb_strdup(port_start);
            if (!port) {
                flb_errno();
                goto error;
            }
        }
        else if (*(end + 1) == '\0') {
            port = flb_strdup("80");
            if (!port) {
                flb_errno();
                goto error;
            }
        }
        else {
            flb_error("invalid HTTP proxy host");
            goto error;
        }
    }
    else {
        tmp = strrchr(authority, ':');
        if (tmp) {
            host = flb_copy_host(authority, 0, tmp - authority);
            if (!host) {
                flb_error("invalid HTTP proxy host");
                goto error;
            }

            port_start = tmp + 1;
            if (*port_start == '\0') {
                flb_error("invalid HTTP proxy port");
                goto error;
            }

            port = flb_strdup(port_start);
            if (!port) {
                flb_errno();
                goto error;
            }
        }
        else {
            host = flb_copy_host(authority, 0, strlen(authority));
            if (!host) {
                flb_error("invalid HTTP proxy host");
                goto error;
            }

            port = flb_strdup("80");
            if (!port) {
                flb_errno();
                goto error;
            }
        }
    }

    if (!host || *host == '\0') {
        flb_error("HTTP proxy host is missing");
        goto error;
    }

    *out_protocol = protocol;
    *out_host = host;
    *out_port = port;
    if (out_username) {
        *out_username = username;
    }
    else if (username) {
        flb_free(username);
    }

    if (out_password) {
        *out_password = password;
    }
    else if (password) {
        flb_free(password);
    }

    return 0;

error:
    if (protocol) {
        flb_free(protocol);
    }
    if (username) {
        flb_free(username);
    }
    if (password) {
        flb_free(password);
    }
    if (host) {
        flb_free(host);
    }
    if (port) {
        flb_free(port);
    }

    return -1;
}


char *flb_utils_get_os_name()
{
#ifdef _WIN64
    return "win64";
#elif _WIN32
    return "win32";
#elif __APPLE__ || __MACH__
    return "macos";
#elif __linux__
    return "linux";
#elif __FreeBSD__
    return "freebsd";
#elif __unix || __unix__
    return "unix";
#else
    return "other";
#endif
}

#ifdef FLB_HAVE_OPENSSL
int flb_utils_uuid_v4_gen(char *buf)
{
    int ret;
    union {
        struct {
            uint32_t time_low;
            uint16_t time_mid;
            uint16_t time_hi_and_version;
            uint8_t  clk_seq_hi_res;
            uint8_t  clk_seq_low;
            uint8_t  node[6];
        };
        uint8_t __rnd[16];
    } uuid;

    ret = RAND_bytes(uuid.__rnd, sizeof(uuid));

    uuid.clk_seq_hi_res = (uint8_t) ((uuid.clk_seq_hi_res & 0x3F) | 0x80);
    uuid.time_hi_and_version = (uint16_t) ((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

    snprintf(buf, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
            uuid.clk_seq_hi_res, uuid.clk_seq_low,
            uuid.node[0], uuid.node[1], uuid.node[2],
            uuid.node[3], uuid.node[4], uuid.node[5]);

    if (ret == 1) {
        return 0;
    }

    return -1;
}
#else
int flb_utils_uuid_v4_gen(char *buf)
{
    snprintf(buf, 38, "ddad00f1-3806-46ab-88d1-277a8c863cd6");
    return 0;
}
#endif

int flb_utils_read_file(char *path, char **out_buf, size_t *out_size)
{
    return flb_utils_read_file_offset(path, 0, 0, out_buf, out_size);
}

int flb_utils_read_file_offset(char *path, off_t offset_start, off_t offset_end, char **out_buf, size_t *out_size)
{
    int fd;
    int ret;
    size_t bytes;
    size_t bytes_to_read;
    size_t total_bytes_read = 0;
    struct stat st;
    flb_sds_t buf;
    FILE *fp;

    fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }
    fd = fileno(fp);

    ret = fstat(fd, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    if (offset_start > st.st_size || offset_end > st.st_size) {
        flb_error("offsets exceed file size (%jd bytes)", (intmax_t) st.st_size);
        fclose(fp);
        return -1;
    }

    if (offset_start > 0) {
        ret = fseek(fp, offset_start, SEEK_SET);
        if (ret != 0) {
            flb_errno();
            fclose(fp);
            return -1;
        }
    }

    if (offset_end == 0) {
        offset_end = st.st_size;
    }

    bytes_to_read = offset_end - offset_start;

    buf = flb_calloc(1, bytes_to_read + 1);
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    while (total_bytes_read < bytes_to_read) {
        bytes = fread(buf + total_bytes_read, 1, bytes_to_read - total_bytes_read, fp);
        if (bytes < 1) {
            if (feof(fp)) {
                break;
            }
            if (ferror(fp)) {
                flb_errno();
                free(buf);
                fclose(fp);
                return -1;
            }
        }
        total_bytes_read += bytes;
    }
    fclose(fp);

    *out_buf = buf;
    *out_size = total_bytes_read;

    return 0;
}

static int machine_id_read_and_sanitize(char *path,
                                        char **out_buf, size_t *out_size)
{
    int ret;
    size_t s;
    char *p;
    char *buf;
    size_t bytes;

    ret = flb_utils_read_file(path, &buf, &bytes);
    if (ret != 0) {
        return -1;
    }

    p = buf + bytes - 1;
    while (*p == ' ' || *p == '\n') {
        p--;
    }

    /* set new size */
    s = p - buf + 1;

    buf[s] = '\0';
    *out_size = s;
    *out_buf = buf;

    return 0;
}

int flb_utils_get_machine_id(char **out_id, size_t *out_size)
{
    int ret;
    char *id;
    size_t bytes;
    char *uuid;
    int fallback = FLB_FALSE;

#ifdef __linux__
    char *dbus_var = "/var/lib/dbus/machine-id";
    char *dbus_etc = "/etc/machine-id";

    /* dbus */
    if (access(dbus_var, F_OK) == 0) { /* check if the file exists first */
        ret = machine_id_read_and_sanitize(dbus_var, &id, &bytes);
        if (ret == 0) {
            if (bytes == 0) {
                /* guid is somewhat corrupted */
                fallback = FLB_TRUE;
                goto fallback;
            }
            *out_id = id;
            *out_size = bytes;
            return 0;
        }
    }

    /* etc */
    if (access(dbus_etc, F_OK) == 0) { /* check if the file exists first */
        ret = machine_id_read_and_sanitize(dbus_etc, &id, &bytes);
        if (ret == 0) {
            if (bytes == 0) {
                /* guid is somewhat corrupted */
                fallback = FLB_TRUE;
                goto fallback;
            }
            *out_id = id;
            *out_size = bytes;
            return 0;
        }
    }
#elif defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__) || defined(__DragonFly__)

    char *hostid = "/etc/hostid";

    /* hostid */
    ret = machine_id_read_and_sanitize(hostid, &id, &bytes);
    if (ret == 0) {
        *out_id = id;
        *out_size = bytes;
        return 0;
    }
#elif defined(FLB_SYSTEM_WINDOWS)
    LSTATUS status;
    HKEY hKey = 0;
    DWORD dwType = REG_SZ;
    char buf[255] = {0};
    DWORD dwBufSize = sizeof(buf)-1;

    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                          TEXT("SOFTWARE\\Microsoft\\Cryptography"),
                          0,
                          KEY_QUERY_VALUE|KEY_WOW64_64KEY,
                          &hKey);

    if (status != ERROR_SUCCESS) {
        return -1;
    }

    status = RegQueryValueEx(hKey, TEXT("MachineGuid"), 0, &dwType, (LPBYTE)buf, &dwBufSize );
    RegCloseKey(hKey);

    if (status == ERROR_SUCCESS) {
        *out_id = flb_calloc(1, dwBufSize+1);

        if (*out_id == NULL) {
            return -1;
        }

        memcpy(*out_id, buf, dwBufSize);

        /* RegQueryValueEx sets dwBufSize to strlen()+1 for the NULL
         * terminator, but we only need strlen(). */
        *out_size = dwBufSize-1;
        return 0;
    }
    else {
        flb_error("unable to retrieve MachineGUID, error code: %d", status);
    }
#elif defined (FLB_SYSTEM_MACOS)
    bool bret;
    CFStringRef serialNumber;
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice"));

    if (platformExpert) {
        CFTypeRef serialNumberAsCFString =
            IORegistryEntryCreateCFProperty(platformExpert,
                                        CFSTR(kIOPlatformSerialNumberKey),
                                        kCFAllocatorDefault, 0);
        if (serialNumberAsCFString) {
            serialNumber = (CFStringRef)serialNumberAsCFString;
        }
        else {
            IOObjectRelease(platformExpert);
            return -1;
        }
        IOObjectRelease(platformExpert);

        *out_size = CFStringGetLength(serialNumber);
        *out_id = flb_malloc(CFStringGetLength(serialNumber)+1);

        if (*out_id == NULL) {
            return -1;
        }

        bret = CFStringGetCString(serialNumber, *out_id,
                                  CFStringGetLength(serialNumber)+1,
                                  kCFStringEncodingUTF8);
        CFRelease(serialNumber);

        if (bret == false) {
            *out_size = 0;
            return -1;
        }

        return 0;
    }
#endif

fallback:

    flb_warn("falling back on random machine UUID");

    /* generate a random uuid */
    uuid = flb_malloc(38);
    if (!uuid) {
        flb_errno();
        return -1;
    }
    ret = flb_utils_uuid_v4_gen(uuid);
    if (ret == 0) {
        *out_id = uuid;
        *out_size = strlen(uuid);
        if (fallback == FLB_TRUE) {
            return 2;
        }
        return 0;
    }

    return -1;
}

void flb_utils_set_plugin_string_property(const char *name,
                                          flb_sds_t *field_storage,
                                          flb_sds_t  new_value)
{
    if (field_storage == NULL) {
        flb_error("[utils] invalid field storage pointer for property '%s'",
                  name);

        return;
    }

    if (*field_storage != NULL) {
        flb_warn("[utils] property '%s' is already specified with value '%s'."
                 " Overwriting with '%s'",
                 name,
                 *field_storage,
                 new_value);

        flb_sds_destroy(*field_storage);

        *field_storage = NULL;
    }

    *field_storage = new_value;
}

#ifdef FLB_SYSTEM_WINDOWS
#define _mkdir(a, b) mkdir(a)
#else
#define _mkdir(a, b) mkdir(a, b)
#endif

/* recursively create directories, based on:
 *   https://stackoverflow.com/a/2336245
 * who found it at:
 *   http://nion.modprobe.de/blog/archives/357-Recursive-directory-creation.html
 */
int flb_utils_mkdir(const char *dir, int perms) {
    char tmp[CALYPTIA_MAX_DIR_SIZE];
    char *ptr = NULL;
    size_t len;
    int ret;

    ret = snprintf(tmp, sizeof(tmp),"%s",dir);
    if (ret < 0 || ret >= sizeof(tmp)) {
        flb_error("directory too long for flb_utils_mkdir: %s", dir);
        return -1;
    }

    len = strlen(tmp);
    /* len == ret but verifying index is valid */
    if ( len > 0 && tmp[len - 1] == PATH_SEPARATOR[0]) {
        tmp[len - 1] = 0;
    }

#ifndef FLB_SYSTEM_WINDOWS
    for (ptr = tmp + 1; *ptr; ptr++) {
#else
    for (ptr = tmp + 3; *ptr; ptr++) {
#endif

        if (*ptr == PATH_SEPARATOR[0]) {
            *ptr = 0;
            if (access(tmp, F_OK) != 0) {
                ret = _mkdir(tmp, perms);
                if (ret != 0) {
                    return ret;
                }
            }
            *ptr = PATH_SEPARATOR[0];
        }
    }

    return _mkdir(tmp, perms);
}
