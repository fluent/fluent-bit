/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifdef FLB_HAVE_AWS_ERROR_REPORTER
#include <fluent-bit/aws/flb_aws_error_reporter.h>

extern struct flb_aws_error_reporter *error_reporter;
#endif

#ifdef FLB_HAVE_OPENSSL
#include <openssl/rand.h>
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
        flb_errno();
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
        flb_errno();
        return -1;
    }

    return 0;
}

int64_t flb_utils_size_to_bytes(const char *size)
{
    int i;
    int len;
    int plen = 0;
    int64_t val;
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
    val = atoll(size);

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
        return val;
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
        if (val >= 9223372036854775 || val <= -9223372036854774)
        {
            return -1;
        }
        return (val * KB);
    }
    else if (tmp[0] == 'M') {
        /* set upper bound (2**64/MB)/2 to avoid overflows */
        if (val >= 9223372036854 || val <= -9223372036853) {
            return -1;
        }
        return (val * MB);
    }
    else if (tmp[0] == 'G') {
        /* set upper bound (2**64/GB)/2 to avoid overflows */
        if (val >= 9223372036 || val <= -9223372035) {
            return -1;
        }
        return (val * GB);
    }
    else {
        return -1;
    }

    return val;
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

/*
 * Write string pointed by 'str' to the destination buffer 'buf'. It's make sure
 * to escape sepecial characters and convert utf-8 byte characters to string
 * representation.
 */
int flb_utils_write_str(char *buf, int *off, size_t size,
                        const char *str, size_t str_len)
{
    int i;
    int b;
    int ret;
    int written = 0;
    int required;
    int len;
    int hex_bytes;
    int is_valid;
    int utf_sequence_number;
    int utf_sequence_length;
    uint32_t codepoint;
    uint32_t state = 0;
    char tmp[16];
    size_t available;
    uint32_t c;
    char *p;
    uint8_t *s;

    available = (size - *off);
    required = str_len;
    if (available <= required) {
        return FLB_FALSE;
    }

    p = buf + *off;
    for (i = 0; i < str_len; i++) {
        if ((available - written) < 2) {
            return FLB_FALSE;
        }

        c = (uint32_t) str[i];
        if (c == '\"') {
            *p++ = '\\';
            *p++ = '\"';
        }
        else if (c == '\\') {
            *p++ = '\\';
            *p++ = '\\';
        }
        else if (c == '\n') {
            *p++ = '\\';
            *p++ = 'n';
        }
        else if (c == '\r') {
            *p++ = '\\';
            *p++ = 'r';
        }
        else if (c == '\t') {
            *p++ = '\\';
            *p++ = 't';
        }
        else if (c == '\b') {
            *p++ = '\\';
            *p++ = 'b';
        }
        else if (c == '\f') {
            *p++ = '\\';
            *p++ = 'f';
        }
        else if (c < 32 || c == 0x7f) {
            if ((available - written) < 6) {
                return FLB_FALSE;
            }
            len = snprintf(tmp, sizeof(tmp) - 1, "\\u%.4hhx", (unsigned char) c);
            if ((available - written) < len) {
                return FLB_FALSE;
            }
            encoded_to_buf(p, tmp, len);
            p += len;
        }
        else if (c >= 0x80 && c <= 0xFFFF) {
            hex_bytes = flb_utf8_len(str + i);
            if (available - written < 6) {
                return FLB_FALSE;
            }

            if (i + hex_bytes > str_len) {
                break; /* skip truncated UTF-8 */
            }

            state = FLB_UTF8_ACCEPT;
            codepoint = 0;

            for (b = 0; b < hex_bytes; b++) {
                s = (unsigned char *) str + i + b;
                ret = flb_utf8_decode(&state, &codepoint, *s);
                if (ret == 0) {
                    break;
                }
            }

            if (state != FLB_UTF8_ACCEPT) {
                /* Invalid UTF-8 hex, just skip utf-8 bytes */
                flb_warn("[pack] invalid UTF-8 bytes found, skipping bytes");
            }
            else {
                len = snprintf(tmp, sizeof(tmp) - 1, "\\u%.4x", codepoint);
                if ((available - written) < len) {
                    return FLB_FALSE;
                }
                encoded_to_buf(p, tmp, len);
                p += len;
            }
            i += (hex_bytes - 1);
        }
        else if (c > 0xFFFF) {
            utf_sequence_length = flb_utf8_len(str + i);

            if (i + utf_sequence_length > str_len) {
                break; /* skip truncated UTF-8 */
            }

            is_valid = FLB_TRUE;
            for (utf_sequence_number = 0; utf_sequence_number < utf_sequence_length;
                utf_sequence_number++) {
                /* Leading characters must start with bits 11 */
                if (utf_sequence_number == 0 && ((str[i] & 0xC0) != 0xC0)) {
                    /* Invalid unicode character. replace */
                    flb_debug("[pack] unexpected UTF-8 leading byte, "
                             "substituting character with replacement character");
                    tmp[utf_sequence_number] = str[i];
                    ++i; /* Consume invalid leading byte */
                    utf_sequence_length = utf_sequence_number + 1;
                    is_valid = FLB_FALSE;
                    break;
                }
                /* Trailing characters must start with bits 10 */
                else if (utf_sequence_number > 0 && ((str[i] & 0xC0) != 0x80)) {
                    /* Invalid unicode character. replace */
                    flb_debug("[pack] unexpected UTF-8 continuation byte, "
                             "substituting character with replacement character");
                    /* This byte, i, is the start of the next unicode character */
                    utf_sequence_length = utf_sequence_number;
                    is_valid = FLB_FALSE;
                    break;
                }

                tmp[utf_sequence_number] = str[i];
                ++i;
            }
            --i;

            if (is_valid) {
                if (available - written < utf_sequence_length) {
                    return FLB_FALSE;
                }

                encoded_to_buf(p, tmp, utf_sequence_length);
                p += utf_sequence_length;
            }
            else {
                if (available - written < utf_sequence_length * 3) {
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
                }
            }
        }
        else {
            *p++ = c;
        }
        written = (p - (buf + *off));
    }

    *off += written;

    return FLB_TRUE;
}


int flb_utils_write_str_buf(const char *str, size_t str_len, char **out, size_t *out_size)
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
        ret = flb_utils_write_str(buf, &off, s, str, str_len);
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
        if (string[pos_end-1] != ']')
            return NULL;

        return mk_string_copy_substr(string, pos_init + 1, pos_end - 1);
    }
    else
        return mk_string_copy_substr(string, pos_init, pos_end);
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

    /* Check for first '/' */
    sep = strchr(p, '/');
    tmp = strchr(p, ':');

    /* Validate port separator is found before the first slash */
    if (sep && tmp) {
        if (tmp > sep) {
            tmp = NULL;
        }
    }

    if (tmp) {
        host = flb_copy_host(p, 0, tmp - p);
        if (!host) {
            flb_errno();
            goto error;
        }
        p = tmp + 1;

        /* Look for an optional URI */
        tmp = strchr(p, '/');
        if (tmp) {
            port = mk_string_copy_substr(p, 0, tmp - p);
            uri = flb_strdup(tmp);
        }
        else {
            port = flb_strdup(p);
            uri = flb_strdup("/");
        }
    }
    else {
        tmp = strchr(p, '/');
        if (tmp) {
            host = flb_copy_host(p, 0, tmp - p);
            uri = flb_strdup(tmp);
        }
        else {
            host = flb_copy_host(p, 0, strlen(p));
            uri = flb_strdup("/");
        }
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

    return -1;
}


/*
 * flb_utils_proxy_url_split parses a proxy's information from a http_proxy URL.
 * The URL is in the form like `http://username:password@myproxy.com:8080`.
 * Note: currently only HTTP is supported.
 */
int flb_utils_proxy_url_split(const char *in_url, char **out_protocol,
                              char **out_username, char **out_password,
                              char **out_host, char **out_port)
{
    char *protocol = NULL;
    char *username = NULL;
    char *password = NULL;
    char *host = NULL;
    char *port = NULL;
    char *proto_sep;
    char *at_sep;
    char *tmp;

    /*  Parse protocol */
    proto_sep = strstr(in_url, "://");
    if (!proto_sep) {
        return -1;
    }
    if (proto_sep == in_url) {
        return -1;
    }

    protocol = mk_string_copy_substr(in_url, 0, proto_sep - in_url);
    if (!protocol) {
        flb_errno();
        return -1;
    }
    /* Only HTTP proxy is supported for now. */
    if (strcmp(protocol, "http") != 0) {
        flb_free(protocol);
        return -1;
    }

    /* Advance position after protocol */
    proto_sep += 3;

    /* Seperate `username:password` and `host:port` */
    at_sep = strrchr(proto_sep, '@');
    if (at_sep) {
        /* Parse username:passwrod part. */
        tmp = strchr(proto_sep, ':');
        if (!tmp) {
            flb_free(protocol);
            return -1;
        }
        username = mk_string_copy_substr(proto_sep, 0, tmp - proto_sep);
        tmp += 1;
        password = mk_string_copy_substr(tmp, 0, at_sep - tmp);

        /* Parse host:port part. */
        at_sep += 1;
        tmp = strchr(at_sep, ':');
        if (tmp) {
            host = flb_copy_host(at_sep, 0, tmp - at_sep);
            tmp += 1;
            port = strdup(tmp);
        }
        else {
            host = flb_copy_host(at_sep, 0, strlen(at_sep));
            port = flb_strdup("80");
        }
    }
    else {
        /* Parse host:port part. */
        tmp = strchr(proto_sep, ':');
        if (tmp) {
            host = flb_copy_host(proto_sep, 0, tmp - proto_sep);
            tmp += 1;
            port = strdup(tmp);
        }
        else {
            host = flb_copy_host(proto_sep, 0, strlen(proto_sep));
            port = flb_strdup("80");
        }
    }

    *out_protocol = protocol;
    *out_host = host;
    *out_port = port;
    if (username) {
        *out_username = username;
    }
    if (password) {
        *out_password = password;
    }

    return 0;
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
    int fd;
    int ret;
    size_t bytes;
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

    buf = flb_calloc(1, st.st_size + 1);
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes < 1) {
        flb_errno();
        flb_free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    *out_buf = buf;
    *out_size = st.st_size;
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

#ifdef __linux__
    char *dbus_var = "/var/lib/dbus/machine-id";
    char *dbus_etc = "/etc/machine-id";

    /* dbus */
    ret = machine_id_read_and_sanitize(dbus_var, &id, &bytes);
    if (ret == 0) {
        *out_id = id;
        *out_size = bytes;
        return 0;
    }

    /* etc */
    ret = machine_id_read_and_sanitize(dbus_etc, &id, &bytes);
    if (ret == 0) {
        *out_id = id;
        *out_size = bytes;
        return 0;
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
#endif

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
        return 0;
    }

    return -1;
}
