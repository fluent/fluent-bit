/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

void flb_utils_error(int err)
{
    char *msg = NULL;

    switch (err) {
    case FLB_ERR_CFG_FILE:
        msg = "Could not open configuration file";
        break;
    case FLB_ERR_CFG_FILE_FORMAT:
        msg = "Configuration file contains format errors";
        break;
    case FLB_ERR_CFG_FILE_STOP:
        msg = "Configuration file contain errors";
        break;
    case FLB_ERR_CFG_FLUSH:
        msg = "Invalid flush value";
        break;
    case FLB_ERR_CFG_FLUSH_CREATE:
        msg = "Could not create timer for flushing";
        break;
    case FLB_ERR_CFG_FLUSH_REGISTER:
        msg = "Could not register timer for flushing";
        break;
    case FLB_ERR_INPUT_INVALID:
        msg = "Invalid input type";
        break;
    case FLB_ERR_INPUT_UNDEF:
        msg = "No Input(s) have been defined";
        break;
    case FLB_ERR_INPUT_UNSUP:
        msg = "Unsupported Input";
        break;
    case FLB_ERR_OUTPUT_UNDEF:
        msg = "You must specify an output target";
        break;
    case FLB_ERR_OUTPUT_INVALID:
        msg = "Invalid output target";
        break;
    case FLB_ERR_OUTPUT_UNIQ:
        msg = "Just one output type is supported";
        break;
    case FLB_ERR_FILTER_INVALID:
        msg = "Invalid filter plugin";
        break;
    case FLB_ERR_CFG_PARSER_FILE:
        msg = "Could not open parser configuration file";
        break;
    case FLB_ERR_JSON_INVAL:
        msg = "Invalid JSON string";
        break;
    case FLB_ERR_JSON_PART:
        msg = "Truncated JSON string";
        break;
    case FLB_ERR_CORO_STACK_SIZE:
        msg = "Invalid coroutine stack size";
        break;
    }

    if (!msg) {
        fprintf(stderr,
                "%sError%s: undefined. Aborting",
                ANSI_BOLD ANSI_RED, ANSI_RESET);
    }
    else {
        fprintf(stderr,
                "%sError%s: %s. Aborting\n\n",
                ANSI_BOLD ANSI_RED, ANSI_RESET, msg);
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
    flb_info("switching to background mode (PID=%lu)", getpid());

    fclose(stderr);
    fclose(stdout);

    return 0;
}
#endif

void flb_utils_print_setup(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *plugin;
    struct flb_input_collector *collector;
    struct flb_input_instance *in;

    flb_info("Configuration");

    /* general */
    flb_info(" flush time     : %i seconds", config->flush);

    /* Inputs */
    flb_info(" input plugins  : ");
    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        flb_info("%s ", in->p->name);
    }

    /* Collectors */
    flb_info(" collectors     : ");
    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        plugin = collector->instance->p;

        if (collector->seconds > 0) {
            flb_info("[%s %lus,%luns] ",
                     plugin->name,
                     collector->seconds,
                     collector->nanoseconds);
        }
        else {
            printf("[%s] ", plugin->name);
        }

    }
}

struct mk_list *flb_utils_split(char *line, int separator, int max_split)
{
    int i = 0;
    int count = 0;
    int val_len;
    int len;
    int end;
    char *val;
    struct mk_list *list;
    struct flb_split_entry *new;

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    len = strlen(line);
    while (i < len) {
        end = mk_string_char_search(line + i, separator, len - i);
        if (end >= 0 && end + i < len) {
            end += i;

            if (i == (unsigned int) end) {
                i++;
                continue;
            }

            val = mk_string_copy_substr(line, i, end);
            val_len = end - i;
        }
        else {
            val = mk_string_copy_substr(line, i, len);
            val_len = len - i;
            end = len;
        }

        /* Update last position */
        i = end;

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

void flb_utils_split_free(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_split_entry *entry;

    mk_list_foreach_safe(head, tmp, list) {
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        mk_list_del(&entry->_head);
        flb_free(entry->value);
        flb_free(entry);
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

ssize_t flb_utils_size_to_bytes(char *size)
{
    int i;
    int len;
    int plen = 0;
    size_t val;
    char c;
    char tmp[3] = {0};
    int64_t KB = 1000;
    int64_t MB = 1000 * KB;
    int64_t GB = 1000 * MB;

    if (!size) {
        return -1;
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
        return (val * KB);
    }
    else if (tmp[0] == 'M') {
        return (val * MB);
    }
    else if (tmp[0] == 'G') {
        return (val * GB);
    }
    else {
        return -1;
    }

    return val;
}

int flb_utils_time_to_seconds(char *time)
{
    int len;
    size_t val;

    len = strlen(time);
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

int flb_utils_bool(char *val)
{
    if (strcasecmp(val, "true") == 0 ||
        strcasecmp(val, "on") == 0 ||
        strcasecmp(val, "yes") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* Convert a 'string' time seconds.nanoseconds to int and long values */
int flb_utils_time_split(char *time, int *sec, long *nsec)
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


static inline void encoded_to_buf(char *out, char *in, int len)
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
                        char *str, size_t str_len)
{
    int i;
    int b;
    int ret;
    int written = 0;
    int required;
    int len;
    int hex_bytes;
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

    written = *off;
    p = buf + *off;
    for (i = 0; i < str_len; i++) {
        if ((available - written) < 2) {
            return FLB_FALSE;
        }

        c = (uint32_t) str[i];
        if (c == '\\' || c == '"') {
            *p++ = '\\';
            *p++ = c;
        }
        else if (c >= '\a' && c <= '\r') {
            *p++ = '\\';
            switch (c) {
            case '\n':
                *p++ = 'n';
                break;
            case '\t':
                *p++ = 't';
                break;
            case '\b':
                *p++ = 'b';
                break;
            case '\f':
                *p++ = 'f';
                break;
            case '\r':
                *p++ = 'r';
                break;
            case '\a':
                *p++ = 'a';
                break;
            case '\v':
                *p++ = 'v';
                break;
            }
        }
        else if (c < 32 || c == 0x7f) {
            if ((available - written) < 6) {
                return FLB_FALSE;
            }
            len = snprintf(tmp, sizeof(tmp) - 1, "\\u%.4hhx", (unsigned char) c);
            encoded_to_buf(p, tmp, len);
            p += len;
        }
        else if (c >= 0x80 && c <= 0xFFFF) {
            hex_bytes = flb_utf8_len(str + i);
            if ((available - written) < (2 + hex_bytes)) {
                return FLB_FALSE;
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
                break;
            }
            else {
                len = snprintf(tmp, sizeof(tmp) - 1, "\\u%.4x", codepoint);
                encoded_to_buf(p, tmp, len);
                p += len;
            }
            i += (hex_bytes - 1);
        }
        else if (c > 0xFFFF) {
            hex_bytes = flb_utf8_len(str + i);
            if ((available - written) < (4 + hex_bytes)) {
                return FLB_FALSE;
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
                flb_warn("[pack] invalid UTF-8 bytes, skipping");
                break;
            }
            else {
                len = snprintf(tmp, sizeof(tmp) - 1, "\\u%04x", codepoint);
                encoded_to_buf(p, tmp, len);
                p += len;
            }
            i += (hex_bytes - 1);
        }
        else {
            *p++ = c;
        }
        written = (p - (buf + *off));
    }

    *off += written;
    return FLB_TRUE;
}


int flb_utils_write_str_buf(char *str, size_t str_len, char **out, size_t *out_size)
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

int flb_utils_url_split(char *in_url, char **out_protocol,
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
        host = mk_string_copy_substr(p, 0, tmp - p);
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
            host = mk_string_copy_substr(p, 0, tmp - p);
            uri = flb_strdup(tmp);
        }
        else {
            host = flb_strdup(p);
            uri = flb_strdup("/");
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
    if (port) {
        flb_free(port);
    }
    return -1;
}
