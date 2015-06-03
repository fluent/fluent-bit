/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <msgpack.h>

#include <mk_core/mk_core.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>

char *flb_utils_pack_hello(struct flb_config *config, int *size)
{
    int tag_len;
    char *buf;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    tag_len = strlen(config->tag);

    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&pck, 2);

    /* pack Tag, Time and Record */

    /* TAG */
    msgpack_pack_raw(&pck, tag_len);
    msgpack_pack_raw_body(&pck, config->tag, tag_len);

    /* Primary Array: ['TAG', [ */
    msgpack_pack_array(&pck, 1);

    /* Array entry #0: ['TAG', [[time, {'key': 'val'}]]] */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_uint64(&pck, time(NULL));

    msgpack_pack_map(&pck, 1);

    msgpack_pack_raw(&pck, 5);
    msgpack_pack_raw_body(&pck, "dummy", 5);

    msgpack_pack_uint64(&pck, time(NULL));

    /* dump data back to a new buffer */
    *size = sbuf.size;
    buf = malloc(sbuf.size);
    memcpy(buf, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    return buf;
}

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
    case FLB_ERR_JSON_INVAL:
        msg = "Invalid JSON string";
        break;
    case FLB_ERR_JSON_PART:
        msg = "Truncated JSON string";
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

    if (err <= FLB_ERR_OUTPUT_INVALID) {
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

void flb_message(int type, char *fmt, ...)
{
    time_t now;
    struct tm *current;

    const char *header_color = NULL;
    const char *header_title = NULL;
    const char *bold_color = ANSI_BOLD;
    const char *reset_color = ANSI_RESET;
    const char *white_color = ANSI_WHITE;
    va_list args;

    if (type == FLB_MSG_DEBUG) {
        if (__flb_config_verbose == FLB_FALSE) {
            return;
        }
    }

    va_start(args, fmt);

    switch (type) {
    case FLB_MSG_INFO:
        header_title = "info";
        header_color = ANSI_GREEN;
        break;
    case FLB_MSG_WARN:
        header_title = "warn";
        header_color = ANSI_YELLOW;
        break;
    case FLB_MSG_ERROR:
        header_title = "error";
        header_color = ANSI_RED;
        break;
    case FLB_MSG_DEBUG:
        header_title = "debug";
        header_color = ANSI_YELLOW;
        break;
    }

    /* Only print colors to a terminal */
    if (!isatty(STDOUT_FILENO)) {
        header_color = "";
        bold_color = "";
        reset_color = "";
        white_color = "";
    }

    now = time(NULL);
    struct tm result;
    current = localtime_r(&now, &result);
    printf("%s[%s%i/%02i/%02i %02i:%02i:%02i%s]%s ",
           bold_color, reset_color,
           current->tm_year + 1900,
           current->tm_mon + 1,
           current->tm_mday,
           current->tm_hour,
           current->tm_min,
           current->tm_sec,
           bold_color, reset_color);

    printf("%s[%s%5s%s]%s ",
           "", header_color, header_title, white_color, reset_color);

    vprintf(fmt, args);
    va_end(args);
    printf("%s\n", reset_color);
    fflush(stdout);
}

void flb_utils_print_setup(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *plugin;
    struct flb_input_collector *collector;

    flb_info("Configuration");

    /* general */
    printf(" flush time     : %i seconds\n", config->flush);

    /* Inputs */
    printf(" input plugins  : ");
    mk_list_foreach(head, &config->inputs) {
        plugin = mk_list_entry(head, struct flb_input_plugin, _head);
        if (plugin->active == FLB_TRUE) {
            printf("%s ", plugin->name);
        }
    }
    printf("\n");

    /* Outputs
    printf(" output tag     : %s\n", config->tag);
    printf(" output protocol: ");

    switch (config->out_protocol) {
    case FLB_OUTPUT_FLUENT:  p="fluentd";  break;
    case FLB_OUTPUT_HTTP:    p="http";     break;
    case FLB_OUTPUT_HTTPS:   p="https";    break;
    case FLB_OUTPUT_TD_HTTP: p="td+http";  break;
    case FLB_OUTPUT_TD_HTTPS:p="td+https"; break;
    }
    printf("%s\n", p);

    printf(" output host    : %s\n", config->out_host);
    printf(" output port    : %i\n", config->out_port);
    printf(" output address : %s\n", config->out_address);
    */

    /* Collectors */
    printf(" collectors     : ");
    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        plugin = collector->plugin;

        if (collector->seconds > 0) {
            printf("[%s %lus,%luns] ",
                   plugin->name,
                   collector->seconds,
                   collector->nanoseconds);
        }
        else {
            printf("[%s] ", plugin->name);
        }

    }
    printf("\n");
}
