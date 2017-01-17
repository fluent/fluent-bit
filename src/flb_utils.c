/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
    case FLB_ERR_FILTER_INVALID:
        msg = "Invalid filter plugin";
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

struct mk_list *flb_utils_split(char *line, int separator)
{
    int i = 0;
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

        /* Create new entry */
        new = flb_malloc(sizeof(struct flb_split_entry));
        new->value = val;
        new->len = val_len;

        mk_list_add(&new->_head, list);
        i = end + 1;
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
