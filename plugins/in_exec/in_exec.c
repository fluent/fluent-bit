/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "in_exec.h"

/* cb_collect callback */
static int in_exec_collect(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    int ret = -1;
    size_t str_len = 0;
    FILE *cmdp = NULL;
    char buf[DEFAULT_BUF_SIZE] = {0};
    struct flb_in_exec_config *exec_config = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* variables for parser */
    int parser_ret = -1;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    cmdp = popen(exec_config->cmd, "r");
    if (cmdp == NULL) {
        flb_debug("[in_exec] %s failed", exec_config->cmd);
        goto collect_end;
    }

    if (exec_config->parser) {
        while (fgets(buf, DEFAULT_BUF_SIZE - 1,cmdp) != NULL) {
            str_len = strlen(buf);
            buf[str_len-1] = '\0'; /* chomp */

            flb_time_get(&out_time);
            parser_ret = flb_parser_do(exec_config->parser, buf, str_len-1,
                                &out_buf, &out_size, &out_time);
            if (parser_ret >= 0) {
                if (flb_time_to_double(&out_time) == 0.0) {
                    flb_time_get(&out_time);
                }

                /* Initialize local msgpack buffer */
                msgpack_sbuffer_init(&mp_sbuf);
                msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

                msgpack_pack_array(&mp_pck, 2);
                flb_time_append_to_msgpack(&out_time, &mp_pck, 0);
                msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);

                flb_input_chunk_append_raw(i_ins, NULL, 0,
                                           mp_sbuf.data, mp_sbuf.size);
                msgpack_sbuffer_destroy(&mp_sbuf);
                flb_free(out_buf);
            }
        }
    }
    else {
        while (fgets(buf, DEFAULT_BUF_SIZE - 1,cmdp) != NULL) {
            str_len = strlen(buf);
            buf[str_len-1] = '\0'; /* chomp */

            /* Initialize local msgpack buffer */
            msgpack_sbuffer_init(&mp_sbuf);
            msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

            msgpack_pack_array(&mp_pck, 2);
            flb_pack_time_now(&mp_pck);
            msgpack_pack_map(&mp_pck, 1);

            msgpack_pack_str(&mp_pck, 4);
            msgpack_pack_str_body(&mp_pck, "exec", 4);
            msgpack_pack_str(&mp_pck, str_len-1);
            msgpack_pack_str_body(&mp_pck,
                                  buf, str_len-1);

            flb_input_chunk_append_raw(i_ins, NULL, 0,
                                       mp_sbuf.data, mp_sbuf.size);
            msgpack_sbuffer_destroy(&mp_sbuf);
        }
    }

    ret = 0; /* success */

 collect_end:
    if(cmdp != NULL){
        pclose(cmdp);
    }

    return ret;
}

/* read config file and*/
static int in_exec_config_read(struct flb_in_exec_config *exec_config,
                               struct flb_input_instance *in,
                               struct flb_config *config,
                               int *interval_sec,
                               int *interval_nsec
)
{
    char *cmd = NULL;
    char *pval = NULL;

    /* filepath setting */
    cmd = flb_input_get_property("command", in);
    if (cmd == NULL) {
        flb_error("[in_exec] no input 'command' was given");
        return -1;
    }
    exec_config->cmd = cmd;

    pval = flb_input_get_property("parser", in);
    if (pval != NULL) {
        exec_config->parser = flb_parser_get(pval, config);
        if (exec_config->parser == NULL) {
            flb_error("[in_exec] requested parser '%s' not found", pval);
        }
    }

    /* interval settings */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        *interval_sec = atoi(pval);
    }
    else {
        *interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        *interval_nsec = atoi(pval);
    }
    else {
        *interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (*interval_sec <= 0 && *interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        *interval_sec = DEFAULT_INTERVAL_SEC;
        *interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    flb_debug("[in_exec] interval_sec=%d interval_nsec=%d",
              *interval_sec, *interval_nsec);

    return 0;
}

static void delete_exec_config(struct flb_in_exec_config *exec_config)
{
    if (exec_config) {
        flb_free(exec_config);
    }
}

/* Initialize plugin */
static int in_exec_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    struct flb_in_exec_config *exec_config = NULL;
    int ret = -1;
    int interval_sec  = 0;
    int interval_nsec = 0;

    /* Allocate space for the configuration */
    exec_config = flb_malloc(sizeof(struct flb_in_exec_config));
    if (exec_config == NULL) {
        return -1;
    }
    exec_config->parser = NULL;

    /* Initialize exec config */
    ret = in_exec_config_read(exec_config, in, config, &interval_sec, &interval_nsec);
    if (ret < 0) {
        goto init_error;
    }

    flb_input_set_context(in, exec_config);

    ret = flb_input_set_collector_time(in,
                                       in_exec_collect,
                                       interval_sec,
                                       interval_nsec, config);
    if (ret < 0) {
        flb_error("could not set collector for exec input plugin");
        goto init_error;
    }

    return 0;

  init_error:
    delete_exec_config(exec_config);

    return -1;
}

static int in_exec_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_exec_config *exec_config = data;

    delete_exec_config(exec_config);
    return 0;
}


struct flb_input_plugin in_exec_plugin = {
    .name         = "exec",
    .description  = "Exec Input",
    .cb_init      = in_exec_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_exec_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_exec_exit
};
