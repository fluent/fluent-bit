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

#ifndef FLB_INPUT_H
#define FLB_INPUT_H

#include <inttypes.h>
#include <fluent-bit/flb_config.h>

#define FLB_COLLECT_TIME        1
#define FLB_COLLECT_FD_EVENT    2
#define FLB_COLLECT_FD_SERVER   4

struct flb_input_plugin {
    /* Is this Input an active one ? */
    int  active;

    /* The Input name */
    char *name;

    /* Plugin Description */
    char *description;

    /* Initalization */
    int (*cb_init)    (struct flb_config *);

    /* Pre run */
    int (*cb_pre_run) (void *, struct flb_config *);

    /*
     * Collect: every certain amount of time, Fluent Bit
     * trigger this callback.
     */
    int (*cb_collect) (struct flb_config *, void *);

    /*
     * Flush: each plugin during a collection, it does some buffering,
     * when the Flush timer takes place on the Engine, it will trigger
     * the cb_flush(...) to obtain the plugin buffer data. This data is
     * a MsgPack buffer which will be processed by the Engine and delivered
     * to the target output.
     */

    /* Flush a buffer type (raw data) */
    void *(*cb_flush_buf) (void *, int *);

    /* Flush an iovec struct array */
    void *(*cb_flush_iov) (void *, int *);

    /* Notify that a flush have completed on the collector (buf + iov) */
    void (*cb_flush_end) (void *);

    /* Input handler configuration */
    void *in_context;

    /* Link to global list from flb_config->inputs */
    struct mk_list _head;
};

struct flb_input_collector {
    int type;                            /* collector type             */

    /* FLB_COLLECT_FD_EVENT */
    int fd_event;                        /* fd being watched           */

    /* FLB_COLLECT_TIME */
    int fd_timer;                        /* timer fd                   */
    time_t seconds;                      /* expire time in seconds     */
    long nanoseconds;                    /* expire nanoseconds         */

    /* Callbacks */
    int (*cb_collect) (struct flb_config *, /* collect callback           */
                       void *);

    /* General references */
    struct flb_input_plugin *plugin;     /* owner plugin               */
    struct mk_list _head;                /* link to list of collectors */
};

int flb_input_register_all(struct flb_config *config);
int flb_input_enable(char *name, struct flb_config *config);
int flb_input_check(struct flb_config *config);
int flb_input_set_context(char *name, void *in_context, struct flb_config *config);
int flb_input_set_collector_time(char *name,
                                 int (*cb_collect) (struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config);
int flb_input_set_collector_event(char *name,
                                  int (*cb_collect) (struct flb_config *, void *),
                                  int fd,
                                  struct flb_config *config);
void flb_input_pre_run_all(struct flb_config *config);

#endif
