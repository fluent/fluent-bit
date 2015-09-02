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

#ifndef FLB_OUTPUT_H
#define FLB_OUTPUT_H

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif
#include <ucontext.h>

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_thread.h>

/* Output plugin masks */
#define FLB_OUTPUT_TCP         1  /* use plain TCP     */
#define FLB_OUTPUT_TLS         2  /* use TLS/SSL layer */
#define FLB_OUTPUT_NOPROT      4  /* do not validate protocol info */

/* Internal macros for setup */
#define FLB_OUTPUT_FLUENT      0
#define FLB_OUTPUT_HTTP        1
#define FLB_OUTPUT_HTTPS       2
#define FLB_OUTPUT_TD_HTTP     3
#define FLB_OUTPUT_TD_HTTPS    4

struct flb_output_plugin {
    int active;

    int flags;

    /* The plugin name */
    char *name;

    /* Plugin description */
    char *description;

    /* Original output address */
    char *address;

    /* Output backend address */
    int   port;
    char *host;

    /* Socket connection */
    int conn;

    /* Initalization */
    int (*cb_init)    (struct flb_config *);

    /* Pre run */
    int (*cb_pre_run) (void *, struct flb_config *);

    /* Flush callback */
    int (*cb_flush) (void *, size_t, void *, struct flb_config *);

    /* Exit */
    int (*cb_exit) (void *, struct flb_config *);

    /* Output handler configuration */
    void *out_context;

    /* IO upstream context, if flags & (FLB_OUTPUT_TCP | FLB_OUTPUT TLS)) */
    struct flb_io_upstream *upstream;

    /*
     * Co-routines specific data
     * =========================
     *
     */

    /*
     * th_context: when the event loop (flb_engine.c) have to flush some
     * data through an output plugin, the output plugin 'may' use the
     * flb_io.c interface which handle all I/O operations with co-routines.
     *
     * The core is not aware of that until flb_io_write() is called, so this
     * variable helps to set the stack context of the caller in the engine. If
     * for some reason the flb_io_write() needs to yield, it will know how to
     * return to the event loop.
     *
     * This variable is only used when creating the co-routine.
     */
    ucontext_t th_context;

    int th_yield;

    /*
     * The threads_queue is the head for the linked list that holds co-routines
     * nodes information that needs to be processed.
     */
    struct mk_list th_queue;

    /* Link to global list from flb_config->outputs */
    struct mk_list _head;
};

/* Default TCP port for Fluentd */
#define FLB_OUTPUT_FLUENT_PORT  "12224"

static FLB_INLINE struct flb_thread *flb_output_thread(struct flb_output_plugin *out,
                                                       struct flb_config *config,
                                                       void *buf, size_t size)
{
    struct flb_thread *th;

    th = flb_thread_new();
    if (!th) {
        return NULL;
    }

    makecontext(&th->callee, (void (*)()) out->cb_flush,
                4, buf, size, out->out_context, config);
    pthread_setspecific(flb_thread_key, (void *) th);
    return th;
}


int flb_output_set(struct flb_config *config, char *output);
void flb_output_pre_run(struct flb_config *config);
void flb_output_exit(struct flb_config *config);
int flb_output_set_context(char *name, void *out_context, struct flb_config *config);
int flb_output_init(struct flb_config *config);

#endif
