/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <fluent-bit/flb_stats.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>

/* Output plugin masks */
#define FLB_OUTPUT_NET         32  /* output address may set host and port */

struct flb_output_instance;

struct flb_output_plugin {
    int flags;

    /* The plugin name */
    char *name;

    /* Plugin description */
    char *description;

    /*
     * Output network info:
     *
     * An output plugin can be specified just using it shortname or using the
     * complete network address format, e.g:
     *
     *  $ fluent-bit -i cpu -o plugin://hostname:port/uri
     *
     * where:
     *
     *   plugin   = the output plugin shortname
     *   name     = IP address or hostname of the target
     *   port     = target TCP port
     *   uri      = extra information that may be used by the plugin
     */
    struct flb_net_host host;

    /* Socket connection */
    //int conn;

    /* Initalization */
    int (*cb_init)    (struct flb_output_instance *, struct flb_config *, void *);

    /* Pre run */
    int (*cb_pre_run) (void *, struct flb_config *);

    /* Flush callback */
    int (*cb_flush) (void *, size_t,
                     char *, int,
                     struct flb_input_instance *,
                     void *,
                     struct flb_config *);

    /* Exit */
    int (*cb_exit) (void *, struct flb_config *);

    /* Link to global list from flb_config->outputs */
    struct mk_list _head;
};

/*
 * Each initialized plugin must have an instance, same plugin may be
 * loaded more than one time.
 *
 * An instance try to contain plugin data separating what is fixed data
 * and the variable one that is generated when the plugin is invoked.
 */
struct flb_output_instance {
    char name[16];                       /* numbered name (cpu -> cpu.0) */
    struct flb_output_plugin *p;         /* original plugin              */
    void *context;                       /* plugin configuration context */

    /* Plugin properties */
    int use_tls;                         /* bool, try to use TLS for I/O */
    char *match;                         /* match rule for tag/routing   */

#ifdef HAVE_TLS
    int tls_verify;                      /* Verify certs (default: true) */
    char *tls_ca_file;                   /* CA root cert                 */
    char *tls_crt_file;                  /* Certificate                  */
    char *tls_key_file;                  /* Cert Key                     */
    char *tls_key_passwd;                /* Cert Key Password            */
#endif

    /*
     * network info:
     *
     * An input plugin can be specified just using it shortname or using the
     * complete network address format, e.g:
     *
     *  $ fluent-bit -i cpu -o plugin://hostname:port/uri
     *
     * where:
     *
     *   plugin   = the output plugin shortname
     *   name     = IP address or hostname of the target
     *   port     = target TCP port
     *   uri      = extra information that may be used by the plugin
     */
    struct flb_net_host host;

    /*
     * Optional data passed to the plugin, this info is useful when
     * running Fluent Bit in library mode and the target plugin needs
     * some specific data from it caller.
     */
    void *data;

        /* Output handler configuration */
    void *out_context;

    /* IO upstream context, if flags & (FLB_OUTPUT_TCP | FLB_OUTPUT TLS)) */
    struct flb_upstream *upstream;

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

#ifdef HAVE_STATS
    int stats_fd;
#endif

#ifdef HAVE_TLS
    struct flb_tls tls;
#else
    void *tls;
#endif

    struct mk_list _head;                /* link to config->inputs       */
};

static FLB_INLINE
struct flb_thread *flb_output_thread(struct flb_engine_task *task,
                                     struct flb_input_instance *i_ins,
                                     struct flb_output_instance *o_ins,
                                     struct flb_config *config,
                                     void *buf, size_t size,
                                     char *tag, int tag_len)
{
    struct flb_thread *th;

    th = flb_thread_new();
    if (!th) {
        return NULL;
    }

    th->data = o_ins;
    th->output_buffer = buf;
    th->task = task;
    th->config = config;

    makecontext(&th->callee, (void (*)()) o_ins->p->cb_flush,
                7,                     /* number of arguments */
                buf,                   /* the buffer     */
                size,                  /* buffer size    */
                tag,                   /* matched tag    */
                tag_len,               /* tag len        */
                i_ins,                 /* input instance */
                o_ins->context,        /* output plugin context */
                config);
    return th;
}

struct flb_output_instance *flb_output_new(struct flb_config *config,
                                           char *output, void *data);

int flb_output_set_property(struct flb_output_instance *out, char *k, char *v);

void flb_output_pre_run(struct flb_config *config);
void flb_output_exit(struct flb_config *config);
void flb_output_set_context(struct flb_output_instance *ins, void *context);
int flb_output_init(struct flb_config *config);

#endif
