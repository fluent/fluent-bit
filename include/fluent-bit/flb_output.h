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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_bits.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_stats.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_engine_task.h>

#include <unistd.h>

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
    uint64_t mask_id;                    /* internal bitmask for routing */
    char name[16];                       /* numbered name (cpu -> cpu.0) */
    struct flb_output_plugin *p;         /* original plugin              */
    void *context;                       /* plugin configuration context */

    /* Plugin properties */
    int use_tls;                         /* bool, try to use TLS for I/O */
    char *match;                         /* match rule for tag/routing   */

#ifdef FLB_HAVE_TLS
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
    //ucontext_t th_context;

    //int th_yield;

    /*
     * The threads_queue is the head for the linked list that holds co-routines
     * nodes information that needs to be processed.
     */
    struct mk_list th_queue;

#ifdef FLB_HAVE_STATS
    int stats_fd;
#endif

#ifdef FLB_HAVE_TLS
    struct flb_tls tls;
#else
    void *tls;
#endif

    struct mk_list properties;           /* properties / configuration   */
    struct mk_list _head;                /* link to config->inputs       */
};

#ifdef FLB_HAVE_FLUSH_UCONTEXT
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

#elif defined FLB_HAVE_FLUSH_PTHREADS
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

    /* pthread reference data */
    th->pth_cb.buf     = buf;
    th->pth_cb.size    = size;
    th->pth_cb.tag     = tag;
    th->pth_cb.tag_len = tag_len;
    th->pth_cb.i_ins   = i_ins;
    th->pth_cb.o_ins   = o_ins;

    return th;
}
#endif

/*
 * This function is used by the output plugins to return. It's mandatory
 * as it will take care to signal the event loop letting know the flush
 * callback has done.
 *
 * The signal emmited indicate the 'Task' number that have finished plus
 * a return value. The return value is either FLB_OK or FLB_ERROR.
 */
static inline int flb_output_return(int ret) {
    int n;
    uint32_t set;
    uint64_t val;
    struct flb_thread *th;
    struct flb_engine_task *task;

    th = (struct flb_thread *) pthread_getspecific(flb_thread_key);
    task = th->task;

    /*
     * To compose the signal event the relevant info is:
     *
     * - Unique Task events id: 2 in this case
     * - Return value: FLB_OK (0) or FLB_ERROR (1)
     * - Task ID
     *
     * We put together the return value with the task_id on the 32 bits at right
     */

    set = FLB_ENGINE_TASK_SET(ret, task->id, th->id);
    val = FLB_BITS_U64_SET(2, set);

    n = write(task->config->ch_manager[1], &val, sizeof(val));
    if (n == -1) {
        perror("write");
        return -1;
    }

    return 0;
}

#define FLB_OUTPUT_RETURN(x)                                            \
    return flb_output_return(x);

struct flb_output_instance *flb_output_new(struct flb_config *config,
                                           char *output, void *data);

int flb_output_set_property(struct flb_output_instance *out, char *k, char *v);
char *flb_output_get_property(char *key, struct flb_output_instance *i);

void flb_output_pre_run(struct flb_config *config);
void flb_output_exit(struct flb_config *config);
void flb_output_set_context(struct flb_output_instance *ins, void *context);
int flb_output_init(struct flb_config *config);

#endif
