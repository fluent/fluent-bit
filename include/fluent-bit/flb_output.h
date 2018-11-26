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

#ifndef FLB_OUTPUT_H
#define FLB_OUTPUT_H

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_bits.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
#endif

/* Output plugin masks */
#define FLB_OUTPUT_NET          32  /* output address may set host and port */
#define FLB_OUTPUT_PLUGIN_CORE   0
#define FLB_OUTPUT_PLUGIN_PROXY  1

struct flb_output_instance;

struct flb_output_plugin {
    /*
     * The type defines if this is a core-based plugin or it's handled by
     * some specific proxy.
     */
    int type;
    void *proxy;

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

    /* Initalization */
    int (*cb_init)    (struct flb_output_instance *, struct flb_config *, void *);

    /* Pre run */
    int (*cb_pre_run) (void *, struct flb_config *);

    /* Flush callback */
    void (*cb_flush) (void *, size_t,
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
    int flags;                           /* inherit flags from plugin    */
    struct flb_output_plugin *p;         /* original plugin              */
    void *context;                       /* plugin configuration context */

    /* Plugin properties */
    int retry_limit;                     /* max of retries allowed       */
    int use_tls;                         /* bool, try to use TLS for I/O */
    char *match;                         /* match rule for tag/routing   */
#ifdef FLB_HAVE_REGEX
    struct flb_regex *match_regex;       /* match rule (regex) based on Tags */
#endif

#ifdef FLB_HAVE_TLS
    int tls_verify;                      /* Verify certs (default: true) */
    int tls_debug;                       /* mbedtls debug level          */
    char *tls_ca_path;                   /* Path to certificates         */
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
     * The threads_queue is the head for the linked list that holds co-routines
     * nodes information that needs to be processed.
     */
    struct mk_list th_queue;

#ifdef FLB_HAVE_TLS
    struct flb_tls tls;
#else
    void *tls;
#endif

    struct mk_list properties;           /* properties / configuration   */
    struct mk_list _head;                /* link to config->inputs       */

#ifdef FLB_HAVE_METRICS
    struct flb_metrics *metrics;         /* metrics                      */
#endif

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};

struct flb_output_thread {
    int id;                            /* out-thread ID      */
    void *buffer;                      /* output buffer      */
    struct flb_task *task;             /* Parent flb_task    */
    struct flb_config *config;         /* FLB context        */
    struct flb_output_instance *o_ins; /* output instance    */
    struct flb_thread *parent;         /* parent thread addr */
    struct mk_list _head;              /* Link to struct flb_task->threads */
};

static FLB_INLINE
struct flb_output_thread *flb_output_thread_get(int id, struct flb_task *task)
{
    struct mk_list *head;
    struct flb_output_thread *out_th = NULL;

    mk_list_foreach(head, &task->threads) {
        out_th = mk_list_entry(head, struct flb_output_thread, _head);
        if (out_th->id == id) {
            return out_th;
        }
    }

    return NULL;
}

static FLB_INLINE int flb_output_thread_destroy_id(int id, struct flb_task *task)
{
    struct flb_output_thread *out_th;
    struct flb_thread *thread;

    out_th = flb_output_thread_get(id, task);
    if (!out_th) {
        return -1;
    }

    mk_list_del(&out_th->_head);
    thread = out_th->parent;

    flb_thread_destroy(thread);
    task->users--;

    return 0;
}

/* When an output_thread is going to be destroyed, this callback is triggered */
static FLB_INLINE void cb_output_thread_destroy(void *data)
{
    struct flb_output_thread *out_th;

    out_th = (struct flb_output_thread *) data;

    flb_debug("[out thread] cb_destroy thread_id=%i", out_th->id);

    out_th->task->users--;
    mk_list_del(&out_th->_head);
}

#if defined FLB_HAVE_FLUSH_LIBCO

/*
 * libco do not support parameters in the entrypoint function due to the
 * complexity of implementation in terms of architecture and compiler, but
 * it provide a workaround using a global structure as a middle entry-point
 * that achieve the same stuff.
 */
struct flb_libco_out_params {
    void  *data;
    size_t bytes;
    char *tag;
    int tag_len;
    struct flb_input_instance *i_ins;
    void *out_context;
    struct flb_config *config;
    struct flb_output_plugin *out_plugin;
    struct flb_thread *th;
};

struct flb_libco_out_params libco_param;

static FLB_INLINE void output_params_set(struct flb_thread *th,
                              void *data, size_t bytes,
                              char *tag, int tag_len,
                              struct flb_input_instance *i_ins,
                              struct flb_output_plugin *out_plugin,
                              void *out_context, struct flb_config *config)
{
    /* Callback parameters in order */
    libco_param.data        = data;
    libco_param.bytes       = bytes;
    libco_param.tag         = tag;
    libco_param.tag_len     = tag_len;
    libco_param.i_ins       = i_ins;
    libco_param.out_context = out_context;
    libco_param.config      = config;
    libco_param.out_plugin  = out_plugin;

    libco_param.th = th;
    co_switch(th->callee);
}

static FLB_INLINE void output_pre_cb_flush()
{
    void *data   = libco_param.data;
    size_t bytes = libco_param.bytes;
    char *tag    = libco_param.tag;
    int tag_len  = libco_param.tag_len;
    struct flb_input_instance *i_ins = libco_param.i_ins;
    struct flb_output_plugin *out_p  = libco_param.out_plugin;
    void *out_context                = libco_param.out_context;
    struct flb_config *config        = libco_param.config;
    struct flb_thread *th            = libco_param.th;

    /*
     * Until this point the th->callee already set the variables, so we
     * wait until the core wanted to resume so we really trigger the
     * output callback.
     */
    co_switch(th->caller);

    /* Continue, we will resume later */
    out_p->cb_flush(data, bytes, tag, tag_len, i_ins, out_context, config);
}

static FLB_INLINE
struct flb_thread *flb_output_thread(struct flb_task *task,
                                     struct flb_input_instance *i_ins,
                                     struct flb_output_instance *o_ins,
                                     struct flb_config *config,
                                     void *buf, size_t size,
                                     char *tag, int tag_len)
{
    size_t stack_size;
    struct flb_output_thread *out_th;
    struct flb_thread *th;

    /* Create a new thread */
    th = flb_thread_new(sizeof(struct flb_output_thread),
                        cb_output_thread_destroy);
    if (!th) {
        return NULL;
    }

    /* Custom output-thread info */
    out_th = (struct flb_output_thread *) FLB_THREAD_DATA(th);
    if (!out_th) {
        flb_errno();
        return NULL;
    }

    /*
     * Each 'Thread' receives an 'id'. This is assigned when this thread
     * is linked into the parent Task by flb_task_add_thread(...). The
     * 'id' is always incremental.
     */
    out_th->id      = 0;
    out_th->o_ins   = o_ins;
    out_th->task    = task;
    out_th->buffer  = buf;
    out_th->config  = config;
    out_th->parent  = th;

    th->caller = co_active();
    th->callee = co_create(config->coro_stack_size,
                           output_pre_cb_flush, &stack_size);

#ifdef FLB_HAVE_VALGRIND
    th->valgrind_stack_id = VALGRIND_STACK_REGISTER(th->callee,
                                                    ((char *)th->callee) + stack_size);
#endif

    /* Workaround for makecontext() */
    output_params_set(th,
                      buf,
                      size,
                      tag,
                      tag_len,
                      i_ins,
                      o_ins->p,
                      o_ins->context,
                      config);
    return th;
}

#elif defined FLB_HAVE_FLUSH_PTHREADS

static FLB_INLINE
struct flb_thread *flb_output_thread(struct flb_task *task,
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
 * a return value. The return value is either FLB_OK, FLB_RETRY or FLB_ERROR.
 */
static inline void flb_output_return(int ret, struct flb_thread *th) {
    int n;
    uint32_t set;
    uint64_t val;
    struct flb_task *task;
    struct flb_output_thread *out_th;
#ifdef FLB_HAVE_METRICS
    int records;
#endif

    out_th = (struct flb_output_thread *) FLB_THREAD_DATA(th);
    task = out_th->task;

    /*
     * To compose the signal event the relevant info is:
     *
     * - Unique Task events id: 2 in this case
     * - Return value: FLB_OK (0) or FLB_ERROR (1)
     * - Task ID
     *
     * We put together the return value with the task_id on the 32 bits at right
     */
    set = FLB_TASK_SET(ret, task->id, out_th->id);
    val = FLB_BITS_U64_SET(2 /* FLB_ENGINE_TASK */, set);

    n = flb_pipe_w(task->config->ch_manager[1], &val, sizeof(val));
    if (n == -1) {
        flb_errno();
    }

#ifdef FLB_HAVE_METRICS
    if (out_th->o_ins->metrics) {
        if (ret == FLB_OK) {
            records = flb_mp_count(task->buf, task->size);
            flb_metrics_sum(FLB_METRIC_OUT_OK_RECORDS, records,
                            out_th->o_ins->metrics);
            flb_metrics_sum(FLB_METRIC_OUT_OK_BYTES, task->size,
                            out_th->o_ins->metrics);
        }
        else if (ret == FLB_ERROR) {
            flb_metrics_sum(FLB_METRIC_OUT_ERROR, 1, out_th->o_ins->metrics);
        }
        else if (ret == FLB_RETRY) {
            /*
             * Counting retries is happening in the event loop/scheduler side
             * since it also needs to count if some retry fails to re-schedule.
             */
        }
    }
#endif
}

static inline void flb_output_return_do(int x)
{
    struct flb_thread *th;
    th = (struct flb_thread *) pthread_getspecific(flb_thread_key);
    flb_output_return(x, th);
    /*
     * Each co-routine handler have different ways to handle a return,
     * just use the wrapper.
     */
    flb_thread_yield(th, FLB_TRUE);
}

#define FLB_OUTPUT_RETURN(x)                                            \
    flb_output_return_do(x);                                            \
    return

struct flb_output_instance *flb_output_new(struct flb_config *config,
                                           char *output, void *data);

int flb_output_set_property(struct flb_output_instance *out, char *k, char *v);
char *flb_output_get_property(char *key, struct flb_output_instance *o_ins);
void flb_output_net_default(char *host, int port,
                            struct flb_output_instance *o_ins);
void flb_output_pre_run(struct flb_config *config);
void flb_output_exit(struct flb_config *config);
void flb_output_set_context(struct flb_output_instance *ins, void *context);
int flb_output_instance_destroy(struct flb_output_instance *ins);
int flb_output_init(struct flb_config *config);
int flb_output_check(struct flb_config *config);

#endif
