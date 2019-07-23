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

#ifndef FLB_INPUT_H
#define FLB_INPUT_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_bits.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_mp.h>

#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics.h>
#endif

#include <monkey/mk_core.h>
#include <msgpack.h>

#include <inttypes.h>

#define FLB_COLLECT_TIME        1
#define FLB_COLLECT_FD_EVENT    2
#define FLB_COLLECT_FD_SERVER   4

/* Input plugin masks */
#define FLB_INPUT_NET          4  /* input address may set host and port   */
#define FLB_INPUT_THREAD     128  /* plugin requires a thread on callbacks */
#define FLB_INPUT_PRIVATE    256  /* plugin is not published/exposed       */
#define FLB_INPUT_NOTAG      512  /* plugin might don't have tags          */

/* Input status */
#define FLB_INPUT_RUNNING     1
#define FLB_INPUT_PAUSED      0

struct flb_input_instance;

struct flb_input_plugin {
    int flags;

    /* The Input name */
    char *name;

    /* Plugin Description */
    char *description;

    /* Initalization */
    int (*cb_init)    (struct flb_input_instance *, struct flb_config *, void *);

    /* Pre run */
    int (*cb_pre_run) (struct flb_input_instance *, struct flb_config *, void *);

    /* Collect: every certain amount of time, Fluent Bit trigger this callback */
    int (*cb_collect) (struct flb_input_instance *, struct flb_config *, void *);

    /*
     * Flush: each plugin during a collection, it does some buffering,
     * when the Flush timer takes place on the Engine, it will trigger
     * the cb_flush(...) to obtain the plugin buffer data. This data is
     * a MsgPack buffer which will be processed by the Engine and delivered
     * to the target output.
     */

    /* Flush a buffer type (raw data) */
    void *(*cb_flush_buf) (void *, size_t *);

    /* Notify that a flush have completed on the collector (buf + iov) */
    void (*cb_flush_end) (void *);

    /*
     * Callbacks to notify the plugin when it becomes paused (cannot longer append
     * data) and when it can resume operations.
     */
    void (*cb_pause) (void *, struct flb_config *);
    void (*cb_resume) (void *, struct flb_config *);

    /*
     * Optional callback that can be used from a parent caller to ingest
     * data into the engine.
     */
    int (*cb_ingest) (void *in_context, void *, size_t);

    /* Exit */
    int (*cb_exit) (void *, struct flb_config *);

    struct mk_list _head;
};

/*
 * Each initialized plugin must have an instance, same plugin may be
 * loaded more than one time.
 *
 * An instance try to contain plugin data separating what is fixed data
 * and the variable one that is generated when the plugin is invoked.
 */
struct flb_input_instance {
    /*
     * The instance flags are derivated from the fixed plugin flags. This
     * is done to offer some flexibility where a plugin instance per
     * configuration would like to change some specific behavior.
     *
     * e.g By default in_tail plugin supports fixed tag, but if a wildcard
     * is added to the 'tag', it will instruct to perform dyntag operations
     * as the tags will be composed used the file name being watched.
     */
    int flags;

    int id;                              /* instance id                  */
    flb_pipefd_t channel[2];             /* pipe(2) channel              */
    int threaded;                        /* bool / Threaded instance ?   */
    char name[32];                       /* numbered name (cpu -> cpu.0) */
    char *alias;                         /* alias name for the instance  */
    void *context;                       /* plugin configuration context */
    struct flb_input_plugin *p;          /* original plugin              */

    /* Plugin properties */
    char *tag;                           /* Input tag for routing        */
    int tag_len;

    /* By default all input instances are 'routable' */
    int routable;

    /*
     * Input network info:
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

    /* Reference to struct flb_storage_input context */
    void *storage;

    /*
     * Buffers counter: it count the total of memory used by fixed and dynamic
     * messgage pack buffers used by the input plugin instance.
     */
    size_t mem_chunks_size;
    size_t mp_total_buf_size; /* FIXME: to be deprecated */

    /*
     * Buffer limit: optional limit set by configuration so this input instance
     * cannot exceed more than mp_buf_limit (bytes unit).
     *
     * As a reference, if an input plugin exceeds the limit, the pause() callback
     * will be triggered to notirfy the input instance it cannot longer append
     * more data, on that moment Fluent Bit will avoid to add more records.
     *
     * When the buffer size goes down (because data was flushed), a resume()
     * callback will be triggered, from that moment the plugin can append more
     * data.
     */
    size_t mem_buf_limit;

    /*
     * Define the buffer status:
     *
     * - FLB_INPUT_RUNNING -> can append more data
     * - FLB_INPUT_PAUSED  -> cannot append data
     */
    int mem_buf_status;

    /*
     * Optional data passed to the plugin, this info is useful when
     * running Fluent Bit in library mode and the target plugin needs
     * some specific data from it caller.
     */
    void *data;

    struct mk_list _head;                /* link to config->inputs     */
    struct mk_list routes;               /* flb_router_path's list     */
    struct mk_list chunks;               /* storage chunks             */
    struct mk_list properties;           /* properties / configuration */
    struct mk_list collectors;           /* collectors                 */

    /*
     * Every co-routine created by the engine when flushing data, it's
     * linked into this list header.
     */
    struct mk_list tasks;

    struct mk_list threads;              /* engine taskslist           */

#ifdef FLB_HAVE_METRICS
    struct flb_metrics *metrics;         /* metrics                    */
#endif

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};

struct flb_input_collector {
    int id;                              /* collector id               */
    int type;                            /* collector type             */
    int running;                         /* is running ? (True/False)  */

    /* FLB_COLLECT_FD_EVENT */
    flb_pipefd_t fd_event;               /* fd being watched           */

    /* FLB_COLLECT_TIME */
    flb_pipefd_t fd_timer;               /* timer fd                   */
    time_t seconds;                      /* expire time in seconds     */
    long nanoseconds;                    /* expire nanoseconds         */

    /* Callback */
    int (*cb_collect) (struct flb_input_instance *,
                       struct flb_config *, void *);

    struct mk_event event;

    /* General references */
    struct flb_input_instance *instance; /* plugin instance             */
    struct mk_list _head;                /* link to global collectors   */
    struct mk_list _head_ins;            /* link to instance collectors */
};

struct flb_input_thread {
    int id;                      /* ID obtained from config->in_table_id */
    time_t start_time;           /* start time  */
    time_t end_time;             /* end time    */
    struct flb_config *config;   /* FLB context */
    struct flb_thread *parent;   /* Back reference to parent thread */
    struct mk_list _head;        /* link to list on input_instance->threads */
};

/*
 * Every thread created for an input instance plugin, requires to have an
 * unique Thread-ID. This function lookup the static table in the context
 * and return the lowest available ID.
 */
static FLB_INLINE
int flb_input_thread_get_id(struct flb_config *config)
{
    unsigned int i;

    for (i = 0; i < (sizeof(config->in_table_id)/sizeof(uint16_t)); i++) {
        if (config->in_table_id[i] == 0) {
            config->in_table_id[i] = FLB_TRUE;
            return i;
        }
    }

    return -1;
}

/*
 * When an input thread ends, it needs to release it ID. This function
 * just mark the ID as unused.
 */
static FLB_INLINE
void flb_input_thread_del_id(int id, struct flb_config *config)
{
    config->in_table_id[id] = FLB_FALSE;
}

static FLB_INLINE
int flb_input_thread_destroy_id(int id, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *head_th;
    struct flb_input_thread *in_th;
    struct flb_input_instance *i_ins;

    /* Iterate input-instances to find the thread */
    mk_list_foreach(head, &config->inputs) {
        i_ins = mk_list_entry(head, struct flb_input_instance, _head);
        mk_list_foreach_safe(head_th, tmp, &i_ins->threads) {
            in_th = mk_list_entry(head_th, struct flb_input_thread, _head);
            if (in_th->id != id) {
                continue;
            }

            mk_list_del(&in_th->_head);
            flb_input_thread_del_id(id, config);
            flb_thread_destroy(in_th->parent);
            flb_debug("[input] destroy input_thread id=%i", id);
            return 0;
        }
    }

    return -1;
}

static FLB_INLINE
struct flb_thread *flb_input_thread(struct flb_input_instance *i_ins,
                                    struct flb_config *config)
{
    int id;
    struct flb_thread *th;
    struct flb_input_thread *in_th;

    th = flb_thread_new(sizeof(struct flb_input_thread), NULL);
    if (!th) {
        return NULL;
    }

    /* Try to obtain an id */
    id = flb_input_thread_get_id(config);
    if (id == -1) {
        flb_thread_destroy(th);
        return NULL;
    }

    /* Setup thread specific data */
    in_th = (struct flb_input_thread *) FLB_THREAD_DATA(th);
    in_th->id         = id;
    in_th->start_time = time(NULL);
    in_th->parent     = th;
    in_th->config     = config;
    mk_list_add(&in_th->_head, &i_ins->threads);

    return th;
}

struct flb_libco_in_params {
    struct flb_config *config;
    struct flb_input_collector *coll;
    struct flb_thread *th;
};

struct flb_libco_in_params libco_in_param;

static FLB_INLINE void input_params_set(struct flb_thread *th,
                             struct flb_input_collector *coll,
                             struct flb_config *config,
                             void *context)
{
    /* Set callback parameters */
    libco_in_param.coll    = coll;
    libco_in_param.config  = config;
    libco_in_param.th      = th;
    co_switch(th->callee);
}

static FLB_INLINE void input_pre_cb_collect(void)
{
    struct flb_input_collector *coll = libco_in_param.coll;
    struct flb_config *config = libco_in_param.config;
    struct flb_thread *th     = libco_in_param.th;

    co_switch(th->caller);
    coll->cb_collect(coll->instance, config, coll->instance->context);
}

static FLB_INLINE
struct flb_thread *flb_input_thread_collect(struct flb_input_collector *coll,
                                            struct flb_config *config)
{
    size_t stack_size;
    struct flb_thread *th;

    th = flb_input_thread(coll->instance, config);
    if (!th) {
        return NULL;
    }

    th->caller = co_active();
    th->callee = co_create(config->coro_stack_size,
                           input_pre_cb_collect, &stack_size);

#ifdef FLB_HAVE_VALGRIND
    th->valgrind_stack_id = VALGRIND_STACK_REGISTER(th->callee,
                                                    ((char *)th->callee) + stack_size);
#endif

    /* Set parameters */
    input_params_set(th, coll, config, coll->instance->context);
    return th;
}

/*
 * This function is used by the output plugins to return. It's mandatory
 * as it will take care to signal the event loop letting know the flush
 * callback has done.
 *
 * The signal emmited indicate the 'Task' number that have finished plus
 * a return value. The return value is either FLB_OK, FLB_RETRY or FLB_ERROR.
 *
 * If the caller have requested a FLB_RETRY, it will be issued depending of the
 * number of retries, if it have exceed the 'retry_limit' option, a FLB_ERROR
 * will be returned instead.
 */
static inline void flb_input_return(struct flb_thread *th) {
    int n;
    uint64_t val;
    struct flb_input_thread *in_th;

    in_th = (struct flb_input_thread *) FLB_THREAD_DATA(th);

    /*
     * To compose the signal event the relevant info is:
     *
     * - Unique Task events id: 2 in this case
     * - Return value: FLB_OK (0) or FLB_ERROR (1)
     * - Task ID
     *
     * We put together the return value with the task_id on the 32 bits at right
     */
    val = FLB_BITS_U64_SET(3 /* FLB_ENGINE_IN_THREAD */, in_th->id);
    n = flb_pipe_w(in_th->config->ch_manager[1], (void *) &val, sizeof(val));
    if (n == -1) {
        flb_errno();
    }
}

static inline int flb_input_buf_paused(struct flb_input_instance *i)
{
    if (i->mem_buf_status == FLB_INPUT_PAUSED) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static inline void FLB_INPUT_RETURN()
{
    struct flb_thread *th;
    th = (struct flb_thread *) pthread_getspecific(flb_thread_key);
    flb_input_return(th);
    flb_thread_return(th);
}

int flb_input_register_all(struct flb_config *config);
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         const char *input, void *data,
                                         int public_only);
int flb_input_set_property(struct flb_input_instance *in,
                           const char *k, const char *v);
const char *flb_input_get_property(const char *key, struct flb_input_instance *i);

int flb_input_check(struct flb_config *config);
void flb_input_set_context(struct flb_input_instance *in, void *context);
int flb_input_channel_init(struct flb_input_instance *in);

int flb_input_collector_start(int coll_id, struct flb_input_instance *in);
int flb_input_collectors_start(struct flb_config *config);
int flb_input_collector_pause(int coll_id, struct flb_input_instance *in);
int flb_input_collector_resume(int coll_id, struct flb_input_instance *in);
int flb_input_collector_fd(flb_pipefd_t fd, struct flb_config *config);
int flb_input_set_collector_time(struct flb_input_instance *in,
                                 int (*cb_collect) (struct flb_input_instance *,
                                                    struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config);
int flb_input_set_collector_event(struct flb_input_instance *in,
                                  int (*cb_collect) (struct flb_input_instance *,
                                                     struct flb_config *, void *),
                                  flb_pipefd_t fd,
                                  struct flb_config *config);
int flb_input_set_collector_socket(struct flb_input_instance *in,
                                   int (*cb_new_connection) (struct flb_input_instance *,
                                                             struct flb_config *,
                                                             void*),
                                   flb_pipefd_t fd,
                                   struct flb_config *config);
int flb_input_collector_running(int coll_id, struct flb_input_instance *in);
int flb_input_instance_init(struct flb_input_instance *in,
                            struct flb_config *config);
void flb_input_instance_exit(struct flb_input_instance *in,
                             struct flb_config *config);
void flb_input_instance_free(struct flb_input_instance *in);

void flb_input_initialize_all(struct flb_config *config);
void flb_input_pre_run_all(struct flb_config *config);
void flb_input_exit_all(struct flb_config *config);

void *flb_input_flush(struct flb_input_instance *i_ins, size_t *size);
int flb_input_pause_all(struct flb_config *config);
const char *flb_input_name(struct flb_input_instance *in);

#endif
