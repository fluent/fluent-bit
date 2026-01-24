/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_engine_macros.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_bits.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_hash_table.h>

#include <fluent-bit/flb_input_event.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_input_trace.h>
#include <fluent-bit/flb_input_profiles.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_processor.h>

#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics.h>
#endif
#include <fluent-bit/flb_pthread.h>

#include <cmetrics/cmetrics.h>
#include <monkey/mk_core.h>
#include <cfl/cfl.h>

#include <msgpack.h>
#include <inttypes.h>

#define FLB_COLLECT_TIME        1
#define FLB_COLLECT_FD_EVENT    2
#define FLB_COLLECT_FD_SERVER   4

/* Input plugin flag masks */
#define FLB_INPUT_NET           4   /* input address may set host and port   */
#define FLB_INPUT_PLUGIN_CORE   0
#define FLB_INPUT_PLUGIN_PROXY  1
#define FLB_INPUT_CORO        128   /* plugin requires a thread on callbacks */
#define FLB_INPUT_PRIVATE     256   /* plugin is not published/exposed       */
#define FLB_INPUT_NOTAG       512   /* plugin might don't have tags          */
#define FLB_INPUT_THREADED   1024   /* plugin must run in a separate thread  */
#define FLB_INPUT_NET_SERVER 2048   /* Input address may set host and port.
                                     * In addition, if TLS is enabled then a
                                     * private key and certificate are required.
                                     */

/* Input status */
#define FLB_INPUT_RUNNING     1
#define FLB_INPUT_PAUSED      0

struct flb_input_instance;

/*
 * Tests callbacks
 * ===============
 */
struct flb_test_in_formatter {
    /*
     * Runtime Library Mode
     * ====================
     * When the runtime library enable the test formatter mode, it needs to
     * keep a reference of the context and other information:
     *
     * - rt_ctx : context created by flb_create()
     *
     * - rt_ffd : this plugin assigned 'integer' created by flb_output()
     *
     * - rt_in_calback: intermediary function to receive the results of
     *                  the formatter plugin test function.
     *
     * - rt_data: opaque data type for rt_step_callback()
     */

    /* runtime library context */
    void *rt_ctx;

    /* runtime library: assigned plugin integer */
    int rt_ffd;

    /* optional format context */
    void *format_ctx;

    /*
     * "runtime step callback": this function pointer is used by Fluent Bit
     * library mode to reference a test function that must retrieve the
     * results of 'callback'. Consider this an intermediary function to
     * transfer the results to the runtime test.
     *
     * This function is private and should not be set manually in the plugin
     * code, it's set on src/flb_lib.c .
     */
    void (*rt_in_callback) (void *, int, int, void *, size_t, void *);

    /*
     * opaque data type passed by the runtime library to be used on
     * rt_step_test().
     */
    void *rt_data;

    /*
     * Callback
     * =========
     * "Formatter callback": it references the plugin function that performs
     * data formatting (msgpack -> local data). This entry is mostly to
     * expose the plugin local function.
     */
    int (*callback) (/* Fluent Bit context */
                     struct flb_config *,
                     /* plugin that ingested the records */
                     struct flb_input_instance *,
                     void *,         /* plugin instance context */
                     const void *,   /* incoming unformatted data */
                     size_t,         /* incoming unformatted size */
                     void **,        /* output buffer      */
                     size_t *);      /* output buffer size */
};

struct flb_input_plugin {
    /*
     * The type defines if this is a core-based plugin or it's handled by
     * some specific proxy.
     */
    int type;
    void *proxy;

    int flags;                /* plugin flags */

    /* The Input name */
    char *name;

    /* Plugin Description */
    char *description;

    struct flb_config_map *config_map;

    /* Initialization */
    int (*cb_init)    (struct flb_input_instance *, struct flb_config *, void *);

    /* Pre run */
    int (*cb_pre_run) (struct flb_input_instance *, struct flb_config *, void *);

    /* Collect: every certain amount of time, Fluent Bit trigger this callback */
    int (*cb_collect) (struct flb_input_instance *, struct flb_config *, void *);

    /* Notification: this callback will be invoked anytime a notification is received*/
    int (*cb_notification) (struct flb_input_instance *, struct flb_config *, void *);

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

    /* Destroy */
    void (*cb_destroy) (struct flb_input_plugin *);

    /* Tests */
    struct flb_test_in_formatter test_formatter;

    void *instance;

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
    struct mk_event event;           /* events handler */

    struct flb_processor *processor;

    /*
     * The instance flags are derived from the fixed plugin flags. This
     * is done to offer some flexibility where a plugin instance per
     * configuration would like to change some specific behavior.
     *
     * e.g By default in_tail plugin supports fixed tag, but if a wildcard
     * is added to the 'tag', it will instruct to perform dyntag operations
     * as the tags will be composed used the file name being watched.
     */
    int flags;

    int id;                              /* instance id                  */
#ifdef FLB_HAVE_CHUNK_TRACE
    struct flb_chunk_trace_context *chunk_trace_ctxt;
    pthread_mutex_t chunk_trace_lock;
#endif /* FLB_HAVE_CHUNK_TRACE */
    int log_level;                       /* log level for this plugin    */
    int log_suppress_interval;           /* log suppression interval     */
    flb_pipefd_t channel[2];             /* pipe(2) channel              */
    int runs_in_coroutine;               /* instance runs in coroutine ? */
    char name[32];                       /* numbered name (cpu -> cpu.0) */
    char *alias;                         /* alias name for the instance  */
    int test_mode;                       /* running tests? (default:off) */
    void *context;                       /* plugin configuration context */
    flb_pipefd_t ch_events[2];           /* channel for events           */
    struct flb_input_plugin *p;          /* original plugin              */

    /* Plugin properties */
    char *tag;                           /* Input tag for routing        */
    int tag_len;
    int tag_default;                     /* is it using the default tag? */

    /* By default all input instances are 'routable' */
    int routable;

    /* flag to pause input when storage is full */
    int storage_pause_on_chunks_overlimit;

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

    /* Type of storage: CIO_STORE_FS (filesystem) or CIO_STORE_MEM (memory) */
    int storage_type;

    /*
     * Buffers counter: it counts the total of memory used by fixed and dynamic
     * message pack buffers used by the input plugin instance.
     */
    size_t mem_chunks_size;
    size_t mp_total_buf_size; /* FIXME: to be deprecated */

    /*
     * Buffer limit: optional limit set by configuration so this input instance
     * cannot exceed more than mp_buf_limit (bytes unit).
     *
     * As a reference, if an input plugin exceeds the limit, the pause() callback
     * will be triggered to notify the input instance it cannot longer append
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
     * Define the buffer status:
     *
     * - FLB_INPUT_RUNNING -> can append more data
     * - FLB_INPUT_PAUSED  -> cannot append data
     */
    int storage_buf_status;

    /*
     * Optional data passed to the plugin, this info is useful when
     * running Fluent Bit in library mode and the target plugin needs
     * some specific data from it caller.
     */
    void *data;

    struct mk_list *config_map;          /* configuration map        */

    struct mk_list _head;                /* link to config->inputs     */

    struct cfl_list routes_direct;        /* direct routes set by API   */
    struct cfl_list routes;               /* flb_router_path's list     */
    struct mk_list  properties;           /* properties / configuration */
    struct mk_list  collectors;           /* collectors                 */

    /* Storage Chunks */
    struct mk_list chunks;               /* linked list of all chunks  */

    /*
     * The following list helps to separate the chunks per its
     * status, it can be 'up' or 'down'.
     */
    struct mk_list chunks_up;            /* linked list of all chunks up */
    struct mk_list chunks_down;          /* linked list of all chunks down */

    /*
     * Every co-routine created by the engine when flushing data, it's
     * linked into this list header.
     */
    struct mk_list tasks;

    /* co-routines for input plugins with FLB_INPUT_CORO flag */
    int input_coro_id;
    struct mk_list input_coro_list;
    struct mk_list input_coro_list_destroy;

#ifdef FLB_HAVE_METRICS
    /* old metrics API */
    struct flb_metrics *metrics;         /* metrics                    */
#endif

    /* Tests */
    struct flb_test_in_formatter test_formatter;

    /* is the plugin running in a separate thread ? */
    int is_threaded;
    struct flb_input_thread_instance *thi;

    /*
     * ring buffer: the ring buffer is used by the instance if is running
     * in threaded mode; so when registering a msgpack buffer this happens
     * in the ring buffer.
     */
    struct flb_ring_buffer *rb;
    size_t ring_buffer_size;           /* ring buffer size */
    uint8_t ring_buffer_window;        /* ring buffer window percentage */
    int ring_buffer_retry_limit;       /* ring buffer write retry limit */

    /* List of upstreams */
    struct mk_list upstreams;

    /* List of downstreams */
    struct mk_list downstreams;

    /*
     * CMetrics
     * --------
     *
     * All metrics available for an input plugin instance.
     */
    struct cmt *cmt;                     /* parent context              */
    struct cmt_counter *cmt_bytes;       /* metric: input_bytes_total   */
    struct cmt_counter *cmt_records;     /* metric: input_records_total */

    /* is the input instance overlimit ?: 1 or 0 */
    struct cmt_gauge   *cmt_storage_overlimit;

    /* is the input instance paused or not ?: 1 or 0 */
    struct cmt_gauge   *cmt_ingestion_paused;

    /* memory bytes used by chunks */
    struct cmt_gauge   *cmt_storage_memory_bytes;

    /* total number of chunks */
    struct cmt_gauge   *cmt_storage_chunks;

    /* total number of chunks up in memory */
    struct cmt_gauge   *cmt_storage_chunks_up;

    /* total number of chunks down */
    struct cmt_gauge   *cmt_storage_chunks_down;

    /* number of chunks in a busy state */
    struct cmt_gauge   *cmt_storage_chunks_busy;

    /* total bytes used by chunks in a busy state */
    struct cmt_gauge   *cmt_storage_chunks_busy_bytes;

    /* memory ring buffer (memrb) metrics */
    struct cmt_counter *cmt_memrb_dropped_chunks;
    struct cmt_counter *cmt_memrb_dropped_bytes;

    /* ring buffer 'write' metrics */
    struct cmt_counter *cmt_ring_buffer_writes;
    struct cmt_counter *cmt_ring_buffer_retries;
    struct cmt_counter *cmt_ring_buffer_retry_failures;

    /*
     * Indexes for generated chunks: simple hash tables that keeps the latest
     * available chunks for writing data operations. This optimizes the
     * lookup for candidates chunks to write data.
     */
    struct flb_hash_table *ht_log_chunks;
    struct flb_hash_table *ht_metric_chunks;
    struct flb_hash_table *ht_trace_chunks;
    struct flb_hash_table *ht_profile_chunks;

    /* TLS settings */
    int use_tls;                         /* bool, try to use TLS for I/O */
    int tls_verify;                      /* Verify certs (default: true) */
    int tls_verify_hostname;             /* Verify hostname (default: false) */
    int tls_debug;                       /* mbedtls debug level          */
    char *tls_vhost;                     /* Virtual hostname for SNI     */
    char *tls_ca_path;                   /* Path to certificates         */
    char *tls_ca_file;                   /* CA root cert                 */
    char *tls_crt_file;                  /* Certificate                  */
    char *tls_key_file;                  /* Cert Key                     */
    char *tls_key_passwd;                /* Cert Key Password            */
    char *tls_min_version;               /* Minimum protocol version of TLS */
    char *tls_max_version;               /* Maximum protocol version of TLS */
    char *tls_ciphers;                   /* TLS ciphers */

    struct mk_list *tls_config_map;

#ifdef FLB_HAVE_TLS
    struct flb_tls *tls;
#else
    void *tls;
#endif

    /* General network options like timeouts and keepalive */
    struct flb_net_setup net_setup;
    struct mk_list *net_config_map;
    struct mk_list net_properties;

    struct mk_list *oauth2_jwt_config_map;
    struct mk_list oauth2_jwt_properties;

    flb_pipefd_t notification_channel;

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};

struct flb_input_collector {
    struct mk_event event;
    struct mk_event_loop *evl;           /* event loop */

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


    /* General references */
    struct flb_input_instance *instance; /* plugin instance             */
    struct mk_list _head;                /* link to instance collectors */
};

struct flb_input_coro {
    int id;                         /* id returned from flb_input_coro_id_get() */
    time_t start_time;              /* start time  */
    time_t end_time;                /* end time    */
    struct flb_input_instance *ins; /* parent input instance */
    struct flb_coro *coro;          /* coroutine context */
    struct flb_config *config;      /* FLB context */
    struct mk_list _head;           /* link to list on input_instance->coros */
};

int flb_input_coro_id_get(struct flb_input_instance *ins);

static FLB_INLINE
struct flb_input_coro *flb_input_coro_create(struct flb_input_instance *ins,
                                             struct flb_config *config)
{
    struct flb_coro *coro;
    struct flb_input_coro *input_coro;

    /* input_coro context */
    input_coro = (struct flb_input_coro *) flb_calloc(1,
                                                      sizeof(struct flb_input_coro));
    if (!input_coro) {
        flb_errno();
        return NULL;
    }

    /* coroutine context */
    coro = flb_coro_create(input_coro);
    if (!coro) {
        flb_free(input_coro);
        return NULL;
    }

    input_coro->id         = flb_input_coro_id_get(ins);
    input_coro->ins        = ins;
    input_coro->start_time = time(NULL);
    input_coro->coro       = coro;
    input_coro->config     = config;

    mk_list_add(&input_coro->_head, &ins->input_coro_list);

    return input_coro;
}

struct flb_libco_in_params {
    struct flb_config *config;
    struct flb_input_collector *coll;
    struct flb_coro *coro;
};

extern pthread_key_t libco_in_param_key;
extern struct flb_libco_in_params libco_in_param;
void flb_input_coro_prepare_destroy(struct flb_input_coro *input_coro);

static FLB_INLINE void input_params_set(struct flb_coro *coro,
                             struct flb_input_collector *coll,
                             struct flb_config *config,
                             void *context)
{
    struct flb_libco_in_params *params;

    params = pthread_getspecific(libco_in_param_key);
    if (params == NULL) {
        params = flb_calloc(1, sizeof(struct flb_libco_in_params));
        if (params == NULL) {
            flb_errno();
            return;
        }
        pthread_setspecific(libco_in_param_key, params);
    }

    /* Set callback parameters */
    params->coll    = coll;
    params->config  = config;
    params->coro    = coro;
    co_switch(coro->callee);
}

static FLB_INLINE void input_pre_cb_collect(void)
{
    struct flb_input_collector *coll;
    struct flb_config *config;
    struct flb_coro *coro;
    struct flb_libco_in_params *params;

    params = pthread_getspecific(libco_in_param_key);
    if (params == NULL) {
        params = flb_calloc(1, sizeof(struct flb_libco_in_params));
        if (params == NULL) {
            flb_errno();
            return;
        }
        pthread_setspecific(libco_in_param_key, params);
    }
    coll = params->coll;
    config = params->config;
    coro = params->coro;

    co_switch(coro->caller);
    coll->cb_collect(coll->instance, config, coll->instance->context);
}

static FLB_INLINE void flb_input_coro_resume(struct flb_input_coro *input_coro)
{
    flb_coro_resume(input_coro->coro);
}

static void libco_in_param_key_destroy(void *data)
{
    struct flb_libco_inparams *params = (struct flb_libco_inparams*)data;

    flb_free(params);
}

static FLB_INLINE
struct flb_input_coro *flb_input_coro_collect(struct flb_input_collector *coll,
                                              struct flb_config *config)
{
    size_t stack_size;
    struct flb_coro *coro;
    struct flb_input_coro *input_coro;

    input_coro = flb_input_coro_create(coll->instance, config);
    if (!input_coro) {
        return NULL;
    }

    pthread_key_create(&libco_in_param_key, libco_in_param_key_destroy);

    coro = input_coro->coro;
    if (!coro) {
        return NULL;
    }

    coro->caller = co_active();
    coro->callee = co_create(config->coro_stack_size,
                             input_pre_cb_collect, &stack_size);

#ifdef FLB_HAVE_VALGRIND
    coro->valgrind_stack_id = VALGRIND_STACK_REGISTER(coro->callee,
                                                      ((char *)coro->callee) + stack_size);
#endif

    /* Set parameters */
    input_params_set(coro, coll, config, coll->instance->context);
    return input_coro;
}

static FLB_INLINE int flb_input_is_threaded(struct flb_input_instance *ins)
{
    return ins->is_threaded;
}

/*
 * This function is used by the output plugins to return. It's mandatory
 * as it will take care to signal the event loop letting know the flush
 * callback has done.
 *
 * The signal emitted indicate the 'Task' number that have finished plus
 * a return value. The return value is either FLB_OK, FLB_RETRY or FLB_ERROR.
 *
 * If the caller have requested an FLB_RETRY, it will be issued depending on the
 * number of retries, if it has exceeded the 'retry_limit' option, an FLB_ERROR
 * will be returned instead.
 */
static FLB_INLINE void flb_input_return(struct flb_coro *coro) {
    int n;
    uint64_t val;
    struct flb_input_coro *input_coro;
    struct flb_input_instance *ins;

    input_coro = (struct flb_input_coro *) coro->data;
    ins = input_coro->ins;

    /*
     * Message the event loop by identifying the message coming from an input
     * coroutine and passing the input plugin ID that triggered the event.
     */
    val = FLB_BITS_U64_SET(FLB_ENGINE_IN_CORO, ins->id);
    n = flb_pipe_w(ins->ch_events[1], (void *) &val, sizeof(val));
    if (n == -1) {
        flb_pipe_error();
    }

    flb_input_coro_prepare_destroy(input_coro);
}

static FLB_INLINE void flb_input_return_do(int ret) {
    struct flb_coro *coro = flb_coro_get();

    flb_input_return(coro);
    flb_coro_yield(coro, FLB_TRUE);
}

#define FLB_INPUT_RETURN(x) \
    flb_input_return_do(x); \
    return x;

static inline int flb_input_buf_paused(struct flb_input_instance *i)
{
    if (i->mem_buf_status == FLB_INPUT_PAUSED) {
        return FLB_TRUE;
    }
    if (i->storage_buf_status == FLB_INPUT_PAUSED) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static inline int flb_input_config_map_set(struct flb_input_instance *ins,
                                           void *context)
{
    int ret;

    ret = -1;

    /* Process normal properties */
    if (ins->config_map) {
        ret = flb_config_map_set(&ins->properties, ins->config_map, context);

        if (ret == -1) {
            return -1;
        }
    }

    /* Net properties */
    if (ins->net_config_map) {
        ret = flb_config_map_set(&ins->net_properties, ins->net_config_map,
                                 &ins->net_setup);
        if (ret == -1) {
            return -1;
        }
    }

    return ret;
}

struct mk_list *flb_input_get_global_config_map(struct flb_config *config);

int flb_input_register_all(struct flb_config *config);
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         const char *input, void *data,
                                         int public_only);
struct flb_input_instance *flb_input_get_instance(struct flb_config *config,
                                                  int ins_id);

int flb_input_set_property(struct flb_input_instance *ins,
                           const char *k, const char *v);
const char *flb_input_get_property(const char *key,
                                   struct flb_input_instance *ins);
#ifdef FLB_HAVE_METRICS
void *flb_input_get_cmt_instance(struct flb_input_instance *ins);
#endif

int flb_input_check(struct flb_config *config);
void flb_input_set_context(struct flb_input_instance *ins, void *context);
int flb_input_channel_init(struct flb_input_instance *ins);


int flb_input_collector_start(int coll_id, struct flb_input_instance *ins);
int flb_input_collectors_start(struct flb_config *config);
int flb_input_collector_pause(int coll_id, struct flb_input_instance *ins);
int flb_input_collector_resume(int coll_id, struct flb_input_instance *ins);
int flb_input_collector_delete(int coll_id, struct flb_input_instance *ins);
int flb_input_collector_destroy(struct flb_input_collector *coll);
int flb_input_collector_fd(flb_pipefd_t fd, struct flb_config *config);
struct mk_event *flb_input_collector_get_event(int coll_id,
                                               struct flb_input_instance *ins);
int flb_input_set_collector_time(struct flb_input_instance *ins,
                                 int (*cb_collect) (struct flb_input_instance *,
                                                    struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config);
int flb_input_set_collector_event(struct flb_input_instance *ins,
                                  int (*cb_collect) (struct flb_input_instance *,
                                                     struct flb_config *, void *),
                                  flb_pipefd_t fd,
                                  struct flb_config *config);
int flb_input_set_collector_socket(struct flb_input_instance *ins,
                                   int (*cb_new_connection) (struct flb_input_instance *,
                                                             struct flb_config *,
                                                             void*),
                                   flb_pipefd_t fd,
                                   struct flb_config *config);
int flb_input_collector_running(int coll_id, struct flb_input_instance *ins);
int flb_input_coro_id_get(struct flb_input_instance *ins);
int flb_input_coro_finished(struct flb_config *config, int ins_id);

int flb_input_instance_init(struct flb_input_instance *ins,
                            struct flb_config *config);
void flb_input_instance_exit(struct flb_input_instance *ins,
                             struct flb_config *config);
void flb_input_instance_destroy(struct flb_input_instance *ins);

int flb_input_net_property_check(struct flb_input_instance *ins,
                                 struct flb_config *config);
int flb_input_plugin_property_check(struct flb_input_instance *ins,
                                    struct flb_config *config);

int flb_input_init_all(struct flb_config *config);
void flb_input_pre_run_all(struct flb_config *config);
void flb_input_exit_all(struct flb_config *config);

void *flb_input_flush(struct flb_input_instance *ins, size_t *size);

int flb_input_test_pause_resume(struct flb_input_instance *ins, int sleep_seconds);
int flb_input_pause(struct flb_input_instance *ins);
int flb_input_pause_all(struct flb_config *config);
int flb_input_resume(struct flb_input_instance *ins);

const char *flb_input_name(struct flb_input_instance *ins);
int flb_input_name_exists(const char *name, struct flb_config *config);

void flb_input_net_default_listener(const char *listen, int port,
                                    struct flb_input_instance *ins);

int flb_input_log_check(struct flb_input_instance *ins, int l);

struct mk_event_loop *flb_input_event_loop_get(struct flb_input_instance *ins);
int flb_input_upstream_set(struct flb_upstream *u, struct flb_input_instance *ins);
int flb_input_downstream_set(struct flb_downstream *stream,
                             struct flb_input_instance *ins);


/* processors */
int flb_input_instance_processors_load(struct flb_input_instance *ins, struct flb_cf_group *processors);

#endif
