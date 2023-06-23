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
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_callback.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_output_thread.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_processor.h>

#include <cfl/cfl.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_msgpack.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <ctraces/ctr_encode_msgpack.h>
#include <ctraces/ctr_mpack_utils_defs.h>

#include <cprofiles/cprofiles.h>
#include <cprofiles/cprof_decode_msgpack.h>
#include <cprofiles/cprof_encode_msgpack.h>
#include <cprofiles/cprof_mpack_utils_defs.h>

#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
#endif

#ifdef FLB_HAVE_CHUNK_TRACE
/* include prototype directly to avoid cyclical include ... */
int flb_chunk_trace_output(struct flb_chunk_trace *trace, struct flb_output_instance *output, int ret);
#endif

/* Output plugin masks */
#define FLB_OUTPUT_NET            32  /* output address may set host and port */
#define FLB_OUTPUT_PLUGIN_CORE     0
#define FLB_OUTPUT_PLUGIN_PROXY    1
#define FLB_OUTPUT_NO_MULTIPLEX  512  /* run one task at a time, one task per flush */
#define FLB_OUTPUT_PRIVATE      1024
#define FLB_OUTPUT_SYNCHRONOUS  2048  /* run one task at a time, no flush cycle limit */


/*
 * Event type handlers
 *
 * These types are defined by creating a mask using numbers. However, it's important
 * to note that the masks used in this process are different from the ones used
 * in flb_event.h. The original chunk values are not actually masks, but rather set
 * numbers starting from 0; this is for compatibility reasons.
 */
#define FLB_OUTPUT_LOGS        1
#define FLB_OUTPUT_METRICS     2
#define FLB_OUTPUT_TRACES      4
#define FLB_OUTPUT_BLOBS       8
#define FLB_OUTPUT_PROFILES    16

#define FLB_OUTPUT_FLUSH_COMPAT_OLD_18()                 \
    const void *data   = event_chunk->data;              \
    size_t     bytes   = event_chunk->size;              \
    int        tag_len = flb_sds_len(event_chunk->tag);  \
    const char *tag    = event_chunk->tag;

struct flb_output_flush;

/*
 * Tests callbacks
 * ===============
 */
struct flb_test_out_formatter {
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
     * - rt_step_calback: intermediary function to receive the results of
     *                    the formatter plugin test function.
     *
     * - rt_data: opaque data type for rt_step_callback()
     */

    /* runtime library context */
    void *rt_ctx;

    /* runtime library: assigned plugin integer */
    int rt_ffd;

    /*
     * "runtime step callback": this function pointer is used by Fluent Bit
     * library mode to reference a test function that must retrieve the
     * results of 'callback'. Consider this an intermediary function to
     * transfer the results to the runtime test.
     *
     * This function is private and should not be set manually in the plugin
     * code, it's set on src/flb_lib.c .
     */
    void (*rt_out_callback) (void *, int, int, void *, size_t, void *);

    /*
     * opaque data type passed by the runtime library to be used on
     * rt_step_test().
     */
    void *rt_data;

    /* optional context for "flush context callback" */
    void *flush_ctx;

    /*
     * Callback
     * =========
     * Optional "flush context callback": it references the function that extracts
     * optional flush context for "formatter callback".
     */
    void *(*flush_ctx_callback) (/* Fluent Bit context */
                                 struct flb_config *,
                                 /* plugin that ingested the records */
                                 struct flb_input_instance *,
                                 /* plugin instance context */
                                 void *plugin_context,
                                 /* context for "flush context callback" */
                                 void *flush_ctx);

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
                     void *,         /* optional flush context */
                     int,            /* event type */
                     const char *,   /* tag        */
                     int,            /* tag length */
                     const void *,   /* incoming msgpack data */
                     size_t,         /* incoming msgpack size */
                     void **,        /* output buffer      */
                     size_t *);      /* output buffer size */
};

struct flb_test_out_response {
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
     * - rt_step_calback: intermediary function to receive the results of
     *                    the formatter plugin test function.
     *
     * - rt_data: opaque data type for rt_step_callback()
     */

    /* runtime library context */
    void *rt_ctx;

    /* runtime library: assigned plugin integer */
    int rt_ffd;

    /*
     * "runtime step callback": this function pointer is used by Fluent Bit
     * library mode to reference a test function that must retrieve the
     * results of 'callback'. Consider this an intermediary function to
     * transfer the results to the runtime test.
     *
     * This function is private and should not be set manually in the plugin
     * code, it's set on src/flb_lib.c .
     */
    void (*rt_out_response) (void *, int, int, void *, size_t, void *);

    /*
     * opaque data type passed by the runtime library to be used on
     * rt_step_test().
     */
    void *rt_data;

    /* optional context for flush callback */
    void *flush_ctx;

    /*
     * Callback
     * =========
     * "Formatter callback": it references the plugin function that performs
     * data formatting (msgpack -> local data). This entry is mostly to
     * expose the plugin local function.
     */
    int (*callback) (/* Fluent Bit context */
                     struct flb_config *,
                     void *,         /* plugin instance context */
                     int status,     /* HTTP status code */
                     const void *,   /* respond msgpack data */
                     size_t,         /* respond msgpack size */
                     void **,        /* output buffer      */
                     size_t *);      /* output buffer size */
};

struct flb_output_plugin {
    /*
     * a 'mask' to define what kind of data the plugin can manage:
     *
     *  - FLB_OUTPUT_LOGS
     *  - FLB_OUTPUT_METRICS
     */
    int event_type;

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

    struct flb_config_map *config_map;

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
    void (*cb_flush) (struct flb_event_chunk *,
                      struct flb_output_flush *,
                      struct flb_input_instance *,
                      void *,
                      struct flb_config *);

    /* Exit */
    int (*cb_exit) (void *, struct flb_config *);

    /* Destroy */
    void (*cb_destroy) (struct flb_output_plugin *);

    /* Default number of worker threads */
    int workers;

    int (*cb_worker_init) (void *, struct flb_config *);
    int (*cb_worker_exit) (void *, struct flb_config *);

    /* Notification: this callback will be invoked anytime a notification is received*/
    int (*cb_notification) (struct flb_output_instance *, struct flb_config *, void *);

    /* Tests */
    struct flb_test_out_formatter test_formatter;
    struct flb_test_out_response test_response;

    /* Link to global list from flb_config->outputs */
    struct mk_list _head;
};

// constants for retry_limit
#define FLB_OUT_RETRY_UNLIMITED -1
#define FLB_OUT_RETRY_NONE       0

/*
 * Each initialized plugin must have an instance, same plugin may be
 * loaded more than one time.
 *
 * An instance try to contain plugin data separating what is fixed data
 * and the variable one that is generated when the plugin is invoked.
 */
struct flb_output_instance {
    struct mk_event event;               /* events handler               */

    struct flb_processor *processor;

    /*
     * a 'mask' to define what kind of data the plugin can manage:
     *
     *  - FLB_OUTPUT_LOGS
     *  - FLB_OUTPUT_METRICS
     */
    int event_type;
    int id;                              /* instance id                  */
    int log_level;                       /* instance log level           */
    int log_suppress_interval;           /* log suppression interval     */
    char name[32];                       /* numbered name (cpu -> cpu.0) */
    char *alias;                         /* alias name for the instance  */
    int flags;                           /* inherit flags from plugin    */
    int test_mode;                       /* running tests? (default:off) */
    flb_pipefd_t ch_events[2];           /* channel for events           */
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
# if defined(FLB_SYSTEM_WINDOWS)
    char *tls_win_certstore_name;            /* CertStore Name (Windows) */
    int tls_win_use_enterprise_certstore;    /* Use enterprise CertStore */
    char *tls_win_thumbprints;               /* CertStore Thumbprints (Windows) */
# endif
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

#ifdef FLB_HAVE_TLS
    struct flb_tls *tls;
#else
    void *tls;
#endif

    /*
     * configuration properties: incoming properties set by the caller. This
     * list is what the instance received by either a configuration file or
     * through the command line arguments. This list is validated by the
     * plugin.
     */
    struct mk_list properties;

    /*
     * configuration map: a new API is landing on Fluent Bit v1.4 that allows
     * plugins to specify at registration time the allowed configuration
     * properties and it data types. Config map is an optional API for now
     * and some plugins will take advantage of it. When the API is used, the
     * config map will validate the configuration, set default values
     * and merge the 'properties' (above) into the map.
     */
    struct mk_list *config_map;

    /* General network options like timeouts and keepalive */
    struct flb_net_setup net_setup;
    struct mk_list *net_config_map;
    struct mk_list net_properties;

    struct mk_list *oauth2_config_map;
    struct mk_list oauth2_properties;

    struct mk_list *tls_config_map;

    struct mk_list _head;                /* link to config->inputs       */

    /*
     * CMetrics
     * --------
     */
    struct cmt *cmt;                         /* parent context            */
    struct cmt_counter *cmt_proc_records;    /* m: output_proc_records    */
    struct cmt_counter *cmt_proc_bytes;      /* m: output_proc_bytes      */
    struct cmt_counter *cmt_errors;          /* m: output_errors          */
    struct cmt_counter *cmt_retries;         /* m: output_retries         */
    struct cmt_counter *cmt_retries_failed;  /* m: output_retries_failed  */
    struct cmt_counter *cmt_dropped_records; /* m: output_dropped_records */
    struct cmt_counter *cmt_retried_records; /* m: output_retried_records */

    /* m: output_upstream_total_connections */
    struct cmt_gauge   *cmt_upstream_total_connections;
    /* m: output_upstream_busy_connections */
    struct cmt_gauge   *cmt_upstream_busy_connections;
    /* m: output_chunk_available_capacity_percent */
    struct cmt_gauge   *cmt_chunk_available_capacity_percent;
    /* m: output_latency_seconds */
    struct cmt_histogram *cmt_latency;

    /* OLD Metrics API */
#ifdef FLB_HAVE_METRICS
    struct flb_metrics *metrics;         /* metrics                      */
#endif

    /* Callbacks context */
    struct flb_callback *callback;

    /* Tests */
    struct flb_test_out_formatter test_formatter;
    struct flb_test_out_response test_response;

    /*
     * Buffer counter: it counts the total of disk space (filesystem) used by buffers
     */
    size_t fs_chunks_size;

    /*
     * Buffer counter: it counts the total of disk space (filesystem) awaiting to be
     * loaded (in backlog)
     */
    size_t fs_backlog_chunks_size;

    /*
     * Buffer limit: optional limit set by configuration so this output instance
     * cannot buffer more than total_limit_size (bytes unit).
     *
     * Note that this is the limit set to the filesystem buffer mechanism so the
     * input instance routered to this output plugin should configure to use
     * filesystem as buffer type.
     */
    size_t total_limit_size;

    /* Queue for singleplexed tasks */
    struct flb_task_queue *singleplex_queue;

    /* Thread Pool: this is optional for the caller */
    int tp_workers;
    struct flb_tp *tp;

    /* If the thread pool was created, this flag is turned on */
    int is_threaded;

    /* List of upstreams */
    struct mk_list upstreams;

    /*
     * flush context and co-routines
     * -----------------------------
     * Every invocation of flush() output callback runs under a co-routine, this
     * co-routine context (struct flb_coro) is wrapped inside the structure
     * 'flb_output_flush' which is added to the 'flush_list' linked list.
     *
     * In order to assign the coro 'id', we use the 'coro_id' incremental
     * counter to generate the next id. co-routine id's aims to be held
     * in 14 bits so the range goes from 0 to 16383.
     *
     * When the 'flush context' needs to be destroyed, it's moved out from the
     * 'flush_list' and placed into 'flush_list_destroy', a cleanup function will
     * destroy the remaining resources.
     *
     * note on multi-threading mode
     * ----------------------------
     * Every output instance in threaded mode has it own flush context which
     * has similar fields like 'coro_id', 'flush_list' and 'flush_list_destroy'.
     *
     * On that mode, field fields are not used.
     */
    int flush_id;
    struct mk_list flush_list;
    struct mk_list flush_list_destroy;

    flb_pipefd_t notification_channel;

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};

/*
 * [note] this has been renamed from flb_output_coro to flb_output_flush.
 *
 * This structure represents the context of a flush invocation with internal
 * information about the output instance being called plus other internal details.
 */
struct flb_output_flush {
    int id;                            /* out-thread ID      */
    const void *buffer;                /* output buffer      */
    struct flb_task *task;             /* Parent flb_task    */
    struct flb_config *config;         /* FLB context        */
    struct flb_output_instance *o_ins; /* output instance    */
    struct flb_coro *coro;             /* parent coro addr   */

    /*
     * if the original event_chunk has been processed, a new
     * temporary event_chunk is created, so the flush callback
     * receives new data.
     */
    struct flb_event_chunk *processed_event_chunk;

    struct mk_list _head;              /* Link to flb_task->threads */
};

static FLB_INLINE int flb_output_is_threaded(struct flb_output_instance *ins)
{
    return ins->is_threaded;
}

/* When an output_thread is going to be destroyed, this callback is triggered */
static FLB_INLINE void flb_output_flush_destroy(struct flb_output_flush *out_flush)
{
    flb_debug("[out flush] cb_destroy coro_id=%i", out_flush->id);

    mk_list_del(&out_flush->_head);
    flb_coro_destroy(out_flush->coro);
    flb_free(out_flush);
}

/*
 * libco do not support parameters in the entrypoint function due to the
 * complexity of implementation in terms of architecture and compiler, but
 * it provide a workaround using a global structure as a middle entry-point
 * that achieve the same stuff.
 */
struct flb_out_flush_params {
    struct flb_event_chunk *event_chunk;        /* event chunk           */
    struct flb_output_flush *out_flush;         /* output flush          */
    struct flb_input_instance *i_ins;           /* input instance        */
    struct flb_output_plugin *out_plugin;       /* output plugin context */
    void *out_context;                          /* custom plugin context */
    struct flb_config *config;                  /* Fluent Bit context    */
    struct flb_coro *coro;                      /* coroutine context     */
};

#ifndef FLB_HAVE_C_TLS
FLB_TLS_DECLARE(struct flb_out_flush_params, out_flush_params);
#else
extern FLB_TLS_DEFINE(struct flb_out_flush_params, out_flush_params);
#endif

#define FLB_OUTPUT_RETURN(x)                                            \
    flb_output_return_do(x);                                            \
    return

static inline void flb_output_return_do(int x);

static FLB_INLINE void output_params_set(struct flb_output_flush *out_flush,
                                         struct flb_coro *coro,
                                         struct flb_task *task,
                                         struct flb_output_plugin *out_plugin,
                                         void *out_context,
                                         struct flb_config *config)
{
    int s = sizeof(struct flb_out_flush_params);
    struct flb_out_flush_params *params;

    params = (struct flb_out_flush_params *) FLB_TLS_GET(out_flush_params);
    if (!params) {
        params = (struct flb_out_flush_params *) flb_malloc(s);
        if (!params) {
            flb_errno();
            return;
        }
    }

    /* Callback parameters in order */
    if (out_flush->processed_event_chunk) {
        params->event_chunk = out_flush->processed_event_chunk;
    }
    else {
        params->event_chunk = task->event_chunk;
    }
    params->out_flush   = out_flush;
    params->i_ins       = task->i_ins;
    params->out_context = out_context;
    params->config      = config;
    params->out_plugin  = out_plugin;
    params->coro        = coro;

    FLB_TLS_SET(out_flush_params, params);
    co_switch(coro->callee);
}

static FLB_INLINE void output_pre_cb_flush(void)
{
    int route_status;
    struct flb_coro *coro;
    struct flb_output_plugin *out_p;
    struct flb_out_flush_params *params;
    struct flb_out_flush_params persisted_params;

    params = (struct flb_out_flush_params *) FLB_TLS_GET(out_flush_params);
    if (!params) {
        flb_error("[output] no co-routines params defined, unexpected");
        return;
    }

    /*
     * Until this point the th->callee already set the variables, so we
     * wait until the core wanted to resume so we really trigger the
     * output callback.
     *
     * Persist params locally incase ptr data is changed while switched out.
     */
    coro = params->coro;
    persisted_params = *params;

    co_switch(coro->caller);

    /* Skip flush if type is FLB_EVENT_TYPE_LOGS and event chunk has zero records  */
    if (persisted_params.event_chunk &&
        persisted_params.event_chunk->type == FLB_EVENT_TYPE_LOGS &&
        persisted_params.event_chunk->total_events == 0) {
        flb_debug("[output] skipping flush for event chunk with zero records.");
        FLB_OUTPUT_RETURN(FLB_OK);
    }
    /* Skip flush if processed event chunk has no data (empty after processing) */
    else if (persisted_params.event_chunk &&
             persisted_params.event_chunk->type == FLB_EVENT_TYPE_METRICS &&
             persisted_params.event_chunk->size == 0) {
        flb_debug("[output] skipping flush for event chunk with no data after processing.");
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /* Continue, we will resume later */
    out_p = persisted_params.out_plugin;

    flb_task_acquire_lock(persisted_params.out_flush->task);

    route_status = flb_task_get_route_status(
                    persisted_params.out_flush->task,
                    persisted_params.out_flush->o_ins);

    if (route_status == FLB_TASK_ROUTE_DROPPED) {
        flb_task_release_lock(persisted_params.out_flush->task);

        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    flb_task_activate_route(persisted_params.out_flush->task,
                            persisted_params.out_flush->o_ins);

    flb_task_release_lock(persisted_params.out_flush->task);

    out_p->cb_flush(persisted_params.event_chunk,
                    persisted_params.out_flush,
                    persisted_params.i_ins,
                    persisted_params.out_context,
                    persisted_params.config);
}

void flb_output_flush_prepare_destroy(struct flb_output_flush *out_flush);
int flb_output_flush_id_get(struct flb_output_instance *ins);

static FLB_INLINE
struct flb_output_flush *flb_output_flush_create(struct flb_task *task,
                                                 struct flb_input_instance *i_ins,
                                                 struct flb_output_instance *o_ins,
                                                 struct flb_config *config)
{
    int ret;
    size_t records;
    void *p_buf = NULL;
    size_t p_size;
    size_t stack_size;
    struct flb_coro *coro;
    struct flb_output_flush *out_flush;
    struct flb_out_thread_instance *th_ins;
    struct flb_event_chunk *evc;
    struct flb_event_chunk *tmp;
    char *resized_serialization_buffer;
    size_t serialization_buffer_offset;
    cfl_sds_t serialized_profiles_context_buffer;
    char *serialized_context_buffer;
    size_t serialized_context_size;
    struct cmt *metrics_context;
    struct ctrace *trace_context;
    struct cprof *profile_context;
    size_t chunk_offset;
    struct cmt *encode_context = NULL;
    struct cmt *cmt_out_context = NULL;


    /* Custom output coroutine info */
    out_flush = (struct flb_output_flush *) flb_calloc(1, sizeof(struct flb_output_flush));
    if (!out_flush) {
        flb_errno();

        return NULL;
    }

    /* Create a new co-routine */
    coro = flb_coro_create(out_flush);
    if (!coro) {
        flb_free(out_flush);
        return NULL;
    }

    /*
     * Each co-routine receives an 'id', the value is always incremental up to
     * 16383.
     */
    out_flush->id     = flb_output_flush_id_get(o_ins);
    out_flush->o_ins  = o_ins;
    out_flush->task   = task;
    out_flush->buffer = task->event_chunk->data;
    out_flush->config = config;
    out_flush->coro   = coro;
    out_flush->processed_event_chunk = NULL;

    /* Logs processor */
    evc = task->event_chunk;

    if (flb_processor_is_active(o_ins->processor)) {
        if (evc->type == FLB_EVENT_TYPE_LOGS) {
            /* run the processor */
            ret = flb_processor_run(o_ins->processor,
                                    0,
                                    FLB_PROCESSOR_LOGS,
                                    evc->tag, flb_sds_len(evc->tag),
                                    evc->data, evc->size,
                                    &p_buf, &p_size);
            if (ret == -1) {
                flb_coro_destroy(coro);
                flb_free(out_flush);
                return NULL;
            }

            records = flb_mp_count(p_buf, p_size);
            tmp = flb_event_chunk_create(evc->type, records, evc->tag, flb_sds_len(evc->tag), p_buf, p_size);
            if (!tmp) {
                flb_coro_destroy(coro);
                flb_free(out_flush);
                flb_free(p_buf);
                return NULL;
            }
            out_flush->processed_event_chunk = tmp;
        }
        else if (evc->type == FLB_EVENT_TYPE_METRICS) {
            p_buf = flb_calloc(evc->size * 2, sizeof(char));

            if (p_buf == NULL) {
                flb_errno();
                flb_coro_destroy(coro);
                flb_free(out_flush);
                return NULL;
            }

            p_size = evc->size;

            chunk_offset = 0;
            serialization_buffer_offset = 0;

            while ((ret = cmt_decode_msgpack_create(
                            &metrics_context,
                            (char *) evc->data,
                            evc->size,
                            &chunk_offset)) == CMT_DECODE_MSGPACK_SUCCESS) {

                cmt_out_context = NULL;
                ret = flb_processor_run(o_ins->processor,
                                        0,
                                        FLB_PROCESSOR_METRICS,
                                        evc->tag,
                                        flb_sds_len(evc->tag),
                                        (char *) metrics_context,
                                        0,
                                        (void **)&cmt_out_context,
                                        NULL);

                if (ret == 0) {
                    if (cmt_out_context) {
                        encode_context = cmt_out_context;
                    }
                    else {
                        encode_context = metrics_context;
                    }

                    /* if the cmetrics context lacks time series just skip it */
                    if (flb_metrics_is_empty(encode_context)) {
                        if (encode_context != metrics_context) {
                            cmt_destroy(encode_context);
                        }
                        cmt_destroy(metrics_context);
                        continue;
                    }

                    if (cmt_out_context != NULL) {
                        ret = cmt_encode_msgpack_create(cmt_out_context,
                                                        &serialized_context_buffer,
                                                        &serialized_context_size);

                        if (cmt_out_context != metrics_context) {
                            cmt_destroy(cmt_out_context);
                        }
                    }
                    else {
                        ret = cmt_encode_msgpack_create(metrics_context,
                                                        &serialized_context_buffer,
                                                        &serialized_context_size);
                    }

                    cmt_destroy(metrics_context);

                    if (ret != 0) {
                        flb_coro_destroy(coro);
                        flb_free(out_flush);
                        flb_free(p_buf);
                        return NULL;
                    }

                    if ((serialization_buffer_offset + serialized_context_size) > p_size) {
                        resized_serialization_buffer = flb_realloc(p_buf, p_size + serialized_context_size);
                        if (resized_serialization_buffer == NULL) {
                            flb_errno();
                            cmt_encode_msgpack_destroy(serialized_context_buffer);
                            flb_coro_destroy(coro);
                            flb_free(out_flush);
                            flb_free(p_buf);
                            return NULL;
                        }

                        p_size += serialized_context_size;
                        p_buf = resized_serialization_buffer;
                    }

                    memcpy(&(((char *) p_buf)[serialization_buffer_offset]),
                           serialized_context_buffer,
                           serialized_context_size);

                    serialization_buffer_offset += serialized_context_size;

                    cmt_encode_msgpack_destroy(serialized_context_buffer);
                }
                else {
                    cmt_destroy(metrics_context);
                    if (cmt_out_context != NULL && cmt_out_context != metrics_context) {
                        cmt_destroy(cmt_out_context);
                    }
                    flb_coro_destroy(coro);
                    flb_free(out_flush);
                    flb_free(p_buf);
                    return NULL;
                }
            }

            if (serialization_buffer_offset == 0) {
                flb_debug("[output] skipping flush for metrics event chunk with zero metrics after processing.");
                flb_free(p_buf);
                p_buf = NULL; /* Mark as freed to avoid double-free */

                /* Create an empty processed event chunk to signal success */
                out_flush->processed_event_chunk = flb_event_chunk_create(
                                                    evc->type,
                                                    0,
                                                    evc->tag,
                                                    flb_sds_len(evc->tag),
                                                    NULL,
                                                    0);
            }
            else {
                p_size = serialization_buffer_offset;
                out_flush->processed_event_chunk = flb_event_chunk_create(
                                                    evc->type,
                                                    0,
                                                    evc->tag,
                                                    flb_sds_len(evc->tag),
                                                    p_buf,
                                                    p_size);
            }

            if (out_flush->processed_event_chunk == NULL) {
                flb_coro_destroy(coro);
                flb_free(out_flush);
                if (p_buf != NULL) {
                    flb_free(p_buf);
                }
                return NULL;
            }
        }
        else if (evc->type == FLB_EVENT_TYPE_TRACES) {
            p_buf = flb_calloc(evc->size * 2, sizeof(char));

            if (p_buf == NULL) {
                flb_errno();

                flb_coro_destroy(coro);
                flb_free(out_flush);

                return NULL;
            }

            p_size = evc->size;

            chunk_offset = 0;
            serialization_buffer_offset = 0;

            while ((ret = ctr_decode_msgpack_create(
                            &trace_context,
                            (char *) evc->data,
                            evc->size,
                            &chunk_offset)) == CTR_DECODE_MSGPACK_SUCCESS) {
                ret = flb_processor_run(o_ins->processor,
                                        0,
                                        FLB_PROCESSOR_TRACES,
                                        evc->tag,
                                        flb_sds_len(evc->tag),
                                        (char *) trace_context,
                                        0,
                                        NULL,
                                        NULL);

                if (ret == 0) {
                    ret = ctr_encode_msgpack_create(trace_context,
                                                    &serialized_context_buffer,
                                                    &serialized_context_size);

                    ctr_destroy(trace_context);

                    if (ret != 0) {
                        flb_coro_destroy(coro);
                        flb_free(out_flush);
                        flb_free(p_buf);

                        return NULL;
                    }

                    if ((serialization_buffer_offset +
                         serialized_context_size) > p_size) {
                        resized_serialization_buffer = \
                            flb_realloc(p_buf, p_size + serialized_context_size);

                        if (resized_serialization_buffer == NULL) {
                            flb_errno();

                            ctr_encode_msgpack_destroy(serialized_context_buffer);
                            flb_coro_destroy(coro);
                            flb_free(out_flush);
                            flb_free(p_buf);

                            return NULL;
                        }

                        p_size += serialized_context_size;
                        p_buf = resized_serialization_buffer;
                    }

                    memcpy(&(((char *) p_buf)[serialization_buffer_offset]),
                           serialized_context_buffer,
                           serialized_context_size);

                    serialization_buffer_offset += serialized_context_size;

                    ctr_encode_msgpack_destroy(serialized_context_buffer);
                }
            }

            if (serialization_buffer_offset == 0) {
                flb_coro_destroy(coro);
                flb_free(out_flush);
                flb_free(p_buf);

                return NULL;
            }

            out_flush->processed_event_chunk = flb_event_chunk_create(
                                                evc->type,
                                                0,
                                                evc->tag,
                                                flb_sds_len(evc->tag),
                                                p_buf,
                                                p_size);

            if (out_flush->processed_event_chunk == NULL) {
                flb_coro_destroy(coro);
                flb_free(out_flush);
                flb_free(p_buf);

                return NULL;
            }
        }
        else if (evc->type == FLB_EVENT_TYPE_PROFILES) {
            p_buf = flb_calloc(evc->size * 2, sizeof(char));

            if (p_buf == NULL) {
                flb_errno();

                flb_coro_destroy(coro);
                flb_free(out_flush);

                return NULL;
            }

            p_size = evc->size;

            chunk_offset = 0;
            serialization_buffer_offset = 0;

            while ((ret = cprof_decode_msgpack_create(
                            &profile_context,
                            (unsigned char *) evc->data,
                            evc->size,
                            &chunk_offset)) == CPROF_DECODE_MSGPACK_SUCCESS) {
                ret = flb_processor_run(o_ins->processor,
                                        0,
                                        FLB_PROCESSOR_PROFILES,
                                        evc->tag,
                                        flb_sds_len(evc->tag),
                                        (char *) profile_context,
                                        0,
                                        NULL,
                                        NULL);

                if (ret == 0) {
                    ret = cprof_encode_msgpack_create(&serialized_profiles_context_buffer,
                                                      profile_context);

                    cprof_destroy(profile_context);

                    if (ret != 0) {
                        flb_coro_destroy(coro);
                        flb_free(out_flush);
                        flb_free(p_buf);

                        return NULL;
                    }

                    if ((serialization_buffer_offset +
                         cfl_sds_len(serialized_profiles_context_buffer)) > p_size) {
                        resized_serialization_buffer = \
                            flb_realloc(p_buf, p_size + cfl_sds_len(serialized_profiles_context_buffer));

                        if (resized_serialization_buffer == NULL) {
                            flb_errno();

                            cprof_encode_msgpack_destroy(serialized_profiles_context_buffer);
                            flb_coro_destroy(coro);
                            flb_free(out_flush);
                            flb_free(p_buf);

                            return NULL;
                        }

                        p_size += cfl_sds_len(serialized_profiles_context_buffer);
                        p_buf = resized_serialization_buffer;
                    }

                    memcpy(&(((char *) p_buf)[serialization_buffer_offset]),
                           serialized_profiles_context_buffer,
                           cfl_sds_len(serialized_profiles_context_buffer));

                    serialization_buffer_offset += cfl_sds_len(serialized_profiles_context_buffer);

                    cprof_encode_msgpack_destroy(serialized_profiles_context_buffer);
                }
            }

            if (serialization_buffer_offset == 0) {
                flb_coro_destroy(coro);
                flb_free(out_flush);
                flb_free(p_buf);

                return NULL;
            }

            out_flush->processed_event_chunk = flb_event_chunk_create(
                                                evc->type,
                                                0,
                                                evc->tag,
                                                flb_sds_len(evc->tag),
                                                p_buf,
                                                p_size);

            if (out_flush->processed_event_chunk == NULL) {
                flb_coro_destroy(coro);
                flb_free(out_flush);
                flb_free(p_buf);

                return NULL;
            }
        }
    }

    coro->caller = co_active();
    coro->callee = co_create(config->coro_stack_size,
                             output_pre_cb_flush, &stack_size);

    if (coro->callee == NULL) {
        flb_coro_destroy(coro);
        if (out_flush->processed_event_chunk) {
            flb_free(out_flush->processed_event_chunk->data);
            flb_event_chunk_destroy(out_flush->processed_event_chunk);
        }
        flb_free(out_flush);
        return NULL;
    }

#ifdef FLB_HAVE_VALGRIND
    coro->valgrind_stack_id = \
        VALGRIND_STACK_REGISTER(coro->callee, ((char *) coro->callee) + stack_size);
#endif

    if (o_ins->is_threaded == FLB_TRUE) {
        th_ins = flb_output_thread_instance_get();

        pthread_mutex_lock(&th_ins->flush_mutex);
        mk_list_add(&out_flush->_head, &th_ins->flush_list);
        pthread_mutex_unlock(&th_ins->flush_mutex);
    }
    else {
        mk_list_add(&out_flush->_head, &o_ins->flush_list);
    }

    /* Workaround for makecontext() */
    output_params_set(out_flush, coro, task, o_ins->p, o_ins->context, config);
    return out_flush;
}

/*
 * This function is used by the output plugins to return. It's mandatory
 * as it will take care to signal the event loop letting know the flush
 * callback has done.
 *
 * The signal emmited indicate the 'Task' number that have finished plus
 * a return value. The return value is either FLB_OK, FLB_RETRY or FLB_ERROR.
 */
static inline void flb_output_return(int ret, struct flb_coro *co) {
    int n;
    int pipe_fd;
    uint32_t set;
    uint64_t val;
    struct flb_task *task;
    struct flb_output_flush *out_flush;
    struct flb_output_instance *o_ins;
    struct flb_out_thread_instance *th_ins = NULL;

    out_flush = (struct flb_output_flush *) co->data;
    o_ins = out_flush->o_ins;
    task = out_flush->task;

    flb_task_acquire_lock(task);

    flb_task_deactivate_route(task, o_ins);

    flb_task_release_lock(task);

#ifdef FLB_HAVE_CHUNK_TRACE
    if (task->event_chunk) {
        if (task->event_chunk->trace) {
             flb_chunk_trace_output(task->event_chunk->trace, o_ins, ret);
        }
    }
#endif

    if (out_flush->processed_event_chunk) {

        if (task->event_chunk->data != out_flush->processed_event_chunk->data) {
            flb_free(out_flush->processed_event_chunk->data);
        }

        flb_event_chunk_destroy(out_flush->processed_event_chunk);
        out_flush->processed_event_chunk = NULL;
    }

    /*
     * To compose the signal event the relevant info is:
     *
     * - Unique Task events id: 2 in this case
     * - Return value: FLB_OK (0), FLB_ERROR (1) or FLB_RETRY (2)
     * - Task ID
     * - Output Instance ID (struct flb_output_instance)->id
     *
     * We put together the return value with the task_id on the 32 bits at right
     */
    set = FLB_TASK_SET(ret, task->id, o_ins->id);
    val = FLB_BITS_U64_SET(2 /* FLB_ENGINE_TASK */, set);

    /*
     * Set the target pipe channel: if this return code is running inside a
     * thread pool worker, use the specific worker pipe/event loop to handle
     * the return status, otherwise use the channel connected to the parent
     * event loop.
     */
    if (flb_output_is_threaded(o_ins) == FLB_TRUE) {
        /* Retrieve the thread instance and prepare pipe channel */
        th_ins = flb_output_thread_instance_get();
        pipe_fd = th_ins->ch_thread_events[1];
    }
    else {
        pipe_fd = out_flush->o_ins->ch_events[1];
    }

    /* Notify the event loop about our return status */
    n = flb_pipe_w(pipe_fd, (void *) &val, sizeof(val));
    if (n == -1) {
        flb_pipe_error();
    }

    /*
     * Prepare the co-routine to be destroyed: real-destroy happens in the
     * event loop cleanup functions.
     */
    flb_output_flush_prepare_destroy(out_flush);
}

/* return the number of co-routines running in the instance */
static inline int flb_output_coros_size(struct flb_output_instance *ins)
{
    int size = 0;

    if (flb_output_is_threaded(ins) == FLB_TRUE) {
        /*
         * On threaded mode, we need to count the active co-routines of
         * every running thread of the thread pool.
         */
        size = flb_output_thread_pool_coros_size(ins);
    }
    else {
        size = mk_list_size(&ins->flush_list);
    }

    return size;
}

static inline void flb_output_return_do(int x)
{
    struct flb_coro *coro;

    coro = flb_coro_get();
    flb_output_return(x, coro);
    /*
     * Each co-routine handler have different ways to handle a return,
     * just use the wrapper.
     */
    flb_coro_yield(coro, FLB_TRUE);
}

#define FLB_OUTPUT_RETURN(x)                                            \
    flb_output_return_do(x);                                            \
    return

static inline int flb_output_config_map_set(struct flb_output_instance *ins,
                                            void *context)
{
    int ret;

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

    /* OAuth2 properties are validated but not automatically applied here.
     * Plugins should call flb_config_map_set() with &ctx->oauth2_config
     * in their init callback after calling flb_output_config_map_set(). */

    return 0;
}

int flb_output_help(struct flb_output_instance *ins, void **out_buf, size_t *out_size);

struct flb_output_instance *flb_output_get_instance(struct flb_config *config,
                                                    int out_id);
int flb_output_flush_finished(struct flb_config *config, int out_id);

int flb_output_task_singleplex_enqueue(struct flb_task_queue *queue,
                                       struct flb_task_retry *retry,
                                       struct flb_task *task,
                                       struct flb_output_instance *out_ins,
                                       struct flb_config *config);
int flb_output_task_singleplex_flush_next(struct flb_task_queue *queue);
struct flb_output_instance *flb_output_new(struct flb_config *config,
                                           const char *output, void *data,
                                           int public_only);
const char *flb_output_name(struct flb_output_instance *in);
int flb_output_set_property(struct flb_output_instance *out,
                            const char *k, const char *v);
const char *flb_output_get_property(const char *key, struct flb_output_instance *ins);
#ifdef FLB_HAVE_METRICS
void *flb_output_get_cmt_instance(struct flb_output_instance *ins);
#endif
void flb_output_net_default(const char *host, int port,
                            struct flb_output_instance *ins);
int flb_output_enable_multi_threading(struct flb_output_instance *ins,
                                      struct flb_config *config);
const char *flb_output_name(struct flb_output_instance *ins);
void flb_output_pre_run(struct flb_config *config);
void flb_output_exit(struct flb_config *config);
void flb_output_set_context(struct flb_output_instance *ins, void *context);
int flb_output_instance_destroy(struct flb_output_instance *ins);
int flb_output_net_property_check(struct flb_output_instance *ins,
                                  struct flb_config *config);
int flb_output_oauth2_property_check(struct flb_output_instance *ins,
                                      struct flb_config *config);
int flb_output_plugin_property_check(struct flb_output_instance *ins,
                                     struct flb_config *config);
int flb_output_init_all(struct flb_config *config);
int flb_output_check(struct flb_config *config);
int flb_output_log_check(struct flb_output_instance *ins, int l);

int flb_output_upstream_set(struct flb_upstream *u, struct flb_output_instance *ins);
int flb_output_upstream_ha_set(void *ha, struct flb_output_instance *ins);

void flb_output_prepare();
int flb_output_set_http_debug_callbacks(struct flb_output_instance *ins);

int flb_output_task_flush(struct flb_task *task,
                          struct flb_output_instance *out_ins,
                          struct flb_config *config);

struct mk_list *flb_output_get_global_config_map(struct flb_config *config);

#endif
